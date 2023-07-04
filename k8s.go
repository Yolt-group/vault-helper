package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

func k8s(c *cli.Context) error {
	statePath, err := getStatePath(c)
	if err != nil {
		return errors.Wrapf(err, "failed to get state path")
	}

	r := stateFileReader{statePath: statePath}
	state, err := loadState(r)
	if err != nil {
		return errors.Wrap(err, "failed to load state")
	}

	if state.Role == "" {
		return errors.New("failed to get role from state file, please run 'vault-helper login' first")
	}

	cluster := c.String("cluster")
	region := c.String("region")

	err = createOrUpdateEKSProfile(c, cluster, region, state.Role)
	if err != nil {
		return errors.Wrap(err, "failed to create AWS profile")
	}

	profile := fmt.Sprintf("yolt-eks-%s", cluster)
	sess, err := session.NewSessionWithOptions(session.Options{
		Profile: profile,
		Config: aws.Config{
			Region: aws.String(region),
		},
	})

	eksSvc := eks.New(sess)
	eksCluster, err := eksSvc.DescribeCluster(&eks.DescribeClusterInput{Name: &cluster})
	if err != nil {
		return errors.Wrapf(err, "failed to eks:DescribeCluster with profile %q", profile)
	}

	filePath := c.String("path")
	configPath := filepath.Join(filePath, "config")
	namespace := c.String("namespace")
	if namespace == "" {
		namespace = getEKSContextNamespace(state.Role)
	}

	if err = createOrUpdateEKSContext(eksCluster.Cluster, configPath, region, namespace); err != nil {
		return errors.Wrapf(err, "failed to update kubeconfig for EKS")
	}

	statePath, err = getStatePath(c)
	if err != nil {
		return errors.Wrapf(err, "failed to get state path")
	}

	// Delete old cached token, if any.
	delete(state.EKS, profile)

	if err = saveState(statePath, state); err != nil {
		return errors.Wrapf(err, "failed to save state")
	}

	fmt.Printf("kubectl config use-context %s\n", *eksCluster.Cluster.Name)
	if !isDefaultKubeConfigPath(filePath) {
		fmt.Printf("Add the '--kubeconfig=%s' option to all your kubectl commands to use this config\n", configPath)
	}

	return nil
}

func getEKSContextNamespace(stateRole string) string {

	switch stateRole {
	case "sre", "security":
		return "infra"
	case "dataplatform", "datascience":
		return "dataplatform"
	case "devops", "platform":
		return "ycs"
	}

	return "default"
}

func createOrUpdateEKSContext(cluster *eks.Cluster, configPath, region, namespace string) error {
	ca, err := base64.StdEncoding.DecodeString(aws.StringValue(cluster.CertificateAuthority.Data))
	if err != nil {
		return err
	}
	loadingRules := clientcmd.ClientConfigLoadingRules{
		Precedence: []string{configPath},
	}
	config, err := loadingRules.Load()
	if err != nil {
		return err
	}

	clusterConfig := config.Clusters[*cluster.Name]
	if clusterConfig == nil {
		clusterConfig = api.NewCluster()
	}

	clusterConfig.Server = aws.StringValue(cluster.Endpoint)
	clusterConfig.CertificateAuthorityData = ca
	clusterConfig.LocationOfOrigin = configPath

	authInfo := config.AuthInfos[*cluster.Arn]
	if authInfo == nil {
		authInfo = api.NewAuthInfo()
	}

	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}

	authInfo.LocationOfOrigin = configPath
	authInfo.Exec = &api.ExecConfig{
		APIVersion: "client.authentication.k8s.io/v1beta1",
		Command:    ex,
		Args:       []string{"eks-token", "-cluster", *cluster.Name, "-region", region},
		Env: []api.ExecEnvVar{
			{
				Name:  "AWS_PROFILE",
				Value: "yolt-eks-" + *cluster.Name,
			},
		},
	}

	context := config.Contexts[*cluster.Name]
	if context == nil {
		context = api.NewContext()
	}
	context.LocationOfOrigin = configPath
	context.Cluster = *cluster.Name
	context.AuthInfo = *cluster.Arn
	context.Namespace = namespace

	config.Clusters[*cluster.Name] = clusterConfig
	config.AuthInfos[*cluster.Arn] = authInfo
	config.Contexts[*cluster.Name] = context

	config.CurrentContext = *cluster.Name

	configAccess := newPathOptions(configPath)
	if err := clientcmd.ModifyConfig(configAccess, *config, true); err != nil {
		return err
	}

	return nil
}

func newPathOptions(path string) *clientcmd.PathOptions {
	return &clientcmd.PathOptions{
		GlobalFile:   path,
		LoadingRules: clientcmd.NewDefaultClientConfigLoadingRules(),
	}
}

func getDefaultKubeConfigPath() string {
	homedir, _ := getHomeDir()
	return filepath.Join(homedir, ".kube")
}

func isDefaultKubeConfigPath(path string) bool {
	return path == getDefaultKubeConfigPath()
}

func createOrUpdateEKSProfile(c *cli.Context, cluster string, region string, role string) error {

	ttl := c.String("ttl")
	client, err := getClient(c)
	if err != nil {
		return errors.Wrap(err, "failed to get vault client")
	}

	if c.String("role") != "" {
		role = c.String("role")
	}

	vaultPath := fmt.Sprintf("aws/sts/%s-eks-%s", cluster, role)
	data := map[string]interface{}{
		"ttl": ttl,
	}

	credsPath, err := getAWSCredsPath()
	if err != nil {
		return err
	}

	creds, err := newAWSCredentials(credsPath)
	if err != nil {
		return errors.Wrapf(err, "failed to create AWS credentials from %q", credsPath)
	}

	secret, err := client.Logical().Write(vaultPath, data)
	if err != nil {
		return err
	}

	accessKey := secret.Data["access_key"].(string)
	secretKey := secret.Data["secret_key"].(string)
	sessionToken := secret.Data["security_token"].(string)

	p := awsProfile{header: "[yolt-eks-" + cluster + "]",
		entries: []string{
			"aws_access_key_id = " + accessKey,
			"aws_secret_access_key = " + secretKey,
			"aws_session_token = " + sessionToken,
			"region = " + c.String("region"),
		}}

	creds.setProfile(p)

	if err = creds.store(); err != nil {
		return errors.Wrapf(err, "failed to store AWS credentials: %s", creds.path)
	}
	return nil
}
