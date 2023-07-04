package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

func approvedSecretList(c *cli.Context) error {
	client, err := getClient(c)
	if err != nil {
		return errors.Wrap(err, "failed to get vault client")
	}

	vaultPath := "approved-secrets/roles"
	secret, err := client.Logical().List(vaultPath)
	if err != nil {
		return errors.Wrapf(err, "failed to list vault-path %q", vaultPath)
	} else if secret == nil {
		return nil
	}

	filter := c.String("filter")
	reg, err := regexp.Compile(filter)
	if err != nil {
		return errors.Wrapf(err, "failed to compile regexp: %s", filter)
	}

	keys := secret.Data["keys"].([]interface{})
	for _, key := range keys {
		if reg.MatchString(key.(string)) {
			fmt.Println(key)
		}
	}

	return nil
}

func approvedSecretRequest(c *cli.Context) error {
	client, err := getClient(c)
	if err != nil {
		return errors.Wrap(err, "failed to get vault client")
	}

	data := map[string]interface{}{
		"reason": c.String("reason"),
	}

	role := c.String("role")
	vaultPath := path.Join("approved-secrets/request", role)
	secret, err := client.Logical().Write(vaultPath, data)
	if err != nil {
		return errors.Wrapf(err, "failed to write vault-path %q", vaultPath)
	} else if secret == nil {
		return nil
	}

	for key, val := range secret.Data {
		if val == nil {
			fmt.Printf("%s: n/a\n", key)
		} else {
			fmt.Printf("%s: %s\n", key, val)
		}
	}

	fmt.Printf("Approval: vault-helper asa -role %s -nonce %s\n", role, secret.Data["nonce"])
	fmt.Printf("Issue: vault-helper asi -role %s -nonce %s\n", role, secret.Data["nonce"])

	return nil
}

func approvedSecretApprove(c *cli.Context) error {
	client, err := getClient(c)
	if err != nil {
		return errors.Wrap(err, "failed to get vault client")
	}

	data := map[string]interface{}{
		"nonce": c.String("nonce"),
	}

	vaultPath := path.Join("approved-secrets/approve", c.String("role"))
	secret, err := client.Logical().Write(vaultPath, data)
	if err != nil {
		return errors.Wrapf(err, "failed to write vault-path %q", vaultPath)
	} else if secret == nil {
		return nil
	}

	for key, val := range secret.Data {
		if val == nil {
			fmt.Printf("%s: n/a\n", key)
		} else {
			fmt.Printf("%s: %s\n", key, val)
		}
	}

	return nil
}

func approvedSecretIssue(ctx *cli.Context) error {

	clt, err := getClient(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to get vault client")
	}

	data := map[string]interface{}{
		"nonce": ctx.String("nonce"),
	}

	// Forward addition arguments in format key=value. For example:
	// vault-helper si -role app-prd-ssh -nonce 0adf330c-fb1d-7977-4b9b-75745aaadde7 public_key=@/home/user/.ssh/id_rsa.pub
	for _, arg := range ctx.Args().Slice() {
		kv := strings.SplitN(arg, "=", 2)
		if len(kv) != 2 {
			return errors.Errorf("expected key=val, got: %s", arg)
		}

		if strings.HasPrefix(kv[1], "@") {
			content, err := ioutil.ReadFile(strings.TrimPrefix(kv[1], "@"))
			if err != nil {
				return errors.Wrapf(err, "could not read file: %s", kv[1])
			}
			kv[1] = string(content)
		}

		data[kv[0]] = kv[1]
	}

	role := ctx.String("role")
	roleData, err := approvedSecretReadRole(clt, role)
	if err != nil {
		return errors.Wrapf(err, "failed to get secret_type from role")
	}

	switch roleData["secret_type"].(string) {
	case "ssh":
		return approvedSecretIssueSSH(ctx, clt, data)
	case "eks":
		return approvedSecretIssueEKS(ctx, clt, data, roleData)
	case "vault-token":
		return approvedSecretIssueVaultToken(ctx, clt, data)
	case "aws":
		return approvedSecretIssueAWS(ctx, clt, data, roleData)
	case "nexus":
		return approvedSecretIssueNexus(ctx, clt, data)
	default:
		return approvedSecretIssueDefault(ctx, clt, data)
	}
}

func approvedSecretIssueAWS(ctx *cli.Context, clt *api.Client, data map[string]interface{}, roleData map[string]interface{}) error {

	role := ctx.String("role")
	secret, err := approvedSecretWriteIssue(clt, role, data)
	if err != nil {
		return err
	}

	homedir, _ := getHomeDir()
	dotPath := filepath.Join(homedir, ".aws")
	if _, err := os.Stat(dotPath); os.IsNotExist(err) {
		err = os.MkdirAll(dotPath, 0700)
		if err != nil {
			return errors.Wrapf(err, "failed to make dir %q", dotPath)
		}
	}

	credsPath := filepath.Join(dotPath, "credentials")
	if _, err := os.Stat(credsPath); os.IsNotExist(err) {
		file, err := os.OpenFile(credsPath, os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return errors.Wrapf(err, "failed to create file %q", credsPath)
		}
		file.Close()
	}

	creds, err := newAWSCredentials(credsPath)
	if err != nil {
		return errors.Wrapf(err, "failed to create AWS credentials from %q", credsPath)
	}

	accessKey := secret["access_key"].(string)
	secretKey := secret["secret_key"].(string)
	sessionToken := secret["security_token"].(string)

	signinURL, err := createSigninURL(accessKey, secretKey, sessionToken)
	if err != nil {
		return errors.Wrap(err, "failed to create signin URL")
	}

	account := roleData["secret_environment"].(string)
	p := awsProfile{header: "[yolt-" + account + "]",
		entries: []string{
			"aws_access_key_id = " + accessKey,
			"aws_secret_access_key = " + secretKey,
			"aws_session_token = " + sessionToken,
			"region = " + ctx.String("region"),
			"signin_url = " + signinURL,
			"sts_regional_endpoints = regional",
		}}

	statePath, err := getStatePath(ctx)
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

	tfStateRole := roleData["secret_aws_state_role"].(string)

	stateProfile := awsProfile{header: "[yolt-state]",
		entries: []string{
			"source_profile = yolt-" + account,
			"role_arn = arn:aws:iam::495023470469:role/" + tfStateRole,
			"role_session_name = " + tfStateRole + "-" + state.Username,
			"duration_seconds = 3600",
		}}

	creds.setProfile(p)
	creds.setProfile(stateProfile)

	if err = creds.store(); err != nil {
		return errors.Wrapf(err, "failed to store AWS credentials: %s", creds.path)
	}

	fmt.Printf("Signin URL:\n%s\n\n", signinURL)
	fmt.Printf("Credentials are added to profile %q in %s.\n", "yolt-"+account, credsPath)

	return nil
}

func approvedSecretIssueEKS(ctx *cli.Context, clt *api.Client, data, roleData map[string]interface{}) error {

	role := ctx.String("role")
	secret, err := approvedSecretWriteIssue(clt, role, data)
	if err != nil {
		return err
	}

	homedir, _ := getHomeDir()
	dotPath := filepath.Join(homedir, ".aws")
	if _, err := os.Stat(dotPath); os.IsNotExist(err) {
		err = os.MkdirAll(dotPath, 0700)
		if err != nil {
			return errors.Wrapf(err, "failed to make dir %q", dotPath)
		}
	}

	credsPath := filepath.Join(dotPath, "credentials")
	if _, err := os.Stat(credsPath); os.IsNotExist(err) {
		file, err := os.OpenFile(credsPath, os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return errors.Wrapf(err, "failed to create file %q", credsPath)
		}
		file.Close()
	}

	accessKey := secret["access_key"].(string)
	secretKey := secret["secret_key"].(string)
	sessionToken := secret["security_token"].(string)

	region := ctx.String("region")
	account := roleData["secret_environment"].(string)
	profileName := "yolt-eks-" + account

	p := awsProfile{header: "[" + profileName + "]",
		entries: []string{
			"aws_access_key_id = " + accessKey,
			"aws_secret_access_key = " + secretKey,
			"aws_session_token = " + sessionToken,
			"region = " + region,
		}}

	creds, err := newAWSCredentials(credsPath)
	if err != nil {
		return errors.Wrapf(err, "failed to create AWS credentials from %q", credsPath)
	}

	creds.setProfile(p)
	if err = creds.store(); err != nil {
		return errors.Wrapf(err, "failed to store AWS credentials: %s", creds.path)
	}

	fmt.Printf("EKS credentials are added to profile %q in %s.\n", profileName, credsPath)

	sess, err := session.NewSessionWithOptions(session.Options{
		Profile: profileName,
		Config: aws.Config{
			Region: aws.String(region),
		},
	})

	eksSvc := eks.New(sess)
	eksCluster, err := eksSvc.DescribeCluster(&eks.DescribeClusterInput{Name: &account})
	if err != nil {
		return errors.Wrapf(err, "failed to eks:DescribeCluster with profile %q", profileName)
	}

	statePath, err := getStatePath(ctx)
	if err != nil {
		return errors.Wrapf(err, "failed to get state path")
	}

	r := stateFileReader{statePath: statePath}
	state, err := loadState(r)
	if err != nil {
		return errors.Wrap(err, "failed to load state")
	}

	home, _ := getHomeDir()
	configPath := filepath.Join(home, ".kube", "config")
	namespace := getEKSContextNamespace(state.Role)
	if err = createOrUpdateEKSContext(eksCluster.Cluster, configPath, region, namespace); err != nil {
		return errors.Wrapf(err, "failed to update kubeconfig for EKS")
	}

	// Delete old cached token, if any.
	delete(state.EKS, profileName)

	if err = saveState(statePath, state); err != nil {
		return errors.Wrapf(err, "failed to save state")
	}

	fmt.Printf("kubectl config use-context %s\n", *eksCluster.Cluster.Name)

	return nil
}

func approvedSecretIssueVaultToken(ctx *cli.Context, clt *api.Client, data map[string]interface{}) error {

	role := ctx.String("role")
	secret, err := approvedSecretWriteIssue(clt, role, data)
	if err != nil {
		return err
	}

	token, ok := secret["client_token"].(string)
	if !ok {
		return errors.New("expected client_token")
	}

	helper, err := newTokenHelper(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to create token helper")
	}

	err = helper.Store(token)
	if err != nil {
		return errors.Wrap(err, "failed to store token")
	}

	duration, ok := secret["lease_duration"].(json.Number)
	if !ok {
		return errors.New("expected lease_duration")
	}

	num, _ := duration.Int64()
	fmt.Printf("Token stored: %s\n", helper.Path())
	fmt.Printf("Expires: %v\n", time.Duration(num)*time.Second)
	fmt.Printf("Accessor: %v\n", secret["accessor"])
	return nil
}

func approvedSecretIssueDefault(ctx *cli.Context, clt *api.Client, data map[string]interface{}) error {

	role := ctx.String("role")
	secret, err := approvedSecretWriteIssue(clt, role, data)
	if err != nil {
		return err
	}

	format := ctx.String("format")
	if format == "json" {
		b, _ := json.Marshal(secret)
		var out bytes.Buffer
		json.Indent(&out, b, "", "\t")
		fmt.Printf(out.String())
	} else {
		for key, val := range secret {
			fmt.Printf("%s: %v\n", key, val)
		}
	}

	return nil
}

func approvedSecretIssueSSH(ctx *cli.Context, clt *api.Client, data map[string]interface{}) error {

	home, _ := getHomeDir()
	var publicKeyPath, publicKeyType string
	var err error
	if data["public_key"] == nil {
		sshKeyDir := filepath.Join(home, ".ssh")
		publicKeyPath, publicKeyType, err = findPublicKey(sshKeyDir)
		if err != nil {
			return errors.Wrapf(err, "could not find a valid ssh key in %s", sshKeyDir)
		}
		content, err := ioutil.ReadFile(publicKeyPath)
		if err != nil {
			return errors.Wrapf(err, "could not read file: %s", publicKeyPath)
		}

		data["public_key"] = string(content)
	}

	role := ctx.String("role")
	var envMatcher = regexp.MustCompile(`-ssh$`)
	env := envMatcher.ReplaceAllString(role, "")

	secret, err := approvedSecretWriteIssue(clt, role, data)
	if err != nil {
		return err
	}

	signedKey := secret["signed_key"].(string)
	certPath := filepath.Join(home, ".ssh", fmt.Sprintf("id_%s_%s.pub", publicKeyType, env))
	if err = writeFile(certPath, strings.Trim(signedKey, "\n")); err != nil {
		return errors.Wrapf(err, "failed to write file: %s", certPath)
	}

	fmt.Printf("Wrote signed key to %s\n", certPath)

	return nil
}

func approvedSecretIssueNexus(ctx *cli.Context, clt *api.Client, data map[string]interface{}) error {

	role := ctx.String("role")
	secret, err := approvedSecretWriteIssue(clt, role, data)
	if err != nil {
		return err
	}

	userId := secret["user_id"].(string)
	password := secret["password"].(string)
	ttl := secret["ttl"].(string)

	roles := []string{}
	rolesRaw := secret["roles"].([]interface{})
	for _, roleRaw := range rolesRaw {
		roles = append(roles, roleRaw.(string))
	}

	fmt.Printf("username:  %s\n", userId)
	fmt.Printf("password:  %s\n", password)
	fmt.Printf("ttl:       %s\n", ttl)
	fmt.Printf("roles:     %s\n", roles)
	return nil
}

func approvedSecretReadRole(clt *api.Client, role string) (map[string]interface{}, error) {

	vaultPath := path.Join("approved-secrets/roles", role)
	secret, err := clt.Logical().Read(vaultPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to write vault-path %q", vaultPath)
	} else if secret == nil {
		return nil, errors.Errorf("no such role: %s", role)
	}

	return secret.Data, nil
}

func approvedSecretWriteIssue(clt *api.Client, role string, data map[string]interface{}) (map[string]interface{}, error) {

	nonce, ok := data["nonce"].(string)
	if !ok {
		return nil, errors.New("expected nonce in data")
	}

	vaultPath := path.Join("approved-secrets/issue", role, nonce)
	secret, err := clt.Logical().Write(vaultPath, data)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to write vault-path %q", vaultPath)
	} else if secret == nil {
		return nil, errors.Errorf("failed to issue secret from vault-path: %q", vaultPath)
	}

	return secret.Data, nil
}

func findPublicKey(keydir string) (string, string, error) {
	types := []string{"rsa", "ed25519", "ecdsa", "dsa"}
	for _, keyType := range types {
		path := filepath.Join(keydir, fmt.Sprintf("id_%s.pub", keyType))
		if _, err := os.Stat(path); err == nil {
			return path, keyType, nil
		}
	}
	return "", "", errors.New(fmt.Sprintf("failed to find ssh key of types %s", types))
}
