package main

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	dockerConfig "github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/types"
)

const (
	ecrRole = "ecr-employees"
)

func ecrLogin(c *cli.Context) error {

	if c.Bool("docker-command") {
		return ecrLoginPrintDockerCommand(c)
	}

	secret, err := getAWSCreds(c)
	if err != nil {
		return err
	}

	ecrClient, err := getECRClient(secret)
	if err != nil {
		return err
	}

	ecrToken, err := ecrClient.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return err
	}

	dockerConfigDir, err := getDockerConfigDir()
	if err != nil {
		return err
	}

	dc, err := dockerConfig.Load(dockerConfigDir)
	if err != nil {
		return err
	}

	registry := *ecrToken.AuthorizationData[0].ProxyEndpoint
	fmt.Printf("Adding registry: %s to your docker config file: %s \n", registry, dc.Filename)

	var ecrAuth types.AuthConfig
	ecrAuth.Auth = *ecrToken.AuthorizationData[0].AuthorizationToken

	if !exists(dc.Filename) || dc.CredentialsStore == "" {
		username, password, err := decodeECRToken(ecrToken)
		if err != nil {
			return err
		}

		dc.AuthConfigs[registry] = types.AuthConfig{Username: username, Password: password}
		if dc.Save() != nil {
			return err
		}
	}

	dc.AuthConfigs[registry] = ecrAuth

	err = dc.Save()
	if err != nil {
		return err
	}

	fmt.Printf("You can start use your docker command with registry: %s\n", registry)

	return nil
}

func ecrLoginPrintDockerCommand(c *cli.Context) error {
	secret, err := getAWSCreds(c)
	if err != nil {
		return err
	}

	ecrClient, err := getECRClient(secret)
	if err != nil {
		return err
	}

	ecrToken, err := ecrClient.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return err
	}

	username, password, err := decodeECRToken(ecrToken)
	if err != nil {
		return err
	}

	registry := *ecrToken.AuthorizationData[0].ProxyEndpoint

	fmt.Printf("\ndocker login --username %s --password %s %s", username, password, registry)

	return nil
}

func getAWSCreds(c *cli.Context) (*api.Secret, error) {
	client, err := getClient(c)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get vault client")
	}

	target := c.String("target")
	vaultPath := fmt.Sprintf("aws/sts/management-%s-"+ecrRole, target)

	data := map[string]interface{}{}
	secret, err := client.Logical().Write(vaultPath, data)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to write to vault-path %q", vaultPath)
	}

	return secret, nil
}

func getECRClient(secret *api.Secret) (*ecr.ECR, error) {
	accessKey := secret.Data["access_key"].(string)
	secretKey := secret.Data["secret_key"].(string)
	sessionToken := secret.Data["security_token"].(string)

	awsSession, err := session.NewSession(&aws.Config{
		Region:      aws.String("eu-central-1"),
		Credentials: credentials.NewStaticCredentials(accessKey, secretKey, sessionToken),
	})

	if err != nil {
		return nil, err
	}

	return ecr.New(awsSession), nil
}

func decodeECRToken(ecrToken *ecr.GetAuthorizationTokenOutput) (username string, password string, err error) {
	decodedToken, err := base64.StdEncoding.DecodeString(*ecrToken.AuthorizationData[0].AuthorizationToken)
	if err != nil {
		return "", "", err
	}

	parts := strings.SplitN(string(decodedToken), ":", 2)
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid token: expected two parts, got %d", len(parts))
	}

	return parts[0], parts[1], nil
}
