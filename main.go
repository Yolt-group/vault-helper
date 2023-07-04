package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

const (
	minStateVersion = "0.1.3"
)

var (
	version = "20.0.0"
)

func convertConfigPath() error {

	home, _ := getHomeDir()
	oldStatePath := filepath.Join(home, ".vault-helper-state")
	oldTokenPath := filepath.Join(home, ".vault-token")
	if !(exists(oldStatePath) && exists(oldTokenPath)) {
		return nil
	}

	configPath := filepath.Join(home, ".vault-helper", "dta")
	err := os.MkdirAll(configPath, os.ModePerm)
	if err != nil {
		return errors.Wrapf(err, "failed to make config path: %s", configPath)
	}

	newStatePath := filepath.Join(configPath, "state")
	err = os.Rename(oldStatePath, newStatePath)
	if err != nil {
		return errors.Wrapf(err, "failed to move %s to %s", oldStatePath, newStatePath)
	}

	newTokenPath := filepath.Join(configPath, "token")
	err = os.Rename(oldTokenPath, newTokenPath)
	if err != nil {
		return errors.Wrapf(err, "failed to move %s to %s", oldTokenPath, newTokenPath)
	}

	return nil
}

func init() {
	log.SetFlags(0)
}

func main() {
	homedir, err := getHomeDir()
	if err != nil {
		log.Fatal(err)
	}

	err = convertConfigPath()
	if err != nil {
		log.Fatalf("failed to convert config path: %s", err)
	}

	app := cli.NewApp()
	app.Version = version
	app.Usage = "CLI for getting secrets from HashiCorp Vault"
	app.Description = "CLI for getting secrets from HasiCorp Vault and configuring client laptops for ephemeral access to Yolt's AWS resources"
	app.EnableBashCompletion = true

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "address",
			Aliases: []string{"a"},
			Usage:   "The Vault address",
			EnvVars: []string{"VAULT_ADDR"},
		},
	}

	app.Commands = []*cli.Command{
		{
			Name:    "login",
			Aliases: []string{"l"},
			Usage:   "Login to Vault using OIDC",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "role, r",
					Usage: "role to request",
				},
			},
			Action: checkError(
				validateNArg(loginer(), 0, 0)),
		},
		{
			Name:    "renew",
			Aliases: []string{"r"},
			Usage:   "Renew secrets",
			Action: checkError(
				requireAuth(
					validateNArg(renewer(), 0, 0))),
		},
		{
			Name:    "openvpn",
			Aliases: []string{"o"},
			Usage:   "Deprecated. Get OpenVPN client credentials and config",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "path",
					Usage: "store VPN certificates in `PATH`",
				},
				&cli.StringFlag{
					Name:  "target",
					Usage: "which target VPN (prd is default, dta is SRE only)",
				},
				&cli.BoolFlag{
					Name:  "tunnelblick",
					Usage: "generate configuration for TunnelBlick",
				},
			},
			Action: checkError(
				requireAuth(
					validateNArg(openvpn, 0, 0))),
		},
		{
			Name:    "eks-token",
			Aliases: []string{"t"},
			Usage:   "Get Kubernetes token",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "cluster",
					Usage: "target Kubernetes cluster (e.g. teamX, security-dta, security-prd, performance, yfb-acc, app-acc, app-prd, yfb-ext-prd, yfb-prd, yfb-sandbox, management-dta, management-prd)",
				},
				&cli.StringFlag{
					Name:  "region",
					Usage: "AWS region",
					Value: "eu-central-1",
				},
				&cli.StringFlag{
					Name:  "ttl",
					Usage: "TTL",
					Value: "12h",
				},
			},
			Action: checkError(
				requireAuth(
					validateMandatory(
						validateNArg(eksToken, 0, 0), "cluster"))),
		},
		{
			Name:    "k8s",
			Aliases: []string{"k"},
			Usage:   "Get Kubernetes client credentials and config",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "cluster",
					Usage: "target Kubernetes cluster (e.g. teamX, security-dta, security-prd, performance, yfb-acc, app-acc, app-prd, yfb-ext-prd, yfb-prd, yfb-sandbox, management-dta, management-prd)",
				},
				&cli.StringFlag{
					Name:  "path",
					Usage: "base path for Kubernetes config and apiserver certificates",
					Value: getDefaultKubeConfigPath(),
				},
				&cli.StringFlag{
					Name:  "role",
					Usage: "AWS role for EKS token",
				},
				&cli.BoolFlag{
					Name:  "no-cache",
					Usage: "do not use cached EKS token (useful when switching roles)",
					Value: false,
				},
				&cli.StringFlag{
					Name:  "region",
					Usage: "AWS region",
					Value: "eu-central-1",
				},
				&cli.StringFlag{
					Name:  "ttl",
					Usage: "TTL",
					Value: "12h",
				},
				&cli.StringFlag{
					Name:    "namespace",
					Aliases: []string{"ns"},
					Usage:   "Set namespace on kubeconfig context",
				},
			},
			Action: checkError(
				requireAuth(
					validatePath(
						validateMandatory(
							validateNArg(k8s, 0, 0), "path", "cluster")))),
		},
		{
			Name:    "aws",
			Aliases: []string{"a"},
			Usage:   "Get AWS STS credentials and config",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "account",
					Usage: "alias of target AWS account",
					Value: "root",
				},
				&cli.StringFlag{
					Name:  "ttl",
					Usage: "TTL of AWS credentials",
					Value: "12h",
				},
				&cli.StringFlag{
					Name:  "region",
					Usage: "AWS region",
					Value: "eu-central-1",
				},
				&cli.StringFlag{
					Name:  "role",
					Usage: "override role to assume when -rw flag is set",
				},
				&cli.BoolFlag{
					Name:  "rw",
					Usage: "set flag to enable read-write access",
					Value: false,
				},
				&cli.StringFlag{
					Name:  "tf-role",
					Usage: "specify different terraform state role to assume. Default: terraform-state-ro-<account>",
				},
			},
			Action: checkError(
				requireAuth(
					validateNArg(awsAccount, 0, 0))),
		},
		{
			Name:    "ssh",
			Aliases: []string{"s"},
			Usage:   "Get SSH client certificate and config",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "env",
					Usage: "target environment (e.g. teamX or integration)",
				},
				&cli.StringFlag{
					Name:  "path",
					Usage: "path for storing SSH certificate",
					Value: filepath.Join(homedir, ".ssh"),
				},
				&cli.StringFlag{
					Name:  "private-key",
					Usage: "path to private key",
					Value: filepath.Join(homedir, ".ssh", "id_rsa"),
				},
				&cli.StringFlag{
					Name:  "public-key",
					Usage: "path to public key for signing",
					Value: filepath.Join(homedir, ".ssh", "id_rsa.pub"),
				},
			},
			Action: checkError(
				requireAuth(
					validatePath(
						validateMandatory(
							validateNArg(ssh, 0, 0), "env")))),
		},
		{
			Name:  "kafka",
			Usage: "Get Kafka client super user credentials (SRE only)",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "env",
					Usage: "target environment (e.g. teamX or integration)",
				},
				&cli.StringFlag{
					Name:  "path",
					Usage: "path for storing credentials",
					Value: filepath.Join(homedir, ".kafka"),
				},
			},
			Action: checkError(
				requireAuth(
					validatePath(
						validateMandatory(
							validateNArg(kafka, 0, 0), "env")))),
		},
		{
			Name:    "cassa",
			Aliases: []string{"c"},
			Usage:   "Get Cassandra credentials for superuser (specific keyspaces with ro/rw access is under construction)",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "env",
					Usage: "target environment (e.g. teamX or integration)",
				},
				&cli.StringFlag{
					Name:  "role, r",
					Usage: "role to request (default: auth role for superuser)",
				},
				&cli.StringFlag{
					Name:  "format, f",
					Usage: "output format (default plain text, optional 'json' and 'env')",
					Value: "plain",
				},
			},
			Action: checkError(
				requireAuth(
					validateMandatory(
						validateNArg(databaseHandler("cassa"), 0, 0), "env"))),
		},
		{
			Name:  "rds",
			Usage: "Get RDS credentials",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "env",
					Usage: "target environment (e.g. teamX or integration)",
				},
				&cli.StringFlag{
					Name:  "instance",
					Usage: "database instance (default: rds)",
					Value: "rds",
				},
				&cli.StringFlag{
					Name:  "format, f",
					Usage: "output format (default: plain text, optional 'json' and 'env')",
					Value: "plain",
				},
				&cli.StringFlag{
					Name:  "path",
					Usage: "path to save the output (default: /tmp/rds)",
					Value: "/tmp/rds",
				},
				&cli.BoolFlag{
					Name:  "rw",
					Usage: "set flag to enable read-write access",
					Value: false,
				},
			},
			Action: checkError(
				requireAuth(
					validateMandatory(
						validateNArg(databaseHandler("rds"), 0, 0), "env"))),
		},
		{
			Name:    "elasticsearch",
			Aliases: []string{"e"},
			Usage:   "Get Elasticsearch credentials for superuser (specific keyspaces with ro/rw access is under construction)",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "env",
					Usage: "target environment (e.g. teamX or integration)",
				},
				&cli.StringFlag{
					Name:  "role, r",
					Usage: "role to request (default: auth role for superuser)",
				},
				&cli.StringFlag{
					Name:  "format, f",
					Usage: "output format (default plain text, optional 'json' and 'env')",
					Value: "plain",
				},
				&cli.StringFlag{
					Name:  "path",
					Usage: "path to save the output (default: /tmp/elasticsearch)",
					Value: "/tmp/elasticsearch",
				},
			},
			Action: checkError(
				requireAuth(
					validateMandatory(
						validateNArg(databaseHandler("elasticsearch"), 0, 0), "env"))),
		},
		{
			Name:    "approved-secret-list",
			Aliases: []string{"asl"},
			Usage:   "List high-privileged secret roles",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "filter, f",
					Value: ".+",
					Usage: "regex filter",
				},
			},
			Action: checkError(validateNArg(approvedSecretList, 0, 0)),
		},
		{
			Name:    "approved-secret-request",
			Aliases: []string{"asr"},
			Usage:   "Request high-privileged secret",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "role, r",
					Usage: "role to request",
				},
				&cli.StringFlag{
					Name:  "reason",
					Usage: "reason for requesting secret",
				},
			},
			Action: checkError(
				validateMandatory(
					validateNArg(approvedSecretRequest, 0, 0), "role", "reason")),
		},
		{
			Name:    "approved-secret-approve",
			Aliases: []string{"asa"},
			Usage:   "Approve high-privileged secret request",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "role, r",
					Usage: "role of request",
				},
				&cli.StringFlag{
					Name:  "nonce, n",
					Usage: "nonce generated by request",
				},
			},
			Action: checkError(
				validateMandatory(
					validateNArg(approvedSecretApprove, 0, 0), "role", "nonce")),
		},
		{
			Name:    "approved-secret-issue",
			Aliases: []string{"asi"},
			Usage:   "Issue approved high-privileged secret request",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "role, r",
					Usage: "role of approved request",
				},
				&cli.StringFlag{
					Name:  "nonce, n",
					Usage: "nonce generated by approved request",
				},
				&cli.StringFlag{
					Name:  "format, f",
					Value: "table",
					Usage: `Valid formats are "table", "json"`,
				},
				&cli.StringFlag{
					Name:  "region",
					Usage: "AWS region",
					Value: "eu-central-1",
				},
			},
			Action: checkError(
				validateMandatory(
					validateNArg(approvedSecretIssue, 0, 0), "role", "nonce")),
		},
		{
			Name:    "pagerduty-secret-list",
			Aliases: []string{"psl"},
			Usage:   "List high-privileged pagerduty secret roles",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "filter, f",
					Value: ".+",
					Usage: "regex filter",
				},
			},
			Action: checkError(validateNArg(pagerdutySecretList, 0, 0)),
		},
		{
			Name:    "pagerduty-secret-issue",
			Aliases: []string{"psi"},
			Usage:   "Issue approved high-privileged pagerduty secret request",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "role, r",
					Usage: "role of secret request",
				},
				&cli.StringFlag{
					Name:  "reason",
					Usage: "reason for requesting secret",
				},
				&cli.StringFlag{
					Name:  "format, f",
					Value: "table",
					Usage: `Valid formats are "table", "json"`,
				},
			},
			Action: checkError(
				validateMandatory(
					validateNArg(pagerdutySecretIssue, 0, 0), "role", "reason")),
		},
		{
			Name:      "git-encrypt",
			Aliases:   []string{"encrypt", "ge"},
			Usage:     "Encrypt data for storage in Git:",
			UsageText: "vault-helper git-encrypt [command options] PLAINTEXT",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "key, k",
					Usage: "encryption key name (prd-provisioner as default for prd secrets, dta-provisioner for encrypting test secrets)",
					Value: "prd-provisioner",
				},
				&cli.StringFlag{
					Name:  "derivation-context",
					Usage: "context required for key derivation (base64 encoded) - only use if you know what you are doing!",
					Value: "eW9sdC1naXQtc3RvcmFnZQo=",
				},
				&cli.BoolFlag{
					Name:  "skip-validation",
					Value: false,
					Usage: "skip validatation of plaintext (no trailing newline/space)",
				},
				&cli.BoolFlag{
					Name:    "base64-encode",
					Aliases: []string{"base64", "b64"},
					Value:   false,
					Usage:   "Encodes the plaintext base64 before encryption",
				},
			},
			Action: checkError(
				validateMandatory(
					validateNArg(encrypt, 0, 1), "key", "derivation-context")),
		},
		{
			Name:    "ecr-login",
			Usage:   "AWS Elastic Container Registry",
			Aliases: []string{"ecr", "el"},
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:    "docker-command",
					Aliases: []string{"dc"},
					Usage:   "Print full docker command for login instead of modify config file for docker",
				},
				&cli.StringFlag{
					Name:    "target",
					Aliases: []string{"t"},
					Value:   "prd",
					Usage:   "Use prd for management-prd and dta for management-dta",
				},
			},
			Action: checkError(
				requireAuth(
					validateNArg(ecrLogin, 0, 1))),
		},
		{
			Name:    "nexus",
			Aliases: []string{"n"},
			Usage:   "Request nexus credentials",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "role, r",
					Usage: "role to request",
					Value: "rw",
				},
			},
			Action: checkError(validateNArg(nexus, 0, 0)),
		},
	}

	app.Run(os.Args)
}
