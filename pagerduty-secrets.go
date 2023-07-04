package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

func pagerdutySecretList(c *cli.Context) error {
	client, err := getClient(c)
	if err != nil {
		return errors.Wrap(err, "failed to get vault client")
	}

	vaultPath := "pagerduty-secrets/roles"
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

func pagerdutySecretIssue(ctx *cli.Context) error {

	clt, err := getClient(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to get vault client")
	}

	data := map[string]interface{}{
		"reason": ctx.String("reason"),
	}

	// Forward addition arguments in format key=value. For example:
	// vault-helper psi -role app-prd-ssh public_key=@/home/user/.ssh/id_rsa.pub
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
	roleData, err := pagerdutySecretReadRole(clt, role)
	if err != nil {
		return errors.Wrapf(err, "failed to get secret_type from role")
	}

	switch roleData["secret_type"].(string) {
	case "ssh":
		return pagerdutySecretIssueSSH(ctx, clt, data)
	case "vault-token":
		return pagerdutySecretIssueVaultToken(ctx, clt, data)
	default:
		return pagerdutySecretIssueDefault(ctx, clt, data)
	}
}

func pagerdutySecretIssueVaultToken(ctx *cli.Context, clt *api.Client, data map[string]interface{}) error {

	role := ctx.String("role")
	secret, err := pagerdutySecretWriteIssue(clt, role, data)
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

func pagerdutySecretIssueDefault(ctx *cli.Context, clt *api.Client, data map[string]interface{}) error {

	role := ctx.String("role")
	secret, err := pagerdutySecretWriteIssue(clt, role, data)
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

func pagerdutySecretIssueSSH(ctx *cli.Context, clt *api.Client, data map[string]interface{}) error {

	home, _ := getHomeDir()
	if data["public_key"] == nil {
		publicKeyPath := filepath.Join(home, ".ssh", "id_rsa.pub")
		content, err := ioutil.ReadFile(publicKeyPath)
		if err != nil {
			return errors.Wrapf(err, "could not read file: %s", publicKeyPath)
		}

		data["public_key"] = string(content)
	}

	role := ctx.String("role")
	var envMatcher = regexp.MustCompile(`-ssh$`)
	env := envMatcher.ReplaceAllString(role, "")

	secret, err := pagerdutySecretWriteIssue(clt, role, data)
	if err != nil {
		return err
	}

	signedKey := secret["signed_key"].(string)
	certPath := filepath.Join(home, ".ssh", fmt.Sprintf("id_rsa_%s.pub", env))
	if err = writeFile(certPath, strings.Trim(signedKey, "\n")); err != nil {
		return errors.Wrapf(err, "failed to write file: %s", certPath)
	}

	fmt.Printf("Wrote signed key to %s\n", certPath)

	return nil
}

func pagerdutySecretReadRole(clt *api.Client, role string) (map[string]interface{}, error) {

	vaultPath := path.Join("pagerduty-secrets/roles", role)
	secret, err := clt.Logical().Read(vaultPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to write vault-path %q", vaultPath)
	} else if secret == nil {
		return nil, errors.Errorf("no such role: %s", role)
	}

	return secret.Data, nil
}

func pagerdutySecretWriteIssue(clt *api.Client, role string, data map[string]interface{}) (map[string]interface{}, error) {

	vaultPath := path.Join("pagerduty-secrets/issue", role)
	secret, err := clt.Logical().Write(vaultPath, data)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to write vault-path %q", vaultPath)
	} else if secret == nil {
		return nil, errors.Errorf("failed to issue secret from vault-path: %q", vaultPath)
	}

	return secret.Data, nil
}
