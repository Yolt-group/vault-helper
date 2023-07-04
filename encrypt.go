package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

func encrypt(c *cli.Context) error {
	client, err := getClient(c)
	if err != nil {
		return errors.Wrap(err, "failed to get vault client")
	}
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

	input := c.Args().First()
	if len(input) == 0 {
		data, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return errors.Wrapf(err, "failed to read plaintext from stdin")
		}

		input = string(data)
	}

	encoded := input
	if c.Bool("base64-encode") {
		encoded = base64.StdEncoding.EncodeToString([]byte(input))
	}

	if !c.Bool("skip-validation") {
		err = validateInput(c, encoded)
		if err != nil {
			return errors.Wrapf(err, "failed to validate input")
		}
	}

	data := map[string]interface{}{
		"plaintext": encoded,
		"context":   c.String("derivation-context"),
	}

	vaultPath := fmt.Sprintf("transit/git/encrypt/%s", c.String("key"))

	secret, err := client.Logical().Write(vaultPath, data)
	if err != nil {
		return errors.Wrapf(err, "failed to write to vault-path %q", vaultPath)
	}

	ciphertext := secret.Data["ciphertext"].(string)
	fmt.Println(ciphertext)

	return nil
}

func validateInput(c *cli.Context, encoded string) error {

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return errors.Wrapf(err, "input not base64 encoded")
	}

	decoded := string(data)
	if strings.HasSuffix(decoded, "\n") {
		return errors.New("trailing newline detected")
	} else if strings.HasSuffix(decoded, " ") {
		return errors.New("trailing space detected")
	}

	return nil
}
