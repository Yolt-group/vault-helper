package main

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

func kafka(c *cli.Context) error {
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

	env := c.String("env")

	vaultPath := fmt.Sprintf("%s/kafka/issue/sre", env)
	credPath := c.String("path")
	paths := newDefaultCredentialPaths(credPath)

	expiry, err := getCredentials(c, client, vaultPath, "sre", paths)
	if err != nil {
		return errors.Wrap(err, "failed to get credentials")
	}

	fmt.Printf("Credentials stored in %s\n", credPath)
	fmt.Printf("Credentials valid until: %s\n", time.Until(*expiry))

	return nil
}
