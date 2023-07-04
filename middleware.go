package main

import (
	"encoding/json"
	"log"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

func validateNArg(a cli.ActionFunc, min, max int) cli.ActionFunc {
	return func(c *cli.Context) error {

		if c.NArg() < min {
			return errors.Errorf("received arguments: %s (command requires at least %d arguments)", c.Args().Slice(), min)
		}

		if c.NArg() > max {
			return errors.Errorf("received arguments: %s (command requires at most %d arguments)", c.Args().Slice(), max)
		}

		return a(c)
	}
}

func validateMandatory(a cli.ActionFunc, args ...string) cli.ActionFunc {
	return func(c *cli.Context) error {

		for _, arg := range args {
			value := c.String(arg)
			if value == "" {
				return errors.Errorf("argument '-%s' is mandatory.", arg)
			}
		}

		return a(c)
	}
}

func validatePath(a cli.ActionFunc) cli.ActionFunc {
	return func(c *cli.Context) error {

		arg := c.String("path")
		if !filepath.IsAbs(arg) {
			return errors.New("argument '-path' must be an absolute path")
		}

		return a(c)
	}
}

func requireAuth(a cli.ActionFunc) cli.ActionFunc {
	return func(c *cli.Context) error {

		client, err := getClient(c)
		if err != nil {
			return errors.Wrap(err, "failed to get vault client")
		}

		if client.Token() == "" {
			return errors.New("no vault token found: authenticate first with 'vault-helper login'")
		}

		token, err := client.Auth().Token().LookupSelf()
		if err != nil {
			return errors.Wrap(err, "failed to lookup self token")
		}

		tokenpolicies, err := token.TokenPolicies()
		if err != nil {
			return errors.Wrap(err, "failed to get the tokenpolicies")
		}

		isRoot := contains(tokenpolicies, "root")
		if isRoot {
			log.Printf("Root token in use: please check SEM-alerts channel on your actions\n")
		}

		ttl, err := token.Data["ttl"].(json.Number).Int64()
		if err != nil {
			return errors.Wrap(err, "failed to get int64 from json.Number")
		}

		if ttl < 0 {
			return errors.New("vault token expired: re-authenticate with 'vault-helper login'")
		}

		return a(c)
	}
}

func loginer() cli.ActionFunc {
	return func(c *cli.Context) error {
		statePath, err := getStatePath(c)
		if err != nil {
			return errors.Wrapf(err, "failed to get state path")
		}

		return login(c,
			stateFileLoader{statePath: statePath},
			userInputCmdline{})
	}
}

func renewer() cli.ActionFunc {
	return func(c *cli.Context) error {
		statePath, err := getStatePath(c)
		if err != nil {
			return errors.Wrapf(err, "failed to get state path")
		}

		return renew(c, stateFileLoader{statePath: statePath})
	}
}

func checkError(a cli.ActionFunc) cli.ActionFunc {
	return func(c *cli.Context) error {
		err := a(c)
		if err != nil {
			log.Fatalf("error: %s", err)
		}

		return nil
	}
}

func databaseHandler(dbType string) cli.ActionFunc {
	return func(c *cli.Context) error {
		return database(c, dbType)
	}
}
