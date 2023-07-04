package main

import (
	"bytes"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

func writeFile(name, contents string) error {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return errors.Wrapf(err, "failed to write file %q", name)
	}
	defer f.Close()

	buf := bytes.NewBufferString(contents)
	if _, err := io.Copy(f, buf); err != nil {
		return errors.Wrapf(err, "failed to write file %q", name)
	}

	return nil
}

func getHomeDir() (string, error) {
	dir, err := homedir.Dir()
	if err != nil {
		return "", errors.Wrap(err, "could not determine homedir")
	}
	return dir, nil
}

func getVaultAddr(ctx *cli.Context) string {

	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		if ctx.String("address") != "" {
			vaultAddr = ctx.String("address")
		} else {
			vaultAddr = "https://vault.yolt.io"
		}
	}

	return vaultAddr
}

func getConfigPath(ctx *cli.Context) (string, error) {

	homePath, err := getHomeDir()
	if err != nil {
		return "", errors.Wrap(err, "failed to get homedir")
	}

	u, err := url.Parse(getVaultAddr(ctx))
	if err != nil {
		log.Fatal(err)
	}

	return filepath.Join(homePath, ".vault-helper", u.Hostname()), nil
}

func exists(path string) bool {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func contains(list []string, x string) bool {
	for _, item := range list {
		if item == x {
			return true
		}
	}
	return false
}

func getDockerConfigDir() (string, error) {
	homePath, err := getHomeDir()
	if err != nil {
		return "", errors.Wrap(err, "failed to get homedir")
	}

	return filepath.Join(homePath, ".docker"), nil
}
