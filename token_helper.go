package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/vault/command/config"
	"github.com/hashicorp/vault/command/token"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

func newTokenHelper(ctx *cli.Context) (token.TokenHelper, error) {

	vaultConfig, err := config.Config()
	if err != nil {
		return nil, errors.New("failed to get Vault default config")
	}

	if vaultConfig.TokenHelper != "" {
		return config.DefaultTokenHelper()
	}

	configPath, err := getConfigPath(ctx)
	if err != nil {
		return nil, errors.New("failed to get config path")
	}

	return FileTokenHelper{tokenPath: filepath.Join(configPath, "token")}, nil
}

type FileTokenHelper struct {
	tokenPath string
}

func (h FileTokenHelper) Path() string {
	return h.tokenPath
}

// Get gets the value of the stored token, if any
func (h FileTokenHelper) Get() (string, error) {
	f, err := os.Open(h.tokenPath)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer f.Close()

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, f); err != nil {
		return "", err
	}

	return strings.TrimSpace(buf.String()), nil
}

// Store stores the value of the token to the file
func (h FileTokenHelper) Store(input string) error {
	configPath, _ := filepath.Split(h.tokenPath)
	err := os.MkdirAll(configPath, os.ModePerm)
	if err != nil {
		return errors.Wrapf(err, "failed to make dir: %s", configPath)
	}

	f, err := os.OpenFile(h.tokenPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	buf := bytes.NewBufferString(input)
	if _, err := io.Copy(f, buf); err != nil {
		return err
	}

	return nil
}

// Erase erases the value of the token
func (h FileTokenHelper) Erase() error {
	if err := os.Remove(h.tokenPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}
