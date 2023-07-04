package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

var defaultSSHConfig string = `
  Host *.ENV
    IdentityFile IDENTITY_FILE
    CertificateFile CERTIFICATE_FILE
    User core
    Hostname %h.yolt.io
`

func ssh(c *cli.Context) error {
	client, err := getClient(c)
	if err != nil {
		return errors.Wrap(err, "failed to get vault client")
	}

	token, err := client.Auth().Token().LookupSelf()
	if err != nil {
		return errors.Wrap(err, "failed to lookup self token")
	}

	homedir, _ := getHomeDir()
	sshPath := filepath.Join(homedir, ".ssh")
	if _, err := os.Stat(sshPath); os.IsNotExist(err) {
		return errors.Wrapf(err, "path does not exist: %s", sshPath)
	}

	privateKeyPath := c.String("private-key")
	publicKeyPath := c.String("public-key")
	publicKey, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return errors.Wrapf(err, "failed to read public key: %s", publicKeyPath)
	}

	name := token.Data["display_name"].(string)
	data := map[string]interface{}{
		"key_id":           name,
		"valid_principals": "core",
		"public_key":       string(publicKey),
	}

	filePath := c.String("path")
	_, err = os.Stat(filePath)
	if err != nil {
		return errors.Wrapf(err, "path does not exist or not readable: %s", filePath)
	}

	env := c.String("env")
	vaultPath := fmt.Sprintf("%s/ssh/clt/sign/cert", env)
	secret, err := client.Logical().Write(vaultPath, data)
	if err != nil {
		return errors.Wrapf(err, "failed to write to vault-path %q", vaultPath)
	}

	key := secret.Data["signed_key"].(string)
	certPath := filepath.Join(filePath, fmt.Sprintf("%s_%s.pub", filepath.Base(privateKeyPath), env))
	err = writeFile(certPath, key)
	if err != nil {
		return errors.Wrapf(err, "failed to write file: %s", certPath)
	}

	vaultPath = fmt.Sprintf("%s/ssh/host/config/ca", env)
	secret, err = client.Logical().Read(vaultPath)
	if err != nil {
		return errors.Wrapf(err, "failed to read vault-path %q", vaultPath)
	}

	key = secret.Data["public_key"].(string)
	key = strings.TrimRight(key, "\n")

	knownHostsEntries := map[string]bool{
		fmt.Sprintf("@cert-authority *.%s.yolt.io %s", env, key):               true,
		fmt.Sprintf("@cert-authority *.eu-central-1.compute.internal %s", key): true,
		fmt.Sprintf("@cert-authority 10.*.*.* %s", key):                        true,
	}

	var knownHosts bytes.Buffer
	knownHostsPath := filepath.Join(sshPath, "known_hosts")
	file, err := os.Open(knownHostsPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return errors.Wrapf(err, "failed to open file: %s", knownHostsPath)
		}
	} else {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			entry := scanner.Text()
			knownHosts.WriteString(entry + "\n")
			delete(knownHostsEntries, entry)
		}

		if err = scanner.Err(); err != nil {
			return errors.Wrapf(err, "failed to scan file: %s", knownHostsPath)
		}
	}

	for entry, _ := range knownHostsEntries {
		knownHosts.WriteString(entry + "\n")
	}

	writeFile(knownHostsPath, knownHosts.String())

	sshConfig := strings.Replace(defaultSSHConfig, "ENV", env, -1)
	sshConfig = strings.Replace(sshConfig, "IDENTITY_FILE", privateKeyPath, -1)
	sshConfig = strings.Replace(sshConfig, "CERTIFICATE_FILE", certPath, -1)

	fmt.Printf("Using private key %s\n", privateKeyPath)
	fmt.Printf("Using public key %s\n", publicKeyPath)
	fmt.Printf("Wrote signed certificate to %s\n", certPath)
	fmt.Printf("Wrote trusted host entries to %s\n", knownHostsPath)
	fmt.Printf("Configure SSH in %s/config with:\n%s\n", sshPath, sshConfig)
	fmt.Printf("SSH to hosts with:\n\n  ssh cassa.%s\n", env)
	fmt.Printf("  ssh kafka.%s\n\n", env)

	return nil
}
