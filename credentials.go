package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

type CertificatePaths struct {
	IssuingCA   string
	Certificate string
	PrivateKey  string
}

func newDefaultCredentialPaths(prefix string) CertificatePaths {
	return CertificatePaths{IssuingCA: filepath.Join(prefix, "ca.pem"),
		Certificate: filepath.Join(prefix, "client.pem"),
		PrivateKey:  filepath.Join(prefix, "client-key.pem"),
	}
}

func newCredentialPaths(prefix, issuingCA, clientCert, privateKey string) CertificatePaths {
	return CertificatePaths{IssuingCA: filepath.Join(prefix, issuingCA),
		Certificate: filepath.Join(prefix, clientCert),
		PrivateKey:  filepath.Join(prefix, privateKey),
	}
}

func getCredentials(ctx *cli.Context, client *api.Client, vaultPath, cn string, paths CertificatePaths) (*time.Time, error) {
	token, err := client.Auth().Token().LookupSelf()
	if err != nil {
		return nil, errors.Wrap(err, "failed to lookup self token")
	}

	// We dont wanna put display name in vault helper state for renewals,
	// so we add it manually if cn is not specified.
	if cn == "" {
		meta, ok := token.Data["meta"].(map[string]interface{})
		if ok {
			// TODO: After migration, email _must_ be in meta data via oidc.
			// So return error if not. For now, fall-back on display_name for back-compat.
			if email, ok := meta["email"]; ok {
				cn = email.(string)
			}
		}

		if cn == "" {
			cn = token.Data["display_name"].(string)
		}
	}

	data := map[string]interface{}{
		"common_name": cn,
	}

	secret, err := client.Logical().Write(vaultPath, data)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to write to vault-path %q", vaultPath)
	}

	dir := filepath.Dir(paths.IssuingCA)
	err = os.MkdirAll(dir, 0700)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to make dir %q", dir)
	}

	err = writeFile(paths.IssuingCA, secret.Data["issuing_ca"].(string))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to write file %q", paths.IssuingCA)
	}

	err = writeFile(paths.Certificate, secret.Data["certificate"].(string))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to write file %q", paths.Certificate)
	}

	err = writeFile(paths.PrivateKey, secret.Data["private_key"].(string))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to write file %q", paths.PrivateKey)
	}

	certTime := time.Now()
	var expiry time.Time
	if secret.LeaseDuration > 0 {
		expiry = certTime.Add(time.Duration(secret.LeaseDuration) * time.Second)
	} else {
		// If generate_lease isn't enabled, we will have to parse the certificate
		certData, _ := pem.Decode([]byte(secret.Data["certificate"].(string)))
		cert, err := x509.ParseCertificate(certData.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse certificate")
		}

		expiry = cert.NotAfter
	}

	statePath, err := getStatePath(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get state path")
	}

	r := stateFileReader{statePath: statePath}
	state, err := loadState(r)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load state")
	}

	state.Certificates[dir] = CertificateState{
		Paths:     paths,
		VaultPath: vaultPath,
		CN:        cn,
		Serial:    secret.Data["serial_number"].(string),
		Expiry:    expiry,
	}

	err = saveState(statePath, state)
	if err != nil {
		return nil, errors.Wrap(err, "failed to save state")
	}

	return &expiry, nil
}
