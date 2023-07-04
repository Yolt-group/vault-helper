package main

import (
	"net"
	"net/http"
	"time"

	"git.yolt.io/infra/pkg.git/http/pinner"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

func getClient(ctx *cli.Context) (*api.Client, error) {

	c := api.DefaultConfig()
	if c == nil {
		return nil, errors.New("could not create/read default configuration")
	}
	if c.Error != nil {
		return nil, errors.Wrapf(c.Error, "error encountered setting up default configuration")
	}

	// Force one TLS dialer for TLS and non-TLS endpoints.
	dialTLS := pinner.NewPinningDialer(pinnedPublicKeysPEM, allowedRootCertsPEM)

	c.HttpClient.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          10,
		IdleConnTimeout:       5 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialTLS:               dialTLS,
		Dial:                  dialTLS,
	}

	c.Address = getVaultAddr(ctx)

	clt, err := api.NewClient(c)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create vault client")
	}

	if clt.Token() == "" {
		helper, err := newTokenHelper(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create token helper")
		}

		token, err := helper.Get()
		if err != nil {
			return nil, errors.Wrap(err, "failed to get token")
		}

		clt.SetToken(token)
	}

	return clt, nil
}
