package main

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

func renew(c *cli.Context, l stateLoader) error {

	client, err := getClient(c)
	if err != nil {
		return errors.Wrap(err, "failed to get vault client")
	}

	secret, err := client.Auth().Token().RenewSelf(86400)
	if err != nil {
		return errors.Wrap(err, "failed to renew token (try to run auth command first)")
	}

	fmt.Printf("Renewed token for %s\n", time.Duration(secret.Auth.LeaseDuration)*time.Second)

	state, err := l.load()
	if err != nil {
		return errors.Wrap(err, "failed to load state")
	}

	for filePath, certState := range state.Certificates {
		validFor := time.Until(certState.Expiry)
		fmt.Printf("%s valid for %s\n", filePath, validFor)
		if validFor > 8*time.Hour {
			continue
		}

		fmt.Print("Renewing... ")
		expiry, err := getCredentials(c, client, certState.VaultPath, certState.CN, certState.Paths)
		if err != nil {
			fmt.Printf("Failed!\n%s\n", err)
			continue
		}
		fmt.Printf("Renewed for %s\n", time.Until(*expiry))
	}

	return nil
}
