package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

// isWSL tests if the binary is being run in Windows Subsystem for Linux
func isWSL() bool {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		return false
	}
	data, err := ioutil.ReadFile("/proc/version")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read /proc/version.\n")
		return false
	}
	return strings.Contains(strings.ToLower(string(data)), "microsoft")
}

// openURL opens the specified URL in the default browser of the user.
// Source: https://stackoverflow.com/a/39324149/453290
func openURL(url string) error {
	var cmd string
	var args []string

	switch {
	case "windows" == runtime.GOOS || isWSL():
		cmd = "cmd.exe"
		args = []string{"/c", "start"}
		url = strings.Replace(url, "&", "^&", -1)
	case "darwin" == runtime.GOOS:
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
	}
	args = append(args, url)
	return exec.Command(cmd, args...).Start()
}

func openvpn(c *cli.Context) error {

	fmt.Printf("This command is deprecated and will return an error in future release.\n")
	if c.String("path") != "" {
		fmt.Printf("Option --path is ignored.\n")
	}
	if c.String("target") != "" {
		fmt.Printf("Option --target is ignored.\n")
	}
	if c.Bool("tunnelblick") {
		fmt.Printf("Option --tunnelblick is ignored.\n")
	}
	fmt.Printf("Opening browser to Yolt's VPN access service.\n")

	if err := openURL("https://access.yolt.io"); err != nil {
		return errors.Wrap(err, "Could not open browser")
	}

	os.Exit(1) // Let any scripts using this command fail.
	return nil
}
