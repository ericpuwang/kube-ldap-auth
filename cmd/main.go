package main

import (
	"github.com/periky/kube-ldap-auth/cmd/app"
	"k8s.io/component-base/cli"
	"os"
)

func main() {
	command := app.NewKubeLdapAuthCommand()
	code := cli.Run(command)
	os.Exit(code)
}
