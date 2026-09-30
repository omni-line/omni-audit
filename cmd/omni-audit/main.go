package main

import (
	"os"

	"github.com/omni-line/omni-audit/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
