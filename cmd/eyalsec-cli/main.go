// Command eyalsec-cli reads your EyalSec events and machines from a terminal
// or a script, through the EyalSec API (https://eyalsec.com/docs/api).
//
// Install with Homebrew (brew install eyalsec/tap/eyalsec-cli), a .deb or
// .rpm from the GitHub release, or:
//
//	go install eyalsec.com/cli/cmd/eyalsec-cli@latest
package main

import (
	"os"

	"eyalsec.com/cli/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
