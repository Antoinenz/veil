package main

import (
	"flag"
	"fmt"

	"github.com/veilvpn/veil/internal/buildinfo"
)

func newFlagSet(name string) *flag.FlagSet {
	return flag.NewFlagSet("veil-server "+name, flag.ContinueOnError)
}

func version() string {
	return fmt.Sprintf("veil-server %s (%s)", buildinfo.Version, buildinfo.Commit)
}
