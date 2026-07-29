package main

import (
	"fmt"

	"github.com/veilvpn/veil/internal/buildinfo"
)

func version() string {
	return fmt.Sprintf("veil %s (%s)", buildinfo.Version, buildinfo.Commit)
}
