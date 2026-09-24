//go:build !windows

package main

import (
	"errors"
	"os"
)

func requireAdmin() error {
	if os.Geteuid() != 0 {
		return errors.New("this needs root: run it with sudo")
	}
	return nil
}
