//go:build windows

package main

import (
	"errors"

	"golang.org/x/sys/windows"
)

func requireAdmin() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("this needs an elevated (Administrator) prompt")
	}
	return nil
}
