//go:build !windows

package service

import "context"

// RunAsService is Windows-only; launchd and systemd run the agent as a plain process.
func RunAsService(func(ctx context.Context) error) (bool, error) { return false, nil }
