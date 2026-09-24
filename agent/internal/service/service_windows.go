package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var InstallDir = filepath.Join(programFiles(), "Nexus")

const BinName = "nexus-agent.exe"

func programFiles() string {
	if p := os.Getenv("ProgramFiles"); p != "" {
		return p
	}
	return `C:\Program Files`
}

func Install(bin, stateDir string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(WindowsName); err == nil {
		_, _ = s.Control(svc.Stop)
		_ = s.Delete()
		s.Close()
		time.Sleep(2 * time.Second)
	}
	s, err := m.CreateService(WindowsName, bin, mgr.Config{
		DisplayName: "Votal Nexus agent",
		Description: "Reports device security posture to Votal Nexus.",
		StartType:   mgr.StartAutomatic,
	}, "run", "--state-dir", stateDir)
	if err != nil {
		return err
	}
	defer s.Close()
	// Restart whenever the agent exits, including the deliberate exit after a self-update.
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 5 * time.Second}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, 86400); err != nil {
		return err
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return err
	}
	return s.Start()
}

func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(WindowsName)
	if err != nil {
		return nil // not installed
	}
	defer s.Close()
	_, _ = s.Control(svc.Stop)
	return s.Delete()
}

func Describe() string {
	return fmt.Sprintf("Windows service %s (logs: Event Viewer / stderr)", WindowsName)
}

// RunAsService runs fn under the Service Control Manager when started by it.
// It returns false when this is an interactive run.
func RunAsService(fn func(ctx context.Context) error) (bool, error) {
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return false, err
	}
	return true, svc.Run(WindowsName, handler{fn})
}

type handler struct {
	fn func(ctx context.Context) error
}

func (h handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.fn(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				return true, 1 // non-zero: the SCM's recovery actions restart us
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		}
	}
}
