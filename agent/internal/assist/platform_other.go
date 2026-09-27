//go:build !windows

package assist

import (
	"fmt"
	"os"
	"runtime"
)

// ForThisOS is the macOS side of Remote Assist (Screen Sharing through launchd). Elsewhere the
// Runner refuses requests.
func ForThisOS(string) Deps {
	mac := Mac{Run: ExecRun}
	return Deps{GOOS: runtime.GOOS, ConsoleUser: mac.ConsoleUser, Ask: mac.Ask, Showing: mac.Showing, Notify: mac.Notify, Sharing: mac, DialVNC: DialVNC}
}

// HelperMain exists only on Windows, where screen sharing needs a helper in the person's session.
func HelperMain([]string) int {
	fmt.Fprintln(os.Stderr, "assist-helper runs only on Windows")
	return 2
}
