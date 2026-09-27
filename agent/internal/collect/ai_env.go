package collect

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// aiEnv lists the accounts and locations to look at on this machine. The agent
// runs as root / SYSTEM, so it sees every account's home directory.
func aiEnv() AIEnv {
	env := AIEnv{OS: runtime.GOOS}
	var root string
	skip := map[string]bool{"shared": true, "guest": true, "public": true, "default": true, "default user": true, "all users": true, "lost+found": true}
	switch runtime.GOOS {
	case "darwin":
		root = "/Users"
		env.AppDirs = []string{"/Applications"}
		env.BinDirs = []string{"/usr/local/bin", "/opt/homebrew/bin"}
	case "windows":
		drive := os.Getenv("SystemDrive")
		if drive == "" {
			drive = "C:"
		}
		root = drive + `\Users`
	default:
		root = "/home"
		env.BinDirs = []string{"/usr/local/bin", "/usr/bin"}
		env.Homes = append(env.Homes, Home{User: "root", Dir: "/root"})
	}
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || strings.HasPrefix(name, ".") || skip[strings.ToLower(name)] {
			continue
		}
		env.Homes = append(env.Homes, Home{User: name, Dir: filepath.Join(root, name)})
	}
	return env
}
