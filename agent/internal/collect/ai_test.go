package collect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	ghToken   = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	notionKey = "ntn_1234567890abcdefghij"
	plainPass = "hunter2-hunter2"
)

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fixtureHome(t *testing.T) (AIEnv, string) {
	root := t.TempDir()
	home := filepath.Join(root, "Users", "sam")
	write(t, filepath.Join(home, "Library/Application Support/Claude/claude_desktop_config.json"), `{
	  "mcpServers": {
	    "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github@2025.1.0"], "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "`+ghToken+`"}},
	    "sast": {"command": "npx", "args": ["-y", "mcp-remote", "https://mcp.vendor.example/api/mcp?tenant=acme", "--header", "Authorization: Bearer ${AUTH}"], "env": {"AUTH": "${env:VENDOR}"}},
	    "fs": {"command": "/Users/sam/.nvm/versions/node/v22/bin/node", "args": ["/Users/sam/code/secret-project/server.js"]}
	  }
	}`)
	write(t, filepath.Join(home, ".cursor/mcp.json"), `{"mcpServers": {
	    "linear": {"url": "https://mcp.linear.app/sse", "headers": {"Authorization": "Bearer lin_api_abcdefghijklmnop"}},
	    "nexus-github": {"url": "https://api.nexus.example.com/mcp/acme/github"}
	}}`)
	write(t, filepath.Join(home, ".claude.json"), `{"numStartups": 9, "mcpServers": {"notion": {"type": "http", "url": "https://mcp.notion.com/mcp"}},
	  "projects": {"/Users/sam/code/secret-project": {"mcpServers": {"db": {"command": "docker", "args": ["run", "-i", "--rm", "-e", "PGPASSWORD=`+plainPass+`", "mcp/postgres:latest", "postgres://db"]}}}}}`)
	write(t, filepath.Join(home, "Library/Application Support/Code/User/settings.json"), `{
	  // VS Code settings are JSONC
	  "editor.fontSize": 13,
	  "mcp": { "servers": { "sentry": { "type": "sse", "url": "https://mcp.sentry.dev/sse", }, }, }, /* trailing */
	}`)
	write(t, filepath.Join(home, ".codex/config.toml"), `model = "gpt-5"
[mcp_servers.docs]
command = "uvx"
args = ["mcp-server-fetch==0.6", "--ignore-robots"]

[mcp_servers.notion]
url = "https://mcp.notion.com/mcp"
bearer_token = "`+notionKey+`"

[mcp_servers."old one"]
command = "node"
enabled = false
[mcp_servers.docs.env]
API_KEY = "${DOCS_KEY}"
`)
	write(t, filepath.Join(home, ".config/zed/settings.json"), `{"context_servers": {"brave": {"command": {"path": "npx", "args": ["-y", "@brave/brave-search-mcp-server"], "env": {"BRAVE_API_KEY": "BSAabcdefghijk123"}}}}}`)
	write(t, filepath.Join(home, ".gemini/settings.json"), `{"mcpServers": {"remote": {"httpUrl": "https://user:pw@mcp.example.org/mcp"}}}`)
	// Installed tools.
	write(t, filepath.Join(root, "Applications/Claude.app/Contents/Info.plist"), `<plist><dict><key>CFBundleShortVersionString</key>
	<string>0.14.2</string></dict></plist>`)
	write(t, filepath.Join(home, "Applications/Cursor.app/Contents/Info.plist"), `<plist/>`)
	write(t, filepath.Join(home, ".local/bin/claude"), "#!/bin/sh")
	write(t, filepath.Join(home, ".vscode/extensions/github.copilot-chat-0.22.4/package.json"), "{}")
	write(t, filepath.Join(home, ".vscode/extensions/saoudrizwan.claude-dev-3.2.0-darwin-arm64/package.json"), "{}")
	write(t, filepath.Join(home, ".vscode/extensions/esbenp.prettier-vscode-10.1.0/package.json"), "{}")
	write(t, filepath.Join(root, "bin/ollama"), "")
	return AIEnv{OS: "darwin", Homes: []Home{{User: "sam", Dir: home}}, AppDirs: []string{filepath.Join(root, "Applications")}, BinDirs: []string{filepath.Join(root, "bin")}}, root
}

func find(inv *AIInventory, client, name string) MCPServer {
	for _, s := range inv.MCPServers {
		if s.Client == client && s.Name == name {
			return s
		}
	}
	return MCPServer{}
}

func TestDiscoverAI(t *testing.T) {
	env, _ := fixtureHome(t)
	inv := DiscoverAI(env)

	cases := []struct {
		client, name string
		want         MCPServer
	}{
		{"Claude Desktop", "github", MCPServer{Transport: "stdio", Command: "npx", Package: "@modelcontextprotocol/server-github", EnvKeys: []string{"GITHUB_PERSONAL_ACCESS_TOKEN"}, InlineSecrets: true}},
		{"Claude Desktop", "sast", MCPServer{Transport: "http", URL: "https://mcp.vendor.example/api/mcp", Command: "npx", Package: "mcp-remote", EnvKeys: []string{"AUTH"}}},
		{"Claude Desktop", "fs", MCPServer{Transport: "stdio", Command: "node", Package: "server.js"}},
		{"Cursor", "linear", MCPServer{Transport: "http", URL: "https://mcp.linear.app/sse", InlineSecrets: true}},
		{"Cursor", "nexus-github", MCPServer{Transport: "http", URL: "https://api.nexus.example.com/mcp/acme/github"}},
		{"Claude Code", "notion", MCPServer{Transport: "http", URL: "https://mcp.notion.com/mcp"}},
		{"Claude Code", "db", MCPServer{Scope: "project", Transport: "stdio", Command: "docker", Package: "mcp/postgres:latest", InlineSecrets: true}},
		{"VS Code", "sentry", MCPServer{Transport: "sse", URL: "https://mcp.sentry.dev/sse"}},
		{"Codex", "docs", MCPServer{Transport: "stdio", Command: "uvx", Package: "mcp-server-fetch", EnvKeys: []string{"API_KEY"}}},
		{"Codex", "notion", MCPServer{Transport: "http", URL: "https://mcp.notion.com/mcp", InlineSecrets: true}},
		{"Codex", "old one", MCPServer{Transport: "stdio", Command: "node", Disabled: true}},
		{"Zed", "brave", MCPServer{Transport: "stdio", Command: "npx", Package: "@brave/brave-search-mcp-server", EnvKeys: []string{"BRAVE_API_KEY"}, InlineSecrets: true}},
		{"Gemini CLI", "remote", MCPServer{Transport: "http", URL: "https://mcp.example.org/mcp", InlineSecrets: true}},
	}
	for _, c := range cases {
		got := find(inv, c.client, c.name)
		want := c.want
		want.Client, want.User, want.Name = c.client, "sam", c.name
		if want.Scope == "" {
			want.Scope = "user"
		}
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(want)
		if string(g) != string(w) {
			t.Errorf("%s/%s:\n got %s\nwant %s", c.client, c.name, g, w)
		}
	}
	if len(inv.MCPServers) != len(cases) {
		t.Errorf("found %d servers, want %d", len(inv.MCPServers), len(cases))
	}

	tools := map[string]AITool{}
	for _, tl := range inv.Tools {
		tools[tl.Name+"/"+tl.Kind] = tl
	}
	for key, want := range map[string]AITool{
		"Claude Desktop/app":            {Name: "Claude Desktop", Kind: "app", Version: "0.14.2"},
		"Cursor/app":                    {Name: "Cursor", Kind: "app", User: "sam"},
		"Claude Code/cli":               {Name: "Claude Code", Kind: "cli", User: "sam"},
		"GitHub Copilot Chat/extension": {Name: "GitHub Copilot Chat", Kind: "extension", Version: "0.22.4", User: "sam"},
		"Cline/extension":               {Name: "Cline", Kind: "extension", Version: "3.2.0", User: "sam"},
		"Ollama/cli":                    {Name: "Ollama", Kind: "cli"},
	} {
		if tools[key] != want {
			t.Errorf("tool %s = %+v, want %+v", key, tools[key], want)
		}
	}
	if len(inv.Tools) != 6 {
		t.Errorf("tools = %+v", inv.Tools)
	}
}

func TestDiscoverAINeverReportsSecretsOrPaths(t *testing.T) {
	env, _ := fixtureHome(t)
	out, _ := json.Marshal(DiscoverAI(env))
	for _, leak := range []string{ghToken, notionKey, plainPass, "lin_api_", "BSAabcdef", "secret-project", "tenant=acme", "user:pw", "postgres://db", ".nvm", "--ignore-robots"} {
		if strings.Contains(string(out), leak) {
			t.Errorf("report contains %q: %s", leak, out)
		}
	}
}

func TestDiscoverAIToleratesJunk(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "u")
	write(t, filepath.Join(home, ".cursor/mcp.json"), `{not json`)
	write(t, filepath.Join(home, ".claude.json"), `{"mcpServers": {"x": "not an object"}, "projects": []}`)
	write(t, filepath.Join(home, ".codex/config.toml"), "[mcp_servers.\n= = =")
	os.MkdirAll(filepath.Join(home, "Library/Application Support/Claude/claude_desktop_config.json"), 0o755) // a directory, not a file
	inv := DiscoverAI(AIEnv{OS: "darwin", Homes: []Home{{User: "u", Dir: home}}})
	if inv == nil || inv.MCPServers == nil || inv.Tools == nil {
		t.Fatalf("want empty lists, got %+v", inv)
	}
	if b, _ := json.Marshal(inv); string(b) != `{"tools":[],"mcp_servers":[]}` {
		t.Errorf("got %s", b)
	}
}

func TestPackageOf(t *testing.T) {
	for _, c := range []struct {
		cmd  string
		args []string
		want string
	}{
		{"npx", []string{"-y", "@scope/pkg@1.2.3"}, "@scope/pkg"},
		{"pnpm", []string{"dlx", "server-x"}, "server-x"},
		{"uvx", []string{"--from", "x", "mcp-server-git>=1.0"}, "x"},
		{"uv", []string{"run", "--with", "fastmcp", "server.py"}, "fastmcp"},
		{"docker", []string{"run", "-i", "--rm", "-e", "TOKEN", "-v", "/a:/b", "ghcr.io/github/github-mcp-server"}, "ghcr.io/github/github-mcp-server"},
		{"python3", []string{"/home/x/private/srv.py"}, "srv.py"},
		{"mybinary", []string{"--flag"}, ""},
	} {
		if got := packageOf(c.cmd, c.args); got != c.want {
			t.Errorf("packageOf(%s %v) = %q, want %q", c.cmd, c.args, got, c.want)
		}
	}
}

func TestStripJSONC(t *testing.T) {
	in := `{"a": "http://x//y", /* c */ "b": [1, 2,], // tail
	"c": "\"//\"",}`
	var v map[string]any
	if err := json.Unmarshal(StripJSONC([]byte(in)), &v); err != nil {
		t.Fatal(err)
	}
	if v["a"] != "http://x//y" || v["c"] != `"//"` {
		t.Errorf("got %v", v)
	}
}
