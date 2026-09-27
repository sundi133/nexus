package collect

import (
	"bufio"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// AI discovery: which AI apps, CLIs and editor extensions are installed, and
// which MCP servers each AI client is configured to use.
//
// Privacy: it reads only the known config files below and reports what an
// admin needs to govern them. It never sends secret values, arguments beyond
// a package name, project paths or file contents. For each server: its name,
// transport, target (URL without query or credentials, or the package / command
// it runs), the names of its environment variables, and whether a secret is
// written into the config in plain text.

type AITool struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"` // app, cli, extension
	Version string `json:"version,omitempty"`
	User    string `json:"user,omitempty"` // local account, for per-user installs
}

type MCPServer struct {
	Client        string   `json:"client"` // "Cursor", "Claude Desktop", …
	User          string   `json:"user"`   // local account whose config it is
	Scope         string   `json:"scope"`  // user, or project (Claude Code per-project servers)
	Name          string   `json:"name"`
	Transport     string   `json:"transport"`         // stdio, http, sse
	URL           string   `json:"url,omitempty"`     // remote servers: scheme://host/path
	Command       string   `json:"command,omitempty"` // local servers: the program's base name
	Package       string   `json:"package,omitempty"` // npm/PyPI package or container image, when recognisable
	EnvKeys       []string `json:"env_keys,omitempty"`
	InlineSecrets bool     `json:"inline_secrets,omitempty"`
	Disabled      bool     `json:"disabled,omitempty"`
}

type AIInventory struct {
	Tools      []AITool    `json:"tools"`
	MCPServers []MCPServer `json:"mcp_servers"`
}

// Home is one local account's home directory.
type Home struct{ User, Dir string }

// AIEnv says where to look; aiEnv() in collect_<os>.go fills it for the running OS.
type AIEnv struct {
	OS      string // darwin, windows, linux
	Homes   []Home
	AppDirs []string // macOS: /Applications
	BinDirs []string // system-wide CLI locations
}

const (
	maxServers   = 300
	maxTools     = 100
	maxFileBytes = 8 << 20 // ~/.claude.json keeps history and can be large
)

// ---- Where AI clients keep MCP servers -----------------------------------------------------

type mcpSource struct {
	client string
	path   map[string]string // OS → path relative to home ("" = everywhere)
	keys   []string          // JSON path to the servers object
	format string            // json (JSONC tolerated), claude_code, codex_toml, zed
}

func vscodeUser(os string) string {
	switch os {
	case "darwin":
		return "Library/Application Support/Code/User"
	case "windows":
		return "AppData/Roaming/Code/User"
	}
	return ".config/Code/User"
}

func sources(goos string) []mcpSource {
	all := func(p string) map[string]string { return map[string]string{"": p} }
	claude := map[string]string{"darwin": "Library/Application Support/Claude/claude_desktop_config.json", "windows": "AppData/Roaming/Claude/claude_desktop_config.json", "linux": ".config/Claude/claude_desktop_config.json"}
	vs := vscodeUser(goos)
	return []mcpSource{
		{client: "Claude Desktop", path: claude, keys: []string{"mcpServers"}, format: "json"},
		{client: "Claude Code", path: all(".claude.json"), format: "claude_code"},
		{client: "Cursor", path: all(".cursor/mcp.json"), keys: []string{"mcpServers"}, format: "json"},
		{client: "Windsurf", path: all(".codeium/windsurf/mcp_config.json"), keys: []string{"mcpServers"}, format: "json"},
		{client: "VS Code", path: all(vs + "/mcp.json"), keys: []string{"servers"}, format: "json"},
		{client: "VS Code", path: all(vs + "/settings.json"), keys: []string{"mcp", "servers"}, format: "json"},
		{client: "Cline", path: all(vs + "/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"), keys: []string{"mcpServers"}, format: "json"},
		{client: "Gemini CLI", path: all(".gemini/settings.json"), keys: []string{"mcpServers"}, format: "json"},
		{client: "Codex", path: all(".codex/config.toml"), format: "codex_toml"},
		{client: "Zed", path: map[string]string{"darwin": ".config/zed/settings.json", "linux": ".config/zed/settings.json", "windows": "AppData/Roaming/Zed/settings.json"}, keys: []string{"context_servers"}, format: "json"},
	}
}

// DiscoverAI finds AI tools and MCP servers for every account in env.
func DiscoverAI(env AIEnv) *AIInventory {
	inv := &AIInventory{Tools: []AITool{}, MCPServers: []MCPServer{}}
	for _, h := range env.Homes {
		for _, src := range sources(env.OS) {
			rel, ok := src.path[env.OS]
			if !ok {
				rel = src.path[""]
			}
			if rel == "" {
				continue
			}
			data := readSmall(filepath.Join(h.Dir, filepath.FromSlash(rel)))
			if data == nil {
				continue
			}
			for _, s := range parseSource(src, data) {
				s.Client, s.User = src.client, h.User
				inv.MCPServers = append(inv.MCPServers, s)
			}
		}
		inv.Tools = append(inv.Tools, userTools(env, h)...)
	}
	inv.Tools = append(inv.Tools, systemTools(env)...)
	inv.Tools = dedupeTools(inv.Tools)
	sort.SliceStable(inv.MCPServers, func(i, j int) bool {
		a, b := inv.MCPServers[i], inv.MCPServers[j]
		return a.User+a.Client+a.Scope+a.Name < b.User+b.Client+b.Scope+b.Name
	})
	if len(inv.MCPServers) > maxServers {
		inv.MCPServers = inv.MCPServers[:maxServers]
	}
	if len(inv.Tools) > maxTools {
		inv.Tools = inv.Tools[:maxTools]
	}
	return inv
}

func readSmall(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() || st.Size() > maxFileBytes {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes))
	if err != nil {
		return nil
	}
	return data
}

func parseSource(src mcpSource, data []byte) []MCPServer {
	switch src.format {
	case "codex_toml":
		return parseCodexToml(string(data))
	case "claude_code":
		var doc struct {
			MCPServers map[string]json.RawMessage `json:"mcpServers"`
			Projects   map[string]struct {
				MCPServers map[string]json.RawMessage `json:"mcpServers"`
			} `json:"projects"`
		}
		if json.Unmarshal(data, &doc) != nil {
			return nil
		}
		out := serversFrom(doc.MCPServers, "user")
		// Per-project servers: the project path stays on the device.
		for _, p := range doc.Projects {
			out = append(out, serversFrom(p.MCPServers, "project")...)
		}
		return out
	}
	var doc any
	if json.Unmarshal(StripJSONC(data), &doc) != nil {
		return nil
	}
	for _, k := range src.keys {
		m, ok := doc.(map[string]any)
		if !ok {
			return nil
		}
		doc = m[k]
	}
	m, ok := doc.(map[string]any)
	if !ok {
		return nil
	}
	raw := map[string]json.RawMessage{}
	for k, v := range m {
		b, _ := json.Marshal(v)
		raw[k] = b
	}
	return serversFrom(raw, "user")
}

// rawServer is the union of the shapes clients use for one server.
type rawServer struct {
	Type      string            `json:"type"`
	Transport string            `json:"transport"`
	Command   json.RawMessage   `json:"command"` // a string, or Zed's {path, args, env}
	Args      []string          `json:"args"`
	Env       map[string]string `json:"env"`
	URL       string            `json:"url"`
	ServerURL string            `json:"serverUrl"` // Windsurf
	HTTPURL   string            `json:"httpUrl"`   // Gemini CLI
	Headers   map[string]string `json:"headers"`
	Disabled  bool              `json:"disabled"`
	Enabled   *bool             `json:"enabled"`
}

func serversFrom(m map[string]json.RawMessage, scope string) []MCPServer {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	var out []MCPServer
	for _, name := range names {
		var r rawServer
		if json.Unmarshal(m[name], &r) != nil {
			continue
		}
		command := ""
		if len(r.Command) > 0 {
			if json.Unmarshal(r.Command, &command) != nil {
				var zed struct {
					Path string            `json:"path"`
					Args []string          `json:"args"`
					Env  map[string]string `json:"env"`
				}
				if json.Unmarshal(r.Command, &zed) == nil {
					command, r.Args, r.Env = zed.Path, zed.Args, zed.Env
				}
			}
		}
		out = append(out, describe(name, scope, r.Type+r.Transport, command, r.Args, r.Env, r.Headers, firstNonEmpty(r.URL, r.ServerURL, r.HTTPURL), r.Disabled || (r.Enabled != nil && !*r.Enabled)))
	}
	return out
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

// describe turns one configured server into what's reported.
func describe(name, scope, transport, command string, args []string, env, headers map[string]string, rawURL string, disabled bool) MCPServer {
	s := MCPServer{Scope: scope, Name: clip(name), Disabled: disabled}
	for k, v := range env {
		s.EnvKeys = append(s.EnvKeys, clip(k))
		if secretValue(k, v) {
			s.InlineSecrets = true
		}
	}
	sort.Strings(s.EnvKeys)
	if len(s.EnvKeys) > 30 {
		s.EnvKeys = s.EnvKeys[:30]
	}
	for k, v := range headers {
		if !isReference(v) && v != "" && (secretName(k) || looksLikeToken(v)) {
			s.InlineSecrets = true
		}
	}
	if rawURL != "" {
		s.Transport = "http"
		if strings.Contains(strings.ToLower(transport), "sse") {
			s.Transport = "sse"
		}
		u, err := url.Parse(strings.TrimSpace(rawURL))
		if err == nil && u.Host != "" {
			if u.User != nil {
				s.InlineSecrets = true
			}
			for k, vs := range u.Query() {
				for _, v := range vs {
					if secretValue(k, v) {
						s.InlineSecrets = true
					}
				}
			}
			s.URL = clip(strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + u.EscapedPath())
		}
		return s
	}
	s.Transport = "stdio"
	s.Command = clip(baseName(command))
	s.Package = clip(packageOf(s.Command, args))
	for i, a := range args {
		if looksLikeToken(a) || (i > 0 && secretFlag(args[i-1]) && !isReference(a)) {
			s.InlineSecrets = true
		}
		if k, v, ok := strings.Cut(a, "="); ok && strings.HasPrefix(k, "-") && secretFlag(k) && !isReference(v) && v != "" {
			s.InlineSecrets = true
		}
		// NAME=value, e.g. docker run -e PGPASSWORD=…
		if k, v, ok := strings.Cut(a, "="); ok && !strings.HasPrefix(k, "-") && !strings.Contains(k, "/") && secretValue(k, v) {
			s.InlineSecrets = true
		}
		// --header "Authorization: Bearer abc…" (mcp-remote and friends).
		if i > 0 && (args[i-1] == "--header" || args[i-1] == "-H") {
			if k, v, ok := strings.Cut(a, ":"); ok && secretValue(k, strings.TrimSpace(v)) {
				s.InlineSecrets = true
			}
		}
	}
	// Local proxies to a remote server: report where they really connect.
	if proxies[s.Package] {
		for _, a := range args {
			if u, err := url.Parse(a); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
				if u.User != nil {
					s.InlineSecrets = true
				}
				s.Transport, s.URL = "http", clip(strings.ToLower(u.Scheme)+"://"+strings.ToLower(u.Host)+u.EscapedPath())
				break
			}
		}
	}
	return s
}

// Packages that bridge a local stdio client to a remote MCP server given as an argument.
var proxies = map[string]bool{"mcp-remote": true, "supergateway": true, "mcp-proxy": true, "@modelcontextprotocol/mcp-remote": true, "mcp-remote-client": true}

func clip(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

func baseName(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if i := strings.LastIndexAny(cmd, `/\`); i >= 0 {
		cmd = cmd[i+1:]
	}
	return strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(cmd), ".exe"), ".cmd")
}

var dockerValueFlags = map[string]bool{"-e": true, "--env": true, "-v": true, "--volume": true, "--name": true, "-p": true, "--publish": true, "--network": true, "--env-file": true, "-w": true, "--workdir": true, "-u": true, "--user": true, "--entrypoint": true, "--mount": true, "--platform": true, "-l": true, "--label": true}

// packageOf names what a launcher runs: "npx -y @scope/server@1.2" → "@scope/server".
func packageOf(cmd string, args []string) string {
	firstPlain := func(skip map[string]bool) string {
		for _, a := range args {
			if skip[a] || strings.HasPrefix(a, "-") {
				continue
			}
			return a
		}
		return ""
	}
	switch cmd {
	case "npx", "bunx", "pnpx":
		return stripVersion(firstPlain(map[string]bool{}))
	case "pnpm", "yarn", "bun", "npm":
		return stripVersion(firstPlain(map[string]bool{"dlx": true, "x": true, "exec": true}))
	case "uvx", "pipx":
		p := firstPlain(map[string]bool{"run": true})
		if i := strings.IndexAny(p, "=<>@["); i > 0 {
			p = p[:i]
		}
		return p
	case "uv":
		// uv run --with pkg script / uv tool run pkg
		for i, a := range args {
			if a == "--with" && i+1 < len(args) {
				return args[i+1]
			}
		}
		return firstPlain(map[string]bool{"run": true, "tool": true})
	case "docker", "podman":
		seenRun := false
		for i := 0; i < len(args); i++ {
			a := args[i]
			if !seenRun {
				seenRun = a == "run"
				continue
			}
			if dockerValueFlags[a] {
				i++
				continue
			}
			if strings.HasPrefix(a, "-") {
				continue
			}
			return a
		}
	case "node", "python", "python3", "deno", "bun.exe":
		// A script path: its base name only (the path can reveal a user or project).
		if p := firstPlain(map[string]bool{"run": true}); p != "" {
			return baseName(p)
		}
	}
	return ""
}

func stripVersion(p string) string {
	if i := strings.LastIndex(p, "@"); i > 0 {
		return p[:i]
	}
	return p
}

var (
	secretNameRe = regexp.MustCompile(`(?i)(token|secret|password|passwd|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|auth|bearer|pat$|^pat_|session|cookie|(^|[_-])key$|^key$)`)
	tokenRe      = regexp.MustCompile(`^(ghp_|gho_|ghu_|ghs_|github_pat_|glpat-|xox[abprs]-|sk-|sk_live_|rk_live_|AKIA|ASIA|AIza|ya29\.|eyJ[A-Za-z0-9_-]{10,}\.|ntn_|secret_|lin_api_|pk_live_|npm_|dop_v1_|shpat_)`)
)

func secretName(k string) bool    { return secretNameRe.MatchString(k) }
func secretFlag(flag string) bool { return strings.HasPrefix(flag, "-") && secretName(flag) }
func looksLikeToken(v string) bool {
	v = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(v, "Bearer "), "bearer "))
	return len(v) >= 12 && tokenRe.MatchString(v)
}

// isReference: a value that points at a secret elsewhere (an environment variable or input).
func isReference(v string) bool {
	return strings.Contains(v, "${") || strings.HasPrefix(v, "$") || strings.Contains(v, "{env:") || strings.Contains(v, "%") && strings.Count(v, "%") >= 2
}

func secretValue(k, v string) bool {
	if v == "" || isReference(v) {
		return false
	}
	return looksLikeToken(v) || (secretName(k) && len(v) >= 8)
}

// StripJSONC removes // and /* */ comments and trailing commas (VS Code, Zed settings).
func StripJSONC(in []byte) []byte {
	out := make([]byte, 0, len(in))
	inStr, esc := false, false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inStr {
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			out = append(out, c)
			continue
		}
		if c == '/' && i+1 < len(in) && in[i+1] == '/' {
			for i < len(in) && in[i] != '\n' {
				i++
			}
			out = append(out, '\n')
			continue
		}
		if c == '/' && i+1 < len(in) && in[i+1] == '*' {
			i += 2
			for i+1 < len(in) && !(in[i] == '*' && in[i+1] == '/') {
				i++
			}
			i++
			continue
		}
		out = append(out, c)
	}
	// Trailing commas: ",   }" → "}".
	return regexp.MustCompile(`,(\s*[}\]])`).ReplaceAll(out, []byte("$1"))
}

// parseCodexToml reads [mcp_servers.<name>] tables from Codex's config.toml (enough TOML for that).
func parseCodexToml(doc string) []MCPServer {
	type acc struct {
		command, url string
		args         []string
		env, headers map[string]string
		disabled     bool
	}
	servers := map[string]*acc{}
	var order []string
	var cur *acc
	sub := "" // "", env or http_headers
	sc := bufio.NewScanner(strings.NewReader(doc))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			cur, sub = nil, ""
			h := strings.Trim(line, "[] ")
			if !strings.HasPrefix(h, "mcp_servers.") {
				continue
			}
			parts := splitTomlKey(strings.TrimPrefix(h, "mcp_servers."))
			if len(parts) == 0 {
				continue
			}
			if servers[parts[0]] == nil {
				servers[parts[0]] = &acc{env: map[string]string{}, headers: map[string]string{}}
				order = append(order, parts[0])
			}
			cur = servers[parts[0]]
			if len(parts) > 1 {
				sub = parts[1]
			}
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.Trim(strings.TrimSpace(k), `"`), strings.TrimSpace(v)
		switch {
		case sub == "env":
			cur.env[k] = tomlString(v)
		case sub == "http_headers":
			cur.headers[k] = tomlString(v)
		case k == "command":
			cur.command = tomlString(v)
		case k == "url":
			cur.url = tomlString(v)
		case k == "args":
			cur.args = tomlArray(v)
		case k == "enabled":
			cur.disabled = v == "false"
		case k == "env" || k == "http_headers":
			for key, val := range tomlInline(v) {
				if k == "env" {
					cur.env[key] = val
				} else {
					cur.headers[key] = val
				}
			}
		case k == "bearer_token":
			cur.headers["Authorization"] = tomlString(v)
		}
	}
	var out []MCPServer
	for _, name := range order {
		a := servers[name]
		out = append(out, describe(name, "user", "", a.command, a.args, a.env, a.headers, a.url, a.disabled))
	}
	return out
}

func splitTomlKey(k string) []string {
	var parts []string
	for k != "" {
		if strings.HasPrefix(k, `"`) {
			end := strings.Index(k[1:], `"`)
			if end < 0 {
				return append(parts, k)
			}
			parts = append(parts, k[1:end+1])
			k = strings.TrimPrefix(k[end+2:], ".")
			continue
		}
		p, rest, _ := strings.Cut(k, ".")
		parts = append(parts, p)
		k = rest
	}
	return parts
}

func tomlString(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, " #"); i > 0 && !strings.HasPrefix(v, `"`) {
		v = v[:i]
	}
	return strings.Trim(v, `"'`)
}

var tomlQuoted = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"|'([^']*)'`)

func tomlArray(v string) []string {
	var out []string
	for _, m := range tomlQuoted.FindAllStringSubmatch(v, -1) {
		out = append(out, m[1]+m[2])
	}
	return out
}

func tomlInline(v string) map[string]string {
	out := map[string]string{}
	v = strings.Trim(strings.TrimSpace(v), "{}")
	for _, kv := range strings.Split(v, ",") {
		k, val, ok := strings.Cut(kv, "=")
		if ok {
			out[strings.Trim(strings.TrimSpace(k), `"`)] = tomlString(val)
		}
	}
	return out
}

// ---- Installed AI tools ------------------------------------------------------------------

var macApps = map[string]string{
	"Claude.app": "Claude Desktop", "ChatGPT.app": "ChatGPT", "Cursor.app": "Cursor", "Windsurf.app": "Windsurf",
	"Ollama.app": "Ollama", "LM Studio.app": "LM Studio", "Perplexity.app": "Perplexity", "Msty.app": "Msty",
	"Jan.app": "Jan", "Kiro.app": "Kiro", "Trae.app": "Trae", "GitHub Copilot for Xcode.app": "GitHub Copilot for Xcode",
	"Microsoft Copilot.app": "Microsoft Copilot", "Gemini.app": "Gemini", "Warp.app": "Warp",
}

// Per-user Windows installs, under AppData/Local.
var winApps = map[string]string{
	"AnthropicClaude": "Claude Desktop", "Programs/cursor": "Cursor", "Programs/Windsurf": "Windsurf",
	"Programs/Ollama": "Ollama", "Programs/LM Studio": "LM Studio", "Programs/ChatGPT": "ChatGPT", "Programs/Kiro": "Kiro",
}

var clis = map[string]string{"claude": "Claude Code", "codex": "Codex CLI", "gemini": "Gemini CLI", "ollama": "Ollama", "aider": "Aider", "goose": "Goose", "opencode": "opencode", "cursor-agent": "Cursor CLI", "amp": "Amp", "q": "Amazon Q CLI"}

var extensions = map[string]string{
	"github.copilot": "GitHub Copilot", "github.copilot-chat": "GitHub Copilot Chat", "saoudrizwan.claude-dev": "Cline",
	"continue.continue": "Continue", "anthropic.claude-code": "Claude Code (extension)", "openai.chatgpt": "Codex (extension)",
	"rooveterinaryinc.roo-cline": "Roo Code", "google.geminicodeassist": "Gemini Code Assist", "amazonwebservices.amazon-q-vscode": "Amazon Q",
	"sourcegraph.cody-ai": "Cody", "tabnine.tabnine-vscode": "Tabnine", "codeium.codeium": "Windsurf (Codeium) extension", "kilocode.kilo-code": "Kilo Code",
}

var plistVersion = regexp.MustCompile(`<key>CFBundleShortVersionString</key>\s*<string>([^<]{1,40})</string>`)

func macApp(dir, bundle, name string, user string) (AITool, bool) {
	p := filepath.Join(dir, bundle)
	if st, err := os.Stat(p); err != nil || !st.IsDir() {
		return AITool{}, false
	}
	t := AITool{Name: name, Kind: "app", User: user}
	if m := plistVersion.FindSubmatch(readSmall(filepath.Join(p, "Contents", "Info.plist"))); m != nil {
		t.Version = string(m[1])
	}
	return t, true
}

func systemTools(env AIEnv) []AITool {
	var out []AITool
	for _, dir := range env.AppDirs {
		for bundle, name := range macApps {
			if t, ok := macApp(dir, bundle, name, ""); ok {
				out = append(out, t)
			}
		}
	}
	for _, dir := range env.BinDirs {
		for bin, name := range clis {
			if isFile(filepath.Join(dir, bin)) || isFile(filepath.Join(dir, bin+".exe")) {
				out = append(out, AITool{Name: name, Kind: "cli"})
			}
		}
	}
	return out
}

func userTools(env AIEnv, h Home) []AITool {
	var out []AITool
	if env.OS == "darwin" {
		for bundle, name := range macApps {
			if t, ok := macApp(filepath.Join(h.Dir, "Applications"), bundle, name, h.User); ok {
				out = append(out, t)
			}
		}
	}
	if env.OS == "windows" {
		for rel, name := range winApps {
			if st, err := os.Stat(filepath.Join(h.Dir, "AppData", "Local", filepath.FromSlash(rel))); err == nil && st.IsDir() {
				out = append(out, AITool{Name: name, Kind: "app", User: h.User})
			}
		}
	}
	bins := []string{".local/bin", ".claude/local", ".npm-global/bin", ".bun/bin", ".cargo/bin", "bin", ".volta/bin", "AppData/Roaming/npm"}
	for _, b := range bins {
		for bin, name := range clis {
			p := filepath.Join(h.Dir, filepath.FromSlash(b), bin)
			if isFile(p) || isFile(p+".cmd") || isFile(p+".exe") {
				out = append(out, AITool{Name: name, Kind: "cli", User: h.User})
			}
		}
	}
	for _, extDir := range []string{".vscode/extensions", ".cursor/extensions", ".windsurf/extensions", ".vscode-insiders/extensions"} {
		entries, err := os.ReadDir(filepath.Join(h.Dir, filepath.FromSlash(extDir)))
		if err != nil {
			continue
		}
		for _, e := range entries {
			id, version := splitExtension(e.Name())
			if name, ok := extensions[id]; ok {
				out = append(out, AITool{Name: name, Kind: "extension", Version: version, User: h.User})
			}
		}
	}
	return out
}

// "github.copilot-chat-0.22.4" → ("github.copilot-chat", "0.22.4"); platform suffixes are dropped.
var extVersion = regexp.MustCompile(`^(.+?)-(\d+\.\d+\.\d+)(?:-[a-z0-9-]+)?$`)

func splitExtension(dir string) (string, string) {
	if m := extVersion.FindStringSubmatch(strings.ToLower(dir)); m != nil {
		return m[1], m[2]
	}
	return strings.ToLower(dir), ""
}

func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// dedupeTools keeps one entry per (name, kind, user), preferring the newest version seen.
func dedupeTools(ts []AITool) []AITool {
	seen := map[string]int{}
	out := []AITool{}
	for _, t := range ts {
		k := t.Name + "|" + t.Kind + "|" + t.User
		if i, ok := seen[k]; ok {
			if t.Version > out[i].Version {
				out[i].Version = t.Version
			}
			continue
		}
		seen[k] = len(out)
		out = append(out, t)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name+out[i].User < out[j].Name+out[j].User })
	return out
}
