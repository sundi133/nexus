package updates

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Third-party app patching: apps people install themselves (browsers, Zoom, Slack…) go stale
// faster than the OS. Windows: winget knows what's installed and what's newer. macOS: a small
// catalog of vendor "latest" downloads, each trusted only if it carries the vendor's Apple
// code-signing Team ID, and installed only when it's newer than what's there and the app isn't
// open. Linux: apt and dnf already update third-party repositories with the OS.

// MacApp is one app the macOS catalog keeps up to date.
type MacApp struct {
	ID     string // what the server calls it
	Name   string
	Bundle string // under /Applications
	URL    string // the vendor's always-latest download (https)
	Kind   string // dmg | zip | pkg
	TeamID string // Apple Developer Team ID the app must be signed by
}

// MacCatalog: vendors' own download links and signing identities.
var MacCatalog = []MacApp{
	{ID: "google-chrome", Name: "Google Chrome", Bundle: "Google Chrome.app", URL: "https://dl.google.com/chrome/mac/universal/stable/GGRO/googlechrome.dmg", Kind: "dmg", TeamID: "EQHXZ8M8AV"},
	{ID: "firefox", Name: "Firefox", Bundle: "Firefox.app", URL: "https://download.mozilla.org/?product=firefox-latest-ssl&os=osx&lang=en-US", Kind: "dmg", TeamID: "43AQ936H96"},
	{ID: "slack", Name: "Slack", Bundle: "Slack.app", URL: "https://slack.com/ssb/download-osx-universal", Kind: "dmg", TeamID: "BQR82RBBHL"},
	{ID: "zoom", Name: "Zoom", Bundle: "zoom.us.app", URL: "https://zoom.us/client/latest/ZoomInstallerIT.pkg", Kind: "pkg", TeamID: "BJ4HAAB9B3"},
	{ID: "vscode", Name: "Visual Studio Code", Bundle: "Visual Studio Code.app", URL: "https://update.code.visualstudio.com/latest/darwin-universal/stable", Kind: "zip", TeamID: "UBF8T346G9"},
	{ID: "1password", Name: "1Password", Bundle: "1Password.app", URL: "https://downloads.1password.com/mac/1Password.zip", Kind: "zip", TeamID: "2BUA8C4S2C"},
}

// ---- Windows (winget) --------------------------------------------------------------------------

// ParseWingetUpgrade reads `winget upgrade` (its table: Name, Id, Version, Available, Source).
func ParseWingetUpgrade(out string) []Update {
	// winget draws a spinner with carriage returns: keep what a terminal would show (after the last \r).
	lines := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
	for i, l := range lines {
		if j := strings.LastIndexByte(l, '\r'); j >= 0 {
			lines[i] = l[j+1:]
		}
	}
	var cols []int
	start := -1
	for i, l := range lines {
		idIdx, verIdx, avIdx := strings.Index(l, " Id "), strings.Index(l, " Version "), strings.Index(l, " Available")
		if strings.HasPrefix(strings.TrimLeft(l, " \b-\\|/"), "Name") && idIdx > 0 && verIdx > idIdx && avIdx > verIdx {
			nameIdx := strings.Index(l, "Name")
			cols = []int{nameIdx, idIdx + 1, verIdx + 1, avIdx + 1}
			if src := strings.Index(l, " Source"); src > avIdx {
				cols = append(cols, src+1)
			}
			start = i + 1
			break
		}
	}
	if start < 0 {
		return nil
	}
	field := func(l string, n int) string {
		r := []rune(l)
		from := cols[n]
		to := len(r)
		if n+1 < len(cols) {
			to = cols[n+1]
		}
		if from >= len(r) {
			return ""
		}
		if to > len(r) {
			to = len(r)
		}
		return strings.TrimSpace(string(r[from:to]))
	}
	var ups []Update
	for _, l := range lines[start:] {
		t := strings.TrimSpace(l)
		if t == "" || strings.Trim(t, "-") == "" {
			continue
		}
		if strings.Contains(t, "upgrades available") || strings.Contains(t, "upgrade available") || strings.HasPrefix(t, "The following packages") {
			break
		}
		id := field(l, 1)
		if id == "" || strings.Contains(id, " ") {
			continue
		}
		ups = append(ups, Update{Name: field(l, 0), ID: id, Current: field(l, 2), Version: field(l, 3), ThirdParty: true})
	}
	return ups
}

var wingetID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$`)

// ---- macOS catalog ------------------------------------------------------------------------------

// versionNewer says whether a is newer than b ("121.0.6167.85" > "120.0.1").
func versionNewer(a, b string) bool {
	pa, pb := strings.FieldsFunc(a, func(r rune) bool { return r == '.' || r == ' ' || r == '(' || r == ')' }), strings.FieldsFunc(b, func(r rune) bool { return r == '.' || r == ' ' || r == '(' || r == ')' })
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(strings.TrimLeft(pa[i], "v"))
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(strings.TrimLeft(pb[i], "v"))
		}
		if x != y {
			return x > y
		}
	}
	return false
}

// Mac is the macOS side, with its commands replaceable in tests.
type Mac struct {
	Run      Run
	Dir      string                                               // where downloads are staged
	Download func(ctx context.Context, rawURL, dest string) error // https only
	Exists   func(path string) bool                               // default os.Stat
	Apps     string                                               // /Applications
	Catalog  []MacApp                                             // default MacCatalog
	Staged   func(dir string) (string, error)                     // finds the .app inside an unpacked download (tests)
	Running  func(ctx context.Context, bundlePath string) bool    // default pgrep
}

func (m Mac) apps() string {
	if m.Apps != "" {
		return m.Apps
	}
	return "/Applications"
}
func (m Mac) catalog() []MacApp {
	if m.Catalog != nil {
		return m.Catalog
	}
	return MacCatalog
}
func (m Mac) exists(p string) bool {
	if m.Exists != nil {
		return m.Exists(p)
	}
	_, err := os.Stat(p)
	return err == nil
}

func (m Mac) version(ctx context.Context, app string) string {
	out, err := m.Run(ctx, "plutil", "-extract", "CFBundleShortVersionString", "raw", "-o", "-", filepath.Join(app, "Contents", "Info.plist"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

var teamRe = regexp.MustCompile(`(?m)^TeamIdentifier=([A-Z0-9]{10})$`)

// signedBy checks the app's code signature is valid and made by team.
func (m Mac) signedBy(ctx context.Context, app, team string) error {
	// Not --strict: that also rejects harmless extended attributes installed apps pick up (Finder info).
	if _, err := m.Run(ctx, "codesign", "--verify", "--deep", app); err != nil {
		return fmt.Errorf("%s isn't validly signed", filepath.Base(app))
	}
	out, _ := m.Run(ctx, "codesign", "-dv", "--verbose=2", app)
	got := teamRe.FindStringSubmatch(out)
	if got == nil || got[1] != team {
		return fmt.Errorf("%s isn't signed by its vendor (team %s)", filepath.Base(app), team)
	}
	return nil
}

// stage downloads the latest release and unpacks it; returns the .app inside and a cleanup.
func (m Mac) stage(ctx context.Context, a MacApp) (string, func(), error) {
	dir := filepath.Join(m.Dir, "thirdparty", a.ID)
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", func() {}, err
	}
	var detach []string
	cleanup := func() {
		for _, mp := range detach {
			_, _ = m.Run(context.Background(), "hdiutil", "detach", "-force", mp)
		}
		_ = os.RemoveAll(dir)
	}
	file := filepath.Join(dir, "download."+a.Kind)
	if err := m.Download(ctx, a.URL, file); err != nil {
		return "", cleanup, err
	}
	unpacked := filepath.Join(dir, "unpacked")
	switch a.Kind {
	case "dmg":
		if out, err := m.Run(ctx, "hdiutil", "attach", "-nobrowse", "-readonly", "-noautoopen", "-mountpoint", unpacked, file); err != nil {
			return "", cleanup, fmt.Errorf("couldn't open the disk image: %s", firstLine(out, err))
		}
		detach = append(detach, unpacked)
	case "zip":
		if out, err := m.Run(ctx, "ditto", "-x", "-k", file, unpacked); err != nil {
			return "", cleanup, fmt.Errorf("couldn't unzip: %s", firstLine(out, err))
		}
	case "pkg":
		if out, err := m.Run(ctx, "pkgutil", "--check-signature", file); err != nil || !strings.Contains(out, "("+a.TeamID+")") {
			return "", cleanup, fmt.Errorf("the %s package isn't signed by its vendor (team %s)", a.Name, a.TeamID)
		}
		if out, err := m.Run(ctx, "pkgutil", "--expand-full", file, unpacked); err != nil {
			return "", cleanup, fmt.Errorf("couldn't read the package: %s", firstLine(out, err))
		}
	default:
		return "", cleanup, fmt.Errorf("unknown download kind %s", a.Kind)
	}
	find := m.Staged
	if find == nil {
		find = func(root string) (string, error) {
			var hit string
			_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
				if err == nil && d.IsDir() && d.Name() == a.Bundle {
					hit = p
					return filepath.SkipAll
				}
				return nil
			})
			if hit == "" {
				return "", fmt.Errorf("%s isn't in the download", a.Bundle)
			}
			return hit, nil
		}
	}
	app, err := find(unpacked)
	if err != nil {
		return "", cleanup, err
	}
	// pkg payloads can't be codesign-checked before install as reliably as apps: the package signature was checked above.
	if a.Kind != "pkg" {
		if err := m.signedBy(ctx, app, a.TeamID); err != nil {
			return "", cleanup, err
		}
	}
	return app, cleanup, nil
}

// Check lists catalog apps that are installed and have a newer release.
func (m Mac) Check(ctx context.Context) ([]Update, []string) {
	var ups []Update
	var errs []string
	for _, a := range m.catalog() {
		path := filepath.Join(m.apps(), a.Bundle)
		if !m.exists(path) {
			continue
		}
		cur := m.version(ctx, path)
		app, cleanup, err := m.stage(ctx, a)
		if err != nil {
			cleanup()
			errs = append(errs, fmt.Sprintf("%s: %v", a.Name, err))
			continue
		}
		latest := m.version(ctx, app)
		cleanup()
		if latest != "" && (cur == "" || versionNewer(latest, cur)) {
			ups = append(ups, Update{Name: a.Name, ID: a.ID, Current: cur, Version: latest, ThirdParty: true})
		}
	}
	return ups, errs
}

// Install updates the listed catalog apps (all outdated ones when ids is empty). Open apps are skipped.
func (m Mac) Install(ctx context.Context, ids []string) (string, error) {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var done, skipped, failed []string
	for _, a := range m.catalog() {
		if len(want) > 0 && !want[a.ID] {
			continue
		}
		path := filepath.Join(m.apps(), a.Bundle)
		if !m.exists(path) {
			continue
		}
		running := m.Running
		if running == nil {
			running = func(ctx context.Context, bundle string) bool {
				_, err := m.Run(ctx, "pgrep", "-f", filepath.Join(bundle, "Contents", "MacOS"))
				return err == nil
			}
		}
		if running(ctx, path) {
			skipped = append(skipped, a.Name+" (open)")
			continue
		}
		cur := m.version(ctx, path)
		app, cleanup, err := m.stage(ctx, a)
		if err != nil {
			cleanup()
			failed = append(failed, fmt.Sprintf("%s: %v", a.Name, err))
			continue
		}
		latest := m.version(ctx, app)
		if latest == "" || (cur != "" && !versionNewer(latest, cur)) {
			cleanup()
			continue
		}
		if a.Kind == "pkg" {
			pkg := filepath.Join(m.Dir, "thirdparty", a.ID, "download.pkg")
			if out, err := m.Run(ctx, "installer", "-pkg", pkg, "-target", "/"); err != nil {
				failed = append(failed, fmt.Sprintf("%s: %s", a.Name, firstLine(out, err)))
				cleanup()
				continue
			}
		} else {
			// Copy beside the old one, then swap: an interrupted copy never leaves a half app.
			next := path + ".nexus-new"
			_, _ = m.Run(ctx, "rm", "-rf", next)
			if out, err := m.Run(ctx, "ditto", app, next); err != nil {
				failed = append(failed, fmt.Sprintf("%s: %s", a.Name, firstLine(out, err)))
				cleanup()
				continue
			}
			if out, err := m.Run(ctx, "rm", "-rf", path); err != nil {
				failed = append(failed, fmt.Sprintf("%s: %s", a.Name, firstLine(out, err)))
				cleanup()
				continue
			}
			if out, err := m.Run(ctx, "mv", next, path); err != nil {
				failed = append(failed, fmt.Sprintf("%s: %s", a.Name, firstLine(out, err)))
				cleanup()
				continue
			}
		}
		cleanup()
		done = append(done, fmt.Sprintf("%s %s", a.Name, latest))
	}
	msg := summary(done, skipped)
	if len(failed) > 0 {
		return msg, errors.New(strings.Join(failed, "; "))
	}
	return msg, nil
}

func summary(done, skipped []string) string {
	parts := []string{}
	if len(done) > 0 {
		parts = append(parts, "updated "+strings.Join(done, ", "))
	}
	if len(skipped) > 0 {
		parts = append(parts, "skipped "+strings.Join(skipped, ", "))
	}
	if len(parts) == 0 {
		return "apps up to date"
	}
	return strings.Join(parts, "; ")
}

// ---- Both --------------------------------------------------------------------------------------

// ThirdParty lists outdated third-party apps on this OS.
func ThirdParty(ctx context.Context, goos string, run Run, winget string, mac Mac) ([]Update, error) {
	switch goos {
	case "windows":
		if winget == "" {
			return nil, errors.New("winget (App Installer) isn't on this device")
		}
		out, err := run(ctx, winget, "upgrade", "--include-unknown", "--accept-source-agreements", "--disable-interactivity")
		if err != nil && !strings.Contains(out, "Name") && !strings.Contains(out, "No installed package") {
			return nil, fmt.Errorf("winget: %s", firstLine(out, err))
		}
		return ParseWingetUpgrade(out), nil
	case "darwin":
		ups, errs := mac.Check(ctx)
		if len(errs) > 0 {
			return ups, errors.New(strings.Join(errs, "; "))
		}
		return ups, nil
	}
	return nil, nil
}

// InstallThirdParty updates outdated third-party apps (the listed IDs, or all).
func InstallThirdParty(ctx context.Context, goos string, run Run, winget string, mac Mac, ids []string) (string, error) {
	switch goos {
	case "windows":
		if winget == "" {
			return "", errors.New("winget (App Installer) isn't on this device")
		}
		if len(ids) == 0 {
			out, err := run(ctx, winget, "upgrade", "--include-unknown", "--accept-source-agreements", "--disable-interactivity")
			if err != nil && !strings.Contains(out, "Name") {
				return "", fmt.Errorf("winget: %s", firstLine(out, err))
			}
			for _, u := range ParseWingetUpgrade(out) {
				ids = append(ids, u.ID)
			}
		}
		var done, failed []string
		for _, id := range ids {
			if !wingetID.MatchString(id) {
				failed = append(failed, id+": not a winget ID")
				continue
			}
			out, err := run(ctx, winget, "upgrade", "--id", id, "--exact", "--silent", "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity")
			if err != nil {
				failed = append(failed, fmt.Sprintf("%s: %s", id, firstLine(out, err)))
				continue
			}
			done = append(done, id)
		}
		msg := summary(done, nil)
		if len(failed) > 0 {
			return msg, errors.New(strings.Join(failed, "; "))
		}
		return msg, nil
	case "darwin":
		return mac.Install(ctx, ids)
	}
	return "Linux apps are updated with the OS packages", nil
}

// DownloadLatest fetches a vendor's latest release over https (redirects must stay https). There's
// no hash to check against a moving "latest": trust comes from the code signature, checked after.
func DownloadLatest(ctx context.Context, rawURL, dest string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" {
		return errors.New("downloads must be https")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	client := &http.Client{CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if r.URL.Scheme != "https" || len(via) > 10 {
			return errors.New("redirected away from https")
		}
		return nil
	}}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	const max = 3 << 30
	n, err := io.Copy(f, io.LimitReader(resp.Body, max+1))
	f.Close()
	if err == nil && n > max {
		err = errors.New("download: larger than 3 GB")
	}
	return err
}
