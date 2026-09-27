package updates

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const wingetOut = "   - \r   \\ \r" + `Name                               Id                          Version          Available        Source
-----------------------------------------------------------------------------------------------------------
Google Chrome                      Google.Chrome               120.0.6099.130   121.0.6167.85    winget
Zoom Workplace                     Zoom.Zoom                   5.16.10.26186    6.0.2.33403      winget
Microsoft Visual Studio Code (Use… Microsoft.VisualStudioCode  1.85.1           1.86.0           winget
3 upgrades available.
`

func TestParseWinget(t *testing.T) {
	u := ParseWingetUpgrade(wingetOut)
	if len(u) != 3 || u[0].ID != "Google.Chrome" || u[0].Current != "120.0.6099.130" || u[0].Version != "121.0.6167.85" || !u[0].ThirdParty || u[2].ID != "Microsoft.VisualStudioCode" {
		t.Fatalf("%+v", u)
	}
	if len(ParseWingetUpgrade("No installed package found matching input criteria.")) != 0 {
		t.Fatal("found upgrades in nothing")
	}
}

func TestWingetInstallRefusesOddIDs(t *testing.T) {
	var ran []string
	run := func(_ context.Context, name string, args ...string) (string, error) {
		ran = append(ran, name+" "+strings.Join(args, " "))
		return "ok", nil
	}
	msg, err := InstallThirdParty(context.Background(), "windows", run, `C:\winget.exe`, Mac{}, []string{"Google.Chrome", "--override evil"})
	if err == nil || !strings.Contains(err.Error(), "not a winget ID") || !strings.Contains(msg, "Google.Chrome") || len(ran) != 1 {
		t.Fatalf("%q %v %q", msg, err, ran)
	}
}

// fakeMac: Chrome installed at 120, the download holds 121 signed by Google (or by someone else).
type fakeMac struct {
	installed, latest string
	team              string
	open              bool
	ran               []string
}

func (f *fakeMac) mac(t *testing.T) Mac {
	dir := t.TempDir()
	return Mac{
		Dir:      dir,
		Apps:     "/Applications",
		Catalog:  []MacApp{{ID: "google-chrome", Name: "Google Chrome", Bundle: "Google Chrome.app", URL: "https://dl.example/chrome.dmg", Kind: "dmg", TeamID: "EQHXZ8M8AV"}},
		Exists:   func(p string) bool { return p == "/Applications/Google Chrome.app" },
		Download: func(_ context.Context, _ string, dest string) error { return os.WriteFile(dest, []byte("dmg"), 0o600) },
		Staged:   func(root string) (string, error) { return filepath.Join(root, "Google Chrome.app"), nil },
		Running:  func(context.Context, string) bool { return f.open },
		Run: func(_ context.Context, name string, args ...string) (string, error) {
			cmd := name + " " + strings.Join(args, " ")
			f.ran = append(f.ran, cmd)
			switch {
			case name == "plutil" && strings.HasPrefix(args[len(args)-1], "/Applications/"):
				return f.installed, nil
			case name == "plutil":
				return f.latest, nil
			case name == "codesign" && args[0] == "-dv":
				return "Executable=…\nTeamIdentifier=" + f.team + "\n", nil
			}
			return "", nil
		},
	}
}

func TestMacCatalogUpdatesOnlyWhenNewerAndSignedByTheVendor(t *testing.T) {
	f := &fakeMac{installed: "120.0.6099.129", latest: "121.0.6167.85", team: "EQHXZ8M8AV"}
	ups, errs := f.mac(t).Check(context.Background())
	if len(errs) != 0 || len(ups) != 1 || ups[0].Current != "120.0.6099.129" || ups[0].Version != "121.0.6167.85" {
		t.Fatalf("%+v %v", ups, errs)
	}
	f.ran = nil
	msg, err := f.mac(t).Install(context.Background(), nil)
	if err != nil || msg != "updated Google Chrome 121.0.6167.85" {
		t.Fatalf("%q %v", msg, err)
	}
	joined := strings.Join(f.ran, "\n")
	for _, want := range []string{"hdiutil attach -nobrowse -readonly", "codesign --verify --deep", "ditto ", "mv /Applications/Google Chrome.app.nexus-new /Applications/Google Chrome.app", "hdiutil detach"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in:\n%s", want, joined)
		}
	}

	// Same version: nothing to do.
	f2 := &fakeMac{installed: "121.0.6167.85", latest: "121.0.6167.85", team: "EQHXZ8M8AV"}
	if ups, _ := f2.mac(t).Check(context.Background()); len(ups) != 0 {
		t.Fatalf("%+v", ups)
	}
	// Signed by someone else: refused, never installed.
	f3 := &fakeMac{installed: "120", latest: "121", team: "BADTEAM000"}
	_, errs = f3.mac(t).Check(context.Background())
	if len(errs) != 1 || !strings.Contains(errs[0], "isn't signed by its vendor") {
		t.Fatalf("%v", errs)
	}
	if _, err := f3.mac(t).Install(context.Background(), nil); err == nil || strings.Contains(strings.Join(f3.ran, "\n"), "mv ") {
		t.Fatalf("installed a badly signed app: %v", err)
	}
	// Open: skipped, not killed.
	f4 := &fakeMac{installed: "120", latest: "121", team: "EQHXZ8M8AV", open: true}
	if msg, _ := f4.mac(t).Install(context.Background(), nil); msg != "skipped Google Chrome (open)" {
		t.Fatalf("%q", msg)
	}
}

func TestVersionNewer(t *testing.T) {
	for _, c := range [][3]string{{"121.0.6167.85", "120.0.6099.130", "y"}, {"1.10.0", "1.9.9", "y"}, {"5.16.10", "5.16.10", "n"}, {"4.35.126", "4.36.0", "n"}} {
		if versionNewer(c[0], c[1]) != (c[2] == "y") {
			t.Errorf("%v", c)
		}
	}
	_ = errors.New
}
