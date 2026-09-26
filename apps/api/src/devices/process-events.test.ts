import { describe, expect, it } from "vitest";
import { detect, redact } from "./process-events.js";

describe("redact", () => {
  it("removes secrets from command lines", () => {
    const cases: [string, string][] = [
      ["curl -H 'Authorization: Bearer abcdefghijklmnop' https://api.x.com", "curl -H 'Authorization: Bearer <redacted>' https://api.x.com"],
      ["git clone https://sam:hunter2hunter@github.com/acme/app", "git clone https://<redacted>@github.com/acme/app"],
      ["deploy --api-key=sk-abcdefghijklmnopqrstu --env prod", "deploy --api-key=<redacted> --env prod"],
      ["mysql --password s3cretpass -u root", "mysql --password <redacted> -u root"],
      ["gh auth login --with-token ghp_abcdefghijklmnopqrstuvwxyz0123", "gh auth login --with-token <redacted>"],
      ["export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123", "export GITHUB_TOKEN=<redacted>"],
      ["node app.js --port 3000", "node app.js --port 3000"],
    ];
    for (const [cmd, want] of cases) expect(redact(cmd), cmd).toBe(want);
    expect(redact("x".repeat(5000))).toHaveLength(2000);
  });
});

describe("detect", () => {
  const e = (path: string, parent = "", ancestors: string[] = [], responsible = "") => ({ path, parent_path: parent, ancestors, responsible_path: responsible });
  it("flags AI tools running network tools, whoever is in between", () => {
    expect(detect(e("/usr/bin/curl", "/bin/zsh", [], "/Applications/Cursor.app/Contents/MacOS/Cursor"))).toMatchObject({ key: "ai_network_tool", severity: "high", title: "Cursor ran curl" });
    expect(detect(e("/usr/bin/scp", "/bin/bash", ["/home/sam/.local/bin/claude"]))).toMatchObject({ key: "ai_network_tool", title: "Claude ran scp" });
    expect(detect(e("C:\\Windows\\System32\\curl.exe", "C:\\Windows\\System32\\cmd.exe", ["C:\\Users\\sam\\AppData\\Local\\Programs\\cursor\\Cursor.exe"]))).toMatchObject({ key: "ai_network_tool" });
    expect(detect(e("C:\\Windows\\System32\\certutil.exe", "C:\\Users\\sam\\AppData\\Local\\AnthropicClaude\\claude.exe"))).toMatchObject({ key: "ai_network_tool", title: "Claude ran certutil.exe" });
  });
  it("notes shells, and temp-folder programs; ignores the rest", () => {
    expect(detect(e("/bin/zsh", "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper (Plugin).app/Contents/MacOS/Cursor Helper (Plugin)"))).toMatchObject({ key: "ai_shell", severity: "info" });
    expect(detect(e("/Users/sam/Downloads/installer", "/sbin/launchd"))).toMatchObject({ key: "exec_from_temp", severity: "low" });
    expect(detect(e("/tmp/x", "/bin/bash"))).toMatchObject({ key: "exec_from_temp" });
    expect(detect(e("/usr/bin/curl", "/bin/zsh", ["/Applications/iTerm.app/Contents/MacOS/iTerm2"]))).toBeNull(); // a person in a terminal
    expect(detect(e("/Applications/Cursor.app/Contents/MacOS/Cursor Helper", "/Applications/Cursor.app/Contents/MacOS/Cursor"))).toBeNull(); // the AI tool's own helpers
  });
});
