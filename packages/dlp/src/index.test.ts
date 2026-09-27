import { describe, expect, it } from "vitest";
import { ibanValid, luhn, redact, scan } from "./index.js";

const ALL = ["secret", "private_key", "credit_card", "us_ssn", "iban", "email_list"];
const detectors = (text: string) => scan(text, ALL).map((f) => f.detector);

describe("detectors", () => {
  it("finds credentials by shape, and hints without revealing them", () => {
    const cases: [string, string][] = [
      ["AKIAIOSFODNN7EXAMPLE", "AWS access key"],
      ["token ghp_" + "a".repeat(36), "GitHub token"],
      ["xoxb-1234567890-abcdefghij", "Slack token"],
      ["sk-ant-api03-" + "x".repeat(40), "Anthropic key"],
      ["OPENAI_API_KEY=sk-proj-" + "A1b2".repeat(10), "OpenAI key"],
      ["postgres://admin:hunter2secret@db.internal:5432/prod", "Connection string with a password"],
      ["password: Tr0ub4dor&3xyz", "Password"],
      ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "JWT"],
    ];
    for (const [text, name] of cases) {
      const f = scan(text, ["secret"]);
      expect(f, text).toEqual([expect.objectContaining({ detector: "secret", name })]);
      expect(f[0]!.hint).not.toBe(text);
      expect(f[0]!.hint.length).toBeLessThan(12);
    }
  });

  it("doesn't cry wolf on ordinary text and code", () => {
    expect(scan("password = getPassword(); secret: process.env.SECRET_VALUE", ["secret"])).toEqual([]);
    expect(scan('password = "Tr0ub4dor&3"', ["secret"])).toHaveLength(1);
    const benign = [
      "Can you refactor this function to use async/await? const password = input.value;",
      "The build number is 1234567812345678 and the ticket is ABC-123.",
      "Call me at 555-123-4567; case 000-12-3456 and 666-12-3456 aren't valid SSNs",
      "Meeting notes: sk-learn is a python library; AKIA is just a word here.",
      "ISBN 978-3-16-148410-0, order #4111 1111 1111 1112",
      "Contact sam@example.com or pat@example.com",
    ];
    for (const b of benign) expect(detectors(b), b).toEqual([]);
  });

  it("finds payment cards only with a valid checksum and a real network prefix", () => {
    expect(luhn("4242424242424242")).toBe(true);
    expect(luhn("4242424242424241")).toBe(false);
    expect(scan("card 4242 4242 4242 4242 exp 12/28", ["credit_card"])).toEqual([expect.objectContaining({ detector: "credit_card", hint: "•••• 4242" })]);
    expect(scan("amex 3782-822463-10005", ["credit_card"])).toHaveLength(1);
    expect(scan("id 1234567812345670", ["credit_card"])).toEqual([]); // passes Luhn, no network
  });

  it("finds SSNs, IBANs (checksummed), private keys and bulk email lists", () => {
    expect(scan("SSN 123-45-6789", ["us_ssn"])[0]).toMatchObject({ hint: "•••-••-6789" });
    expect(ibanValid("GB82 WEST 1234 5698 7654 32")).toBe(true);
    expect(ibanValid("GB82 WEST 1234 5698 7654 33")).toBe(false);
    expect(scan("pay to DE89 3704 0044 0532 0130 00 please", ["iban"])).toHaveLength(1);
    expect(scan("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n-----END OPENSSH PRIVATE KEY-----", ["private_key"])).toHaveLength(1);
    const list = Array.from({ length: 12 }, (_, i) => `user${i}@acme.com`).join(", ");
    expect(scan(list, ["email_list"])).toEqual([expect.objectContaining({ count: 12 })]);
  });

  it("runs only the detectors that are on, plus the organization's own patterns", () => {
    expect(scan("AKIAIOSFODNN7EXAMPLE and 123-45-6789", ["us_ssn"]).map((f) => f.detector)).toEqual(["us_ssn"]);
    const custom = [{ id: "falcon", name: "Project Falcon", pattern: "project\\s+falcon" }, { id: "bad", name: "Broken", pattern: "([" }];
    expect(scan("Summarize the Project Falcon roadmap", [], custom)).toEqual([expect.objectContaining({ detector: "custom:falcon", name: "Project Falcon" })]);
  });

  it("stays fast on huge pastes", () => {
    const big = "lorem ipsum dolor sit amet ".repeat(40_000) + "AKIAIOSFODNN7EXAMPLE";
    const t = performance.now();
    scan(big, ALL);
    expect(performance.now() - t).toBeLessThan(500);
  });
});

describe("redaction", () => {
  it("replaces what it finds, keeps everything else, and says what it removed", () => {
    const text = [
      "id,name,card,ssn",
      "1,Pat Lee,4242 4242 4242 4242,123-45-6789",
      "config: AWS_KEY=AKIAIOSFODNN7EXAMPLE region=us-east-1",
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7\n-----END RSA PRIVATE KEY-----",
      "build 1234567812345678, order #4111 1111 1111 1112",
    ].join("\n");
    const r = redact(text, ["secret", "private_key", "credit_card", "us_ssn"]);
    expect(r.text).toContain("1,Pat Lee,[redacted: Payment card number],[redacted: US Social Security number]");
    expect(r.text).toContain("AWS_KEY=[redacted: AWS access key] region=us-east-1");
    expect(r.text).toContain("[redacted: Private key]");
    expect(r.text).not.toContain("MIIEowIBAAKCAQEA7");
    expect(r.text).toContain("build 1234567812345678, order #4111 1111 1111 1112"); // not cards: untouched
    expect(r.findings.map((f) => f.detector).sort()).toEqual(["credit_card", "private_key", "secret", "us_ssn"]);
    expect(JSON.stringify(r.findings)).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("leaves text alone when nothing is enabled or found", () => {
    expect(redact("SSN 123-45-6789", [])).toEqual({ text: "SSN 123-45-6789", findings: [] });
    expect(redact("just prose", ["secret", "credit_card"]).text).toBe("just prose");
  });
});
