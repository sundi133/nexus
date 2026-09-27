import { describe, expect, it } from "vitest";
import { LoggedMailer, ResendMailer } from "./mailer.js";

const mail = { to: "alice@acme.test", subject: "Reset your Nexus password", html: "<p>hi</p>", text: "hi" };

describe("ResendMailer", () => {
  it("sends through Resend's API with the key and sender", async () => {
    let seen: { url: string; init: RequestInit } | null = null;
    const fake = (async (url: string, init: RequestInit) => {
      seen = { url, init };
      return new Response(JSON.stringify({ id: "em_1" }), { status: 200 });
    }) as unknown as typeof fetch;
    await new ResendMailer("re_test", "Votal Nexus <no-reply@acme.test>", fake).send(mail);
    expect(seen!.url).toBe("https://api.resend.com/emails");
    expect((seen!.init.headers as Record<string, string>).authorization).toBe("Bearer re_test");
    expect(JSON.parse(seen!.init.body as string)).toEqual({ from: "Votal Nexus <no-reply@acme.test>", to: ["alice@acme.test"], subject: mail.subject, html: mail.html, text: mail.text });
  });

  it("fails with Resend's reason, and the failure is logged without the address", async () => {
    const fake = (async () => new Response(JSON.stringify({ message: "The acme.test domain is not verified" }), { status: 403 })) as unknown as typeof fetch;
    const lines: string[] = [];
    const m = new LoggedMailer(new ResendMailer("re_test", "x@acme.test", fake), (l) => lines.push(l));
    await expect(m.send(mail)).rejects.toThrow("HTTP 403): The acme.test domain is not verified");
    expect(JSON.parse(lines[0]!)).toMatchObject({ msg: "email not sent", to_domain: "acme.test", error: expect.stringContaining("not verified") });
    expect(lines[0]).not.toContain("alice@");
  });
});
