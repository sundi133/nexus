import nodemailer from "nodemailer";

export type Mail = { to: string; subject: string; text: string; html: string };

export interface Mailer {
  send(mail: Mail): Promise<void>;
}

/** SMTP mailer. Locally it delivers to Mailpit (http://localhost:58025). */
export class SmtpMailer implements Mailer {
  private readonly transport;
  constructor(
    url: string,
    private readonly from: string,
  ) {
    this.transport = nodemailer.createTransport(url);
  }
  async send(mail: Mail) {
    await this.transport.sendMail({ from: this.from, ...mail });
  }
}

/** Captures mail in memory (tests). */
export class MemoryMailer implements Mailer {
  readonly sent: Mail[] = [];
  async send(mail: Mail) {
    this.sent.push(mail);
  }
}

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

/** Minimal, client-safe transactional template: one message, one button. */
export function layout(opts: { heading: string; body: string; cta: { label: string; url: string }; footer: string }) {
  const html = `<!doctype html><html><body style="margin:0;background:#f7f7f8;font-family:-apple-system,Segoe UI,Inter,sans-serif;color:#0f1115">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 16px">
<table width="480" cellpadding="0" cellspacing="0" style="background:#fff;border:1px solid #e6e7ea;border-radius:10px">
<tr><td style="padding:28px">
<p style="margin:0 0 20px;font-weight:600;font-size:15px">Votal <span style="color:#5b606b">Nexus</span></p>
<h1 style="margin:0 0 12px;font-size:20px">${esc(opts.heading)}</h1>
<p style="margin:0 0 24px;font-size:14px;line-height:1.5;color:#3b3f47">${esc(opts.body)}</p>
<a href="${esc(opts.cta.url)}" style="display:inline-block;background:#4f46e5;color:#fff;text-decoration:none;padding:10px 18px;border-radius:6px;font-size:14px;font-weight:600">${esc(opts.cta.label)}</a>
<p style="margin:24px 0 0;font-size:12px;color:#8a909b">${esc(opts.footer)}</p>
</td></tr></table></td></tr></table></body></html>`;
  const text = `${opts.heading}\n\n${opts.body}\n\n${opts.cta.label}: ${opts.cta.url}\n\n${opts.footer}`;
  return { html, text };
}
