/**
 * AI apps people use in the browser. Matched by host (and its subdomains); the extension gets
 * this list with the organization's action for each.
 */
export type AIApp = { key: string; name: string; vendor: string; hosts: string[]; category: "chat" | "coding" | "search" | "research" | "companion" };

export const AI_APPS: AIApp[] = [
  { key: "chatgpt", name: "ChatGPT", vendor: "OpenAI", hosts: ["chatgpt.com", "chat.openai.com"], category: "chat" },
  { key: "claude", name: "Claude", vendor: "Anthropic", hosts: ["claude.ai"], category: "chat" },
  { key: "gemini", name: "Gemini", vendor: "Google", hosts: ["gemini.google.com", "aistudio.google.com"], category: "chat" },
  { key: "copilot", name: "Microsoft Copilot", vendor: "Microsoft", hosts: ["copilot.microsoft.com", "copilot.cloud.microsoft"], category: "chat" },
  { key: "meta_ai", name: "Meta AI", vendor: "Meta", hosts: ["meta.ai"], category: "chat" },
  { key: "grok", name: "Grok", vendor: "xAI", hosts: ["grok.com"], category: "chat" },
  { key: "deepseek", name: "DeepSeek", vendor: "DeepSeek", hosts: ["chat.deepseek.com"], category: "chat" },
  { key: "mistral", name: "Le Chat", vendor: "Mistral AI", hosts: ["chat.mistral.ai"], category: "chat" },
  { key: "qwen", name: "Qwen Chat", vendor: "Alibaba", hosts: ["chat.qwen.ai"], category: "chat" },
  { key: "kimi", name: "Kimi", vendor: "Moonshot AI", hosts: ["kimi.com", "kimi.moonshot.cn"], category: "chat" },
  { key: "poe", name: "Poe", vendor: "Quora", hosts: ["poe.com"], category: "chat" },
  { key: "perplexity", name: "Perplexity", vendor: "Perplexity", hosts: ["perplexity.ai"], category: "search" },
  { key: "you", name: "You.com", vendor: "You.com", hosts: ["you.com"], category: "search" },
  { key: "notebooklm", name: "NotebookLM", vendor: "Google", hosts: ["notebooklm.google.com"], category: "research" },
  { key: "phind", name: "Phind", vendor: "Phind", hosts: ["phind.com"], category: "coding" },
  { key: "v0", name: "v0", vendor: "Vercel", hosts: ["v0.dev", "v0.app"], category: "coding" },
  { key: "bolt", name: "Bolt", vendor: "StackBlitz", hosts: ["bolt.new"], category: "coding" },
  { key: "lovable", name: "Lovable", vendor: "Lovable", hosts: ["lovable.dev"], category: "coding" },
  { key: "character_ai", name: "Character.AI", vendor: "Character.AI", hosts: ["character.ai"], category: "companion" },
];

export const APP_KEYS = new Set(AI_APPS.map((a) => a.key));
