import type { AppConfig } from "./config.js";

export function redactSecurityText(value: string, config: AppConfig): string {
  let redacted = value;
  const configuredSecrets = [config.arkApiKey, config.authToken, config.auditHmacKey]
    .map((secret) => secret.trim())
    .filter((secret) => secret.length >= 4)
    .sort((left, right) => right.length - left.length);
  for (const secret of configuredSecrets) {
    redacted = redacted.split(secret).join("[REDACTED]");
  }
  return redacted
    .replace(/\b(Bearer)\s+[A-Za-z0-9._~+\/-]+/gi, "$1 [REDACTED]")
    .replace(
      /\b(api[_-]?key|authorization|cookie|password|secret|token)\s*([:=])\s*([^\s,;&]+)/gi,
      "$1$2[REDACTED]",
    );
}
