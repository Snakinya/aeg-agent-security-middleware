import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
import { redactSecurityText } from "./redaction.js";

describe("security-event redaction", () => {
  it("removes configured and structured credentials before persistence", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      ARK_API_KEY: "configured-secret-value",
      APP_AUTH_TOKEN: "shared-demo-token",
    });
    const result = redactSecurityText(
      "curl -H 'Authorization: Bearer abc.def' -d api_key=raw configured-secret-value shared-demo-token",
      config,
    );
    expect(result).not.toContain("configured-secret-value");
    expect(result).not.toContain("shared-demo-token");
    expect(result).not.toContain("abc.def");
    expect(result).not.toContain("api_key=raw");
    expect(result).toContain("[REDACTED]");
  });
});
