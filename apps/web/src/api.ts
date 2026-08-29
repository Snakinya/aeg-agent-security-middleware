import type {
  Agent,
  AgentRun,
  Approval,
  EffectPreview,
  Message,
  SecurityEvent,
  SecurityModule,
  SecurityOverview,
  SystemInfo,
  PolicyProfile,
  PolicySimulation,
  PolicyTemplate,
} from "./types";

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
  }
}

let authToken = "";

export function setAuthToken(token: string): void {
  authToken = token.trim();
}

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const headers = {
    ...(options?.body ? { "Content-Type": "application/json" } : {}),
    ...(authToken ? { Authorization: "Bearer " + authToken } : {}),
    ...options?.headers,
  };
  const response = await fetch(url, {
    ...options,
    headers,
  });
  const data = (await response.json().catch(() => ({}))) as T & { error?: string };
  if (!response.ok) {
    throw new ApiError(data.error ?? "Request failed", response.status);
  }
  return data;
}

export const api = {
  auth: () => request<{ required: boolean }>("/api/auth"),
  system: () => request<SystemInfo>("/api/system"),
  listAgents: () => request<{ agents: Agent[] }>("/api/agents"),
  createAgent: (body: {
    name: string;
    description: string;
    instructions: string;
  }) =>
    request<{ agent: Agent }>("/api/agents", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateAgent: (
    id: string,
    body: { name: string; description: string; instructions: string },
  ) =>
    request<{ agent: Agent }>("/api/agents/" + id, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deleteAgent: (id: string) =>
    request<{ archivedWorkspace: string }>("/api/agents/" + id, {
      method: "DELETE",
    }),
  startAgent: (id: string) =>
    request<{ agent: Agent }>("/api/agents/" + id + "/start", {
      method: "POST",
    }),
  stopAgent: (id: string) =>
    request<{ agent: Agent }>("/api/agents/" + id + "/stop", {
      method: "POST",
    }),
  messages: (id: string) =>
    request<{ messages: Message[] }>("/api/agents/" + id + "/messages"),
  runs: (id: string) =>
    request<{ runs: AgentRun[] }>("/api/agents/" + id + "/runs"),
  policy: (id: string) =>
    request<{
      profile: PolicyProfile;
      templates: Record<Exclude<PolicyTemplate, "custom">, PolicyProfile>;
      hardDenyRules: string[];
      pendingApprovals: number;
    }>("/api/agents/" + id + "/policy"),
  updatePolicy: (id: string, profile: PolicyProfile) =>
    request<{ profile: PolicyProfile; invalidatedApprovals: number }>("/api/agents/" + id + "/policy", {
      method: "PUT",
      body: JSON.stringify(profile),
    }),
  applyPolicyTemplate: (id: string, template: Exclude<PolicyTemplate, "custom">) =>
    request<{ profile: PolicyProfile; invalidatedApprovals: number }>("/api/agents/" + id + "/policy/template", {
      method: "POST",
      body: JSON.stringify({ template }),
    }),
  simulatePolicy: (
    id: string,
    input: { kind: "file"; resource: string } | { kind: "http"; resource: string; method: string },
    profile?: PolicyProfile,
  ) => request<{ result: PolicySimulation }>("/api/agents/" + id + "/policy/simulate", {
    method: "POST",
    body: JSON.stringify({ ...input, ...(profile ? { profile } : {}) }),
  }),
  sendMessage: (id: string, content: string) =>
    request<{ run: AgentRun; message: Message }>(
      "/api/agents/" + id + "/messages",
      {
        method: "POST",
        body: JSON.stringify({ content }),
      },
    ),
  run: (id: string) => request<{ run: AgentRun }>("/api/runs/" + id),
  approvals: (status?: "pending" | "approved" | "denied" | "expired") =>
    request<{ approvals: Approval[] }>(
      "/api/approvals" + (status ? "?status=" + status : ""),
    ),
  approval: (approvalId: string) =>
    request<{
      approval: Approval;
      run: AgentRun;
      previews: EffectPreview[];
      currentWorkspaceHash: string;
    }>(
      "/api/approvals/" + approvalId,
    ),
  approve: (approvalId: string) =>
    request<{ approval: Approval; run: AgentRun }>(
      "/api/approvals/" + approvalId + "/approve",
      { method: "POST" },
    ),
  deny: (approvalId: string) =>
    request<{ approval: Approval; run: AgentRun }>(
      "/api/approvals/" + approvalId + "/deny",
      { method: "POST" },
    ),
  verifyLedger: () =>
    request<{ valid: boolean; events: number; brokenAt: number | null; head: string }>(
      "/api/ledger/verify",
    ),
  securityOverview: () => request<SecurityOverview>("/api/security/overview"),
  securityModules: () => request<{ modules: SecurityModule[] }>("/api/security/modules"),
  configureSecurityModule: (moduleId: string, body: { enabled?: boolean; config?: Record<string, unknown> }) =>
    request<{ module: SecurityModule; invalidatedApprovals: number }>("/api/security/modules/" + moduleId, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  securityEvents: (query = "") =>
    request<{ events: SecurityEvent[] }>(
      "/api/security/events" + (query ? "?" + query : ""),
    ),
};
