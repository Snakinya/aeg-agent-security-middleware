export type AgentStatus = "ready" | "busy" | "stopped" | "error";
export type RunStatus =
  | "queued"
  | "running"
  | "reviewing_effects"
  | "awaiting_approval"
  | "committing"
  | "rolling_back"
  | "rolled_back"
  | "completed"
  | "failed"
  | "cancelled";

export interface FileEffect {
  id: string;
  runId: string;
  type: "file.create" | "file.modify" | "file.delete";
  resource: string;
  beforeHash: string | null;
  afterHash: string | null;
  size: number;
  decision: "allow" | "require_approval" | "deny";
  ruleId: string;
  reason: string;
}

export interface EffectPreview {
  effectId: string;
  before: string | null;
  after: string | null;
  truncated: boolean;
  binary: boolean;
}

export interface ExternalHttpEffect {
  id: string;
  runId: string;
  type: "http.request";
  resource: string;
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  url: string;
  headerNames: string[];
  bodyHash: string | null;
  bodyBytes: number;
  bodyPreview: string | null;
  requestDigest: string;
  decision: "allow" | "require_approval" | "deny";
  ruleId: string;
  reason: string;
  status: "planned" | "executed" | "denied" | "uncertain";
  receipt: {
    statusCode: number;
    contentType: string | null;
    responseBytes: number;
    responseHash: string;
    bodyPreview: string;
    truncated: boolean;
    executedAt: string;
  } | null;
  error: string | null;
}

export interface TraceEvent {
  id: string;
  runId: string;
  type: "command_execution" | "file_change" | "mcp_tool_call";
  summary: string;
  resources: string[];
  exitCode: number | null;
  createdAt: string;
}

export interface Approval {
  id: string;
  agentId: string;
  runId: string;
  status: "pending" | "approved" | "denied" | "expired";
  manifestDigest: string;
  policyVersion: string;
  expiresAt: string;
  decidedAt: string | null;
  approvedBy: string | null;
  createdAt: string;
}

export interface Agent {
  id: string;
  name: string;
  description: string;
  instructions: string;
  status: AgentStatus;
  ownerHumanId: string;
  principalId: string;
  principalStatus: "active" | "revoked";
  workspacePath: string;
  codexThreadId: string | null;
  lastError: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface Message {
  id: string;
  agentId: string;
  runId: string;
  role: "user" | "assistant";
  content: string;
  createdAt: string;
}

export interface AgentRun {
  id: string;
  agentId: string;
  status: RunStatus;
  prompt: string;
  output: string | null;
  error: string | null;
  usage: {
    inputTokens?: number;
    cachedInputTokens?: number;
    outputTokens?: number;
  } | null;
  effects: FileEffect[];
  externalEffects: ExternalHttpEffect[];
  trace: TraceEvent[];
  manifestDigest: string | null;
  policyVersion: string | null;
  approvalId: string | null;
  securityContextId: string;
  securitySummary: string | null;
  workspaceHashBefore: string | null;
  workspaceHashAfter: string | null;
  pendingThreadId: string | null;
  startedAt: string | null;
  completedAt: string | null;
  createdAt: string;
}

export interface SystemInfo {
  arkConfigured: boolean;
  arkBaseUrl: string;
  arkModel: string | null;
  codexAvailable: boolean;
  codexSandboxMode: string;
  runtimeProvider: "local-process" | "container";
  containerEngine: string | null;
  runtime: string;
  externalHttpGatewayEnabled: boolean;
  externalHttpAllowlist: string[];
}

export type SecurityStage =
  | "identity"
  | "runtime"
  | "observe"
  | "policy"
  | "approval"
  | "execute"
  | "recover"
  | "verify";

export interface SecurityEvent {
  sequence: number;
  createdAt: string;
  type: string;
  moduleId?: string;
  stage?: SecurityStage;
  severity?: "info" | "low" | "medium" | "high" | "critical";
  humanId?: string | null;
  agentPrincipalId?: string | null;
  agentId?: string | null;
  agentName?: string | null;
  runId?: string | null;
  runStatus?: RunStatus | null;
  runPrompt?: string | null;
  effectId?: string | null;
  decision?: string | null;
  ruleId?: string | null;
  reason?: string | null;
  payload?: Record<string, unknown>;
  previousMac: string;
  eventMac: string;
}

export interface SecurityModule {
  id: string;
  name: string;
  version: string;
  kind: "identity" | "runtime" | "effect" | "approval" | "evidence";
  description: string;
  capabilities: string[];
  status: "active" | "disabled";
  statusReason: string;
  events: number;
}

export interface SecurityOverview {
  generatedAt: string;
  posture: "protected" | "degraded";
  scope: string;
  totals: {
    agents: number;
    runs: number;
    effects: number;
    blocked: number;
    awaitingApproval: number;
    rolledBack: number;
    externalExecuted: number;
  };
  ledger: {
    valid: boolean;
    events: number;
    brokenAt: number | null;
    head: string;
  };
  identity: {
    humans: number;
    activeAgentPrincipals: number;
    issuedCapabilities: number;
  };
  modules: SecurityModule[];
  recentEvents: SecurityEvent[];
}
