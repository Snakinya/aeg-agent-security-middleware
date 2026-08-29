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
export type MessageRole = "user" | "assistant";
export type EffectDecision = "allow" | "require_approval" | "deny";
export type ApprovalStatus = "pending" | "approved" | "denied" | "expired";
export type PolicyTemplate = "relaxed" | "balanced" | "strict" | "custom";

export interface PolicyProfile {
  version: number;
  template: PolicyTemplate;
  fileRules: {
    autoAllow: string[];
    requireApproval: string[];
    deny: string[];
  };
  external: {
    allowHosts: string[];
    requireApprovalMethods: Array<"POST" | "PUT" | "PATCH">;
  };
  egress: {
    allow: string[];
  };
  approval: {
    ttlMinutes: number;
  };
  analyzers: {
    "guardrail-model": {
      enabled: boolean;
      denyThreshold: number;
      reviewThreshold: number;
    };
    "secret-scanner": {
      enabled: boolean;
      action: "deny" | "require_approval";
    };
  };
  updatedAt: string;
}

export interface SecurityModuleConfiguration {
  moduleId: string;
  enabled: boolean;
  config: Record<string, unknown>;
  revision: number;
  updatedAt: string;
}

export interface HumanPrincipal {
  id: string;
  displayName: string;
  roles: Array<"operator" | "approver" | "security_admin">;
  status: "active" | "disabled";
  createdAt: string;
}

export interface RunSecurityContext {
  id: string;
  runId: string;
  humanId: string;
  agentId: string;
  agentPrincipalId: string;
  scopes: string[];
  policyProfile: string;
  intakeDecision: EffectDecision;
  intakeSignals: Array<{
    moduleId: string;
    decision: EffectDecision;
    ruleId: string;
    reason: string;
    score?: number;
  }>;
  issuedAt: string;
  expiresAt: string;
  revokedAt: string | null;
}

export interface FileEffect {
  id: string;
  runId: string;
  type: "file.create" | "file.modify" | "file.delete";
  resource: string;
  beforeHash: string | null;
  afterHash: string | null;
  size: number;
  decision: EffectDecision;
  ruleId: string;
  reason: string;
}

export type ExternalEffectStatus =
  | "planned"
  | "executed"
  | "denied"
  | "uncertain";

export interface ExternalHttpReceipt {
  statusCode: number;
  contentType: string | null;
  responseBytes: number;
  responseHash: string;
  bodyPreview: string;
  truncated: boolean;
  executedAt: string;
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
  decision: EffectDecision;
  ruleId: string;
  reason: string;
  status: ExternalEffectStatus;
  receipt: ExternalHttpReceipt | null;
  error: string | null;
}

export interface EffectPreview {
  effectId: string;
  before: string | null;
  after: string | null;
  truncated: boolean;
  binary: boolean;
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
  status: ApprovalStatus;
  scope: "intake" | "manifest";
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
  policyProfile: PolicyProfile;
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
  role: MessageRole;
  content: string;
  createdAt: string;
}

export interface RunUsage {
  inputTokens?: number;
  cachedInputTokens?: number;
  outputTokens?: number;
}

export interface AgentRun {
  id: string;
  agentId: string;
  status: RunStatus;
  prompt: string;
  output: string | null;
  error: string | null;
  usage: RunUsage | null;
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

export interface Database {
  version: 5;
  humans: HumanPrincipal[];
  runSecurityContexts: RunSecurityContext[];
  agents: Agent[];
  messages: Message[];
  runs: AgentRun[];
  approvals: Approval[];
  securityModuleConfigurations: SecurityModuleConfiguration[];
}

export interface CreateAgentInput {
  name: string;
  description?: string | undefined;
  instructions?: string | undefined;
}

export interface UpdateAgentInput {
  name?: string | undefined;
  description?: string | undefined;
  instructions?: string | undefined;
}

export interface RunnerResult {
  output: string;
  threadId: string | null;
  usage: RunUsage | null;
  trace: Omit<TraceEvent, "id" | "runId" | "createdAt">[];
}

export interface RunnerRequest {
  runId: string;
  agentId: string;
  workspacePath: string;
  codexHomePath: string;
  prompt: string;
  threadId: string | null;
}

export interface AgentRunner {
  run(request: RunnerRequest): Promise<RunnerResult>;
  cancel(agentId: string): Promise<boolean>;
  isAvailable(): Promise<boolean>;
}
