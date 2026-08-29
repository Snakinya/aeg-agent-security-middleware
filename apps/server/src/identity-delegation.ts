import { randomUUID } from "node:crypto";
import type { Agent, HumanPrincipal, RunSecurityContext } from "./types.js";

export const LOCAL_OPERATOR_ID = "human:local-operator";

export function localOperator(createdAt = new Date().toISOString()): HumanPrincipal {
  return {
    id: LOCAL_OPERATOR_ID,
    displayName: "Local Operator",
    roles: ["operator", "approver", "security_admin"],
    status: "active",
    createdAt,
  };
}

export function agentPrincipalId(agentId: string): string {
  return "agent:" + agentId;
}

export function issueRunSecurityContext(
  agent: Agent,
  runId: string,
  ttlMs: number,
): RunSecurityContext {
  if (agent.principalStatus !== "active") {
    throw new Error("Agent principal is revoked");
  }
  const issuedAt = new Date();
  return {
    id: randomUUID(),
    runId,
    humanId: agent.ownerHumanId,
    agentId: agent.id,
    agentPrincipalId: agent.principalId,
    scopes: ["workspace:**", "external:http:declared"],
    policyProfile: `agent:${agent.id}@v${agent.policyProfile.version}`,
    intakeDecision: "allow",
    intakeSignals: [],
    issuedAt: issuedAt.toISOString(),
    expiresAt: new Date(issuedAt.getTime() + ttlMs).toISOString(),
    revokedAt: null,
  };
}
