import {
  Agent,
  AgentGrant,
  AgentGrantList,
  AgentList,
  ApplicationDefinition,
  ApplicationList,
  AuditEventList,
  Connection,
  ConnectionAuthResponse,
  ConnectionList,
  HealthResponse,
  OperationJob,
  Routes,
  SessionResponse,
} from '@aab/contracts';
import type {
  AuditEventType,
  CreateAgentRequest,
  CreateConnectionRequest,
  CreateGrantRequest,
  ExecuteOperationRequest,
  LoginRequest,
  RegisterApplicationRequest,
  RevokeConnectionRequest,
} from '@aab/contracts';
import type { ApiClient } from './client.js';

/** Largest page the API serves (ListQuery.limit max). */
const PAGE_SIZE = 200;
/** Upper bound on pages followed when loading a whole collection: 5,000 records. */
const MAX_PAGES = 25;

interface Page<T> {
  items: T[];
  nextCursor: string | null;
}

async function listAll<T>(fetchPage: (cursor: string | undefined) => Promise<Page<T>>) {
  const items: T[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const result = await fetchPage(cursor);
    items.push(...result.items);
    if (result.nextCursor === null) break;
    cursor = result.nextCursor;
  }
  return items;
}

function fill(template: string, params: Record<string, string>): string {
  return template.replace(/:([A-Za-z]+)/g, (_match, name: string) =>
    encodeURIComponent(params[name] ?? ''),
  );
}

export interface AuditFilters {
  agentId?: string | undefined;
  connectionId?: string | undefined;
  eventType?: AuditEventType | undefined;
}

export function createEndpoints(client: ApiClient) {
  return {
    getSession: (signal?: AbortSignal) =>
      client.request({
        path: Routes.authSession,
        schema: SessionResponse,
        signal,
        unauthenticatedIsExpected: true,
      }),

    login: (body: LoginRequest) =>
      client.request({
        method: 'POST',
        path: Routes.authLogin,
        body,
        schema: SessionResponse,
        unauthenticatedIsExpected: true,
      }),

    logout: () => client.request({ method: 'POST', path: Routes.authLogout, schema: null }),

    getHealth: (signal?: AbortSignal) =>
      client.request({ path: Routes.health, schema: HealthResponse, signal }),

    listApplications: (signal?: AbortSignal) =>
      listAll((cursor) =>
        client.request({
          path: Routes.applications,
          query: { limit: PAGE_SIZE, cursor },
          schema: ApplicationList,
          signal,
        }),
      ),

    registerApplication: (body: RegisterApplicationRequest) =>
      client.request({
        method: 'POST',
        path: Routes.applicationsRegister,
        body,
        schema: ApplicationDefinition,
      }),

    listConnections: (signal?: AbortSignal) =>
      listAll((cursor) =>
        client.request({
          path: Routes.connections,
          query: { limit: PAGE_SIZE, cursor },
          schema: ConnectionList,
          signal,
        }),
      ),

    createConnection: (body: CreateConnectionRequest) =>
      client.request({ method: 'POST', path: Routes.connections, body, schema: Connection }),

    getConnection: (id: string, signal?: AbortSignal) =>
      client.request({ path: fill(Routes.connection, { id }), schema: Connection, signal }),

    /** The API answers 200 with the connection `authenticating`; a window opens on the desktop. */
    startConnectionAuth: (id: string) =>
      client.request({
        method: 'POST',
        path: fill(Routes.connectionAuthStart, { id }),
        schema: ConnectionAuthResponse,
      }),

    /** 200 when the handoff finished, 202 while it is still being checked: both parse the same. */
    completeConnectionAuth: (id: string) =>
      client.request({
        method: 'POST',
        path: fill(Routes.connectionAuthComplete, { id }),
        schema: ConnectionAuthResponse,
      }),

    /** 200 (terminal job) and 202 (queued or running job) both parse as an OperationJob. */
    executeOperation: (body: ExecuteOperationRequest) =>
      client.request({
        method: 'POST',
        path: Routes.operationsExecute,
        body,
        schema: OperationJob,
      }),

    getOperation: (jobId: string, signal?: AbortSignal) =>
      client.request({ path: fill(Routes.operation, { jobId }), schema: OperationJob, signal }),

    revokeConnection: (id: string, body: RevokeConnectionRequest) =>
      client.request({
        method: 'POST',
        path: fill(Routes.connectionRevoke, { id }),
        body,
        schema: Connection,
      }),

    listAgents: (signal?: AbortSignal) =>
      listAll((cursor) =>
        client.request({
          path: Routes.agents,
          query: { limit: PAGE_SIZE, cursor },
          schema: AgentList,
          signal,
        }),
      ),

    getAgent: (id: string, signal?: AbortSignal) =>
      client.request({ path: fill(Routes.agent, { id }), schema: Agent, signal }),

    createAgent: (body: CreateAgentRequest) =>
      client.request({ method: 'POST', path: Routes.agents, body, schema: Agent }),

    disableAgent: (id: string) =>
      client.request({ method: 'POST', path: fill(Routes.agentDisable, { id }), schema: Agent }),

    listGrants: (agentId: string, signal?: AbortSignal) =>
      listAll((cursor) =>
        client.request({
          path: fill(Routes.agentGrants, { id: agentId }),
          query: { limit: PAGE_SIZE, cursor },
          schema: AgentGrantList,
          signal,
        }),
      ),

    createGrant: (agentId: string, body: CreateGrantRequest) =>
      client.request({
        method: 'POST',
        path: fill(Routes.agentGrants, { id: agentId }),
        body,
        schema: AgentGrant,
      }),

    revokeGrant: (agentId: string, grantId: string) =>
      client.request({
        method: 'DELETE',
        path: fill(Routes.agentGrant, { id: agentId, grantId }),
        schema: null,
      }),

    listAuditEvents: (
      filters: AuditFilters,
      page: { limit: number; cursor?: string | undefined },
      signal?: AbortSignal,
    ) =>
      client.request({
        path: Routes.auditEvents,
        query: {
          limit: page.limit,
          cursor: page.cursor,
          agentId: filters.agentId,
          connectionId: filters.connectionId,
          eventType: filters.eventType,
        },
        schema: AuditEventList,
        signal,
      }),
  };
}

export type Endpoints = ReturnType<typeof createEndpoints>;
