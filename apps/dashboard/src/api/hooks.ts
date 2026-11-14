import type {
  Connection,
  CreateAgentRequest,
  CreateConnectionRequest,
  CreateGrantRequest,
  ExecuteOperationRequest,
  RegisterApplicationRequest,
  RevokeConnectionRequest,
} from '@aab/contracts';
import { isTerminalJobStatus } from '@aab/contracts';
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { QueryClient } from '@tanstack/react-query';
import { useEffect, useId } from 'react';
import { useApi } from '../auth/SessionContext.js';
import type { AuditFilters } from './endpoints.js';
import { AUTH_POLL_MS, JOB_POLL_MS } from './polling.js';

export const AUDIT_PAGE_SIZE = 50;

export const queryKeys = {
  health: ['health'] as const,
  applications: ['applications'] as const,
  connections: ['connections'] as const,
  agents: ['agents'] as const,
  agent: (id: string) => ['agents', id] as const,
  grants: (agentId: string) => ['grants', agentId] as const,
  audit: ['audit'] as const,
  auditList: (filters: AuditFilters) => ['audit', 'list', filters] as const,
  auditRecent: (limit: number) => ['audit', 'recent', limit] as const,
  operation: (jobId: string) => ['operations', jobId] as const,
};

export function useHealth() {
  const api = useApi();
  return useQuery({
    queryKey: queryKeys.health,
    queryFn: ({ signal }) => api.getHealth(signal),
    refetchInterval: 30_000,
  });
}

export function useApplications() {
  const api = useApi();
  return useQuery({
    queryKey: queryKeys.applications,
    queryFn: ({ signal }) => api.listApplications(signal),
  });
}

export function useRegisterApplication() {
  const api = useApi();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: RegisterApplicationRequest) => api.registerApplication(body),
    onSuccess: () =>
      Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.applications }),
        queryClient.invalidateQueries({ queryKey: queryKeys.audit }),
      ]),
  });
}

export function useConnections() {
  const api = useApi();
  return useQuery({
    queryKey: queryKeys.connections,
    queryFn: ({ signal }) => api.listConnections(signal),
  });
}

export function useCreateConnection() {
  const api = useApi();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateConnectionRequest) => api.createConnection(body),
    onSuccess: () =>
      Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.connections }),
        queryClient.invalidateQueries({ queryKey: queryKeys.audit }),
      ]),
  });
}

/** Puts a fresher copy of one connection into the cached list without waiting for a refetch. */
function replaceInConnectionList(queryClient: QueryClient, connection: Connection) {
  queryClient.setQueryData<Connection[]>(queryKeys.connections, (list) =>
    list?.map((item) => (item.id === connection.id ? connection : item)),
  );
}

export function useStartConnectionAuth() {
  const api = useApi();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.startConnectionAuth(id),
    onSuccess: (response) => {
      replaceInConnectionList(queryClient, response.connection);
      return Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.connections }),
        queryClient.invalidateQueries({ queryKey: queryKeys.audit }),
      ]);
    },
  });
}

export function useCompleteConnectionAuth() {
  const api = useApi();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.completeConnectionAuth(id),
    onSuccess: (response) => {
      replaceInConnectionList(queryClient, response.connection);
      return Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.connections }),
        queryClient.invalidateQueries({ queryKey: queryKeys.audit }),
      ]);
    },
  });
}

/**
 * Re-reads one connection while a login handoff is pending, and hands the answer to the cached
 * list as soon as the status leaves `authenticating`. The key is unique per mount so a finished
 * handoff's answer is never mistaken for the next one's.
 */
export function useConnectionPoll(id: string, enabled: boolean) {
  const api = useApi();
  const queryClient = useQueryClient();
  const instance = useId();
  const query = useQuery({
    queryKey: ['connection-poll', id, instance],
    queryFn: ({ signal }) => api.getConnection(id, signal),
    enabled,
    gcTime: 0,
    refetchInterval: (current) =>
      current.state.data !== undefined && current.state.data.status !== 'authenticating'
        ? false
        : AUTH_POLL_MS,
  });

  const settled = query.data !== undefined && query.data.status !== 'authenticating';
  const latest = query.data;
  useEffect(() => {
    if (!settled || latest === undefined) return;
    replaceInConnectionList(queryClient, latest);
    void queryClient.invalidateQueries({ queryKey: queryKeys.connections });
    void queryClient.invalidateQueries({ queryKey: queryKeys.audit });
  }, [settled, latest, queryClient]);

  return query;
}

export function useRevokeConnection() {
  const api = useApi();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (input: { id: string; body: RevokeConnectionRequest }) =>
      api.revokeConnection(input.id, input.body),
    onSuccess: () =>
      Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.connections }),
        queryClient.invalidateQueries({ queryKey: queryKeys.audit }),
      ]),
  });
}

export function useAgents() {
  const api = useApi();
  return useQuery({
    queryKey: queryKeys.agents,
    queryFn: ({ signal }) => api.listAgents(signal),
  });
}

export function useAgent(id: string) {
  const api = useApi();
  return useQuery({
    queryKey: queryKeys.agent(id),
    queryFn: ({ signal }) => api.getAgent(id, signal),
  });
}

export function useCreateAgent() {
  const api = useApi();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateAgentRequest) => api.createAgent(body),
    onSuccess: () =>
      Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.agents }),
        queryClient.invalidateQueries({ queryKey: queryKeys.audit }),
      ]),
  });
}

export function useDisableAgent() {
  const api = useApi();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.disableAgent(id),
    onSuccess: () =>
      Promise.all([
        // Prefix match: refreshes the list and every agent detail.
        queryClient.invalidateQueries({ queryKey: queryKeys.agents }),
        queryClient.invalidateQueries({ queryKey: queryKeys.audit }),
      ]),
  });
}

export function useAgentGrants(agentId: string) {
  const api = useApi();
  return useQuery({
    queryKey: queryKeys.grants(agentId),
    queryFn: ({ signal }) => api.listGrants(agentId, signal),
  });
}

export function useCreateGrant(agentId: string) {
  const api = useApi();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateGrantRequest) => api.createGrant(agentId, body),
    onSuccess: () =>
      Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.grants(agentId) }),
        queryClient.invalidateQueries({ queryKey: queryKeys.audit }),
      ]),
  });
}

export function useRevokeGrant(agentId: string) {
  const api = useApi();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (grantId: string) => api.revokeGrant(agentId, grantId),
    onSuccess: () =>
      Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.grants(agentId) }),
        queryClient.invalidateQueries({ queryKey: queryKeys.audit }),
      ]),
  });
}

export function useRecentAuditEvents(limit: number) {
  const api = useApi();
  return useQuery({
    queryKey: queryKeys.auditRecent(limit),
    queryFn: ({ signal }) => api.listAuditEvents({}, { limit }, signal),
  });
}

export function useAuditEvents(filters: AuditFilters) {
  const api = useApi();
  return useInfiniteQuery({
    queryKey: queryKeys.auditList(filters),
    queryFn: ({ pageParam, signal }) =>
      api.listAuditEvents(filters, { limit: AUDIT_PAGE_SIZE, cursor: pageParam }, signal),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.nextCursor ?? undefined,
  });
}

export function useExecuteOperation() {
  const api = useApi();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: ExecuteOperationRequest) => api.executeOperation(body),
    onSettled: () => queryClient.invalidateQueries({ queryKey: queryKeys.audit }),
  });
}

/** Reads a queued or running job until it reaches a terminal status. */
export function useOperationJob(jobId: string | null, enabled: boolean) {
  const api = useApi();
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: queryKeys.operation(jobId ?? ''),
    queryFn: ({ signal }) => api.getOperation(jobId ?? '', signal),
    enabled: enabled && jobId !== null,
    refetchOnWindowFocus: false,
    refetchInterval: (current) =>
      current.state.data !== undefined && isTerminalJobStatus(current.state.data.status)
        ? false
        : JOB_POLL_MS,
  });
  const finished = query.data !== undefined && isTerminalJobStatus(query.data.status);
  useEffect(() => {
    if (finished) void queryClient.invalidateQueries({ queryKey: queryKeys.audit });
  }, [finished, queryClient]);
  return query;
}
