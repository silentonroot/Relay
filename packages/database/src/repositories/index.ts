import type { Db } from '../client.js';
import { createAuditRepository } from './audit.js';
import { createJobRepository, createOperationRequestRepository } from './execution.js';
import { createGrantRepository } from './grants.js';
import {
  createOrganizationRepository,
  createSessionRepository,
  createUserRepository,
} from './identity.js';
import {
  createAgentRepository,
  createApplicationRepository,
  createConnectionRepository,
} from './resources.js';
import { createVaultRepository } from './vault.js';

export interface Repositories {
  users: ReturnType<typeof createUserRepository>;
  organizations: ReturnType<typeof createOrganizationRepository>;
  sessions: ReturnType<typeof createSessionRepository>;
  applications: ReturnType<typeof createApplicationRepository>;
  connections: ReturnType<typeof createConnectionRepository>;
  agents: ReturnType<typeof createAgentRepository>;
  grants: ReturnType<typeof createGrantRepository>;
  audit: ReturnType<typeof createAuditRepository>;
  jobs: ReturnType<typeof createJobRepository>;
  operationRequests: ReturnType<typeof createOperationRequestRepository>;
  vault: ReturnType<typeof createVaultRepository>;
  /**
   * Runs `work` in one database transaction with repositories bound to it. Use it to make a
   * change and its audit event atomic: if `work` throws, both are rolled back.
   */
  transaction<T>(work: (repositories: Repositories) => Promise<T>): Promise<T>;
}

export function createRepositories(db: Db): Repositories {
  return {
    users: createUserRepository(db),
    organizations: createOrganizationRepository(db),
    sessions: createSessionRepository(db),
    applications: createApplicationRepository(db),
    connections: createConnectionRepository(db),
    agents: createAgentRepository(db),
    grants: createGrantRepository(db),
    audit: createAuditRepository(db),
    jobs: createJobRepository(db),
    operationRequests: createOperationRequestRepository(db),
    vault: createVaultRepository(db),
    transaction: (work) => db.transaction((tx) => work(createRepositories(tx))),
  };
}
