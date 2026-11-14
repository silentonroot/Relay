export { createDatabase } from './client.js';
export type { CreateDatabaseOptions, DatabaseHandle, Db } from './client.js';
export { migrate, MIGRATIONS_FOLDER } from './migrate.js';
export type { MigrateResult } from './migrate.js';
export {
  ConflictError,
  InvalidCursorError,
  InvalidTransitionError,
  NotFoundError,
  RepositoryError,
  ValidationError,
} from './errors.js';
export type { RepositoryErrorCode } from './errors.js';
export { DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE } from './support.js';
export type { Page, PageRequest, Scope } from './support.js';
export { createRepositories } from './repositories/index.js';
export type { Repositories } from './repositories/index.js';
export type {
  BootstrapLocalOwnerInput,
  BootstrapLocalOwnerResult,
  CreateSessionInput,
  CreateUserInput,
  LoginRecord,
  SessionRecord,
  ValidSession,
} from './repositories/identity.js';
export type {
  ConnectionStatusEvent,
  RecordSessionInput,
  StatusActor,
  TransitionConnectionInput,
} from './repositories/resources.js';
export type {
  ClaimJobInput,
  CompleteJobInput,
  CreateLoginJobInput,
  CreateOperationJobInput,
  CreateOperationRequestInput,
  ExecutionJob,
  OperationRequestRecord,
  OwnerScope,
  RecoverLeasesInput,
} from './repositories/execution.js';
export type {
  ActiveSecret,
  EnsuredSecret,
  SealedSecretRecord,
  SecretDescription,
} from './repositories/vault.js';
export type {
  CreateGrantInput,
  GrantEvaluationKey,
  GrantRevocation,
} from './repositories/grants.js';
export type {
  AuditAppendInput,
  AuditListFilters,
  AuditVerification,
} from './repositories/audit.js';
export * as schema from './schema.js';
