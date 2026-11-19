import { VAULT_PROTOCOL_VERSION } from '@aab/contracts';
import type {
  VaultErrorCode,
  VaultIsolation,
  VaultOperation,
  VaultParams,
  VaultResult,
  VaultRole,
} from '@aab/contracts';
import type { Logger } from 'pino';
import type { VaultKeys } from './keys.js';
import { VAULT_SERVICE_VERSION } from './version.js';

/*
 * Handler plumbing. The real operations of ADR-014 section 4 are built by `createHandlers` in
 * `operations.ts`. `DEFAULT_HANDLERS` is the protocol-level set: `hello` plus stubs that answer
 * `not_implemented`. It never touches a database and is what the protocol tests start the
 * listeners with; production code (`startVault` without `handlers`) uses the real operations.
 * A handler gets the role from the socket (`context.role`), never from the request.
 */

/** Thrown by a handler to answer with a specific error code and no detail. */
export class VaultOperationError extends Error {
  override readonly name = 'VaultOperationError';
  constructor(readonly code: VaultErrorCode) {
    super(code);
  }
}

export interface VaultContext {
  role: VaultRole;
  isolation: VaultIsolation;
  keys: VaultKeys;
  logger: Logger;
}

export type Handler<Op extends VaultOperation> = (
  context: VaultContext,
  params: VaultParams<Op>,
) => Promise<VaultResult<Op>>;

export type VaultHandlers = { [Op in VaultOperation]: Handler<Op> };

function notImplemented(): Promise<never> {
  return Promise.reject(new VaultOperationError('not_implemented'));
}

export const helloHandler: Handler<'hello'> = (context) =>
  Promise.resolve({
    protocolVersion: VAULT_PROTOCOL_VERSION,
    serviceVersion: VAULT_SERVICE_VERSION,
    isolation: context.isolation,
    role: context.role,
    keyDirectory: context.keys.keyDirectory,
    currentKekVersion: context.keys.currentKekVersion,
  });

export const DEFAULT_HANDLERS: VaultHandlers = {
  hello: helloHandler,
  authorizeJobAccess: notImplemented,
  issueAccessCapability: notImplemented,
  readForWorker: notImplemented,
  completeLogin: notImplemented,
  status: notImplemented,
  rewrap: notImplemented,
  kekRetirementCheck: notImplemented,
};
