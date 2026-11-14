import { DisplayName, LoginRequest } from '@aab/contracts';
import { hashPassword, MAX_PASSWORD_BYTES } from '@aab/crypto';
import type { HashPasswordOptions } from '@aab/crypto';
import { ConflictError, createRepositories } from '@aab/database';
import type { BootstrapLocalOwnerResult, Db } from '@aab/database';

export const MIN_OWNER_PASSWORD_LENGTH = 12;
export const DEFAULT_ORGANIZATION_NAME = 'Local organization';

export class OwnerInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OwnerInputError';
  }
}

/** Returns a problem description, or null when the password is acceptable. */
export function passwordProblem(password: string): string | null {
  if ([...password].length < MIN_OWNER_PASSWORD_LENGTH) {
    return `password must be at least ${MIN_OWNER_PASSWORD_LENGTH} characters`;
  }
  if (Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_BYTES) {
    return `password must be at most ${MAX_PASSWORD_BYTES} bytes`;
  }
  if (password.includes('\0')) return 'password must not contain a NUL character';
  return null;
}

export interface CreateOwnerInput {
  email: string;
  password: string;
  organizationName?: string;
  hashOptions?: HashPasswordOptions;
}

/**
 * Creates the first owner and the local organization. Refuses (OwnerInputError) when any
 * user already exists; the check and the insert are one transaction in the repository.
 */
export async function createOwner(
  db: Db,
  input: CreateOwnerInput,
): Promise<BootstrapLocalOwnerResult> {
  const email = LoginRequest.shape.email.safeParse(input.email.trim());
  if (!email.success) throw new OwnerInputError('a valid email address is required');
  const name = DisplayName.safeParse(input.organizationName ?? DEFAULT_ORGANIZATION_NAME);
  if (!name.success) throw new OwnerInputError('organization name must be 1 to 120 characters');
  const problem = passwordProblem(input.password);
  if (problem !== null) throw new OwnerInputError(problem);

  const passwordHash = await hashPassword(input.password, input.hashOptions ?? {});
  try {
    return await createRepositories(db).organizations.bootstrapLocalOwner({
      email: email.data,
      passwordHash,
      organizationName: name.data,
    });
  } catch (error) {
    if (error instanceof ConflictError) {
      throw new OwnerInputError(
        'a user already exists; create-owner only runs on an empty database',
      );
    }
    throw error;
  }
}
