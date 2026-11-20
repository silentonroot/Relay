import type { ConnectionVaultMetadata, VaultKeyStatus } from '@aab/contracts';
import { VAULT_KEY_PROTECTION_STATEMENT } from '@aab/contracts';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import {
  apiError,
  CSRF_TOKEN,
  json,
  makeApplication,
  makeConnection,
  mockApi,
  page,
  renderApp,
  requestsTo,
} from './helpers.js';

/* Synthetic data only. */

const connection = makeConnection(1, { displayName: 'Northstar primary', status: 'active' });
const VAULT_PATH = `/v1/connections/${connection.id}/vault`;

function metadata(overrides: Partial<ConnectionVaultMetadata> = {}): ConnectionVaultMetadata {
  return {
    connectionId: connection.id,
    connectionStatus: 'active',
    secrets: [
      {
        secretType: 'session_snapshot',
        status: 'active',
        activeVersion: 3,
        kekVersion: 2,
        lastAccessedAt: '2026-03-02T09:30:00.000Z',
      },
    ],
    capabilities: {
      windowHours: 24,
      authorized: 7,
      used: 5,
      revoked: 2,
      rejected: [
        { reason: 'expired', count: 4 },
        { reason: 'used', count: 1 },
      ],
    },
    ...overrides,
  };
}

function baseHandlers(vault: () => Response = () => json(metadata())) {
  return {
    'GET /v1/connections': () => json(page([connection])),
    'GET /v1/applications': () => json(page([makeApplication(1)])),
    [`GET ${VAULT_PATH}`]: vault,
  };
}

async function openPanel(user: ReturnType<typeof userEvent.setup>) {
  await user.click(
    await screen.findByRole('button', { name: 'Vault details for Northstar primary' }),
  );
  return screen.findByRole('region', { name: /Vault details for “Northstar primary”/ });
}

describe('Connection vault panel', () => {
  it('renders the metadata and labels each count as the API defines it', async () => {
    mockApi(baseHandlers());
    const user = userEvent.setup();
    renderApp('/connections');
    const panel = await openPanel(user);

    expect(within(panel).getByText('session_snapshot')).toBeInTheDocument();
    expect(within(panel).getByText('Stored')).toBeInTheDocument();
    const facts = (label: string) => within(panel).getByText(label).nextElementSibling;
    expect(facts('Active version')).toHaveTextContent('3');
    expect(facts('Key (KEK) version')).toHaveTextContent('2');
    expect(facts('Last access')).toHaveTextContent(/2026/);
    expect(facts('Authorized')).toHaveTextContent('7');
    expect(facts('Used')).toHaveTextContent('5');
    expect(facts('Revoked')).toHaveTextContent('2');
    expect(
      within(panel).getByText(
        /Capabilities authorized in the window, including those issued to store a session at sign-in\./,
      ),
    ).toBeInTheDocument();
    expect(
      within(panel).getByText(/consumed in the window, whenever they were authorized/),
    ).toBeInTheDocument();
    expect(
      within(panel).getByText(/Revoking is deliberate and is not counted as a rejection/),
    ).toBeInTheDocument();
  });

  it('keeps rejections apart by reason, separate from revocations, and says expired can be a slow worker', async () => {
    mockApi(baseHandlers());
    const user = userEvent.setup();
    renderApp('/connections');
    const panel = await openPanel(user);

    const heading = within(panel).getByRole('heading', { name: /Rejected requests/ });
    const list = heading.nextElementSibling as HTMLElement;
    const items = within(list).getAllByRole('listitem');
    expect(items).toHaveLength(2);
    expect(items[0]).toHaveTextContent('expired: 4');
    expect(items[0]).toHaveTextContent('slow worker');
    expect(items[1]).toHaveTextContent('used: 1');
    expect(items[1]).toHaveTextContent('replay');
    expect(items[1]).not.toHaveTextContent('slow worker');
    // The revoked count is not inside the rejections list.
    expect(list).not.toHaveTextContent(/revoked/i);
  });

  it('says so when there is no stored session or no rejection', async () => {
    mockApi(
      baseHandlers(() =>
        json(
          metadata({
            secrets: [],
            capabilities: { windowHours: 24, authorized: 0, used: 0, revoked: 0, rejected: [] },
          }),
        ),
      ),
    );
    const user = userEvent.setup();
    renderApp('/connections');
    const panel = await openPanel(user);
    expect(
      within(panel).getByText('No session has been stored for this connection.'),
    ).toBeInTheDocument();
    expect(within(panel).getByText('No request was rejected.')).toBeInTheDocument();
  });

  it('never renders fields outside the contract, and refuses a response that carries them', async () => {
    const canaries = [
      'CANARY-CIPHERTEXT-1',
      'CANARY-WRAPPED-DEK-2',
      'CANARY-TOKEN-3',
      'CANARY-MAC-4',
    ];
    // Extra fields at every level. The strict schema rejects the whole body, so nothing is shown.
    const hostile = {
      ...metadata(),
      ciphertext: canaries[0],
      secrets: [{ ...metadata().secrets[0], wrappedDek: canaries[1] }],
      capabilities: { ...metadata().capabilities, token: canaries[2] },
      mac: canaries[3],
    };
    mockApi(baseHandlers(() => json(hostile)));
    const user = userEvent.setup();
    renderApp('/connections');
    await user.click(
      await screen.findByRole('button', { name: 'Vault details for Northstar primary' }),
    );
    expect(await screen.findByText('Vault details could not be loaded')).toBeInTheDocument();
    for (const canary of canaries) {
      expect(document.body.innerHTML).not.toContain(canary);
    }
  });

  it('renders none of the canaries when extra fields are stripped rather than refused (key status)', async () => {
    // The status schema is strict too; this proves the page cannot show a stray field either way.
    const canary = 'CANARY-KEYFILE-5';
    mockApi({
      'GET /v1/vault/status': () => json({ ...keyStatus(), keyMaterial: canary }),
    });
    renderApp('/vault');
    expect(await screen.findByText('Key status could not be loaded')).toBeInTheDocument();
    expect(document.body.innerHTML).not.toContain(canary);
  });

  it('shows an error state when the read fails', async () => {
    mockApi(baseHandlers(() => apiError(404, 'not_found', 'Not found.')));
    const user = userEvent.setup();
    renderApp('/connections');
    await user.click(
      await screen.findByRole('button', { name: 'Vault details for Northstar primary' }),
    );
    expect(await screen.findByText('Vault details could not be loaded')).toBeInTheDocument();
  });
});

describe('Vault actions', () => {
  it('disables Delete stored session, and says why, when nothing is stored', async () => {
    mockApi(
      baseHandlers(() =>
        json(
          metadata({
            secrets: [
              {
                secretType: 'session_snapshot',
                status: 'deleted',
                activeVersion: null,
                kekVersion: null,
                lastAccessedAt: null,
              },
            ],
          }),
        ),
      ),
    );
    const user = userEvent.setup();
    renderApp('/connections');
    const panel = await openPanel(user);
    expect(within(panel).getByRole('button', { name: 'Delete stored session' })).toBeDisabled();
    expect(within(panel).getByText('There is no stored session to delete.')).toBeInTheDocument();
    expect(
      within(panel).getByRole('button', { name: 'Revoke outstanding capabilities' }),
    ).toBeEnabled();
  });

  const del = `/v1/connections/${connection.id}/vault/delete-session`;
  const rev = `/v1/connections/${connection.id}/vault/revoke-capabilities`;

  it('asks for confirmation, says what happens, and sends nothing on cancel', async () => {
    const log = mockApi(baseHandlers());
    const user = userEvent.setup();
    renderApp('/connections');
    const panel = await openPanel(user);

    await user.click(within(panel).getByRole('button', { name: 'Delete stored session' }));
    const confirm = await screen.findByRole('group', {
      name: /Delete the stored session of “Northstar primary”\?/,
    });
    expect(confirm).toHaveTextContent(/reconnect required/);
    expect(confirm).toHaveTextContent(/Queued jobs for this connection are cancelled/);
    expect(confirm).toHaveTextContent(/running jobs are flagged for cancellation/);
    await user.click(within(confirm).getByRole('button', { name: 'Cancel' }));
    expect(
      screen.queryByRole('group', { name: /Delete the stored session/ }),
    ).not.toBeInTheDocument();

    await user.click(
      within(panel).getByRole('button', { name: 'Revoke outstanding capabilities' }),
    );
    const confirm2 = await screen.findByRole('group', {
      name: /Revoke outstanding capabilities of/,
    });
    expect(confirm2).toHaveTextContent(/queued jobs that held one are cancelled/);
    expect(confirm2).toHaveTextContent(/Jobs already running are not touched/);
    await user.click(within(confirm2).getByRole('button', { name: 'Cancel' }));

    expect(requestsTo(log, 'POST', del)).toHaveLength(0);
    expect(requestsTo(log, 'POST', rev)).toHaveLength(0);
  });

  it('deletes the stored session with the CSRF header, announces, and refreshes the panel', async () => {
    let deleted = false;
    const log = mockApi({
      ...baseHandlers(() =>
        json(
          deleted
            ? metadata({
                connectionStatus: 'reconnect_required',
                secrets: [
                  {
                    secretType: 'session_snapshot',
                    status: 'deleted',
                    activeVersion: null,
                    kekVersion: null,
                    lastAccessedAt: null,
                  },
                ],
              })
            : metadata(),
        ),
      ),
      [`POST ${del}`]: () => {
        deleted = true;
        return json({
          connectionId: connection.id,
          connectionStatus: 'reconnect_required',
          versionsDeleted: 3,
          capabilitiesRevoked: 2,
          jobsCancelled: 1,
        });
      },
    });
    const user = userEvent.setup();
    renderApp('/connections');
    const panel = await openPanel(user);
    await user.click(within(panel).getByRole('button', { name: 'Delete stored session' }));
    const confirm = await screen.findByRole('group', { name: /Delete the stored session/ });
    await user.click(within(confirm).getByRole('button', { name: 'Delete stored session' }));

    expect(
      await screen.findByText(/Stored session of “Northstar primary” deleted/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/2 capabilities revoked, 1 job cancelled or flagged/),
    ).toBeInTheDocument();
    const [post] = requestsTo(log, 'POST', del);
    expect(post?.headers.get('x-csrf-token')).toBe(CSRF_TOKEN);
    await waitFor(() => expect(requestsTo(log, 'GET', VAULT_PATH).length).toBeGreaterThan(1));
    expect(await screen.findByText('Deleted')).toBeInTheDocument();
  });

  it('revokes outstanding capabilities with the CSRF header and announces the counts', async () => {
    const log = mockApi({
      ...baseHandlers(),
      [`POST ${rev}`]: () =>
        json({ connectionId: connection.id, capabilitiesRevoked: 1, jobsCancelled: 1 }),
    });
    const user = userEvent.setup();
    renderApp('/connections');
    const panel = await openPanel(user);
    await user.click(
      within(panel).getByRole('button', { name: 'Revoke outstanding capabilities' }),
    );
    const confirm = await screen.findByRole('group', {
      name: /Revoke outstanding capabilities of/,
    });
    await user.click(within(confirm).getByRole('button', { name: 'Revoke capabilities' }));

    expect(
      await screen.findByText(
        /1 capability revoked for “Northstar primary”, 1 queued job cancelled/,
      ),
    ).toBeInTheDocument();
    const [post] = requestsTo(log, 'POST', rev);
    expect(post?.headers.get('x-csrf-token')).toBe(CSRF_TOKEN);
    expect(post?.body).toBeUndefined();
    await waitFor(() => expect(requestsTo(log, 'GET', VAULT_PATH).length).toBeGreaterThan(1));
  });

  it('shows a 409 as not possible in the current state and keeps the confirmation open', async () => {
    mockApi({
      ...baseHandlers(),
      [`POST ${del}`]: () =>
        apiError(409, 'conflict', 'the connection has no stored session', 'req_409'),
    });
    const user = userEvent.setup();
    renderApp('/connections');
    const panel = await openPanel(user);
    await user.click(within(panel).getByRole('button', { name: 'Delete stored session' }));
    const confirm = await screen.findByRole('group', { name: /Delete the stored session/ });
    await user.click(within(confirm).getByRole('button', { name: 'Delete stored session' }));

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Not possible in the connection’s current state');
    expect(alert).toHaveTextContent('the connection has no stored session');
    expect(alert).toHaveTextContent('req_409');
    expect(screen.queryByText(/deleted\. The connection/)).not.toBeInTheDocument();
  });
});

function keyStatus(overrides: Partial<VaultKeyStatus> = {}): VaultKeyStatus {
  return {
    isolation: 'separate-uid',
    kekVersions: [1, 2],
    currentKekVersion: 2,
    versionsByKek: { '1': 3, '2': 5 },
    missingKekVersions: [],
    counters: { requests: 10 },
    protectionStatement: VAULT_KEY_PROTECTION_STATEMENT,
    ...overrides,
  };
}

describe('Installation key status', () => {
  it('shows versions, isolation, the verbatim statement, and no rewrap or retire button', async () => {
    mockApi({ 'GET /v1/vault/status': () => json(keyStatus()) });
    renderApp('/vault');
    expect(await screen.findByRole('heading', { name: 'Key status' })).toBeInTheDocument();
    const fact = (label: string) => screen.getByText(label).nextElementSibling;
    expect(fact('Key versions present')).toHaveTextContent('1, 2');
    expect(fact('Current key (KEK) version')).toHaveTextContent('2');
    expect(fact('Isolation mode')).toHaveTextContent('separate-uid');
    expect(fact('Missing key versions')).toHaveTextContent('None');
    const table = screen.getByRole('table');
    expect(within(table).getByRole('row', { name: /^1 3$/ })).toBeInTheDocument();
    expect(within(table).getByRole('row', { name: /^2 5$/ })).toBeInTheDocument();
    expect(screen.getByText(VAULT_KEY_PROTECTION_STATEMENT)).toBeInTheDocument();
    expect(screen.getByText(/only with the vault’s admin command/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /rewrap|retire/i })).not.toBeInTheDocument();
    expect(screen.queryByText(/shared-uid/)).not.toBeInTheDocument();
    expect(screen.queryByText('Key versions are missing')).not.toBeInTheDocument();
  });

  it('highlights missing key versions and warns on shared-uid', async () => {
    mockApi({
      'GET /v1/vault/status': () =>
        json(keyStatus({ isolation: 'shared-uid', kekVersions: [2], missingKekVersions: [1] })),
    });
    renderApp('/vault');
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Key versions are missing');
    expect(alert).toHaveTextContent(/key version\s*1/);
    expect(screen.getByRole('note')).toHaveTextContent(/shared-uid/);
  });

  it('explains a 403 for a non-owner and shows no status', async () => {
    mockApi({
      'GET /v1/vault/status': () =>
        apiError(403, 'forbidden', 'Only owners can see the vault status.'),
    });
    renderApp('/vault');
    expect(await screen.findByText('Key status is shown to owners only')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Key status' })).not.toBeInTheDocument();
    expect(screen.queryByText(VAULT_KEY_PROTECTION_STATEMENT)).not.toBeInTheDocument();
  });

  it('shows a clear vault-not-available state on 503, and can retry', async () => {
    const log = mockApi({
      'GET /v1/vault/status': () =>
        apiError(503, 'service_unavailable', 'The vault is not available.', 'req_503'),
    });
    const user = userEvent.setup();
    renderApp('/vault');
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Vault not available');
    expect(alert).toHaveTextContent('req_503');
    await user.click(within(alert).getByRole('button', { name: 'Try again' }));
    await waitFor(() => expect(requestsTo(log, 'GET', '/v1/vault/status')).toHaveLength(2));
  });
});
