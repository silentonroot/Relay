import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { json, makeAuditEvent, mockApi, page, renderApp, requestsTo } from './helpers.js';

describe('Activity list', () => {
  it('pages through events using nextCursor', async () => {
    const first = [
      makeAuditEvent(3, { eventType: 'connection.created' }),
      makeAuditEvent(2, { eventType: 'agent.created' }),
    ];
    const second = [makeAuditEvent(1, { eventType: 'auth.login_succeeded' })];
    const log = mockApi({
      'GET /v1/audit-events': (request) =>
        request.query.get('cursor') === 'cursor-2'
          ? json(page(second, null))
          : json(page(first, 'cursor-2')),
    });
    const user = userEvent.setup();
    renderApp('/activity');

    const table = await screen.findByRole('table');
    expect(within(table).getAllByRole('row')).toHaveLength(1 + 2);
    expect(screen.getByText('Showing 2 events')).toBeInTheDocument();
    expect(requestsTo(log, 'GET', '/v1/audit-events')[0]?.query.get('cursor')).toBeNull();
    expect(requestsTo(log, 'GET', '/v1/audit-events')[0]?.query.get('limit')).toBe('50');

    await user.click(screen.getByRole('button', { name: 'Load more' }));

    expect(
      await screen.findByRole('rowheader', { name: 'Auth · login succeeded' }),
    ).toBeInTheDocument();
    expect(within(table).getAllByRole('row')).toHaveLength(1 + 3);
    expect(screen.getByText('Showing 3 events · end of log')).toBeInTheDocument();
    // No cursor left, so no button.
    expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument();

    const audit = requestsTo(log, 'GET', '/v1/audit-events');
    expect(audit.map((request) => request.query.get('cursor'))).toEqual([null, 'cursor-2']);
    // Existing rows were kept, in order.
    const headers = within(table)
      .getAllByRole('rowheader')
      .map((cell) => cell.textContent);
    expect(headers).toEqual(['Connection · created', 'Agent · created', 'Auth · login succeeded']);
  });

  it('restarts from the first page when a filter changes', async () => {
    const log = mockApi({
      'GET /v1/audit-events': (request) =>
        request.query.get('eventType') === 'grant.created'
          ? json(page([makeAuditEvent(9, { eventType: 'grant.created' })], null))
          : json(page([makeAuditEvent(1)], 'cursor-2')),
    });
    const user = userEvent.setup();
    renderApp('/activity');
    await screen.findByRole('rowheader', { name: 'Connection · created' });

    await user.selectOptions(screen.getByLabelText('Event type'), 'grant.created');

    expect(await screen.findByRole('rowheader', { name: 'Grant · created' })).toBeInTheDocument();
    await waitFor(() =>
      expect(
        screen.queryByRole('rowheader', { name: 'Connection · created' }),
      ).not.toBeInTheDocument(),
    );
    const last = requestsTo(log, 'GET', '/v1/audit-events').at(-1);
    expect(last?.query.get('eventType')).toBe('grant.created');
    expect(last?.query.get('cursor')).toBeNull();
    expect(screen.getByRole('button', { name: 'Clear filters' })).toBeInTheDocument();
  });

  it('explains an empty log', async () => {
    mockApi();
    renderApp('/activity');
    expect(await screen.findByText('No events recorded yet')).toBeInTheDocument();
  });
});
