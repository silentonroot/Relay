import { AdapterContractError, sanitizeOperationOutput } from '@aab/adapter-sdk';
import type {
  ApplicationAdapter,
  SanitizedResult,
  ValidatedOperation,
  WorkerContext,
} from '@aab/adapter-sdk';
import { ordersGet, ordersList } from './operations.js';
import type { NorthstarOrderStatus } from './operations.js';
import { NORTHSTAR_UI, northstarField } from './selectors.js';
import type {
  NorthstarOrderDetailField,
  NorthstarOrderItemField,
  NorthstarOrderListField,
} from './selectors.js';

/*
 * Everything read from a page is untrusted text. This file never branches on free text,
 * never builds a path or selector from it, and never logs it: the paths below are assembled
 * from validated operation input and constants only.
 */

/** Pages are visited at most this many times per call (100 rows at 20 per page is 5). */
export const NORTHSTAR_MAX_PAGES = 10;
export const NORTHSTAR_DEFAULT_LIMIT = 20;

/** Fixed failure codes. Messages are fixed too and never contain page text. */
export const NORTHSTAR_ERRORS = {
  unknownOperation: { code: 'unknown_operation', message: 'operation is not supported' },
  invalidArguments: { code: 'invalid_arguments', message: 'arguments are not valid' },
  notFound: { code: 'not_found', message: 'order not found' },
  unexpectedPage: { code: 'unexpected_page', message: 'the page did not have the expected shape' },
  aborted: { code: 'aborted', message: 'the operation was cancelled' },
} as const;

type Failure = (typeof NORTHSTAR_ERRORS)[keyof typeof NORTHSTAR_ERRORS];

function failed(error: Failure): SanitizedResult {
  return { status: 'failed', error: { code: error.code, message: error.message } };
}

/** Thrown internally for a page that does not match the contract; never leaves this file. */
class PageContractError extends Error {
  readonly failure: Failure;
  constructor(failure: Failure) {
    super(failure.code);
    this.failure = failure;
  }
}

const unexpected = (): PageContractError => new PageContractError(NORTHSTAR_ERRORS.unexpectedPage);

const PLAIN_DIGITS = /^\d{1,15}$/;

/** Parses a digit string. Anything else (signs, spaces, separators, decimals) is rejected. */
function parseCount(text: string): number {
  if (!PLAIN_DIGITS.test(text)) throw unexpected();
  return Number(text);
}

function pick<Field extends string>(
  record: Readonly<Record<string, string>>,
  fields: readonly Field[],
): Record<Field, string> {
  const out = {} as Record<Field, string>;
  for (const field of fields) {
    const value = Object.hasOwn(record, field) ? record[field] : undefined;
    if (typeof value !== 'string') throw unexpected();
    out[field] = value.trim();
  }
  return out;
}

/** 'not_found' for the app's 404 page, null for a normal page; any other error page throws. */
async function errorPageKind(ctx: WorkerContext): Promise<'not_found' | null> {
  const status = await ctx.browser.attribute(
    NORTHSTAR_UI.errorPage.container,
    NORTHSTAR_UI.errorPage.statusAttribute,
  );
  if (status === null) return null;
  if (status === '404') return 'not_found';
  throw unexpected();
}

function listPath(status: NorthstarOrderStatus | undefined, page: number): string {
  const query: string[] = [];
  if (status !== undefined) query.push(`${NORTHSTAR_UI.ordersQuery.status}=${status}`);
  if (page > 1) query.push(`${NORTHSTAR_UI.ordersQuery.page}=${String(page)}`);
  const base = NORTHSTAR_UI.paths.orders;
  return query.length === 0 ? base : `${base}?${query.join('&')}`;
}

async function listOrders(
  ctx: WorkerContext,
  status: NorthstarOrderStatus | undefined,
  limit: number,
): Promise<{ orders: Record<NorthstarOrderListField, string>[] } | 'aborted'> {
  const orders: Record<NorthstarOrderListField, string>[] = [];
  let pagesVisited = 0;

  for (let page = 1; page <= NORTHSTAR_MAX_PAGES && orders.length < limit; page += 1) {
    if (ctx.signal.aborted) return 'aborted';
    await ctx.browser.goto(listPath(status, page));
    pagesVisited += 1;
    if ((await errorPageKind(ctx)) !== null) throw unexpected();

    const rows = await ctx.browser.rows(NORTHSTAR_UI.ordersList.row, NORTHSTAR_UI.fieldAttribute);
    if (rows.length === 0) break;
    for (const row of rows) {
      if (orders.length >= limit) break;
      orders.push(pick(row, NORTHSTAR_UI.ordersList.fields));
    }
    if (rows.length < NORTHSTAR_UI.ordersList.pageSize) break;

    const totalPages = await ctx.browser.attribute(
      NORTHSTAR_UI.ordersList.pagination,
      NORTHSTAR_UI.ordersList.totalPagesAttribute,
    );
    if (totalPages !== null && PLAIN_DIGITS.test(totalPages) && page >= Number(totalPages)) break;
  }

  ctx.logger.debug('northstar orders.list finished', {
    pages: pagesVisited,
    rows: orders.length,
  });
  return { orders };
}

async function getOrder(
  ctx: WorkerContext,
  orderId: string,
): Promise<{ order: Record<string, unknown> } | 'not_found' | 'aborted'> {
  if (ctx.signal.aborted) return 'aborted';
  await ctx.browser.goto(NORTHSTAR_UI.paths.order(orderId));
  if ((await errorPageKind(ctx)) === 'not_found') return 'not_found';

  const container = NORTHSTAR_UI.orderDetail.container;
  if ((await ctx.browser.attribute(container, 'data-testid')) === null) throw unexpected();

  const raw: Record<string, string> = {};
  for (const field of NORTHSTAR_UI.orderDetail.fields) {
    const text = await ctx.browser.text(`${container} ${northstarField(field)}`);
    if (text === null) throw unexpected();
    // Notes are passed through exactly as shown; everything else is trimmed.
    raw[field] = field === 'notes' ? text : text.trim();
  }
  // The page must be the order that was asked for.
  if (raw['id'] !== orderId) throw unexpected();
  const fields = pick(raw, NORTHSTAR_UI.orderDetail.fields);

  const itemRows = await ctx.browser.rows(
    NORTHSTAR_UI.orderDetail.itemRow,
    NORTHSTAR_UI.fieldAttribute,
  );
  const items = itemRows.map((row) => {
    const item: Record<NorthstarOrderItemField, string> = pick(
      row,
      NORTHSTAR_UI.orderDetail.itemFields,
    );
    return { ...item, quantity: parseCount(item.quantity) };
  });

  const detailFields: Record<NorthstarOrderDetailField, string> = fields;
  ctx.logger.debug('northstar orders.get finished', { items: items.length });
  return {
    order: { ...detailFields, notes: raw['notes'], version: parseCount(fields.version), items },
  };
}

/** Runs one validated operation. The adapter is passed in to avoid an import cycle. */
export async function executeNorthstar(
  adapter: ApplicationAdapter,
  ctx: WorkerContext,
  operation: ValidatedOperation,
): Promise<SanitizedResult> {
  try {
    let raw: unknown;
    if (operation.name === ordersList.name) {
      const input = ordersList.input.safeParse(operation.arguments);
      if (!input.success) return failed(NORTHSTAR_ERRORS.invalidArguments);
      const result = await listOrders(
        ctx,
        input.data.status,
        input.data.limit ?? NORTHSTAR_DEFAULT_LIMIT,
      );
      if (result === 'aborted') return failed(NORTHSTAR_ERRORS.aborted);
      raw = result;
    } else if (operation.name === ordersGet.name) {
      const input = ordersGet.input.safeParse(operation.arguments);
      if (!input.success) return failed(NORTHSTAR_ERRORS.invalidArguments);
      const result = await getOrder(ctx, input.data.orderId);
      if (result === 'aborted') return failed(NORTHSTAR_ERRORS.aborted);
      if (result === 'not_found') return failed(NORTHSTAR_ERRORS.notFound);
      raw = result;
    } else {
      return failed(NORTHSTAR_ERRORS.unknownOperation);
    }
    return { status: 'succeeded', data: sanitizeOperationOutput(adapter, operation.name, raw) };
  } catch (error) {
    if (error instanceof PageContractError) return failed(error.failure);
    if (error instanceof AdapterContractError) return failed(NORTHSTAR_ERRORS.unexpectedPage);
    throw error;
  }
}
