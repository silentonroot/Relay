/**
 * The Northstar demo's UI contract: paths, form field names, selectors and `data-field`
 * values. The Phase 2 `execute` implementation and its tests read the page through these
 * constants only, so a UI change shows up as one diff here.
 */
export const NORTHSTAR_UI = {
  defaultOrigin: 'http://localhost:4100',
  paths: {
    login: '/login',
    orders: '/orders',
    order: (orderId: string): string => `/orders/${orderId}`,
  },
  /** Query parameters accepted by the orders list. */
  ordersQuery: { status: 'status', page: 'page' },
  login: {
    usernameInput: 'input[name="username"]',
    passwordInput: 'input[name="password"]',
    submit: '[data-testid="login-submit"]',
    error: '[data-testid="login-error"]',
  },
  /** Present on every authenticated page; holds the signed-in username. */
  currentUser: '[data-testid="current-user"]',
  /** Attribute that marks a value-bearing element inside a row or detail view. */
  fieldAttribute: 'data-field',
  /** Every error page (400, 403, 404, 500) carries this marker and its HTTP status. */
  errorPage: { container: '[data-testid="error-page"]', statusAttribute: 'data-status' },
  ordersList: {
    table: '[data-testid="orders-table"]',
    row: '[data-testid="order-row"]',
    rowIdAttribute: 'data-order-id',
    fields: ['id', 'customer', 'status', 'total', 'updatedAt'],
    /** Rows per page; a page with fewer rows is the last one. */
    pageSize: 20,
    /** Pagination bar; `data-total-pages` holds the page count as plain digits. */
    pagination: '[data-testid="pagination"]',
    totalPagesAttribute: 'data-total-pages',
  },
  orderDetail: {
    container: '[data-testid="order-detail"]',
    fields: [
      'id',
      'customer',
      'status',
      'total',
      'shippingMethod',
      'notes',
      'version',
      'updatedAt',
    ],
    itemRow: '[data-testid="order-item"]',
    itemFields: ['sku', 'name', 'quantity', 'unitPrice'],
  },
} as const;

export type NorthstarUi = typeof NORTHSTAR_UI;
export type NorthstarOrderListField = NorthstarUi['ordersList']['fields'][number];
export type NorthstarOrderDetailField = NorthstarUi['orderDetail']['fields'][number];
export type NorthstarOrderItemField = NorthstarUi['orderDetail']['itemFields'][number];

/** Selector for one `data-field` element, e.g. `[data-field="status"]`. */
export function northstarField(
  field: NorthstarOrderListField | NorthstarOrderDetailField | NorthstarOrderItemField,
): string {
  return `[${NORTHSTAR_UI.fieldAttribute}="${field}"]`;
}
