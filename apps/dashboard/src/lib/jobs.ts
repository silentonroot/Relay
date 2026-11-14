import type { JobErrorCode } from '@aab/contracts';
import { LOGIN_HANDOFF_TIMEOUT_MS } from '@aab/contracts';

export const LOGIN_TIMEOUT_MINUTES = Math.round(LOGIN_HANDOFF_TIMEOUT_MS / 60_000);

/**
 * One human sentence per failure code. The API's own message is fixed text too, but the
 * dashboard says what happened and what to do next. Exhaustive on purpose: a new code in the
 * contracts fails the type check here.
 */
export const JOB_ERROR_TEXT: Record<JobErrorCode, string> = {
  login_not_completed:
    'No signed-in session was found. Finish signing in in the browser window, then press “I’ve signed in” again, or start over.',
  login_window_closed:
    'The sign-in window was closed before sign-in finished. Nothing was saved. Start again to open a new window.',
  identity_mismatch:
    'The account you signed in with is not the account this connection is for. Nothing was saved. Sign in with the right account, or create a separate connection for the other one.',
  timeout: 'This took too long and was stopped. Nothing was saved. You can try again.',
  denied: 'Policy did not allow this when it was checked again, so nothing was done.',
  invalid_arguments:
    'The application’s operation rejected these arguments. Check them and try again.',
  adapter_unavailable:
    'The adapter for this application is not available on the broker, so nothing was done.',
  origin_not_allowed:
    'The browser tried to reach an address that is not on the application’s allowed list. It was blocked.',
  navigation_blocked:
    'The browser tried to navigate somewhere that is not allowed. It was blocked.',
  output_rejected:
    'The application returned data that did not match what the operation promises, so the broker discarded it.',
  not_found:
    'The application reports that the thing you asked for does not exist for this account.',
  unexpected_page:
    'The application’s page did not look the way the adapter expects, so the broker stopped. The application may have changed.',
  session_expired:
    'The application no longer accepts the stored session. Sign in again on the Connections page.',
  cancelled: 'This was cancelled before it finished.',
  worker_failure:
    'The browser worker failed while doing this. Nothing is known about the outcome beyond this message.',
};
