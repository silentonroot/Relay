import type { LoginRequest, SessionResponse } from '@aab/contracts';
import { useQueryClient } from '@tanstack/react-query';
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import type { ReactNode } from 'react';
import { ApiError, createApiClient, toApiError } from '../api/client.js';
import { createEndpoints } from '../api/endpoints.js';
import type { Endpoints } from '../api/endpoints.js';

export type SessionState =
  | { status: 'loading' }
  | { status: 'anonymous'; notice: string | null }
  | { status: 'authenticated'; session: SessionResponse }
  | { status: 'unreachable'; error: ApiError };

interface SessionContextValue {
  state: SessionState;
  api: Endpoints;
  signIn: (credentials: LoginRequest) => Promise<void>;
  signOut: () => Promise<void>;
  retry: () => void;
}

const SessionContext = createContext<SessionContextValue | null>(null);

/**
 * Owns the dashboard session. The session cookie is HttpOnly and never visible here; the only
 * auth value the page holds is the CSRF token, kept in memory and never written to
 * localStorage, sessionStorage or the URL. Reloading the page fetches a fresh one.
 */
export function SessionProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [state, setState] = useState<SessionState>({ status: 'loading' });
  const [attempt, setAttempt] = useState(0);
  const csrfToken = useRef<string | null>(null);

  const api = useMemo(
    () =>
      createEndpoints(
        createApiClient({
          getCsrfToken: () => csrfToken.current,
          onUnauthenticated: () => {
            csrfToken.current = null;
            queryClient.clear();
            setState({
              status: 'anonymous',
              notice: 'Your session ended. Sign in again to continue.',
            });
          },
        }),
      ),
    [queryClient],
  );

  useEffect(() => {
    const controller = new AbortController();
    api.getSession(controller.signal).then(
      (session) => {
        if (controller.signal.aborted) return;
        csrfToken.current = session.csrfToken;
        setState({ status: 'authenticated', session });
      },
      (error: unknown) => {
        if (controller.signal.aborted) return;
        if (error instanceof ApiError && error.code === 'unauthenticated') {
          setState({ status: 'anonymous', notice: null });
        } else {
          setState({ status: 'unreachable', error: toApiError(error) });
        }
      },
    );
    return () => controller.abort();
  }, [api, attempt]);

  const signIn = useCallback(
    async (credentials: LoginRequest) => {
      const session = await api.login(credentials);
      csrfToken.current = session.csrfToken;
      queryClient.clear();
      setState({ status: 'authenticated', session });
    },
    [api, queryClient],
  );

  const signOut = useCallback(async () => {
    let confirmed = true;
    try {
      await api.logout();
    } catch (error) {
      // An already-ended session is as good as a confirmed sign-out.
      confirmed = error instanceof ApiError && error.code === 'unauthenticated';
    }
    csrfToken.current = null;
    queryClient.clear();
    setState({
      status: 'anonymous',
      notice: confirmed
        ? 'You have signed out.'
        : 'Signed out in this window, but the broker did not confirm it. The session may stay valid until it expires.',
    });
  }, [api, queryClient]);

  const retry = useCallback(() => {
    setState({ status: 'loading' });
    setAttempt((value) => value + 1);
  }, []);

  const value = useMemo(
    () => ({ state, api, signIn, signOut, retry }),
    [state, api, signIn, signOut, retry],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionContextValue {
  const value = useContext(SessionContext);
  if (value === null) throw new Error('useSession must be used inside SessionProvider');
  return value;
}

export function useApi(): Endpoints {
  return useSession().api;
}

/** The signed-in session. Only call from components rendered behind the sign-in gate. */
export function useCurrentSession(): SessionResponse {
  const { state } = useSession();
  if (state.status !== 'authenticated') throw new Error('No active session');
  return state.session;
}
