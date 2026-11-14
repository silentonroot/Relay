import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useState } from 'react';
import type { ReactNode } from 'react';
import { BrowserRouter, Link, Navigate, Route, Routes } from 'react-router-dom';
import { ApiError } from './api/client.js';
import { SessionProvider, useSession } from './auth/SessionContext.js';
import { AnnouncerProvider } from './components/Announcer.js';
import { Shell } from './components/Shell.js';
import { ErrorState, Loading, PageHeader } from './components/ui.js';
import { ActivityPage } from './pages/ActivityPage.js';
import { AgentDetailPage } from './pages/AgentDetailPage.js';
import { AgentsPage } from './pages/AgentsPage.js';
import { ApplicationsPage } from './pages/ApplicationsPage.js';
import { ConnectionsPage } from './pages/ConnectionsPage.js';
import { LoginPage } from './pages/LoginPage.js';
import { OverviewPage } from './pages/OverviewPage.js';
import {
  ApprovalsPage,
  PoliciesPage,
  SettingsPage,
  VaultPage,
  WorkflowsPage,
} from './pages/PlannedPages.js';

const MAX_RETRIES = 2;

/** Only failures that can plausibly clear on their own are retried. */
function shouldRetry(failureCount: number, error: unknown): boolean {
  if (failureCount >= MAX_RETRIES) return false;
  if (!(error instanceof ApiError)) return false;
  return error.status === null || error.status >= 500;
}

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: shouldRetry, staleTime: 10_000, refetchOnWindowFocus: false },
      mutations: { retry: false },
    },
  });
}

/** Query cache, session and notices. The router is supplied by the caller. */
export function AppProviders(props: { queryClient: QueryClient; children: ReactNode }) {
  return (
    <QueryClientProvider client={props.queryClient}>
      <SessionProvider>
        <AnnouncerProvider>{props.children}</AnnouncerProvider>
      </SessionProvider>
    </QueryClientProvider>
  );
}

function NotFoundPage() {
  return (
    <>
      <PageHeader title="Page not found" description="There is nothing at this address." />
      <p>
        <Link to="/">Go to the overview</Link>
      </p>
    </>
  );
}

/**
 * The route guard. Whatever the address, nobody without a session sees anything but the sign-in
 * page, and the address is kept so signing in lands back where they were going.
 */
export function AppRoutes() {
  const { state, retry } = useSession();

  if (state.status === 'loading') {
    return (
      <main className="login">
        <Loading label="Checking your session…" />
      </main>
    );
  }
  if (state.status === 'unreachable') {
    return (
      <main className="login">
        <div className="login-card">
          <ErrorState title="The broker API is not reachable" error={state.error} onRetry={retry} />
        </div>
      </main>
    );
  }
  if (state.status === 'anonymous') return <LoginPage notice={state.notice} />;

  return (
    <Routes>
      <Route element={<Shell />}>
        <Route index element={<OverviewPage />} />
        <Route path="applications" element={<ApplicationsPage />} />
        <Route path="connections" element={<ConnectionsPage />} />
        <Route path="vault" element={<VaultPage />} />
        <Route path="agents" element={<AgentsPage />} />
        <Route path="agents/:agentId" element={<AgentDetailPage />} />
        <Route path="policies" element={<PoliciesPage />} />
        <Route path="workflows" element={<WorkflowsPage />} />
        <Route path="approvals" element={<ApprovalsPage />} />
        <Route path="activity" element={<ActivityPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="login" element={<Navigate to="/" replace />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}

export function App() {
  // One client for the life of the page; created lazily so StrictMode does not discard it.
  const [queryClient] = useState(createQueryClient);
  return (
    <AppProviders queryClient={queryClient}>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </AppProviders>
  );
}
