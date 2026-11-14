import { LoginRequest } from '@aab/contracts';
import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { useSession } from '../auth/SessionContext.js';
import { ErrorState, Field } from '../components/ui.js';
import { fieldErrors } from '../lib/forms.js';
import type { FieldErrors } from '../lib/forms.js';

export function LoginPage({ notice }: { notice: string | null }) {
  const { signIn } = useSession();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [errors, setErrors] = useState<FieldErrors>({});
  const [failure, setFailure] = useState<unknown>(null);
  const [pending, setPending] = useState(false);

  useEffect(() => {
    document.title = 'Sign in · Agent Access Broker';
  }, []);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const parsed = LoginRequest.safeParse({ email: email.trim(), password });
    if (!parsed.success) {
      setErrors(fieldErrors(parsed.error));
      return;
    }
    setErrors({});
    setFailure(null);
    setPending(true);
    try {
      await signIn(parsed.data);
    } catch (error) {
      // The server's message is deliberately generic; show it as is and drop the password.
      setFailure(error);
      setPassword('');
      setPending(false);
    }
  }

  return (
    <main className="login">
      <div className="login-card">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true" />
          <span className="brand-name">Agent Access Broker</span>
        </div>
        <h1>Sign in</h1>
        <p className="page-description">
          Manage connections, agents and what each agent may do on your behalf.
        </p>

        {notice !== null && (
          <p className="callout" role="status">
            {notice}
          </p>
        )}
        {failure !== null && <ErrorState title="Sign-in failed" error={failure} />}

        <form onSubmit={(event) => void submit(event)} noValidate>
          <Field label="Email" error={errors.email}>
            {(control) => (
              <input
                {...control}
                type="email"
                name="email"
                autoComplete="username"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                required
              />
            )}
          </Field>
          <Field label="Password" error={errors.password}>
            {(control) => (
              <input
                {...control}
                type="password"
                name="password"
                autoComplete="current-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
              />
            )}
          </Field>
          <button type="submit" className="button button-primary button-block" disabled={pending}>
            {pending ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        <p className="field-hint">
          This is the broker owner account. Passwords for connected applications are never entered
          here or shown to agents.
        </p>
      </div>
    </main>
  );
}
