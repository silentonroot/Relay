import { AuthMode, RegisterApplicationRequest } from '@aab/contracts';
import { useState } from 'react';
import type { FormEvent } from 'react';
import { useApplications, useRegisterApplication } from '../api/hooks.js';
import { useAnnounce } from '../components/Announcer.js';
import {
  EmptyState,
  ErrorState,
  Field,
  Loading,
  PageHeader,
  StatusBadge,
  TableRegion,
} from '../components/ui.js';
import { fieldErrors } from '../lib/forms.js';
import type { FieldErrors } from '../lib/forms.js';
import { ENTITY_STATUS } from '../lib/status.js';

const AUTH_MODE_LABEL: Record<AuthMode, string> = {
  browser_session: 'Browser session',
  oauth: 'OAuth',
  api_key: 'API key',
};

function RegisterApplicationForm({ onDone }: { onDone: () => void }) {
  const register = useRegisterApplication();
  const announce = useAnnounce();
  const [adapterId, setAdapterId] = useState('');
  const [adapterVersion, setAdapterVersion] = useState('');
  const [name, setName] = useState('');
  const [origins, setOrigins] = useState('');
  const [authModes, setAuthModes] = useState<AuthMode[]>(['browser_session']);
  const [errors, setErrors] = useState<FieldErrors>({});

  function submit(event: FormEvent) {
    event.preventDefault();
    const parsed = RegisterApplicationRequest.safeParse({
      adapterId: adapterId.trim(),
      adapterVersion: adapterVersion.trim(),
      name,
      allowedOrigins: origins
        .split(/\s+/)
        .map((origin) => origin.trim())
        .filter((origin) => origin !== ''),
      authModes,
    });
    if (!parsed.success) {
      setErrors(fieldErrors(parsed.error));
      return;
    }
    setErrors({});
    register.mutate(parsed.data, {
      onSuccess: (application) => {
        announce(`Application “${application.name}” registered.`);
        onDone();
      },
    });
  }

  return (
    <form className="panel form" onSubmit={submit} noValidate aria-label="Register application">
      <h2>Register application</h2>
      <Field label="Name" error={errors.name}>
        {(control) => (
          <input
            {...control}
            type="text"
            value={name}
            onChange={(event) => setName(event.target.value)}
            maxLength={120}
          />
        )}
      </Field>
      <div className="form-pair">
        <Field label="Adapter ID" hint="For example northstar." error={errors.adapterId}>
          {(control) => (
            <input
              {...control}
              type="text"
              value={adapterId}
              onChange={(event) => setAdapterId(event.target.value)}
              autoCapitalize="none"
              spellCheck={false}
            />
          )}
        </Field>
        <Field label="Adapter version" hint="For example 1.0.0." error={errors.adapterVersion}>
          {(control) => (
            <input
              {...control}
              type="text"
              value={adapterVersion}
              onChange={(event) => setAdapterVersion(event.target.value)}
              spellCheck={false}
            />
          )}
        </Field>
      </div>
      <Field
        label="Allowed origins"
        hint="One per line, exact hosts only (https://app.example.com). Workers may not navigate anywhere else. Plain http is accepted only for loopback hosts."
        error={errors.allowedOrigins}
      >
        {(control) => (
          <textarea
            {...control}
            rows={3}
            className="mono"
            value={origins}
            onChange={(event) => setOrigins(event.target.value)}
            spellCheck={false}
          />
        )}
      </Field>
      <fieldset className="field">
        <legend>Authentication methods</legend>
        {AuthMode.options.map((mode) => (
          <label className="choice" key={mode}>
            <input
              type="checkbox"
              checked={authModes.includes(mode)}
              onChange={(event) =>
                setAuthModes((current) =>
                  event.target.checked ? [...current, mode] : current.filter((m) => m !== mode),
                )
              }
            />
            {AUTH_MODE_LABEL[mode]}
          </label>
        ))}
        {errors.authModes !== undefined && <p className="field-error">{errors.authModes}</p>}
      </fieldset>
      {register.isError && (
        <ErrorState title="Application was not registered" error={register.error} />
      )}
      <div className="button-row">
        <button type="button" className="button" onClick={onDone} disabled={register.isPending}>
          Cancel
        </button>
        <button type="submit" className="button button-primary" disabled={register.isPending}>
          {register.isPending ? 'Registering…' : 'Register application'}
        </button>
      </div>
    </form>
  );
}

export function ApplicationsPage() {
  const applications = useApplications();
  const [registering, setRegistering] = useState(false);

  return (
    <>
      <PageHeader
        title="Applications"
        description="An application definition ties an adapter version to the origins its workers may visit and the ways an account can sign in."
        actions={
          !registering && (
            <button
              type="button"
              className="button button-primary"
              onClick={() => setRegistering(true)}
            >
              Register application
            </button>
          )
        }
      />

      {registering && <RegisterApplicationForm onDone={() => setRegistering(false)} />}

      {applications.isPending && <Loading label="Loading applications…" />}
      {applications.isError && (
        <ErrorState
          title="Applications could not be loaded"
          error={applications.error}
          onRetry={() => void applications.refetch()}
        />
      )}
      {applications.isSuccess && applications.data.length === 0 && (
        <EmptyState title="No applications registered">
          Register an application to make it available for connections.
        </EmptyState>
      )}
      {applications.isSuccess && applications.data.length > 0 && (
        <TableRegion label="Applications">
          <table>
            <thead>
              <tr>
                <th scope="col">Application</th>
                <th scope="col">Adapter</th>
                <th scope="col">Allowed origins</th>
                <th scope="col">Authentication</th>
                <th scope="col">Status</th>
              </tr>
            </thead>
            <tbody>
              {applications.data.map((application) => (
                <tr key={application.id}>
                  <th scope="row">{application.name}</th>
                  <td>
                    <code>{application.adapterId}</code>{' '}
                    <span className="numeric">{application.adapterVersion}</span>
                  </td>
                  <td>
                    <ul className="plain-list">
                      {application.allowedOrigins.map((origin) => (
                        <li key={origin}>
                          <code>{origin}</code>
                        </li>
                      ))}
                    </ul>
                  </td>
                  <td>{application.authModes.map((mode) => AUTH_MODE_LABEL[mode]).join(', ')}</td>
                  <td>
                    <StatusBadge status={ENTITY_STATUS[application.status]} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableRegion>
      )}
    </>
  );
}
