import React, {useEffect, useState} from 'react';
import {api} from './api.mjs';

export default function TestIdentitySettings({target, onRemove, children}) {
  const origin = new URL(target).origin;
  const [identities, setIdentities] = useState([]);
  const [label, setLabel] = useState('');
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    api('/verification/identities').then(items => {
      if (active) setIdentities(items);
    }).catch(error => {
      if (active) setError(error.message);
    });
    return () => {active = false;};
  }, []);

  const register = async () => {
    setBusy(true);
    setError('');
    try {
      const identity = await api('/verification/identities', {origin, label, token});
      setIdentities(items => [...items, identity]);
      setLabel('');
    } catch (error) {
      setError(error.message);
    } finally {
      setToken('');
      setBusy(false);
    }
  };

  const remove = async id => {
    setBusy(true);
    setError('');
    try {
      await api('/verification/identities/' + id + '/remove', {});
      setIdentities(items => items.filter(identity => identity.id !== id));
      onRemove(id);
    } catch (error) {
      setError(error.message);
    } finally {
      setBusy(false);
    }
  };

  const available = identities.filter(identity => new URL(identity.origin).origin === origin);
  return <>
    <details>
      <summary>Manage test identities</summary>
      <p>New identities are bound to <code>{origin}</code> for this application session.</p>
      <label className="field-label">Identity label<input maxLength={80} value={label} onChange={e => setLabel(e.target.value)}/></label>
      <label className="field-label">Bearer token<input type="password" autoComplete="new-password" maxLength={4096}
        value={token} onChange={e => setToken(e.target.value)}/></label>
      <button type="button" className="secondary" disabled={busy || !label.trim() || !token} onClick={register}>Register test identity</button>
      {identities.length > 0 && <ul>{identities.map(identity => <li key={identity.id}>
        {identity.label} · {identity.origin}{' '}
        <button type="button" className="secondary" disabled={busy} onClick={() => remove(identity.id)}
          aria-label={`Remove test identity ${identity.label}`}>Remove</button>
      </li>)}</ul>}
    </details>
    {error && <p className="local-error" role="alert">{error}</p>}
    {children(available, origin)}
  </>;
}
