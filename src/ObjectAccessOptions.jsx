import React, {useEffect, useState} from 'react';
import {api} from './api.mjs';

export default function ObjectAccessOptions({target, value, onChange}) {
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
      onChange({
        ...value,
        owner_identity_id: value.owner_identity_id === id ? '' : value.owner_identity_id,
        other_identity_id: value.other_identity_id === id ? '' : value.other_identity_id,
      });
    } catch (error) {
      setError(error.message);
    } finally {
      setBusy(false);
    }
  };

  const update = (key, next) => onChange({...value, [key]: next});
  const available = identities.filter(identity => new URL(identity.origin).origin === origin);
  return <section className="scope-summary" aria-label="Object access settings">
    <p>Use two test identities with separate bearer tokens and known object ownership. The check uses direct routing.</p>
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
    <label className="field-label">Resource owner identity<select required value={value.owner_identity_id || ''}
      onChange={e => update('owner_identity_id', e.target.value)}>
      <option value="">Select owner</option>{available.map(identity => <option key={identity.id} value={identity.id}>{identity.label}</option>)}
    </select></label>
    <label className="field-label">Second test identity<select required value={value.other_identity_id || ''}
      onChange={e => update('other_identity_id', e.target.value)}>
      <option value="">Select second identity</option>{available.filter(identity => identity.id !== value.owner_identity_id)
        .map(identity => <option key={identity.id} value={identity.id}>{identity.label}</option>)}
    </select></label>
    <label className="field-label">Second identity's control URL<input type="url" required maxLength={2048}
      placeholder={origin + '/objects/other'} value={value.control_url || ''} onChange={e => update('control_url', e.target.value)}/>
      <small>Choose a different object owned by the second identity within the approved scope.</small>
    </label>
    <label className="field-label">Resource ID JSON Pointer<input required maxLength={256}
      value={value.json_pointer ?? '/id'} onChange={e => update('json_pointer', e.target.value)}/></label>
    <label className="field-label">Expected owner object ID<input required maxLength={128}
      value={value.owner_object || ''} onChange={e => update('owner_object', e.target.value)}/></label>
    <label className="field-label">Expected control object ID<input required maxLength={128}
      value={value.control_object || ''} onChange={e => update('control_object', e.target.value)}/></label>
  </section>;
}
