import React from 'react';
import TestIdentitySettings from './TestIdentitySettings';

export default function ObjectAccessOptions({target, value, onChange}) {
  const update = (key, next) => onChange({...value, [key]: next});
  const remove = id => onChange({
    ...value,
    owner_identity_id: value.owner_identity_id === id ? '' : value.owner_identity_id,
    other_identity_id: value.other_identity_id === id ? '' : value.other_identity_id,
  });

  return <section className="scope-summary" aria-label="Object access settings">
    <p>Use two test identities with separate bearer tokens and known object ownership. The check uses direct routing.</p>
    <TestIdentitySettings target={target} onRemove={remove}>{(available, origin) => <>
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
    </>}</TestIdentitySettings>
  </section>;
}
