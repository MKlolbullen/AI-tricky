import React from 'react';
import TestIdentitySettings from './TestIdentitySettings';

const rowLabels = ['Object A owner', 'Object B owner', 'Third test identity'];

export default function AccessMatrixOptions({target, value, onChange}) {
  const update = (key, next) => onChange({...value, [key]: next});
  const changeRow = (index, next) => update('rows', value.rows.map((row, i) => i === index ? {...row, ...next} : row));
  const remove = id => update('rows', value.rows.map(row => row.identity_id === id ? {...row, identity_id: ''} : row));

  return <section className="scope-summary" aria-label="Access matrix settings">
    <p>Use three bearer identities on the saved GET’s origin. Owner controls run first. Choose the access policy you expect for the other four cells.</p>
    <TestIdentitySettings target={target} onRemove={remove}>{(identities, origin) => <>
      <div className="verification-matrix-objects">
        <div>
          <strong>Object A · saved GET</strong>
          <code>{target}</code>
          <label>Expected object A ID<input required maxLength={128} value={value.first_object} onChange={e => update('first_object', e.target.value)}/></label>
        </div>
        <div>
          <label>Object B URL<input type="url" required maxLength={2048} value={value.second_url} placeholder={origin + '/objects/second'} onChange={e => update('second_url', e.target.value)}/></label>
          <label>Expected object B ID<input required maxLength={128} value={value.second_object} onChange={e => update('second_object', e.target.value)}/></label>
        </div>
      </div>
      <label className="field-label">Resource ID JSON Pointer<input required maxLength={256} value={value.json_pointer} onChange={e => update('json_pointer', e.target.value)}/></label>
      <table className="verification-matrix" aria-label="Expected access by identity">
        <thead><tr><th scope="col">Identity</th><th scope="col">Object A</th><th scope="col">Object B</th></tr></thead>
        <tbody>{value.rows.map((row, i) => <tr key={i}>
          <th scope="row"><label>{rowLabels[i]}<select required value={row.identity_id} onChange={e => changeRow(i, {identity_id: e.target.value})}>
            <option value="">Select test identity</option>
            {identities.filter(test => !value.rows.some((other, j) => j !== i && other.identity_id === test.id))
              .map(test => <option value={test.id} key={test.id}>{test.label}</option>)}
          </select></label></th>
          {row.expected.map((expected, column) => <td key={column}>
            {column === i ? <span>Allow · owner control</span> : <select required aria-label={rowLabels[i] + (column ? ' on object B' : ' on object A')}
              value={expected} onChange={e => changeRow(i, {expected: row.expected.map((access, j) => j === column ? e.target.value : access)})}>
              <option value="">Select policy</option><option value="allow">Allow</option><option value="deny">Deny</option>
            </select>}
          </td>)}
        </tr>)}</tbody>
      </table>
      <small>Object B must be in the recorded scope. A denial needs a successful read by that identity on the same server peer.</small>
    </>}</TestIdentitySettings>
  </section>;
}
