import React, {useState} from 'react';
import {api} from './api.mjs';

export default function WebReconStarter({disabled, onLoad}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [review, setReview] = useState(false);
  const [surface, setSurface] = useState(false);

  const load = async (options = {}) => {
    setBusy(true);
    setError('');
    const query = new URLSearchParams({...options, review, surface});
    try {
      onLoad(await api('/workflow-starters/web-recon?' + query));
    } catch (error) {
      setError(error.message);
    } finally {
      setBusy(false);
    }
  };

  return <section className="scope-summary" aria-label="Web reconnaissance starter">
    <strong>Web reconnaissance starter</strong>
    <p>Enumerate subdomains, probe authorized hosts, crawl live URLs and save linked web sources.</p>
    <label className="http-toggle">
      <input type="checkbox" checked={review} disabled={disabled || busy} onChange={e => setReview(e.target.checked)}/>
      <span>Add specialist evidence review<small>Requires CAI. Analysts review saved HTTP evidence.</small></span>
    </label>
    <label className="http-toggle">
      <input type="checkbox" checked={surface} disabled={disabled || busy} onChange={e => setSurface(e.target.checked)}/>
      <span>Add API Surface analysis<small>Extract endpoints from saved JavaScript and source maps.</small></span>
    </label>
    <button className="secondary" disabled={disabled || busy} onClick={() => load()}>Load web recon workflow</button>{' '}
    <button className="secondary" disabled={disabled || busy} onClick={() => load({fuzz: true})}>Load web recon with path fuzzing</button>{' '}
    <button className="secondary" disabled={disabled || busy} onClick={() => load({scan: true})}>Load web recon with Nuclei</button>
    <small>Bind a wordlist for fuzzing or install the bundled support files for Nuclei. Loading only updates the canvas.</small>
    {error && <p role="alert">{error}</p>}
  </section>;
}
