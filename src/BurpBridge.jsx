import React, {useEffect, useState} from 'react';
import {api} from './api.mjs';

export function RepeaterButton({exchangeId}) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const queue = async () => {
    setBusy(true); setError(''); setMessage('');
    try {
      const result = await api(`/http-history/${encodeURIComponent(exchangeId)}/repeater`, {});
      setMessage(result.already_queued ? 'Already queued. The paired extension will open it in Repeater.' :
        'Queued for Repeater. Review the request in Burp before sending.' +
        (result.adapted ? ' The proxy request line was converted to origin form.' : ''));
    } catch (failure) {setError(failure.message);}
    finally {setBusy(false);}
  };
  return <span className="burp-repeater-action">
    <button className="secondary" type="button" onClick={queue} disabled={busy}>Open in Burp Repeater</button>
    {message && <small role="status">{message}</small>}
    {error && <small role="alert">{error}</small>}
  </span>;
}

export default function BurpBridge({runId}) {
  const [pairing, setPairing] = useState(null);
  const [status, setStatus] = useState(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const base = `/runs/${encodeURIComponent(runId)}/burp-bridge`;
  useEffect(() => {
    let current = true;
    let timer;
    const read = async () => {
      try {
        const value = await api(base);
        if (current) setStatus(value);
      } catch (failure) {
        if (current) setError(failure.message);
      } finally {
        if (current) timer = setTimeout(read, 4000);
      }
    };
    read();
    return () => {current = false;clearTimeout(timer);};
  }, [base]);
  const change = async action => {
    setBusy(true); setError(''); setMessage('');
    try {
      const result = await api(`${base}/${action}`, {});
      if (action === 'pair') {
        setStatus({paired: true, expires_at: result.expires_at, queued: 0});
        setPairing(JSON.stringify({runId: result.run_id, token: result.token}));
        setMessage('Pairing generated. Copy it to the AI-tricky tab in Burp.');
      } else {
        setStatus(result); setPairing(null); setMessage('Pairing revoked and pending requests cleared.');
      }
    } catch (failure) {setError(failure.message);}
    finally {setBusy(false);}
  };
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(pairing);
      setPairing(null); setMessage('Pairing copied. Paste it into the Burp extension, then click Connect.');
    } catch {
      setError('Clipboard access was blocked. Select the pairing field and copy it manually.');
    }
  };
  return <section className="burp-pairing scope-summary" aria-label="Local Burp bridge">
    <strong>Local Burp bridge</strong>
    <p>{status?.paired ? `Paired until ${new Date(status.expires_at).toLocaleTimeString()} · ${status.queued} queued` : 'Pair the Burp extension with this run to import selected exchanges and open saved requests in Repeater.'}</p>
    <div className="evidence-actions">
      <button className="secondary" type="button" disabled={busy} onClick={() => change('pair')}>{status?.paired ? 'Replace Burp pairing' : 'Generate Burp pairing'}</button>
      {status?.paired && <button className="secondary" type="button" disabled={busy} onClick={() => change('disconnect')}>Revoke Burp pairing</button>}
    </div>
    {pairing && <div className="field-label"><label>Burp pairing
      <input readOnly type="password" autoComplete="off" value={pairing} onFocus={event => event.target.select()}/>
    </label><button className="secondary" type="button" onClick={copy}>Copy pairing</button></div>}
    {message && <small role="status">{message}</small>}
    {error && <small role="alert">{error}</small>}
  </section>;
}
