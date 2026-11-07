import React from 'react';

export default function TeamTurnBudget({budget, members=[]}) {
  if (!budget) return null;
  return <section className="comparison-notice team-turn-budget" aria-label="Team model turn budget">
    <strong>Team model turn budget</strong>
    <p>{budget.reserved} / {budget.limit} turns reserved across analysts and lead synthesis.</p>
    <table>
      <thead><tr><th scope="col">Analyst / pass</th><th scope="col">Turn ceiling</th></tr></thead>
      <tbody>{Object.entries(budget.member_limits).map(([role, limit]) => <tr key={role}>
        <th scope="row">{members.find(m => m.role===role)?.name || role}</th>
        <td>{limit || 'Skipped: no budget'}</td>
      </tr>)}
      {budget.synthesis_limit>0 && <tr><th scope="row">Lead synthesis</th><td>{budget.synthesis_limit}</td></tr>}</tbody>
    </table>
    <small>Reserved upper bounds, not measured usage or token costs. Unused turns stay reserved for this team; they are not reassigned.</small>
  </section>;
}
