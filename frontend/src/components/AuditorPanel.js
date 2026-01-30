
import React, { useEffect, useState } from "react";
import api from "../api";

export default function AuditorPanel() {
  const [elections, setElections] = useState([]);
  const [selectedElection, setSelectedElection] = useState("");
  const [voteId, setVoteId] = useState("");
  const [verifyResult, setVerifyResult] = useState(null);
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState({ totalElections:0, totalVotes:0 });
  const [tally, setTally] = useState(null);
  const [loadingTally, setLoadingTally] = useState(false);

  useEffect(() => {
    fetchElections();
    fetchLogs();
  }, []);

  const fetchElections = async () => {
    try {
      const r = await api.get("/list_elections");
      setElections(r.data.elections || []);
      let totalVotes = 0;
      for (const e of r.data.elections) {
        const res = await api.get(`/election/${e.election_id}`);
        totalVotes += res.data.votes_count || 0;
      }
      setStats({ totalElections: r.data.elections.length, totalVotes });
    } catch (err) {
      console.error(err);
    }
  };

  const fetchLogs = async () => {
    try {
      const r = await api.get("/audit_logs?limit=200");
      setLogs(r.data.audit_logs || []);
    } catch (err) {
      console.error(err);
    }
  };

  const verifyVote = async () => {
    try {
      const r = await api.post("/audit/verify_vote", { election_id: selectedElection, vote_id: voteId });
      setVerifyResult(r.data);
    } catch (err) {
      setVerifyResult({ error: err.response?.data?.msg || err.message });
    }
  };

  const fetchTally = async () => {
    if (!selectedElection) {
      alert("Select an election");
      return;
    }
    setLoadingTally(true);
    setTally(null);
    try {
      const r = await api.get(`/audit/election_tally/${selectedElection}`);
      setTally(r.data);
    } catch (err) {
      setTally({ error: err.response?.data?.msg || err.message });
    } finally {
      setLoadingTally(false);
    }
  };

  return (
    <div>
      <h3>Auditor Dashboard</h3>
      <div className="row mb-3">
        <div className="col"><div className="card p-3"><h6>Total Elections</h6><div>{stats.totalElections}</div></div></div>
        <div className="col"><div className="card p-3"><h6>Total Votes (aggregate)</h6><div>{stats.totalVotes}</div></div></div>
      </div>

      <div className="card p-3 mb-3">
        <h5>Election Monitoring</h5>
        <table className="table">
          <thead><tr><th>Name</th><th>Status</th><th>Eligible</th></tr></thead>
          <tbody>
            {elections.map(e => (
              <tr key={e.election_id} onClick={()=>setSelectedElection(e.election_id)} style={{cursor:"pointer", backgroundColor: selectedElection===e.election_id ? "#eef" : "transparent"}}>
                <td>{e.name}</td><td>{e.status}</td><td>{e.eligible ? "Yes" : "No"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="card p-3 mb-3">
        <h5>Verify Vote</h5>
        <div className="mb-2">
          <label>Selected Election ID</label>
          <input className="form-control mb-2" value={selectedElection} onChange={e=>setSelectedElection(e.target.value)} />
          <input className="form-control mb-2" placeholder="vote id" value={voteId} onChange={e=>setVoteId(e.target.value)} />
          <button className="btn btn-primary me-2" onClick={verifyVote}>Verify Vote</button>
          <button className="btn btn-secondary" onClick={fetchTally}>View Tally</button>
        </div>
        {verifyResult && (
          <div className="mt-2">
            <pre>{JSON.stringify(verifyResult, null, 2)}</pre>
          </div>
        )}
      </div>

      <div className="card p-3 mb-3">
        <h5>Election Tally</h5>
        {loadingTally && <div>Loading tally...</div>}
        {tally && tally.error && <div className="alert alert-danger">{tally.error}</div>}
        {tally && !tally.error && (
          <>
            <div><strong>{tally.name}</strong> {tally.published ? <span className="badge bg-success">published</span> : <span className="badge bg-warning">computed</span>}</div>
            <table className="table mt-2">
              <thead><tr><th>Candidate</th><th>Count</th></tr></thead>
              <tbody>
                {tally.tally && tally.tally.length > 0 ? (
                  tally.tally.map((c, i) => <tr key={i}><td>{c.candidate}</td><td>{c.count}</td></tr>)
                ) : (
                  <tr><td colSpan={2}>No votes recorded</td></tr>
                )}
              </tbody>
            </table>

            {tally.decrypted_votes && tally.decrypted_votes.length > 0 && (
              <>
                <h6>Decrypted Votes (sample)</h6>
                <div style={{maxHeight:200, overflow:"auto"}}>
                  <pre>{JSON.stringify(tally.decrypted_votes, null, 2)}</pre>
                </div>
              </>
            )}
          </>
        )}
      </div>

      <div className="card p-3 mb-3">
        <h5>Audit Logs (read-only)</h5>
        <button className="btn btn-sm btn-outline-primary me-2" onClick={fetchLogs}>Refresh</button>
        <div style={{maxHeight:240, overflow:"auto"}}>
          <table className="table table-sm">
            <thead><tr><th>Time</th><th>Action</th><th>Actor</th><th>Details</th></tr></thead>
            <tbody>
              {logs.map((l,i)=>(
                <tr key={i}><td>{l.timestamp}</td><td>{l.action}</td><td>{l.actor}</td><td><pre style={{whiteSpace:"pre-wrap"}}>{JSON.stringify(l.details)}</pre></td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}