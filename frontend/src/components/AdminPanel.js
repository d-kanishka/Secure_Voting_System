
import React, { useEffect, useState } from "react";
import api from "../api";
import { decodedUser } from "../auth";

export default function AdminPanel() {
  const user = decodedUser();
  const [stats, setStats] = useState({});
  const [elections, setElections] = useState([]);
  const [usersList, setUsersList] = useState([]);
  const [logs, setLogs] = useState([]);
  const [outbox, setOutbox] = useState([]);
  const [newElection, setNewElection] = useState({ name: "", description: "", start: "", end: "", candidates: "", anonymize: true });
  const [eligibleUsername, setEligibleUsername] = useState("");
  const [selectedElectionId, setSelectedElectionId] = useState("");
  const [msg, setMsg] = useState("");

  useEffect(() => {
    fetchAll();
  }, []);

  const fetchAll = async () => {
    await Promise.all([fetchStats(), fetchElections(), fetchUsers(), fetchLogs(), fetchOutbox()]);
  };

  const fetchStats = async () => {
    try {
      const usersResp = await api.get("/admin/users");
      const users = usersResp.data.users || [];
      const el = await api.get("/list_elections");
      const electionsArr = el.data.elections || [];
      let totalVotes = 0;
      for (const e of electionsArr) {
        const res = await api.get(`/election/${e.election_id}`);
        totalVotes += res.data.votes_count || 0;
      }
      setStats({
        totalUsers: users.length,
        totalElections: electionsArr.length,
        ongoing: electionsArr.filter(e=>e.status==="ongoing").length,
        completed: electionsArr.filter(e=>e.status==="completed").length,
        totalVotes
      });
    } catch (err) {
      console.error(err);
    }
  };

  const fetchElections = async () => {
    try {
      const r = await api.get("/list_elections");
      setElections(r.data.elections || []);
    } catch (err) {
      console.error(err);
    }
  };

  const fetchUsers = async () => {
    try {
      const r = await api.get("/admin/users");
      setUsersList(r.data.users || []);
    } catch (err) {
      console.error(err);
    }
  };

  const fetchLogs = async () => {
    try {
      const r = await api.get("/admin/audit_logs?limit=200");
      setLogs(r.data.audit_logs || []);
    } catch (err) {
      console.error(err);
    }
  };

  const fetchOutbox = async () => {
    try {
      const r = await api.get("/admin/outbox");
      setOutbox(r.data.outbox || []);
    } catch (err) {
      console.error(err);
    }
  };

  const createElection = async () => {
    setMsg("");
    try {
      const candidatesArr = newElection.candidates.split(",").map(s=>s.trim()).filter(Boolean);
      const r = await api.post("/create_election", {...newElection, candidates: candidatesArr});
      setMsg("Created election " + r.data.election_id);
      await fetchElections();
      await fetchStats();
    } catch (err) {
      setMsg(err.response?.data?.msg || err.message);
    }
  };

  const addEligible = async () => {
    if (!selectedElectionId || !eligibleUsername) {
      setMsg("Select election and enter username");
      return;
    }
    try {
      const r = await api.post("/add_eligible_voter", { election_id: selectedElectionId, username: eligibleUsername });
      setMsg("Added eligible user: " + eligibleUsername);
      setEligibleUsername("");
      await fetchElections();
    } catch (err) {
      setMsg(err.response?.data?.msg || err.message);
    }
  };

  const startElection = async (id) => {
    try {
      await api.post(`/start_election/${id}`);
      setMsg("Election started");
      await fetchElections();
      await fetchStats();
    } catch (err) { setMsg(err.response?.data?.msg || err.message); }
  };

  const stopElection = async (id) => {
    try {
      await api.post(`/stop_election/${id}`);
      setMsg("Election stopped");
      await fetchElections();
      await fetchStats();
    } catch (err) { setMsg(err.response?.data?.msg || err.message); }
  };

  const deleteElection = async (id) => {
    if (!window.confirm("Delete election? This removes tokens and votes.")) return;
    try {
      await api.delete(`/delete_election/${id}`);
      setMsg("Deleted");
      await fetchElections();
      await fetchStats();
    } catch (err) { setMsg(err.response?.data?.msg || err.message); }
  };

  const resetUserPassword = async (username) => {
    const pw = prompt("New password for " + username + ":");
    if (!pw) return;
    try {
      await api.post("/admin/reset_user_password", { username, new_password: pw });
      setMsg("Password reset for " + username);
    } catch (err) { setMsg(err.response?.data?.msg || err.message); }
  };

  const importUsers = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const form = new FormData();
    form.append("file", file);
    try {
      const r = await api.post("/admin/import_users", form, { headers: { "Content-Type": "multipart/form-data" } });
      setMsg(`Imported ${r.data.created.length} users, ${r.data.errors.length} errors.`);
      await fetchUsers();
    } catch (err) {
      setMsg(err.response?.data?.msg || err.message);
    }
  };

  const exportLogsCSV = () => {
    if (!logs || logs.length === 0) { alert("No logs"); return; }
    const header = Object.keys(logs[0]).join(",");
    const rows = logs.map(l => [l.action, l.actor, JSON.stringify(l.details).replace(/"/g,'""'), l.timestamp].map(v=>`"${v}"`).join(","));
    const csv = [header, ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "audit_logs.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div>
      <h3>Admin Dashboard</h3>

      <div className="row mb-3">
        <div className="col"><div className="card p-3"><h6>Total Users</h6><div>{stats.totalUsers || 0}</div></div></div>
        <div className="col"><div className="card p-3"><h6>Total Elections</h6><div>{stats.totalElections || 0}</div></div></div>
        <div className="col"><div className="card p-3"><h6>Ongoing</h6><div>{stats.ongoing || 0}</div></div></div>
        <div className="col"><div className="card p-3"><h6>Completed</h6><div>{stats.completed || 0}</div></div></div>
        <div className="col"><div className="card p-3"><h6>Total Votes</h6><div>{stats.totalVotes || 0}</div></div></div>
      </div>

      <div className="card p-3 mb-3">
        <h5>Create Election</h5>
        <input className="form-control mb-2" placeholder="Name" value={newElection.name} onChange={e=>setNewElection({...newElection, name:e.target.value})} />
        <input className="form-control mb-2" placeholder="Description" value={newElection.description} onChange={e=>setNewElection({...newElection, description:e.target.value})} />
        <input className="form-control mb-2" placeholder="Start (ISO)" value={newElection.start} onChange={e=>setNewElection({...newElection, start:e.target.value})} />
        <input className="form-control mb-2" placeholder="End (ISO)" value={newElection.end} onChange={e=>setNewElection({...newElection, end:e.target.value})} />
        <input className="form-control mb-2" placeholder="Candidates (comma-separated)" value={newElection.candidates} onChange={e=>setNewElection({...newElection, candidates:e.target.value})} />
        <div className="form-check mb-2">
          <input className="form-check-input" type="checkbox" checked={newElection.anonymize} onChange={e=>setNewElection({...newElection, anonymize:e.target.checked})} />
          <label className="form-check-label">Anonymize votes</label>
        </div>
        <button className="btn btn-primary" onClick={createElection}>Create Election</button>
      </div>

      <div className="card p-3 mb-3">
        <h5>Elections</h5>
        <table className="table">
          <thead><tr><th>Name</th><th>Description</th><th>Status</th><th>Eligible</th><th>Actions</th></tr></thead>
          <tbody>
            {elections.map(e => (
              <tr key={e.election_id} onClick={()=>setSelectedElectionId(e.election_id)} style={{cursor:"pointer", backgroundColor:selectedElectionId===e.election_id ? "#f5f5f5": "transparent"}}>
                <td>{e.name}</td>
                <td>{e.description}</td>
                <td>{e.status}</td>
                <td>{e.eligible ? "Yes" : "No"}</td>
                <td>
                  <button className="btn btn-sm btn-success me-1" onClick={(ev)=>{ev.stopPropagation(); startElection(e.election_id);}}>Start</button>
                  <button className="btn btn-sm btn-warning me-1" onClick={(ev)=>{ev.stopPropagation(); stopElection(e.election_id);}}>Stop</button>
                  <button className="btn btn-sm btn-danger" onClick={(ev)=>{ev.stopPropagation(); deleteElection(e.election_id);}}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        <div className="mt-3">
          <h6>Add Eligible Voter</h6>
          <div className="d-flex gap-2">
            <input className="form-control" placeholder="username (e.g., cb.sc.u4cse23155)" value={eligibleUsername} onChange={e=>setEligibleUsername(e.target.value)} />
            <button className="btn btn-primary" onClick={addEligible}>Add to Selected Election</button>
          </div>
          <div className="mt-2"><small>Selected Election ID: {selectedElectionId || "none (click an election row to select)"}</small></div>
        </div>
      </div>

      <div className="card p-3 mb-3">
        <h5>User Management</h5>
        <input type="file" onChange={importUsers} accept=".csv" className="form-control mb-2" />
        <table className="table">
          <thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Actions</th></tr></thead>
          <tbody>
            {usersList.map(u => (
              <tr key={u.username}>
                <td>{u.username}</td>
                <td>{u.email}</td>
                <td>{u.role}</td>
                <td>
                  <button className="btn btn-sm btn-secondary me-1" onClick={()=>resetUserPassword(u.username)}>Reset Password</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="card p-3 mb-3">
        <h5>Audit Logs</h5>
        <button className="btn btn-sm btn-outline-primary me-2" onClick={fetchLogs}>Refresh</button>
        <button className="btn btn-sm btn-outline-success me-2" onClick={exportLogsCSV}>Export CSV</button>
        <div style={{maxHeight: 240, overflow: "auto", marginTop: 10}}>
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

      <div className="card p-3 mb-3">
        <h5>Outbox (dev emails)</h5>
        <div style={{maxHeight:200, overflow:"auto"}}>
          {outbox.map((m,i)=>(
            <div key={i} className="border p-2 mb-2">
              <div><strong>To:</strong> {m.to} <strong>Subject:</strong> {m.subject}</div>
              <div><pre>{m.body}</pre></div>
              <div><small>{m.timestamp}</small></div>
            </div>
          ))}
        </div>
      </div>

      {msg && <div className="alert alert-info">{msg}</div>}
    </div>
  );
}