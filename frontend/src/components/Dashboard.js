
import React, { useState, useEffect } from "react";
import api from "../api";
import { decodedUser, getToken, getTempToken } from "../auth";
import { useNavigate } from "react-router-dom";

export default function Dashboard() {
  const navigate = useNavigate();
  const [elections, setElections] = useState([]);
  const [selectedElection, setSelectedElection] = useState("");
  const [token, setToken] = useState("");
  const [choice, setChoice] = useState("");
  const [msg, setMsg] = useState("");

  useEffect(() => {
    const access = getToken();
    const temp = getTempToken();
    const decoded = decodedUser();

    if (!access) {
      if (temp) {
        navigate("/verify-totp");
      } else {
        navigate("/login");
      }
      return;
    }

    if (decoded && decoded.role && decoded.role !== "voter") {
      if (decoded.role === "admin") {
        navigate("/admin");
        return;
      } else if (decoded.role === "auditor") {
        navigate("/auditor");
        return;
      }
    }

    const fetchElections = async () => {
      try {
        const r = await api.get("/list_elections");
        setElections(r.data.elections || []);
      } catch (err) {
        console.error("Failed to fetch elections", err);
      }
    };
    fetchElections();
  }, [navigate]);

  const requestToken = async (eid) => {
    try {
      const r = await api.post("/issue_token", { election_id: eid });
      setToken(r.data.token);
      setSelectedElection(eid);
      setMsg("Token issued. Store it securely — shown only once.");
    } catch (err) {
      setMsg(err.response?.data?.msg || err.message);
    }
  };

  const cast = async () => {
    if (!selectedElection || !token) {
      setMsg("Select election and request token first");
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(choice);
    } catch (e) {
      parsed = { candidate: choice };
    }
    try {
      const r = await api.post("/cast_vote", { election_id: selectedElection, token, choice: parsed });
      setMsg(r.data.msg + " Vote id: " + (r.data.vote_id || ""));
      setToken("");
    } catch (err) {
      setMsg(err.response?.data?.msg || err.message);
    }
  };

  if (!getToken()) {
    return <div>Loading...</div>;
  }

  const decoded = decodedUser();

  return (
    <div>
      <h4>Voter Dashboard</h4>
      <div className="card p-3 mb-3">
        <div className="mb-2">Hi, {decoded?.username}</div>

        <h5>Available Elections</h5>
        <ul className="list-group mb-3">
          {elections.map(e => (
            <li key={e.election_id} className="list-group-item d-flex justify-content-between align-items-start">
              <div style={{flex:1}}>
                <div className="fw-bold">{e.name} <small className="text-muted">({e.status})</small></div>
                <div className="mb-1"><small>{e.description}</small></div>
                <div><small>Eligible: {e.eligible ? "Yes" : "No"}</small></div>
              </div>
              <div style={{marginLeft:10}}>
                {e.eligible && <button className="btn btn-primary" onClick={() => requestToken(e.election_id)}>Request Token</button>}
              </div>
            </li>
          ))}
        </ul>

        {token && <div className="alert alert-success">One-time token (store safely): <strong>{token}</strong></div>}

        <div className="mb-2">
          <label>Your Choice (JSON or simple string)</label>
          <input className="form-control" value={choice} onChange={e=>setChoice(e.target.value)} placeholder='{"candidate":"John"} or John' />
        </div>
        <button className="btn btn-success" onClick={cast}>Cast Vote</button>
        {msg && <div className="alert alert-info mt-2">{msg}</div>}
      </div>
    </div>
  );
}