
import React, { useState } from "react";
import axios from "axios";
import { saveToken, getTempToken, clearTempToken } from "../auth";
import { useNavigate } from "react-router-dom";

const API_BASE = process.env.REACT_APP_API_URL || "http://localhost:8000";

export default function TOTPVerify() {
  const [code, setCode] = useState("");
  const [msg, setMsg] = useState("");
  const navigate = useNavigate();

  const submit = async (e) => {
    e.preventDefault();
    setMsg("");
    try {
      const temp = getTempToken();
      if (!temp) {
        setMsg("Session expired or no login session found. Please login again.");
        setTimeout(()=>navigate("/login"), 1500);
        return;
      }
      const resp = await axios.post(`${API_BASE}/verify_totp`, { code }, { headers: { Authorization: `Bearer ${temp}` }});
      const access = resp.data.access_token;
      const role = resp.data.role;
      saveToken(access);
      clearTempToken();
      if (role === "admin") navigate("/admin");
      else if (role === "auditor") navigate("/auditor");
      else navigate("/dashboard");
    } catch (err) {
      const body = err.response?.data;
      // handle JWT errors returned by backend handlers
      if (body?.msg === "token_expired" || body?.msg === "missing_token") {
        setMsg("Session expired — please login again.");
        // clear temp token (if any) and redirect to login
        clearTempToken();
        setTimeout(()=>navigate("/login"), 1200);
        return;
      }
      if (body?.msg === "invalid_token") {
        setMsg("Invalid session token. Please login again.");
        clearTempToken();
        setTimeout(()=>navigate("/login"), 1200);
        return;
      }
      // TOTP-specific failure
      if (body?.msg === "invalid TOTP" || body?.msg === "invalid") {
        setMsg("Invalid code. Please check the code on your authenticator app and try again.");
        return;
      }
      // generic fallback
      setMsg(err.response?.data?.msg || err.message || "Verification failed");
    }
  };

  const resendLogin = () => {
    clearTempToken();
    navigate("/login");
  };

  return (
    <div className="card p-3">
      <h4>Verify TOTP</h4>
      <p>Enter the code from your authenticator app.</p>
      <form onSubmit={submit}>
        <input className="form-control mb-2" placeholder="123456" value={code} onChange={e => setCode(e.target.value)} />
        <button className="btn btn-primary">Verify</button>
      </form>
      <div className="mt-2">
        <button className="btn btn-link" onClick={resendLogin}>Login Again</button>
      </div>
      {msg && <div className="alert alert-info mt-2">{msg}</div>}
    </div>
  );
}