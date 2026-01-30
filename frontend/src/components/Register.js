
import React, { useState } from "react";
import api from "../api";

export default function Register() {
  const [form, setForm] = useState({ full_name: "", email: "", password: "" });
  const [msg, setMsg] = useState("");
  const [qr, setQr] = useState(null);
  const [prov, setProv] = useState(null);
  const [role, setRole] = useState(null);

  const submit = async (e) => {
    e.preventDefault();
    setMsg("");
    try {
      const r = await api.post("/register", form);
      setMsg("Registered. Scan the QR code with your authenticator app.");
      setQr(r.data.qr_data_uri);
      setProv(r.data.provisioning_uri);
      setRole(r.data.role);
    } catch (err) {
      setMsg(err.response?.data?.msg || err.message);
    }
  };

  return (
    <div className="card p-3">
      <h4>Register</h4>
      <form onSubmit={submit}>
        <input className="form-control mb-2" placeholder="Full name" value={form.full_name} onChange={e => setForm({...form, full_name:e.target.value})} />
        <input className="form-control mb-2" placeholder="Email" value={form.email} onChange={e => setForm({...form, email:e.target.value})} />
        <input className="form-control mb-2" placeholder="Password" type="password" value={form.password} onChange={e => setForm({...form, password:e.target.value})} />
        <button className="btn btn-primary">Register</button>
      </form>

      {msg && <div className="alert alert-info mt-2">{msg}</div>}
      {role && <div className="mt-2">Role: <strong>{role}</strong></div>}
      {qr && (
        <div className="mt-3">
          <div>Scan this QR code in your authenticator app (Google Authenticator / Authy):</div>
          <img src={qr} alt="TOTP QR" style={{maxWidth: "240px"}} />
          <div className="mt-2"><small>If you cannot scan, use this URI: <code>{prov}</code></small></div>
        </div>
      )}
    </div>
  );
}