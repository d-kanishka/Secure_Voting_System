
import React, { useState } from "react";
import api from "../api";
import { saveTempToken } from "../auth";
import { useNavigate } from "react-router-dom";

export default function Login() {
  const [form, setForm] = useState({ email: "", password: "" });
  const [msg, setMsg] = useState("");
  const navigate = useNavigate();

  const submit = async (e) => {
    e.preventDefault();
    setMsg("");
    try {
      const r = await api.post("/login", form);
      // backend returns temp_token (mfa required)
      saveTempToken(r.data.temp_token);
      navigate("/verify-totp");
    } catch (err) {
      setMsg(err.response?.data?.msg || err.message);
    }
  };

  return (
    <div className="card p-3">
      <h4>Login</h4>
      <form onSubmit={submit}>
        <input className="form-control mb-2" placeholder="Email or username" value={form.email} onChange={e => setForm({...form, email:e.target.value})} />
        <input className="form-control mb-2" placeholder="Password" type="password" value={form.password} onChange={e => setForm({...form, password:e.target.value})} />
        <button className="btn btn-primary">Login</button>
      </form>
      {msg && <div className="alert alert-danger mt-2">{msg}</div>}
      <div className="mt-2"><a href="/reset-password">Forgot password?</a></div>
    </div>
  );
}