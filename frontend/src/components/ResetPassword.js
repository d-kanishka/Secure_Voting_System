
import React, { useState } from "react";
import api from "../api";
import { saveToken } from "../auth";
import { useNavigate } from "react-router-dom";

export default function ResetPassword() {
  const [step, setStep] = useState(1);
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [newPw, setNewPw] = useState("");
  const [msg, setMsg] = useState("");
  const navigate = useNavigate();

  const requestReset = async () => {
    setMsg("");
    try {
      await api.post("/forgot_password", { email });
      setStep(2);
      setMsg("If the email exists, a reset code has been sent.");
    } catch (err) {
      setMsg(err.response?.data?.msg || err.message);
    }
  };

  const doReset = async () => {
    setMsg("");
    try {
      const r = await api.post("/reset_password", { email, code, new_password: newPw });
      if (r.data.access_token) {
        saveToken(r.data.access_token);
        navigate("/dashboard");
      } else {
        setMsg("Password reset complete. Please login.");
        navigate("/login");
      }
    } catch (err) {
      setMsg(err.response?.data?.msg || err.message);
    }
  };

  return (
    <div className="card p-3">
      <h4>Reset Password</h4>
      {step === 1 && (
        <>
          <input className="form-control mb-2" placeholder="Registered email" value={email} onChange={e=>setEmail(e.target.value)} />
          <button className="btn btn-primary" onClick={requestReset}>Request Reset Code</button>
        </>
      )}
      {step === 2 && (
        <>
          <input className="form-control mb-2" placeholder="Reset code" value={code} onChange={e=>setCode(e.target.value)} />
          <input className="form-control mb-2" placeholder="New password" type="password" value={newPw} onChange={e=>setNewPw(e.target.value)} />
          <button className="btn btn-primary" onClick={doReset}>Reset Password</button>
        </>
      )}
      {msg && <div className="alert alert-info mt-2">{msg}</div>}
    </div>
  );
}