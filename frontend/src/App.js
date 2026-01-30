
import React from "react";
import { Routes, Route } from "react-router-dom";
import Navbar from "./components/Navbar";
import Landing from "./components/Landing";
import Register from "./components/Register";
import Login from "./components/Login";
import TOTPVerify from "./components/TOTPVerify";
import Dashboard from "./components/Dashboard";
import AdminPanel from "./components/AdminPanel";
import AuditorPanel from "./components/AuditorPanel";
import Results from "./components/Results";
import ResetPassword from "./components/ResetPassword";

function App() {
  return (
    <>
      <Navbar />
      <div className="container mt-4">
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/register" element={<Register />} />
          <Route path="/login" element={<Login />} />
          <Route path="/verify-totp" element={<TOTPVerify />} />
          <Route path="/reset-password" element={<ResetPassword />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/admin" element={<AdminPanel />} />
          <Route path="/auditor" element={<AuditorPanel />} />
          <Route path="/results/:id" element={<Results />} />
        </Routes>
      </div>
    </>
  );
}

export default App;