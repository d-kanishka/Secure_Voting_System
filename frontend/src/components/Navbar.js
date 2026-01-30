
import React from "react";
import { Link, useNavigate } from "react-router-dom";
import { clearToken, decodedUser, getTempToken } from "../auth";

export default function Navbar() {
  const navigate = useNavigate();
  const user = decodedUser();

  const logout = () => {
    clearToken();
    sessionStorage.removeItem("temp_token");
    navigate("/login");
  };

  const temp = getTempToken();

  return (
    <nav className="navbar navbar-expand-lg navbar-light bg-light">
      <div className="container-fluid">
        <Link className="navbar-brand" to="/">Campus E-Voting</Link>
        <div className="collapse navbar-collapse">
          <ul className="navbar-nav me-auto">
            {user && user.role === "admin" && <li className="nav-item"><Link className="nav-link" to="/admin">Admin</Link></li>}
            {user && user.role === "auditor" && <li className="nav-item"><Link className="nav-link" to="/auditor">Auditor</Link></li>}
            <li className="nav-item"><Link className="nav-link" to="/dashboard">Dashboard</Link></li>
          </ul>
          <ul className="navbar-nav">
            {user ? (
              <>
                <li className="nav-item nav-link">Hi, {user.username}</li>
                <li className="nav-item"><button className="btn btn-outline-secondary" onClick={logout}>Logout</button></li>
              </>
            ) : temp ? (
              <li className="nav-item nav-link">Pending MFA — complete verification</li>
            ) : (
              <>
                <li className="nav-item"><Link className="nav-link" to="/login">Login</Link></li>
                <li className="nav-item"><Link className="nav-link" to="/register">Register</Link></li>
              </>
            )}
          </ul>
        </div>
      </div>
    </nav>
  );
}