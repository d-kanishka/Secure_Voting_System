
import React from "react";
import { Link } from "react-router-dom";

export default function Landing() {
  return (
    <div className="p-5">
    <center><h1>Welcome to Student E‑Voting !</h1></center>
      <p className="lead">
      </p>
      <div className="mt-3"> <center>
        <Link to="/register" className="btn btn-primary me-2">Register</Link>
        <Link to="/login" className="btn btn-outline-primary">Login</Link></center>
      </div>
        
      
    </div>
  );
}