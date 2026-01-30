import React, { useEffect, useState } from "react";
import api from "../api";
import { useParams } from "react-router-dom";

export default function Results() {
  const { id } = useParams();
  const [info, setInfo] = useState(null);

  useEffect(() => {
    if (!id) return;
    const fetch = async () => {
      try {
        const r = await api.get(`/public_election_info/${id}`);
        setInfo(r.data);
      } catch (err) {
        setInfo({ error: err.response?.data?.msg || err.message });
      }
    };
    fetch();
  }, [id]);

  return (
    <div>
      <h4>Election Results</h4>
      {info ? <pre>{JSON.stringify(info, null, 2)}</pre> : <div>Loading...</div>}
    </div>
  );
}