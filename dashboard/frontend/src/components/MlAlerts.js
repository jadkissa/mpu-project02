import React, { useState } from "react";
import "./Tables.css";

const PORT_SERVICES = {
  8080: "WebGoat",
  9090: "WebGoat-WS",
  8000: "API",
  3000: "Frontend",
  5432: "PostgreSQL",
  5678: "n8n",
};

function MlAlerts({ alerts = [] }) {  
  const [filterModel, setFilterModel] = useState("");

  const alertsArray = Array.isArray(alerts) ? alerts : [];

  if (!alertsArray || alertsArray.length === 0) {
    return (
      <div className="table-loading">
        <div className="spinner"></div>
        <p>Loading alerts...</p>
      </div>
    );
  }

  const getProtocolName = (proto) => {
    const protocols = { 6: "TCP", 17: "UDP", 1: "ICMP" };
    return protocols[proto] || proto;
  };

  const getServiceName = (port) => {
    return PORT_SERVICES[port] ? `${port} (${PORT_SERVICES[port]})` : port;
  };

  const scorePercent = (score) => {
    if (score == null || Number.isNaN(Number(score))) return 0;
    const n = Number(score);
    if (n >= 0) return 0;
    const percent = Math.min(100, Math.round(Math.abs(n) * 200));
    return percent;
  };

  const scoreBarColor = (percent) => {
    if (percent >= 80) return "var(--danger)";
    if (percent >= 50) return "var(--warning)";
    return "var(--accent-purple)";
  };

  const filtered = alertsArray.filter((a) => {
    if (filterModel === "") return true;
    return (a.model_version || "")
      .toLowerCase()
      .includes(filterModel.toLowerCase());
  });

  return (
    <div>
      <div className="table-filters">
        <input
          className="filter-input"
          type="text"
          placeholder="Filter by model version..."
          value={filterModel}
          onChange={(e) => setFilterModel(e.target.value)}
        />
        <span className="filter-count">{filtered.length} alerts</span>
      </div>

      <div className="table-container">
        {filtered.length === 0 ? (
          <div className="empty-state">
            <svg
              width="48"
              height="48"
              viewBox="0 0 24 24"
              fill="none"
              stroke="#718096"
              strokeWidth="1.5"
            >
              <circle cx="12" cy="12" r="10" />
              <path d="M8 14s1.5 2 4 2 4-2 4-2" />
              <line x1="9" y1="9" x2="9.01" y2="9" />
              <line x1="15" y1="9" x2="15.01" y2="9" />
            </svg>
            <p>No alerts detected</p>
            <span>All clear! No anomalies reported.</span>
          </div>
        ) : (
          <table className="modern-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Port</th>
                <th>Protocol</th>
                <th>Layer</th>
                <th>Anomaly Score</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((a) => {
                const pct = scorePercent(a.anomaly_score);
                return (
                  <tr key={a.id || Math.random()} className="table-row">
                    <td className="time-cell">
                      {a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : "N/A"}
                    </td>
                    <td className="ip-cell">
                      <code>{a.ip_src || "N/A"}</code>
                    </td>
                    <td className="ip-cell">
                      <code>{a.ip_dst || "N/A"}</code>
                    </td>
                    <td className="port-cell">
                      <span className="port-badge">
                        {getServiceName(a.layer4_dport)}
                      </span>
                    </td>
                    <td>
                      <span className="protocol-badge">
                        {getProtocolName(a.ip_proto)}
                      </span>
                    </td>
                    <td className="signature-cell">{a.detection_layer || "N/A"}</td>
                    <td>
                      <div className="confidence-bar">
                        <div className="confidence-track">
                          <div
                            className="confidence-fill"
                            style={{
                              width: `${Math.min(pct, 100)}%`,
                              background: scoreBarColor(pct),
                            }}
                          />
                        </div>
                        <span className="confidence-text">{pct}%</span>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

export default MlAlerts;