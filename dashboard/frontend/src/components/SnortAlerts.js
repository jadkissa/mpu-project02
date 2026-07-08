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

function SnortAlerts({ alerts }) {
  const [filterPriority, setFilterPriority] = useState("all");
  const [filterSignature, setFilterSignature] = useState("");

  if (!alerts) {
    return (
      <div className="table-loading">
        <div className="spinner"></div>
        <p>Loading alerts...</p>
      </div>
    );
  }

  const getPriorityBadge = (priority) => {
    const config = {
      1: { label: "High", className: "priority-high" },
      2: { label: "Medium", className: "priority-medium" },
      3: { label: "Low", className: "priority-low" },
    };
    const c = config[priority] || { label: "Low", className: "priority-low" };
    return <span className={`priority-badge ${c.className}`}>{c.label}</span>;
  };

  const getProtocolName = (proto) => {
    const protocols = { 6: "TCP", 17: "UDP", 1: "ICMP" };
    return protocols[proto] || proto;
  };

  const getServiceName = (port) => {
    return PORT_SERVICES[port] ? `${port} (${PORT_SERVICES[port]})` : port;
  };

  const filtered = alerts.filter((a) => {
    const priorityMatch =
      filterPriority === "all" || String(a.priority) === filterPriority;
    const sigMatch =
      filterSignature === "" ||
      (a.sig_name || "").toLowerCase().includes(filterSignature.toLowerCase());
    return priorityMatch && sigMatch;
  });

  return (
    <div>
      {/* Filters */}
      <div className="table-filters">
        <select
          className="filter-select"
          value={filterPriority}
          onChange={(e) => setFilterPriority(e.target.value)}
        >
          <option value="all">All Priorities</option>
          <option value="1">High</option>
          <option value="2">Medium</option>
          <option value="3">Low</option>
        </select>
        <input
          className="filter-input"
          type="text"
          placeholder="Filter by signature..."
          value={filterSignature}
          onChange={(e) => setFilterSignature(e.target.value)}
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
            <p>No Snort alerts detected</p>
            <span>All clear! Network is safe.</span>
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
                <th>Signature</th>
                <th>Priority</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((a) => (
                <tr key={`${a.sid}-${a.cid}`} className="table-row">
                  <td className="time-cell">
                    {new Date(a.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="ip-cell">
                    <code>{a.ip_src}</code>
                  </td>
                  <td className="ip-cell">
                    <code>{a.ip_dst}</code>
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
                  <td className="signature-cell">{a.sig_name}</td>
                  <td>{getPriorityBadge(a.priority)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

export default SnortAlerts;
