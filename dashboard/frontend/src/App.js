import React, { useState, useEffect } from "react";
import StatsCards from "./components/StatsCards";
import SnortAlerts from "./components/SnortAlerts";
import ProtocolChart from "./components/ProtocolChart";
import { getSummary, getSnortAlerts, getByProtocol } from "./api";
import "./App.css";

function App() {
  const [stats, setStats] = useState(null);
  const [snort, setSnort] = useState([]);
  const [protocols, setProtocols] = useState([]);
  const [lastUpdate, setLastUpdate] = useState(new Date());

  const fetchData = async () => {
    try {
      const [s, sn, pr] = await Promise.all([
        getSummary(),
        getSnortAlerts(),
        getByProtocol(),
      ]);
      setStats(s.data);
      setSnort(sn.data.data);
      setProtocols(pr.data.data);
      setLastUpdate(new Date());
    } catch (err) {
      console.error("API error:", err);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 500);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="dashboard">
      {/* Header */}
      <header className="header">
        <div className="header-left">
          <div className="logo-container">
            <svg className="logo-icon" viewBox="0 0 50 50" fill="none">
              <circle cx="25" cy="25" r="24" stroke="#00d4ff" strokeWidth="2" />
              <path
                d="M15 30 L25 10 L35 30"
                stroke="#00d4ff"
                strokeWidth="2"
                fill="none"
              />
              <circle
                cx="25"
                cy="25"
                r="8"
                stroke="#00d4ff"
                strokeWidth="1.5"
                fill="none"
                opacity="0.5"
              />
              <circle cx="25" cy="25" r="4" fill="#00d4ff" opacity="0.3">
                <animate
                  attributeName="r"
                  values="3;5;3"
                  dur="2s"
                  repeatCount="indefinite"
                />
              </circle>
            </svg>
          </div>
          <div>
            <h1 className="dashboard-title">M-NIDS</h1>
            <p className="dashboard-subtitle">
              Network Intrusion Detection System
            </p>
          </div>
        </div>
        <div className="header-right">
          <div className="status-indicator">
            <span className="status-dot"></span>
            <span>Live Monitoring</span>
          </div>
          <div className="update-time">
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <circle cx="12" cy="12" r="10" />
              <polyline points="12 6 12 12 16 14" />
            </svg>
            <span>{lastUpdate.toLocaleTimeString()}</span>
          </div>
        </div>
      </header>

      {/* Stats Cards */}
      <section className="stats-section">
        <StatsCards stats={stats} />
      </section>

      {/* Charts + Alerts */}
      <section className="charts-alerts-section">
        <div className="card chart-card">
          <div className="card-header">
            <svg
              width="20"
              height="20"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <rect x="18" y="3" width="4" height="18" />
              <rect x="11" y="8" width="4" height="13" />
              <rect x="4" y="13" width="4" height="8" />
            </svg>
            <h3>Alerts by Protocol</h3>
          </div>
          <ProtocolChart data={protocols} />
        </div>

        <div className="card">
          <div className="card-header">
            <svg
              width="20"
              height="20"
              viewBox="0 0 24 24"
              fill="none"
              stroke="#e74c3c"
              strokeWidth="2"
            >
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
              <line x1="12" y1="9" x2="12" y2="13" />
              <line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
            <h3>Snort Alerts</h3>
            <span className="badge badge-red">{snort.length}</span>
          </div>
          <SnortAlerts alerts={snort} />
        </div>
      </section>

      {/* Footer */}
      <footer className="footer">
        <p>
          M-NIDS - Manara Private University - 01 - Graduation Project •
          Real-time Network Monitoring • {new Date().getFullYear()}
        </p>
      </footer>
    </div>
  );
}

export default App;
