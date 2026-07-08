import React from "react";
import "./StatsCards.css";

function StatCard({ title, value, color, icon }) {
  return (
    <div className="stat-card" style={{ borderTop: `3px solid ${color}` }}>
      <div
        className="stat-icon"
        style={{ background: `${color}20`, color: color }}
      >
        {icon}
      </div>
      <div className="stat-content">
        <h2 className="stat-value" style={{ color: color }}>
          {value?.toLocaleString() || 0}
        </h2>
        <p className="stat-title">{title}</p>
      </div>
    </div>
  );
}

function StatsCards({ stats }) {
  if (!stats) {
    return (
      <div className="stats-grid">
        {[1, 2, 3].map((i) => (
          <div key={i} className="stat-card skeleton">
            <div className="skeleton-icon"></div>
            <div className="skeleton-text"></div>
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="stats-grid">
      <StatCard
        title="Snort Alerts"
        value={stats.total_snort_alerts}
        color="#ef4444"
        icon={
          <svg
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
            <line x1="12" y1="9" x2="12" y2="13" />
            <line x1="12" y1="17" x2="12.01" y2="17" />
          </svg>
        }
      />
      <StatCard
        title="High Threats"
        value={stats.high_threats}
        color="#dc2626"
        icon={
          <svg
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <polygon points="12 2 22 8.5 22 15.5 12 22 2 15.5 2 8.5 12 2" />
            <line x1="12" y1="22" x2="12" y2="15.5" />
            <polyline points="22 8.5 12 15.5 2 8.5" />
          </svg>
        }
      />
      <StatCard
        title="Medium Threats"
        value={stats.medium_threats}
        color="#f59e0b"
        icon={
          <svg
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="8" x2="12" y2="12" />
            <line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
        }
      />
    </div>
  );
}

export default StatsCards;
