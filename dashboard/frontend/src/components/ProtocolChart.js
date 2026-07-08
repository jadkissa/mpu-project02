import React from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

const COLORS = [
  "#00d4ff",
  "#8b5cf6",
  "#10b981",
  "#f59e0b",
  "#ef4444",
  "#ec4899",
];

function CustomTooltip({ active, payload, label }) {
  if (active && payload && payload.length) {
    return (
      <div
        style={{
          background: "#1a1f2e",
          border: "1px solid #2d3748",
          borderRadius: "8px",
          padding: "12px",
          boxShadow: "0 4px 12px rgba(0,0,0,0.4)",
        }}
      >
        <p style={{ color: "#a0aec0", margin: 0, fontSize: "0.8rem" }}>
          Protocol: <strong style={{ color: "#e2e8f0" }}>{label}</strong>
        </p>
        <p
          style={{
            color: "#00d4ff",
            margin: "4px 0 0",
            fontSize: "1.2rem",
            fontWeight: 700,
          }}
        >
          {payload[0].value} alerts
        </p>
      </div>
    );
  }
  return null;
}

function ProtocolChart({ data }) {
  if (!data || data.length === 0) {
    return (
      <div style={{ textAlign: "center", padding: "40px", color: "#718096" }}>
        <p>No protocol data available</p>
      </div>
    );
  }

  return (
    <div style={{ width: "100%", height: 300 }}>
      <ResponsiveContainer>
        <BarChart data={data} barSize={40}>
          <CartesianGrid strokeDasharray="3 3" stroke="#2d3748" />
          <XAxis
            dataKey="protocol"
            stroke="#718096"
            tick={{ fill: "#a0aec0", fontSize: 12 }}
          />
          <YAxis stroke="#718096" tick={{ fill: "#a0aec0", fontSize: 12 }} />
          <Tooltip content={<CustomTooltip />} />
          <Bar dataKey="count" radius={[4, 4, 0, 0]}>
            {data.map((entry, index) => (
              <Cell
                key={`cell-${index}`}
                fill={COLORS[index % COLORS.length]}
                fillOpacity={0.8}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export default ProtocolChart;
