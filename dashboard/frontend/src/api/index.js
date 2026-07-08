import axios from "axios";

const API = axios.create({
  baseURL: "/api",
});

export const getSnortAlerts = () => API.get("/alerts/snort");
export const getSummary = () => API.get("/stats/summary");
export const getByProtocol = () => API.get("/stats/by-protocol");
