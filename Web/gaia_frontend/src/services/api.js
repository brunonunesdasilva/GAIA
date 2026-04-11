import axios from "axios";

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "https://gaia-2spq.onrender.com").replace(/\/$/, "");

const api = axios.create({
  baseURL: `${API_BASE_URL}/api`,
});

export default api;
