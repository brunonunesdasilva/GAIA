// src/api.js
// Configuração axios com suporte a JWT via httpOnly Cookies
// SEGURANÇA: httpOnly Cookies previnem XSS (inacessíveis via JavaScript)
// O navegador automaticamente envia cookies com cada requisição
import axios from "axios";

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "https://gaia-2spq.onrender.com").replace(/\/$/, "");
const API_ROOT = `${API_BASE_URL}/api`;

// ============================================================
// UTILIDADE: Extrair valor de cookie pelo nome
// ============================================================
function getCookie(name) {
  let cookieValue = null;
  if (document.cookie && document.cookie !== '') {
    const cookies = document.cookie.split(';');
    for (let i = 0; i < cookies.length; i++) {
      const cookie = cookies[i].trim();
      if (cookie.substring(0, name.length + 1) === (name + '=')) {
        cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
        break;
      }
    }
  }
  return cookieValue;
}

const api = axios.create({
  baseURL: `${API_ROOT}/`,
  withCredentials: true,  //  Envia cookies automaticamente (httpOnly)
});

// ============================================================
// INTERCEPTADOR: Request - Adicionar X-CSRFToken header
// ============================================================
// Django requer token CSRF em POST/PUT/DELETE/PATCH
// Se houver JWT no Authorization header, Django o isenta automaticamente
// Mas é boa prática enviar o token de qualquer forma (defense-in-depth)
api.interceptors.request.use((config) => {
  const csrfToken = getCookie('csrftoken');
  if (csrfToken) {
    config.headers['X-CSRFToken'] = csrfToken;
  }
  return config;
});

// ============================================================
// INTERCEPTADOR: Response - Trata erros de autenticação
// ============================================================

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    // Se receber 401 (token expirado), tentar refresh automático
    if (error.response?.status === 401) {
      const originalRequest = error.config;
      
      if (!originalRequest._retry) {
        originalRequest._retry = true;
        
        try {
          console.log('[API]  Token expirado, tentando refresh...');
          
          // Backend vai renovar o refresh_token cookie e retornar novo access_token
          await axios.post(
            `${API_ROOT}/token/refresh-cookie/`,
            {},
            { withCredentials: true }
          );
          
          // Retry request original com novo token
          console.log('[API]  Token renovado, retentando requisição...');
          return api(originalRequest);
        } catch (refreshError) {
          // Se refresh falhar, fazer logout
          console.error('[API]  Refresh falhou - fazendo logout');
          localStorage.removeItem("user");
          window.location.href = "/login";
          return Promise.reject(refreshError);
        }
      }
    }

    return Promise.reject(error);
  }
);

export default api;
