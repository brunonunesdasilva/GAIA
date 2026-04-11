import axios from "axios";

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "https://gaia-2spq.onrender.com").replace(/\/$/, "");
const API_URL = `${API_BASE_URL}/api`;

export async function loginSecureCPF(cpf, password, captchaToken = null, captchaAnswer = null) {
  try {
    const payload = {
      cpf,
      password,
    };

    if (captchaToken && captchaAnswer) {
      payload.captcha_token = captchaToken;
      payload.captcha_answer = captchaAnswer;
    }

    const response = await axios.post(`${API_URL}/login/cpf/secure/`, payload, {
      withCredentials: true,
    });

    return response.data;
  } catch (error) {
    throw error;
  }
}

export async function login(cpf, password, captchaToken = null, captchaAnswer = null) {
  try {
    const payload = {
      cpf,
      password,
    };

    if (captchaToken && captchaAnswer) {
      payload.captcha_token = captchaToken;
      payload.captcha_answer = captchaAnswer;
    }

    const response = await axios.post(`${API_URL}/login/cpf/secure/`, payload, {
      withCredentials: true,
    });

    return response.data;
  } catch (error) {
    throw error;
  }
}

export async function loginWithCNPJ(cnpj, password, captchaToken = null, captchaAnswer = null) {
  try {
    const payload = {
      cnpj,
      password,
    };

    if (captchaToken && captchaAnswer) {
      payload.captcha_token = captchaToken;
      payload.captcha_answer = captchaAnswer;
    }

    const response = await axios.post(`${API_URL}/login/cnpj/secure/`, payload, {
      withCredentials: true,
    });

    return response.data;
  } catch (error) {
    throw error;
  }
}

// Função para refresh token (opcional)
export async function refreshToken(refresh) {
  try {
    const response = await axios.post(`${API_URL}/token/refresh/`, {
      refresh
    });
    return response.data;
  } catch (error) {
    console.error("Erro ao refresh token:", error);
    throw error;
  }
}

export async function getCurrentUser(token) {
  try {
    const response = await axios.get(`${API_URL}/user-info/`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    return response.data;
  } catch (error) {
    console.error("Erro ao buscar dados do usuário:", error);
    throw error;
  }
}