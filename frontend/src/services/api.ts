import axios from "axios";

const BASE_URL = import.meta.env.VITE_BACKEND_URL || "http://localhost:8000";

const api = axios.create({
  baseURL: BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
  timeout: 30000,
});

export const setAuthToken = (token: string | null) => {
  if (token) {
    api.defaults.headers.common["Authorization"] = `Bearer ${token}`;
  } else {
    delete api.defaults.headers.common["Authorization"];
  }
};

export interface PredictRequest {
  description: string;
}

export interface ExplainFeature {
  term: string;
  tfidf_weight: number;
  model_importance: number;
  contribution: number;
}

export interface ExplainKeyword {
  keyword: string;
  category: string;
  boost: string;
}

export interface ExplainResponse {
  top_features: ExplainFeature[];
  keyword_matches: ExplainKeyword[];
  auth_context: string;
  base_probability: number;
  boost_applied: boolean;
  final_risk: string;
  final_confidence: number;
}

export interface PredictResponse {
  risk: "HIGH" | "MEDIUM" | "LOW";
  confidence: number;
  cvss_predicted?: number;
  anomalous: boolean;
  anomaly_score: number;
  explanation?: ExplainResponse;
}

export interface CVEItem {
  cve_id: string;
  description?: string;
  risk: "HIGH" | "MEDIUM" | "LOW";
  confidence: number;
  anomalous: boolean;
}

export interface HealthResponse {
  status: string;
  models_loaded: boolean;
}

export interface MetaResponse {
  model_name: string;
  version: string;
  risk_levels: string[];
  features: string[];
  thresholds: {
    high_risk: string;
    medium_risk: string;
    low_risk: string;
  };
}

export interface HistoryStats {
  total_predictions: number;
  risk_distribution: {
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
}

export interface HistoryRecord extends PredictResponse {
  id: number;
  cve_id: string | null;
  description: string;
  source: string;
  created_at: string;
}

export interface HistoryResponse {
  stats: HistoryStats;
  records: HistoryRecord[];
}

export interface User {
  id: number;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
}

export interface Token {
  access_token: string;
  token_type: string;
}

export const registerUser = async (data: any): Promise<User> => {
  const response = await api.post<User>("/api/register", data);
  return response.data;
};

export const loginUser = async (data: any): Promise<Token> => {
  // OAuth2PasswordRequestForm requires form data
  const formData = new URLSearchParams();
  formData.append("username", data.username);
  formData.append("password", data.password);
  
  const response = await api.post<Token>("/api/login", formData, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" }
  });
  return response.data;
};

export const getMe = async (): Promise<User> => {
  const response = await api.get<User>("/api/users/me");
  return response.data;
};

export const predictRisk = async (data: PredictRequest): Promise<PredictResponse> => {
  const response = await api.post<PredictResponse>("/predict", data);
  return response.data;
};

export const explainCve = async (data: PredictRequest): Promise<ExplainResponse> => {
  const response = await api.post<ExplainResponse>("/api/explain", data);
  return response.data;
};

export const getHistory = async (limit = 50, riskLevel?: string): Promise<HistoryResponse> => {
  const params: any = { limit };
  if (riskLevel) params.risk_level = riskLevel;
  const response = await api.get<HistoryResponse>("/api/history", { params });
  return response.data;
};

export const getExportUrl = (type: "csv" | "pdf", limit = 100) => {
  return `${BASE_URL}/api/export/${type}?limit=${limit}`;
};

export const fetchLatestCVEs = async (daysBack = 3, maxResults = 10): Promise<CVEItem[]> => {
  const response = await api.get<CVEItem[]>("/predict/latest-cves", {
    params: { days_back: daysBack, max_results: maxResults },
  });
  return response.data;
};

export const getHealth = async (): Promise<HealthResponse> => {
  const response = await api.get<HealthResponse>("/health");
  return response.data;
};

export const getMeta = async (): Promise<MetaResponse> => {
  const response = await api.get<MetaResponse>("/meta");
  return response.data;
};

export default api;
