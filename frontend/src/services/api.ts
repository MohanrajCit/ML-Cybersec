import axios from "axios";

const BASE_URL = import.meta.env.VITE_BACKEND_URL || "http://localhost:8000";

const api = axios.create({
  baseURL: BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
  timeout: 30000,
});

export interface PredictRequest {
  description: string;
}

export interface PredictResponse {
  risk: "HIGH" | "MEDIUM" | "LOW";
  confidence: number;
  anomalous: boolean;
  anomaly_score: number;
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

export const predictRisk = async (data: PredictRequest): Promise<PredictResponse> => {
  const response = await api.post<PredictResponse>("/predict", data);
  return response.data;
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

