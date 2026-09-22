/**
 * NEXUS-FORECAST Centralized Offline API Client.
 * Provides resilient, typed HTTP communication with backend/app/main.py.
 * Handles validation errors, timeouts, offline indicators, and stateful error rendering.
 */

class NexusAPIError extends Error {
  constructor(message, status, detail = null) {
    super(message);
    this.name = "NexusAPIError";
    this.status = status;
    this.detail = detail;
  }
}

/**
 * Robust fetch wrapper with JSON parsing, HTTP status normalization, and timeout handling.
 * @param {string} url - Target URL path
 * @param {object} [options] - Standard Fetch options
 * @returns {Promise<any>} Parsed response data
 */
async function apiFetch(url, options = {}) {
  const defaultHeaders = {
    "Accept": "application/json",
  };

  if (options.body && typeof options.body === "string") {
    defaultHeaders["Content-Type"] = "application/json";
  }

  const mergedOptions = {
    ...options,
    headers: {
      ...defaultHeaders,
      ...(options.headers || {}),
    },
  };

  try {
    const response = await fetch(url, mergedOptions);

    // Handle Content-Type
    const contentType = response.headers.get("content-type") || "";
    let data;

    if (contentType.includes("application/json")) {
      try {
        data = await response.json();
      } catch (e) {
        data = null;
      }
    } else {
      data = await response.text();
    }

    if (!response.ok) {
      let errorMsg = `HTTP ${response.status}: Request failed`;
      let errorDetail = data;

      if (data && typeof data === "object") {
        if (data.detail) {
          errorMsg = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
        } else if (data.message) {
          errorMsg = data.message;
        }
      }

      if (response.status === 400) {
        throw new NexusAPIError(`Validation Error: ${errorMsg}`, 400, errorDetail);
      } else if (response.status === 404) {
        throw new NexusAPIError(`Resource Unavailable: ${errorMsg}`, 404, errorDetail);
      } else if (response.status === 500) {
        throw new NexusAPIError(`Backend Pipeline Error: ${errorMsg}`, 500, errorDetail);
      } else {
        throw new NexusAPIError(errorMsg, response.status, errorDetail);
      }
    }

    return data;
  } catch (err) {
    if (err instanceof NexusAPIError) {
      throw err;
    }
    // Network failures or offline rejection
    throw new NexusAPIError(
      "Local inference service is not running or unreachable on http://127.0.0.1:8000.",
      0,
      err.message
    );
  }
}

/**
 * Structured API Client for NEXUS-Forecast
 */
const NexusAPI = {
  // System Health & Status
  getHealth: () => apiFetch("/api/health"),
  getStatus: () => apiFetch("/api/status"),

  // Datasets & Scenarios
  getDatasets: () => apiFetch("/api/datasets"),
  getDatasetAnalysis: () => apiFetch("/api/dataset_analysis"),
  getScenarios: () => apiFetch("/api/scenarios"),

  // Dashboard Overview
  getDashboardOverview: (params = {}) => {
    const q = new URLSearchParams();
    if (params.dataset) q.append("dataset", params.dataset);
    if (params.scenario) q.append("scenario", params.scenario);
    if (params.time_range) q.append("time_range", params.time_range);
    return apiFetch(`/api/dashboard/overview?${q.toString()}`);
  },

  // Live Inference Pass
  runInference: (payload) => {
    return apiFetch("/api/inference/run", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  // Upload File Inference Pass (PCAP, CSV, Parquet)
  uploadAndInfer: async (file, options = {}) => {
    const formData = new FormData();
    formData.append("file", file);
    if (options.explain_mode) formData.append("explain_mode", options.explain_mode);
    if (options.enrich_mode) formData.append("enrich_mode", options.enrich_mode);

    try {
      const response = await fetch("/api/inference/upload", {
        method: "POST",
        body: formData,
      });

      const data = await response.json();
      if (!response.ok) {
        const errorMsg = (typeof data?.detail === "string" ? data.detail : JSON.stringify(data?.detail)) || `HTTP ${response.status}: Upload evaluation failed`;
        throw new NexusAPIError(errorMsg, response.status, data);
      }
      return data;
    } catch (err) {
      if (err instanceof NexusAPIError) throw err;
      throw new NexusAPIError(`File evaluation failed: ${err.message}`, 0, err);
    }
  },

  // Forecast History & Listing
  getForecasts: (filters = {}) => {
    const q = new URLSearchParams();
    if (filters.decision && filters.decision !== "ALL") q.append("decision", filters.decision);
    if (filters.stage && filters.stage !== "ALL") q.append("stage", filters.stage);
    if (filters.horizon && filters.horizon !== "ALL") q.append("horizon", filters.horizon);
    if (filters.dataset) q.append("dataset", filters.dataset);
    if (filters.scenario) q.append("scenario", filters.scenario);
    if (filters.limit) q.append("limit", filters.limit);
    const qs = q.toString();
    return apiFetch(qs ? `/api/forecasts?${qs}` : "/api/forecasts");
  },

  getForecastDetail: (forecastId) => {
    return apiFetch(`/api/forecasts/${encodeURIComponent(forecastId)}`);
  },

  getForecastKnowledge: (forecastId) => {
    return apiFetch(`/api/forecasts/${encodeURIComponent(forecastId)}/knowledge`);
  },

  // Explainability
  getExplanation: (forecastId) => {
    if (!forecastId) return apiFetch("/api/explanations");
    return apiFetch(`/api/explanations/${encodeURIComponent(forecastId)}`);
  },

  // Knowledge Enrichment (MITRE / CAPEC)
  getMitreKnowledge: (stage) => {
    const q = stage ? `?stage=${encodeURIComponent(stage)}` : "";
    return apiFetch(`/api/knowledge/mitre${q}`);
  },

  getCapecKnowledge: (query, limit = 100) => {
    const q = new URLSearchParams();
    if (query) q.append("query", query);
    if (limit) q.append("limit", limit);
    return apiFetch(`/api/knowledge/capec?${q.toString()}`);
  },

  getUnifiedKnowledge: (stage = "DISCOVERY") => {
    const q = stage ? `?stage=${encodeURIComponent(stage)}` : "";
    return apiFetch(`/api/knowledge${q}`);
  },

  // Research Reports & Manifests
  getReports: () => apiFetch("/api/reports"),
  getReportDetail: (reportId) => apiFetch(`/api/reports/${encodeURIComponent(reportId)}`),
};

/**
 * UI State Helpers for LOADING, EMPTY, and ERROR transitions
 */
const NexusUI = {
  renderLoading: (container, label = "Loading data from local inference pipeline...") => {
    if (!container) return;
    container.innerHTML = `
      <div class="ui-state-container ui-state-loading" style="padding:24px; text-align:center; color:var(--text-muted); font-size:12px;">
        <span class="system-status-indicator pulse" style="display:inline-block; margin-right:8px;"></span>
        <span>${label}</span>
      </div>
    `;
  },

  renderEmpty: (container, message = "No records found matching the active criteria.") => {
    if (!container) return;
    container.innerHTML = `
      <div class="ui-state-container ui-state-empty" style="padding:32px; text-align:center; color:var(--text-muted); font-size:12px;">
        <p style="margin-bottom:6px;">— EMPTY DATASET —</p>
        <span style="color:var(--text-secondary);">${message}</span>
      </div>
    `;
  },

  renderError: (container, errorMsg, onRetry = null) => {
    if (!container) return;
    const retryBtnHtml = onRetry
      ? `<button class="btn-secondary btn-retry" style="margin-top:10px; padding:4px 10px; font-size:11px;">Retry</button>`
      : "";

    container.innerHTML = `
      <div class="ui-state-container ui-state-error" style="padding:20px; border:1px solid var(--semantic-attack); border-radius:3px; background:rgba(201, 74, 74, 0.05); margin:12px 0;">
        <div style="color:var(--semantic-attack); font-weight:600; font-size:12px; margin-bottom:4px;">OPERATIONAL ALERT</div>
        <div style="color:var(--text-primary); font-size:12px;">${errorMsg}</div>
        ${retryBtnHtml}
      </div>
    `;

    if (onRetry) {
      const btn = container.querySelector(".btn-retry");
      if (btn) btn.addEventListener("click", onRetry);
    }
  }
};
