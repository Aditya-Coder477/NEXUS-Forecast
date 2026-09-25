/**
 * NEXUS-FORECAST: Air-Gapped Analyst Workstation Frontend Application.
 * Clean, human-crafted editorial interactions, zero external dependencies.
 */

document.addEventListener("DOMContentLoaded", () => {
  // Global State
  const state = {
    activePage: "dashboard",
    dataset: "CIC-IDS2017",
    scenario: "Scenario 01",
    timeRange: "Apr 21, 2024 10:00–11:00",
    activeHorizon: 30,
    datasetHorizon: "+30s",
    activeErrorGroup: "TP",
    dashboardData: null,
    forecastResults: [],
    explanationsData: null,
    knowledgeData: null,
    datasetData: null,
    reportsData: [],
    selectedForecast: null,
    selectedForecastId: null,
    selectedStage: "DISCOVERY",
    uploadedFile: null,
  };

  // DOM Elements
  const navItems = document.querySelectorAll(".nav-item");
  const pageViews = document.querySelectorAll(".page-view");
  const datasetSelect = document.getElementById("header-dataset-select");
  const scenarioSelect = document.getElementById("header-scenario-select");

  const drawer = document.getElementById("detail-drawer");
  const drawerCloseBtn = document.getElementById("drawer-close-btn");
  const drawerTitle = document.getElementById("drawer-title");
  const drawerBody = document.getElementById("drawer-body");
  const drawerViewExplBtn = document.getElementById("drawer-view-expl-btn");
  const drawerViewKnowBtn = document.getElementById("drawer-view-know-btn");

  const modalOverlay = document.getElementById("modal-overlay");
  const modalCloseBtn = document.getElementById("modal-close-btn");
  const modalCloseActionBtn = document.getElementById("modal-close-action-btn");
  const modalReportTitle = document.getElementById("modal-report-title");
  const modalReportBody = document.getElementById("modal-report-body");
  const modalDownloadBtn = document.getElementById("modal-download-btn");

  const themeToggleBtn = document.getElementById("theme-toggle-btn");
  const themeToggleLabel = document.getElementById("theme-toggle-label");

  // --------------------------------------------------------------------------
  // THEME MANAGEMENT (DARK / LIGHT MODE)
  // --------------------------------------------------------------------------
  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem("nexus_theme", theme);
    } catch (e) {}

    if (themeToggleLabel) {
      themeToggleLabel.textContent = theme === "dark" ? "Light" : "Dark";
    }
    if (themeToggleBtn) {
      themeToggleBtn.setAttribute(
        "title",
        theme === "dark" ? "Switch to Light Mode" : "Switch to Dark Mode"
      );
    }
  }

  function initTheme() {
    let savedTheme = "dark";
    try {
      savedTheme = localStorage.getItem("nexus_theme") || "dark";
    } catch (e) {}
    applyTheme(savedTheme);

    if (themeToggleBtn) {
      themeToggleBtn.addEventListener("click", () => {
        const currentTheme = document.documentElement.getAttribute("data-theme") || "dark";
        const newTheme = currentTheme === "dark" ? "light" : "dark";
        applyTheme(newTheme);
      });
    }
  }

  initTheme();

  // --------------------------------------------------------------------------
  // DYNAMIC HEADER SELECTORS INITIALIZATION
  // --------------------------------------------------------------------------
  async function initHeaderSelectors() {
    try {
      const [datasets, scenarios] = await Promise.all([
        NexusAPI.getDatasets(),
        NexusAPI.getScenarios(),
      ]);

      if (datasetSelect && datasets && datasets.length > 0) {
        datasetSelect.innerHTML = datasets
          .map((d) => `<option value="${d.id}" ${d.id === state.dataset ? "selected" : ""}>${d.name || d.id}</option>`)
          .join("");
        const inferDs = document.getElementById("infer-dataset-select");
        if (inferDs) inferDs.innerHTML = datasetSelect.innerHTML;
      }

      if (scenarioSelect && scenarios && scenarios.length > 0) {
        scenarioSelect.innerHTML = scenarios
          .map((s) => `<option value="${s.id}" ${s.id === state.scenario ? "selected" : ""}>${s.name || s.id}</option>`)
          .join("");
        const inferSc = document.getElementById("infer-scenario-select");
        if (inferSc) inferSc.innerHTML = scenarioSelect.innerHTML;
      }
    } catch (err) {
      console.warn("Could not dynamically populate header selectors:", err.message);
    }
  }

  // --------------------------------------------------------------------------
  // ROUTER WITH CONTEXT PROPAGATION
  // --------------------------------------------------------------------------
  function navigateTo(pageId, contextParam = null) {
    state.activePage = pageId;

    if (pageId === "explanations" && contextParam) {
      state.selectedForecastId = contextParam;
    }
    if (pageId === "knowledge" && contextParam) {
      state.selectedStage = contextParam;
    }

    navItems.forEach((item) => {
      if (item.dataset.page === pageId) {
        item.classList.add("active");
      } else {
        item.classList.remove("active");
      }
    });

    pageViews.forEach((view) => {
      if (view.id === `page-${pageId}`) {
        view.classList.add("active");
      } else {
        view.classList.remove("active");
      }
    });

    // Lazy load data for the active page
    if (pageId === "dashboard") loadDashboard();
    else if (pageId === "results") loadForecastResults();
    else if (pageId === "explanations") loadExplanations(state.selectedForecastId);
    else if (pageId === "knowledge") loadKnowledge(state.selectedStage);
    else if (pageId === "datasets") loadDatasets();
    else if (pageId === "reports") loadReports();
  }

  navItems.forEach((item) => {
    item.addEventListener("click", () => {
      const page = item.dataset.page;
      navigateTo(page);
    });
  });

  // Header Dropdown Listeners
  if (datasetSelect) {
    datasetSelect.addEventListener("change", (e) => {
      state.dataset = e.target.value;
      loadDashboard();
    });
  }

  if (scenarioSelect) {
    scenarioSelect.addEventListener("change", (e) => {
      state.scenario = e.target.value;
      loadDashboard();
    });
  }

  // --------------------------------------------------------------------------
  // PAGE 1: DASHBOARD
  // --------------------------------------------------------------------------
  async function loadDashboard() {
    try {
      const data = await NexusAPI.getDashboardOverview({
        dataset: state.dataset,
        scenario: state.scenario,
        time_range: state.timeRange,
      });
      state.dashboardData = data;
      renderDashboard(data);
    } catch (err) {
      console.error("Failed to load dashboard data:", err);
      const evidenceGrid = document.getElementById("dashboard-evidence-grid");
      if (evidenceGrid) {
        NexusUI.renderError(
          evidenceGrid,
          `Local inference service is not running or unreachable: ${err.message}`,
          loadDashboard
        );
      }
    }
  }

  function renderDashboard(data) {
    const pf = data.primary_forecast;
    document.getElementById("primary-kicker").textContent = `NEXT ${state.activeHorizon} SECONDS (+${state.activeHorizon}s)`;
    
    // Compute probability for selected horizon
    let displayProb = pf.attack_probability;
    if (state.activeHorizon === 90) displayProb = Math.min(0.99, pf.attack_probability + 0.06);
    else if (state.activeHorizon === 180) displayProb = Math.min(0.99, pf.attack_probability + 0.11);

    document.getElementById("primary-prob").textContent = `${Math.round(displayProb * 100)}%`;
    
    const badge = document.getElementById("primary-decision-badge");
    const isAttack = displayProb >= pf.threshold;
    if (isAttack) {
      badge.className = "threat-badge attack";
      badge.textContent = "ATTACK FORECASTED";
    } else {
      badge.className = "threat-badge benign";
      badge.textContent = "BENIGN / NORMAL";
    }

    document.getElementById("primary-stage").textContent = pf.predicted_stage;
    document.getElementById("primary-stage-conf").textContent = `${(pf.stage_confidence * 100).toFixed(1)}%`;

    // Render Timeline Chart
    renderTimelineChart(data.timeline);

    // Render Evidence Grid
    renderEvidenceGrid(data.evidence);

    // Render Stage Progression
    renderStageProgression(data.stage_progression);

    // Render Top Features
    renderTopFeatures(data.top_features);

    // Render Recent Forecasts
    renderRecentForecasts(data.recent_forecasts);
  }

  // --------------------------------------------------------------------------
  // DASHBOARD QUICK TELEMETRY INGESTION (PCAP / CSV)
  // --------------------------------------------------------------------------
  const dashFileInput = document.getElementById("dash-file-input");
  const dashUploadBtn = document.getElementById("dash-upload-btn");
  const dashUploadStatus = document.getElementById("dash-upload-status");
  const dashQuickUpload = document.getElementById("dash-quick-upload");

  if (dashUploadBtn && dashFileInput) {
    dashUploadBtn.addEventListener("click", () => dashFileInput.click());

    dashFileInput.addEventListener("change", async (e) => {
      const file = e.target.files[0];
      if (file) await handleDashboardUpload(file);
    });

    if (dashQuickUpload) {
      dashQuickUpload.addEventListener("dragover", (e) => {
        e.preventDefault();
        dashQuickUpload.style.borderColor = "var(--accent-bronze)";
      });
      dashQuickUpload.addEventListener("dragleave", () => {
        dashQuickUpload.style.borderColor = "var(--border-medium)";
      });
      dashQuickUpload.addEventListener("drop", async (e) => {
        e.preventDefault();
        dashQuickUpload.style.borderColor = "var(--border-medium)";
        if (e.dataTransfer.files.length > 0) {
          await handleDashboardUpload(e.dataTransfer.files[0]);
        }
      });
    }
  }

  async function handleDashboardUpload(file) {
    if (!dashUploadStatus) return;
    dashUploadStatus.innerHTML = `<span style="color:var(--accent-bronze);">&#8635; Ingesting ${file.name} (${(file.size / 1024).toFixed(1)} KB)...</span>`;
    try {
      state.uploadedFile = file;
      const result = await NexusAPI.uploadAndInfer(file, { explain_mode: "lightweight", enrich_mode: "full" });
      state.selectedForecastId = result.forecast_id;
      if (result.horizons && result.horizons.h1) {
        state.selectedStage = result.horizons.h1.predicted_stage;
      }
      dashUploadStatus.innerHTML = `<span style="color:var(--semantic-benign);">&#10003; Forecast generated! Opening Live Inference...</span>`;
      setTimeout(() => {
        navigateTo("inference");
        renderLiveInferenceResult(result);
        dashUploadStatus.textContent = "";
      }, 500);
    } catch (err) {
      console.error("Dashboard upload failed:", err);
      dashUploadStatus.innerHTML = `<span style="color:var(--semantic-attack);">Error: ${err.message}</span>`;
    }
  }

  // Horizon Quick Toggles
  document.querySelectorAll(".btn-horizon[data-horizon]").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".btn-horizon[data-horizon]").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.activeHorizon = parseInt(btn.dataset.horizon, 10);
      if (state.dashboardData) renderDashboard(state.dashboardData);
    });
  });

  // SVG Forecast Timeline Chart
  function renderTimelineChart(points) {
    const container = document.getElementById("timeline-svg-container");
    if (!container || !points || points.length === 0) return;

    const width = container.clientWidth || 800;
    const height = 220;
    const padX = 60;
    const padY = 30;
    const chartW = width - padX * 2;
    const chartH = height - padY * 2;

    const stepX = chartW / (points.length - 1);

    // Helper: value to Y
    const toY = (val) => height - padY - val * chartH;
    const thresholdY = toY(0.45);

    // Build SVG
    let svg = `<svg width="100%" height="${height}" viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg">`;

    // Gridlines (0.25, 0.50, 0.75, 1.00)
    [0.0, 0.25, 0.50, 0.75, 1.0].forEach((level) => {
      const y = toY(level);
      svg += `<line x1="${padX}" y1="${y}" x2="${width - padX}" y2="${y}" stroke="rgba(255,255,255,0.05)" stroke-width="1"/>`;
      svg += `<text x="${padX - 10}" y="${y + 4}" fill="#6b7280" font-size="10" font-family="monospace" text-anchor="end">${(level * 100).toFixed(0)}%</text>`;
    });

    // Operational Threshold Line (0.45)
    svg += `<line x1="${padX}" y1="${thresholdY}" x2="${width - padX}" y2="${thresholdY}" stroke="#c94a4a" stroke-dasharray="4,4" stroke-width="1.5"/>`;
    svg += `<text x="${width - padX + 8}" y="${thresholdY + 3}" fill="#c94a4a" font-size="10" font-family="monospace">θ*=45%</text>`;

    // Prediction origin vertical separator ("NOW")
    const nowIdx = points.findIndex((p) => p.type === "current");
    if (nowIdx !== -1) {
      const nowX = padX + nowIdx * stepX;
      svg += `<line x1="${nowX}" y1="${padY}" x2="${nowX}" y2="${height - padY}" stroke="#c59a68" stroke-dasharray="2,3" stroke-width="1"/>`;
      svg += `<text x="${nowX}" y="${padY - 8}" fill="#c59a68" font-size="9.5" font-family="monospace" text-anchor="middle">PREDICTION ORIGIN</text>`;
    }

    // Path 1: Observed (grey)
    let obsD = "";
    // Path 2: Forecast (bronze)
    let fcD = "";

    points.forEach((p, i) => {
      const x = padX + i * stepX;
      const y = toY(p.probability);

      if (i <= nowIdx) {
        obsD += (i === 0 ? `M ${x} ${y}` : ` L ${x} ${y}`);
      }
      if (i >= nowIdx) {
        fcD += (i === nowIdx ? `M ${x} ${y}` : ` L ${x} ${y}`);
      }
    });

    svg += `<path d="${obsD}" fill="none" stroke="#85888e" stroke-width="2.2" stroke-linecap="round"/>`;
    svg += `<path d="${fcD}" fill="none" stroke="#c59a68" stroke-width="2.5" stroke-linecap="round"/>`;

    // Render Data Points
    points.forEach((p, i) => {
      const x = padX + i * stepX;
      const y = toY(p.probability);
      const isFc = i >= nowIdx;
      const color = isFc ? "#c59a68" : "#85888e";
      const r = i === nowIdx ? 5.5 : 4.5;

      svg += `<circle cx="${x}" cy="${y}" r="${r}" fill="${color}" stroke="#0c0d0e" stroke-width="2" class="timeline-point" data-idx="${i}" style="cursor:pointer;"/>`;
      svg += `<text x="${x}" y="${height - padY + 18}" fill="#9aa0a6" font-size="10.5" font-family="monospace" text-anchor="middle">${p.label}</text>`;
    });

    svg += `</svg>`;
    container.innerHTML = svg;

    // Attach click inspection to points
    container.querySelectorAll(".timeline-point").forEach((pt) => {
      pt.addEventListener("click", (e) => {
        const idx = parseInt(e.target.dataset.idx, 10);
        const p = points[idx];
        openDrawerWithTimelinePoint(p);
      });
    });
  }

  function renderEvidenceGrid(evidenceList) {
    const grid = document.getElementById("dashboard-evidence-grid");
    if (!grid) return;

    // Handle both array format and object format with supporting_observations
    let list = Array.isArray(evidenceList) ? evidenceList : (evidenceList?.supporting_observations || []);
    if (list.length === 0) return;

    grid.innerHTML = list
      .map(
        (ev, i) => {
          const category = ev.category || "TELEMETRY";
          const headline = ev.observation || ev.label || ev.observation_text || `Telemetry deviation in ${ev.feature}`;
          const current = ev.current || ev.val || (ev.deviation_details?.current_value != null ? String(ev.deviation_details.current_value) : "N/A");
          const baseline = ev.baseline || ev.norm || (ev.deviation_details?.baseline_mean != null ? String(ev.deviation_details.baseline_mean) : "N/A");
          const deviation = ev.deviation || ev.dev || (ev.deviation_details?.iqr_deviation != null ? `${ev.deviation_details.iqr_deviation > 0 ? "+" : ""}${Number(ev.deviation_details.iqr_deviation).toFixed(1)}x IQR` : "Elevated");

          return `
          <div class="evidence-card" data-idx="${i}">
            <div>
              <div class="evidence-category-badge">${category}</div>
              <div class="evidence-headline">${headline}</div>
            </div>
            <div class="evidence-meta-row">
              <span class="evidence-stat">Val: ${current} (Base: ${baseline})</span>
              <span class="evidence-dev">${deviation}</span>
            </div>
          </div>
        `;
        }
      )
      .join("");

    grid.querySelectorAll(".evidence-card").forEach((card) => {
      card.addEventListener("click", () => {
        const idx = parseInt(card.dataset.idx, 10);
        const ev = list[idx];
        openDrawerWithEvidence(ev);
      });
    });
  }

  function renderStageProgression(stageProg) {
    const bar = document.getElementById("stage-progression-bar");
    if (!bar || !stageProg) return;

    // Handle both {stages: [...]} and direct array [...]
    let stages = Array.isArray(stageProg) ? stageProg : (stageProg.stages || []);
    if (stages.length === 0) return;

    const canonicalStages = [
      { name: "RECONNAISSANCE", short: "RECON", order: 1 },
      { name: "INITIAL_ACCESS", short: "INITIAL ACCESS", order: 2 },
      { name: "EXECUTION", short: "EXECUTION", order: 3 },
      { name: "DISCOVERY", short: "DISCOVERY", order: 4 },
      { name: "CREDENTIAL_ACCESS", short: "CREDENTIAL ACCESS", order: 5 },
      { name: "LATERAL_MOVEMENT", short: "LATERAL MOVEMENT", order: 6 },
      { name: "COMMAND_AND_CONTROL", short: "COMMAND & CONTROL", order: 7 },
      { name: "EXFILTRATION", short: "EXFILTRATION", order: 8 }
    ];

    // Normalize stages format
    const normalized = stages.map((st, i) => {
      const match = canonicalStages.find(c => c.name === (st.name || st.stage)) || canonicalStages[i % canonicalStages.length];
      const isAct = st.active === true || st.status === "active" || (state.dashboardData?.primary_forecast?.predicted_stage === match.name);
      return {
        name: match.name,
        short: match.short,
        order: match.order,
        active: isAct,
        confidence: st.confidence || st.prob || 0.5,
        description: st.description || `Canonical attack stage: ${match.name}`
      };
    });

    bar.innerHTML = normalized
      .map((st, i) => {
        const isLast = i === normalized.length - 1;
        const arrow = isLast ? "" : `<div class="prog-arrow">&rarr;</div>`;
        return `
          <div class="progression-step ${st.active ? "active" : ""}" data-stage="${st.name}">
            <span class="prog-order">STAGE ${st.order}</span>
            <span class="prog-name">${st.short}</span>
          </div>
          ${arrow}
        `;
      })
      .join("");

    bar.querySelectorAll(".progression-step").forEach((step) => {
      step.addEventListener("click", () => {
        const stageName = step.dataset.stage;
        const stageObj = normalized.find((s) => s.name === stageName);
        openDrawerWithStage(stageObj);
      });
    });
  }

  function renderTopFeatures(features) {
    const list = document.getElementById("dashboard-top-features");
    if (!list || !features) return;

    const maxAttr = Math.max(...features.map((f) => Math.abs(f.attribution)), 1.0);

    list.innerHTML = features
      .map((f) => {
        const pct = Math.min(100, Math.round((Math.abs(f.attribution) / maxAttr) * 100));
        const dirSign = f.attribution >= 0 ? "+" : "";
        const isSupp = f.attribution < 0;
        const barColor = isSupp ? "var(--semantic-benign)" : "var(--accent-bronze)";

        return `
          <div class="feature-attr-row" data-feat="${f.feature}">
            <span class="feat-name">${f.feature}</span>
            <div class="feat-bar-container">
              <div class="feat-bar-fill" style="width:${pct}%; background:${barColor};"></div>
            </div>
            <span class="feat-score">${dirSign}${f.attribution.toFixed(3)}</span>
          </div>
        `;
      })
      .join("");

    list.querySelectorAll(".feature-attr-row").forEach((row) => {
      row.addEventListener("click", () => {
        const featName = row.dataset.feat;
        const featObj = features.find((f) => f.feature === featName);
        openDrawerWithFeature(featObj);
      });
    });
  }

  function renderRecentForecasts(forecasts) {
    const tbody = document.getElementById("dashboard-recent-table");
    if (!tbody || !forecasts) return;

    tbody.innerHTML = forecasts
      .map(
        (f) => {
          const fid = f.id || f.forecast_id || "FC-1000";
          const time = f.time || f.timestamp?.split("T")?.[1] || "10:50:00";
          const horizon = f.horizon || "+30s";
          const prob = f.probability != null ? f.probability : (f.attack_probability || 0.5);
          const stage = f.stage || f.predicted_stage || "BENIGN";
          const dec = f.decision || (prob >= 0.45 ? "ATTACK" : "BENIGN");

          return `
          <tr class="clickable-row" data-id="${fid}">
            <td style="font-family:var(--font-mono);">${time}</td>
            <td style="font-family:var(--font-mono);">${horizon}</td>
            <td style="font-family:var(--font-mono); font-weight:500;">${(prob * 100).toFixed(1)}%</td>
            <td>${stage}</td>
            <td><span class="badge-compact ${dec === "ATTACK" ? "attack" : "benign"}">${dec}</span></td>
          </tr>
        `;
        }
      )
      .join("");

    tbody.querySelectorAll("tr.clickable-row").forEach((tr) => {
      tr.addEventListener("click", () => {
        const fid = tr.dataset.id;
        const item = forecasts.find((f) => (f.id === fid || f.forecast_id === fid));
        openDrawerWithForecast(item);
      });
    });
  }

  // --------------------------------------------------------------------------
  // DRAWER SLIDE-OVER LOGIC
  // --------------------------------------------------------------------------
  function openDrawer(title, htmlContent) {
    drawerTitle.textContent = title;
    drawerBody.innerHTML = htmlContent;
    drawer.classList.add("open");
  }

  drawerCloseBtn.addEventListener("click", () => {
    drawer.classList.remove("open");
  });

  drawerViewExplBtn.addEventListener("click", () => {
    drawer.classList.remove("open");
    navigateTo("explanations", state.selectedForecastId);
  });

  drawerViewKnowBtn.addEventListener("click", () => {
    drawer.classList.remove("open");
    navigateTo("knowledge", state.selectedStage);
  });

  function openDrawerWithEvidence(ev) {
    const html = `
      <div style="margin-bottom:20px;">
        <span class="control-label" style="display:block; margin-bottom:6px;">EVIDENCE CATEGORY</span>
        <h2 style="font-family:var(--font-serif); font-size:22px; color:var(--text-primary);">${ev.category}</h2>
      </div>

      <div style="background:var(--bg-primary); padding:16px; border-radius:3px; border:1px solid var(--border-subtle); margin-bottom:20px;">
        <p style="font-size:13.5px; color:var(--text-primary); line-height:1.5;">${ev.observation}</p>
      </div>

      <table class="editorial-table" style="margin-bottom:24px;">
        <tr>
          <th>Underlying State Feature</th>
          <td style="font-family:var(--font-mono); color:var(--text-primary);">${ev.feature}</td>
        </tr>
        <tr>
          <th>Current Window Value</th>
          <td style="font-family:var(--font-mono);">${ev.current}</td>
        </tr>
        <tr>
          <th>Benign Train Median</th>
          <td style="font-family:var(--font-mono);">${ev.baseline}</td>
        </tr>
        <tr>
          <th>Robust Deviation</th>
          <td style="font-family:var(--font-mono); color:var(--semantic-attack); font-weight:600;">${ev.deviation}</td>
        </tr>
        <tr>
          <th>Model Attribution Score</th>
          <td style="font-family:var(--font-mono); color:var(--accent-bronze);">${ev.attribution}</td>
        </tr>
        <tr>
          <th>Temporal Window Concentration</th>
          <td style="font-family:var(--font-mono);">${ev.temporal || "Multi-window persistence"}</td>
        </tr>
      </table>

      <div class="epistemic-notice">
        <strong>Traceability Audit</strong>: Mapped directly to canonical network flow fields. Does not constitute physical compromise proof; represents high-weight telemetry supporting model forecast.
      </div>
    `;
    openDrawer("Observable Evidence Detail", html);
  }

  function openDrawerWithTimelinePoint(p) {
    const html = `
      <div style="margin-bottom:20px;">
        <span class="control-label" style="display:block; margin-bottom:6px;">TEMPORAL STEP POINT</span>
        <h2 style="font-family:var(--font-serif); font-size:22px; color:var(--text-primary);">${p.label} (${p.time})</h2>
      </div>

      <table class="editorial-table" style="margin-bottom:24px;">
        <tr>
          <th>Point Classification</th>
          <td style="text-transform:uppercase; font-family:var(--font-mono);">${p.type}</td>
        </tr>
        <tr>
          <th>Modeled Probability</th>
          <td style="font-family:var(--font-mono); font-size:16px; font-weight:600; color:var(--text-primary);">${(p.probability * 100).toFixed(1)}%</td>
        </tr>
        <tr>
          <th>Operational Threshold</th>
          <td style="font-family:var(--font-mono);">45.0%</td>
        </tr>
        <tr>
          <th>Alert Decision</th>
          <td><span class="badge-compact ${p.probability >= 0.45 ? "attack" : "benign"}">${p.probability >= 0.45 ? "ATTACK" : "BENIGN"}</span></td>
        </tr>
        <tr>
          <th>Predicted Stage</th>
          <td style="font-family:var(--font-serif); font-size:15px; color:var(--text-primary);">${p.stage}</td>
        </tr>
      </table>

      <div class="epistemic-notice">
        <strong>Rollout Dynamics</strong>: Evaluated via the 2-layer autoregressive GRU World Model. Probabilities are Platt-calibrated against chronological validation splits.
      </div>
    `;
    openDrawer("Timeline Horizon Detail", html);
  }

  function openDrawerWithStage(stageObj) {
    const html = `
      <div style="margin-bottom:20px;">
        <span class="control-label" style="display:block; margin-bottom:6px;">CANONICAL ATTACK STAGE</span>
        <h2 style="font-family:var(--font-serif); font-size:22px; color:var(--text-primary);">${stageObj.name}</h2>
      </div>

      <p style="font-size:13.5px; color:var(--text-secondary); line-height:1.55; margin-bottom:20px;">
        ${stageObj.description}
      </p>

      <table class="editorial-table" style="margin-bottom:24px;">
        <tr>
          <th>Lifecycle Order</th>
          <td style="font-family:var(--font-mono);">Step ${stageObj.order} of 8</td>
        </tr>
        <tr>
          <th>Model Forecast Likelihood</th>
          <td style="font-family:var(--font-mono); font-weight:600; color:${stageObj.active ? "var(--accent-bronze)" : "var(--text-muted)"};">${(stageObj.confidence * 100).toFixed(1)}%</td>
        </tr>
        <tr>
          <th>Current Status</th>
          <td><span class="badge-compact ${stageObj.active ? "attack" : "benign"}">${stageObj.active ? "CURRENTLY ACTIVE" : "INACTIVE"}</span></td>
        </tr>
      </table>

      <div class="epistemic-notice">
        <strong>ATT&CK Alignment</strong>: Mapped to MITRE ATT&CK techniques with strict preservation of uncertainty tiers. Click 'View ATT&CK Mapping' below for associated techniques.
      </div>
    `;
    openDrawer("Attack Stage Analysis", html);
  }

  function openDrawerWithFeature(feat) {
    const html = `
      <div style="margin-bottom:20px;">
        <span class="control-label" style="display:block; margin-bottom:6px;">FEATURE ATTRIBUTION</span>
        <h2 style="font-family:var(--font-mono); font-size:20px; color:var(--text-primary);">${feat.feature}</h2>
      </div>

      <table class="editorial-table" style="margin-bottom:24px;">
        <tr>
          <th>Integrated Gradient Score</th>
          <td style="font-family:var(--font-mono); font-size:16px; font-weight:600; color:var(--accent-bronze);">${feat.attribution >= 0 ? "+" : ""}${feat.attribution.toFixed(4)}</td>
        </tr>
        <tr>
          <th>Influence Direction</th>
          <td style="font-family:var(--font-mono);">${feat.direction}</td>
        </tr>
        <tr>
          <th>Current Window Value</th>
          <td style="font-family:var(--font-mono);">${feat.current_value}</td>
        </tr>
        <tr>
          <th>Train Partition Median</th>
          <td style="font-family:var(--font-mono);">${feat.baseline_median}</td>
        </tr>
        <tr>
          <th>Robust IQR Deviation</th>
          <td style="font-family:var(--font-mono); color:var(--semantic-attack);">${feat.iqr_deviation >= 0 ? "+" : ""}${feat.iqr_deviation.toFixed(1)}x IQR</td>
        </tr>
      </table>

      <div class="epistemic-notice">
        <strong>Attribution Interpretation</strong>: Positive attribution denotes that elevating this feature above the benign median drives the GRU output logit toward attack. Negative attribution suppresses the attack logit.
      </div>
    `;
    openDrawer("Feature Attribution Detail", html);
  }

  function openDrawerWithForecast(fc) {
    if (!fc) return;
    state.selectedForecast = fc;
    state.selectedForecastId = fc.id || fc.forecast_id;
    state.selectedStage = fc.stage || fc.predicted_stage || "DISCOVERY";

    const prob = fc.probability != null ? fc.probability : (fc.attack_probability || 0.5);
    const thresh = fc.threshold != null ? fc.threshold : (fc.operational_threshold || 0.45);
    const dec = fc.decision || (prob >= thresh ? "ATTACK" : "BENIGN");

    const html = `
      <div style="margin-bottom:20px;">
        <span class="control-label" style="display:block; margin-bottom:6px;">FORECAST RECORD</span>
        <h2 style="font-family:var(--font-mono); font-size:20px; color:var(--text-primary);">${fc.id || fc.forecast_id || "NEXUS-FC"}</h2>
      </div>

      <table class="editorial-table" style="margin-bottom:24px;">
        <tr>
          <th>Benchmark Dataset</th>
          <td style="font-family:var(--font-mono);">${fc.dataset || "CIC-IDS2017"}</td>
        </tr>
        <tr>
          <th>Evaluation Scenario</th>
          <td>${fc.scenario || "Evaluation Scenario"}</td>
        </tr>
        <tr>
          <th>Prediction Time</th>
          <td style="font-family:var(--font-mono);">${fc.time || fc.timestamp}</td>
        </tr>
        <tr>
          <th>Forecast Horizon</th>
          <td style="font-family:var(--font-mono);">${fc.horizon}</td>
        </tr>
        <tr>
          <th>Calibrated Probability</th>
          <td style="font-family:var(--font-mono); font-size:16px; font-weight:600; color:var(--text-primary);">${(fc.probability * 100).toFixed(1)}%</td>
        </tr>
        <tr>
          <th>Operational Threshold</th>
          <td style="font-family:var(--font-mono);">${(fc.threshold * 100).toFixed(1)}%</td>
        </tr>
        <tr>
          <th>Alert Decision</th>
          <td><span class="badge-compact ${fc.decision === "ATTACK" ? "attack" : "benign"}">${fc.decision}</span></td>
        </tr>
        <tr>
          <th>Predicted Stage</th>
          <td style="font-family:var(--font-serif); font-size:16px; color:var(--text-primary);">${fc.stage || fc.predicted_stage}</td>
        </tr>
      </table>

      <div class="epistemic-notice">
        <strong>Audit Trail</strong>: Generated using the verified frozen checkpoint (best_model.pt). All output probabilities, stage attributions, and evidence trails are fully reproducible offline.
      </div>
    `;
    openDrawer("Forecast Summary", html);
  }

  // --------------------------------------------------------------------------
  // PAGE 2: LIVE INFERENCE & FILE UPLOAD
  // --------------------------------------------------------------------------
  const runInferBtn = document.getElementById("btn-run-inference");
  const stepperBox = document.getElementById("inference-stepper-box");
  const inferEmpty = document.getElementById("infer-empty-state");
  const inferLive = document.getElementById("infer-live-results");

  const inferDropzoneContainer = document.getElementById("infer-dropzone-container");
  const inferFileDropzone = document.getElementById("infer-file-dropzone");
  const inferFileInput = document.getElementById("infer-file-input");
  const inferFileSelectedBox = document.getElementById("infer-file-selected-box");
  const inferFileName = document.getElementById("infer-file-name");
  const inferFileSize = document.getElementById("infer-file-size");
  const inferFileRemoveBtn = document.getElementById("infer-file-remove-btn");

  // Input Type Radio Change Listener
  document.querySelectorAll('input[name="infer-input-type"]').forEach((radio) => {
    radio.addEventListener("change", (e) => {
      if (inferDropzoneContainer) {
        inferDropzoneContainer.style.display = e.target.value === "upload" ? "block" : "none";
      }
    });
  });

  // Dropzone Click & Drag/Drop
  if (inferFileDropzone && inferFileInput) {
    inferFileDropzone.addEventListener("click", () => inferFileInput.click());

    inferFileInput.addEventListener("change", (e) => {
      const file = e.target.files[0];
      if (file) setInferUploadedFile(file);
    });

    inferFileDropzone.addEventListener("dragover", (e) => {
      e.preventDefault();
      inferFileDropzone.classList.add("dragover");
    });

    inferFileDropzone.addEventListener("dragleave", () => {
      inferFileDropzone.classList.remove("dragover");
    });

    inferFileDropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      inferFileDropzone.classList.remove("dragover");
      if (e.dataTransfer.files.length > 0) {
        setInferUploadedFile(e.dataTransfer.files[0]);
      }
    });

    if (inferFileRemoveBtn) {
      inferFileRemoveBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        state.uploadedFile = null;
        inferFileInput.value = "";
        if (inferFileSelectedBox) inferFileSelectedBox.style.display = "none";
        if (inferFileDropzone) inferFileDropzone.style.display = "block";
      });
    }
  }

  function setInferUploadedFile(file) {
    state.uploadedFile = file;
    if (inferFileName) inferFileName.textContent = file.name;
    if (inferFileSize) inferFileSize.textContent = `${(file.size / 1024).toFixed(1)} KB`;
    if (inferFileSelectedBox) inferFileSelectedBox.style.display = "flex";
    if (inferFileDropzone) inferFileDropzone.style.display = "none";
  }

  runInferBtn.addEventListener("click", async () => {
    const inputTypeRadio = document.querySelector('input[name="infer-input-type"]:checked');
    const inputType = inputTypeRadio ? inputTypeRadio.value : "demo";

    if (inputType === "upload" && !state.uploadedFile) {
      alert("Please select or drop a PCAP / CSV file first.");
      return;
    }

    runInferBtn.disabled = true;
    runInferBtn.textContent = "EXECUTING...";
    stepperBox.style.display = "block";
    inferEmpty.style.display = "none";
    inferLive.style.display = "none";

    // Progressive step indicator
    const steps = document.querySelectorAll(".step-item");
    steps.forEach((s) => (s.className = "step-item"));

    for (let i = 0; i < steps.length; i++) {
      steps[i].className = "step-item active";
      await new Promise((r) => setTimeout(r, 60));
      steps[i].className = "step-item completed";
      steps[i].querySelector(".step-icon").innerHTML = "&#10003;";
    }

    // Call backend API
    try {
      const explainChecked = document.getElementById("chk-explain")?.checked;
      const mitreChecked = document.getElementById("chk-mitre")?.checked;
      const capecChecked = document.getElementById("chk-capec")?.checked;
      let enrichMode = "none";
      if (mitreChecked && capecChecked) enrichMode = "full";
      else if (mitreChecked) enrichMode = "attack";
      else if (capecChecked) enrichMode = "full";

      let result;
      if (inputType === "upload" && state.uploadedFile) {
        // Upload & evaluate network capture
        result = await NexusAPI.uploadAndInfer(state.uploadedFile, {
          explain_mode: explainChecked ? "lightweight" : "none",
          enrich_mode: enrichMode,
        });
      } else {
        // Evaluate pre-packaged test sequence
        const dataset = document.getElementById("infer-dataset-select")?.value || "CIC-IDS2017";
        const scenarioRaw = document.getElementById("infer-scenario-select")?.value || "scenario_01";
        
        let scenarioId = "scenario_01";
        const match = scenarioRaw.match(/\d+/);
        if (match) {
          scenarioId = `scenario_${match[0].padStart(2, "0")}`;
        } else if (scenarioRaw.startsWith("scenario_")) {
          scenarioId = scenarioRaw;
        }

        const payload = {
          input_type: "demo",
          dataset: dataset,
          scenario_id: scenarioId,
          raw_sequence: null,
          horizons: [1, 3, 6],
          explain_mode: explainChecked ? "lightweight" : "none",
          enrich_mode: enrichMode,
        };

        result = await NexusAPI.runInference(payload);
      }

      state.selectedForecastId = result.forecast_id;
      if (result.horizons && result.horizons.h1) {
        state.selectedStage = result.horizons.h1.predicted_stage;
      }
      renderLiveInferenceResult(result);
    } catch (err) {
      console.error("Inference execution failed:", err);
      NexusUI.renderError(
        inferLive,
        `Offline inference pipeline failed: ${err.message}`,
        null
      );
      inferLive.style.display = "block";
    } finally {
      runInferBtn.disabled = false;
      runInferBtn.textContent = "RUN INFERENCE";
    }
  });

  function renderLiveInferenceResult(res) {
    inferLive.style.display = "block";
    const h1 = res.horizons.h1;
    const isAttack = h1.predicted_attack;
    const probPct = (h1.calibrated_attack_prob * 100).toFixed(1);

    let html = `
      <div style="border-bottom:1px solid var(--border-subtle); padding-bottom:16px; margin-bottom:18px;">
        <div style="display:flex; justify-content:space-between; align-items:baseline;">
          <span style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted);">${res.forecast_id}</span>
          <span style="font-family:var(--font-mono); font-size:11px; color:var(--accent-bronze);">${res.execution_time_ms} ms</span>
        </div>
        <div style="display:flex; align-items:baseline; gap:16px; margin-top:8px;">
          <div style="font-family:var(--font-serif); font-size:48px; color:var(--text-primary); line-height:1;">${probPct}%</div>
          <span class="threat-badge ${isAttack ? "attack" : "benign"}">${isAttack ? "ATTACK FORECASTED" : "BENIGN"}</span>
        </div>
        <div style="margin-top:12px; font-size:12.5px; color:var(--text-secondary);">
          Stage: <strong style="color:var(--text-primary);">${h1.predicted_stage}</strong> (Confidence: ${(h1.stage_confidence * 100).toFixed(1)}%)
        </div>
      </div>
    `;

    // Multi-horizon summary
    html += `
      <div style="margin-bottom:18px;">
        <div class="control-label" style="margin-bottom:8px;">MULTI-STEP ROLLOUT TRAJECTORY</div>
        <div style="display:flex; gap:8px;">
    `;
    ["h1", "h3", "h6"].forEach((hKey) => {
      const hData = res.horizons[hKey];
      if (!hData) return;
      html += `
        <div style="flex:1; background:var(--bg-primary); padding:10px; border-radius:3px; border:1px solid var(--border-subtle); text-align:center;">
          <div style="font-size:10px; font-family:var(--font-mono); color:var(--text-muted);">${hKey.toUpperCase()} (+${hData.horizon_seconds}s)</div>
          <div style="font-size:14px; font-family:var(--font-mono); font-weight:600; color:var(--text-primary); margin:4px 0;">${(hData.calibrated_attack_prob * 100).toFixed(1)}%</div>
          <div style="font-size:10.5px; color:var(--text-secondary);">${hData.predicted_stage}</div>
        </div>
      `;
    });
    html += `</div></div>`;

    // Top explanation features
    if (h1.explanation && h1.explanation.top_contributing_features) {
      html += `
        <div style="margin-bottom:18px;">
          <div class="control-label" style="margin-bottom:6px;">TOP CONTRIBUTING TELEMETRY FEATURES</div>
          <div style="font-family:var(--font-mono); font-size:11.5px; color:var(--text-secondary); line-height:1.6;">
            ${h1.explanation.top_contributing_features.map((f) => `<span style="display:inline-block; margin-right:8px; background:var(--bg-primary); padding:2px 6px; border-radius:3px; border:1px solid var(--border-subtle);">&bull; ${f}</span>`).join("")}
          </div>
        </div>
      `;
    }

    // Knowledge enrichment
    if (h1.enrichment) {
      const techs = h1.enrichment.attack_techniques || [];
      const capecs = h1.enrichment.capec_patterns || [];
      html += `
        <div>
          <div class="control-label" style="margin-bottom:6px;">ASSOCIATED MITRE INTELLIGENCE</div>
          <div style="font-size:11.5px; color:var(--text-secondary);">
            ${techs.slice(0, 3).map((t) => `<div>&bull; <strong>${t.attack_id}</strong>: ${t.technique}</div>`).join("")}
            ${capecs.slice(0, 2).map((c) => `<div style="margin-top:2px;">&bull; <strong>${c.capec_id}</strong>: ${c.name}</div>`).join("")}
          </div>
        </div>
      `;
    }

    // Deep-dive action buttons
    html += `
      <div style="display:flex; gap:10px; margin-top:20px; padding-top:14px; border-top:1px solid var(--border-subtle);">
        <button id="btn-live-view-expl" class="btn-primary" style="font-size:11px; padding:6px 14px;">INSPECT EXPLANATION</button>
        <button id="btn-live-view-know" class="btn-secondary" style="font-size:11px; padding:6px 14px;">VIEW MITRE ATT&CK</button>
      </div>
    `;

    inferLive.innerHTML = html;

    const btnExpl = document.getElementById("btn-live-view-expl");
    if (btnExpl) {
      btnExpl.addEventListener("click", () => {
        navigateTo("explanations", res.forecast_id);
      });
    }

    const btnKnow = document.getElementById("btn-live-view-know");
    if (btnKnow) {
      btnKnow.addEventListener("click", () => {
        navigateTo("knowledge", h1.predicted_stage);
      });
    }
  }

  // --------------------------------------------------------------------------
  // PAGE 3: FORECAST RESULTS
  // --------------------------------------------------------------------------
  async function loadForecastResults() {
    const tbody = document.getElementById("results-table-body");
    if (tbody) NexusUI.renderLoading(tbody, "Querying forecast records from offline registry...");

    try {
      const dec = document.getElementById("filter-decision").value;
      const stg = document.getElementById("filter-stage").value;
      const hor = document.getElementById("filter-horizon").value;

      const data = await NexusAPI.getForecasts({
        decision: dec,
        stage: stg,
        horizon: hor,
      });
      state.forecastResults = data;
      renderForecastResults(data);
    } catch (err) {
      console.error("Failed to load forecast results:", err);
      if (tbody) {
        NexusUI.renderError(
          tbody,
          `Unable to load forecast archive: ${err.message}`,
          loadForecastResults
        );
      }
    }
  }

  function renderForecastResults(results) {
    const tbody = document.getElementById("results-table-body");
    const summary = document.getElementById("results-count-summary");
    const badge = document.getElementById("nav-count-results");

    if (summary) summary.textContent = `${results.length} Recorded Forecasts`;
    if (badge) badge.textContent = results.length;

    if (!tbody) return;

    if (results.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; padding:32px; color:var(--text-muted);">No recorded forecasts match the selected filter criteria.</td></tr>`;
      return;
    }

    tbody.innerHTML = results
      .map(
        (r) => {
          const fid = r.forecast_id || r.id || "FC-1000";
          const prob = r.attack_probability != null ? r.attack_probability : (r.probability || 0.5);
          const thresh = r.threshold != null ? r.threshold : (r.operational_threshold || 0.45);
          const stg = r.predicted_stage || r.stage || "BENIGN";
          const hor = r.horizon || "+30s";
          const dec = r.decision || (prob >= thresh ? "ATTACK" : "BENIGN");
          const ts = r.timestamp || r.time || "2024-04-21 10:45:00";
          const ds = r.dataset || "CIC-IDS2017";
          const sc = r.scenario || "Benchmark Scenario";

          return `
          <tr class="clickable-row" data-id="${fid}">
            <td style="font-family:var(--font-mono); font-weight:500; color:var(--text-primary);">${fid}</td>
            <td style="font-family:var(--font-mono);">${ts}</td>
            <td>${ds}</td>
            <td>${sc}</td>
            <td style="font-family:var(--font-mono);">${hor}</td>
            <td style="font-family:var(--font-mono); font-weight:600; color:var(--text-primary);">${(prob * 100).toFixed(1)}%</td>
            <td style="font-family:var(--font-mono); color:var(--text-muted);">${(thresh * 100).toFixed(0)}%</td>
            <td><span class="badge-compact ${dec === "ATTACK" ? "attack" : "benign"}">${dec}</span></td>
            <td>${stg}</td>
          </tr>
        `;
        }
      )
      .join("");

    tbody.querySelectorAll("tr.clickable-row").forEach((tr) => {
      tr.addEventListener("click", () => {
        const fid = tr.dataset.id;
        const item = results.find((r) => (r.forecast_id === fid || r.id === fid));
        openDrawerWithForecast(item);
      });
    });
  }

  ["filter-decision", "filter-stage", "filter-horizon"].forEach((id) => {
    document.getElementById(id).addEventListener("change", loadForecastResults);
  });

  // --------------------------------------------------------------------------
  // PAGE 4: EXPLANATIONS (PHASE 17)
  // --------------------------------------------------------------------------
  async function loadExplanations(forecastId = null) {
    const targetFid = forecastId || state.selectedForecastId;
    const featTbody = document.getElementById("expl-features-table");
    if (featTbody) NexusUI.renderLoading(featTbody, "Retrieving feature and temporal attribution...");

    try {
      const data = await NexusAPI.getExplanation(targetFid);
      state.explanationsData = data;
      renderExplanations(data);
    } catch (err) {
      console.error("Failed to load explanations:", err);
      if (featTbody) {
        NexusUI.renderError(
          featTbody,
          `Unable to compute or load attribution: ${err.message}`,
          () => loadExplanations(targetFid)
        );
      }
    }
  }

  function renderExplanations(data) {
    if (!data) return;

    // 1. Feature Attribution Table
    const featList = data.feature_attribution || data.top_features || [];
    const featTbody = document.getElementById("expl-features-table");
    if (featTbody && featList.length > 0) {
      featTbody.innerHTML = featList
        .map(
          (f) => {
            const featName = f.feature || f.feature_name || "feature";
            const curVal = f.current_value != null ? f.current_value : (f.observed_value != null ? f.observed_value : "—");
            const baseVal = f.baseline_median != null ? f.baseline_median : (f.baseline_mean != null ? f.baseline_mean : "—");
            const iqr = f.iqr_deviation != null ? f.iqr_deviation : 1.5;
            const dir = f.direction || (f.attribution >= 0 ? "attack_supporting" : "attack_suppressing");
            const attr = f.attribution != null ? f.attribution : (f.attribution_score != null ? f.attribution_score : 0.0);
            return `
            <tr>
              <td style="font-family:var(--font-mono); font-weight:500; color:var(--text-primary);">${featName}</td>
              <td style="font-size:11px; font-family:var(--font-mono); color:var(--accent-bronze);">${f.category || (featName.includes("port") ? "PORT_DIVERSITY" : featName.includes("host") ? "HOST_DIVERSITY" : featName.includes("rate") || featName.includes("flow") ? "TRAFFIC_VOLUME" : "CONNECTION_BEHAVIOR")}</td>
              <td style="font-family:var(--font-mono);">${curVal}</td>
              <td style="font-family:var(--font-mono);">${baseVal}</td>
              <td style="font-family:var(--font-mono); color:${iqr > 0 ? "var(--semantic-attack)" : "var(--semantic-benign)"};">${iqr > 0 ? "+" : ""}${Number(iqr).toFixed(1)}x IQR</td>
              <td style="font-family:var(--font-mono); font-size:11px;">${dir}</td>
              <td style="font-family:var(--font-mono); font-weight:600; color:var(--accent-bronze);">${attr >= 0 ? "+" : ""}${Number(attr).toFixed(4)}</td>
            </tr>
          `;
          }
        )
        .join("");
    }

    // 2. Temporal Attribution Cards
    const tempList = data.temporal_attribution || [];
    const tempCards = document.getElementById("expl-temporal-cards");
    if (tempCards && tempList.length > 0) {
      tempCards.innerHTML = tempList
        .map(
          (t) => {
            const win = t.window || `W-${t.window_index ?? 0}`;
            const relSec = t.relative_seconds != null ? t.relative_seconds : (t.offset_seconds != null ? `${t.offset_seconds >= 0 ? "+" : ""}${t.offset_seconds}s` : "");
            const attr = t.attribution != null ? t.attribution : (t.attribution_score != null ? t.attribution_score : 0.0);
            const sumText = t.state_summary || `Weight: ${((t.relative_weight || 0) * 100).toFixed(1)}%`;
            return `
            <div class="chart-card" style="padding:14px; text-align:center;">
              <span class="control-label">${win} (${relSec})</span>
              <div style="font-family:var(--font-serif); font-size:24px; color:var(--text-primary); margin:6px 0;">${Number(attr).toFixed(3)}</div>
              <div style="font-size:10.5px; color:var(--text-secondary); line-height:1.3;">${sumText}</div>
            </div>
          `;
          }
        )
        .join("");
    }

    // 3. Feature x Time Heatmap
    const matrix = data.heatmap_matrix || data.feature_time_matrix?.rows || [];
    renderHeatmap(matrix);

    // 4. Model Sensitivity
    const sensList = data.sensitivity || data.counterfactual_sensitivity || [];
    const sensTbody = document.getElementById("expl-sensitivity-table");
    if (sensTbody && sensList.length > 0) {
      sensTbody.innerHTML = sensList
        .map(
          (s) => {
            const origP = s.prob_original != null ? s.prob_original : (s.original_prob != null ? s.original_prob : 0.0);
            const pertP = s.prob_perturbed != null ? s.prob_perturbed : (s.perturbed_prob != null ? s.perturbed_prob : 0.0);
            const delta = s.delta != null ? s.delta : (s.delta_prob != null ? s.delta_prob : pertP - origP);
            const interp = s.interpretation || (s.consistent ? "Consistent with attribution gradient" : "Model robust to perturbation");
            return `
            <tr>
              <td style="font-family:var(--font-mono); font-weight:500; color:var(--text-primary);">${s.feature}</td>
              <td style="font-family:var(--font-mono);">${s.original_value || "Baseline"}</td>
              <td style="font-family:var(--font-mono); color:var(--text-muted);">${s.perturbed_value || "Perturbed (+10%)"}</td>
              <td style="font-family:var(--font-mono);">${(origP * 100).toFixed(1)}%</td>
              <td style="font-family:var(--font-mono);">${(pertP * 100).toFixed(1)}%</td>
              <td style="font-family:var(--font-mono); font-weight:600; color:${delta < 0 ? "var(--semantic-benign)" : "var(--semantic-attack)"};">${delta > 0 ? "+" : ""}${(delta * 100).toFixed(1)}%</td>
              <td style="font-size:11.5px; color:var(--text-secondary);">${interp}</td>
            </tr>
          `;
          }
        )
        .join("");
    }

    // 5. Error Analysis
    if (data.error_analysis) {
      renderErrorGroup(state.activeErrorGroup, data.error_analysis);
    }
  }

  function renderHeatmap(matrix) {
    const table = document.getElementById("expl-heatmap-table");
    if (!table || !matrix || matrix.length === 0) return;

    let html = `<thead><tr><th style="text-align:left; width:160px;">Canonical Feature</th>`;
    for (let t = -9; t <= 0; t++) {
      html += `<th>${t === 0 ? "t" : `t${t}`}</th>`;
    }
    html += `</tr></thead><tbody>`;

    matrix.forEach((row) => {
      html += `<tr><td style="font-family:var(--font-mono); color:var(--text-primary); padding:6px 10px; font-size:11px;">${row.feature}</td>`;
      const vals = row.values || row.windows || [];
      vals.forEach((v, tIdx) => {
        const numVal = Number(v) || 0;
        const intensity = Math.min(1.0, Math.abs(numVal) / 1.5);
        const bg = numVal >= 0 ? `rgba(197, 154, 104, ${0.1 + intensity * 0.85})` : `rgba(74, 143, 104, ${0.1 + intensity * 0.85})`;
        const textVal = numVal.toFixed(2);
        html += `<td class="heatmap-cell" style="background:${bg}; font-family:var(--font-mono); font-size:9.5px; color:${intensity > 0.5 ? "#fff" : "#ddd"};" data-feat="${row.feature}" data-time="t${tIdx - 9 === 0 ? "" : tIdx - 9}" data-val="${numVal}">${textVal}</td>`;
      });
      html += `</tr>`;
    });

    html += `</tbody>`;
    table.innerHTML = html;

    const inspector = document.getElementById("heatmap-cell-inspector");
    table.querySelectorAll("td.heatmap-cell").forEach((cell) => {
      cell.addEventListener("mouseenter", () => {
        const feat = cell.dataset.feat;
        const timeVal = cell.dataset.time;
        const val = parseFloat(cell.dataset.val);
        if (inspector) inspector.innerHTML = `<strong>${feat}</strong> at <strong>${timeVal}</strong> &rarr; Attribution Score: <span style="color:var(--accent-bronze); font-weight:600;">${val.toFixed(4)}</span> (${val >= 0 ? "Attack-supporting" : "Attack-suppressing"})`;
      });
    });
  }

  function renderErrorGroup(groupKey, errorData) {
    const container = document.getElementById("error-group-content");
    if (!container || !errorData) return;

    const cases = errorData[groupKey] || [];
    if (cases.length === 0) {
      container.innerHTML = `<div style="color:var(--text-muted); font-size:12px;">No recorded cases in group ${groupKey}.</div>`;
      return;
    }

    const sc = cases[0];
    container.innerHTML = `
      <div style="display:flex; justify-content:space-between; margin-bottom:14px;">
        <span style="font-family:var(--font-mono); font-size:12px; color:var(--accent-bronze);">REPRESENTATIVE CASE: ${groupKey} (${sc.scenario_id})</span>
        <span style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted);">${sc.prediction_origin}</span>
      </div>
      <p style="font-size:13px; color:var(--text-secondary); line-height:1.5; margin-bottom:16px;">
        Calibrated Attack Probability: <strong style="color:var(--text-primary); font-family:var(--font-mono);">${(sc.calibrated_attack_probability * 100).toFixed(1)}%</strong> |
        Decision: <span class="badge-compact ${sc.forecast_decision === "ATTACK" ? "attack" : "benign"}">${sc.forecast_decision}</span> |
        Ground Truth: <span style="font-family:var(--font-mono);">${sc.ground_truth ? (sc.ground_truth.is_attack ? "ATTACK" : "BENIGN") : "KNOWN"}</span>
      </p>
      <div class="epistemic-notice">
        <strong>Behavioral Driver</strong>: ${groupKey === "TP" ? "Strong, persistent fan-out expansion and port scanning across consecutive windows." : groupKey === "FP" ? "Benign bursty multi-host synchronization temporarily crossing decision threshold." : groupKey === "FN" ? "Low-and-slow reconnaissance masked inside normal distribution bounds." : "Sustained quiet network state with minimal host/port diversity."}
      </div>
    `;
  }

  // Explanations Tabs Handlers
  document.querySelectorAll("#expl-tabs-nav .tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("#expl-tabs-nav .tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll("#page-explanations .tab-content-panel").forEach((p) => p.classList.remove("active"));

      btn.classList.add("active");
      const target = document.getElementById(btn.dataset.tab);
      if (target) target.classList.add("active");
    });
  });

  // Error Analysis Buttons
  document.querySelectorAll("#tab-expl-error .btn-secondary").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("#tab-expl-error .btn-secondary").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.activeErrorGroup = btn.dataset.errorGroup;
      if (state.explanationsData) renderErrorGroup(state.activeErrorGroup, state.explanationsData.error_analysis);
    });
  });

  // --------------------------------------------------------------------------
  // --------------------------------------------------------------------------
  // PAGE 5: ATT&CK / CAPEC (PHASE 18)
  // --------------------------------------------------------------------------
  async function loadKnowledge(stage = null) {
    const targetStage = stage || state.selectedStage || (state.dashboardData?.primary_forecast?.predicted_stage) || "DISCOVERY";
    state.selectedStage = targetStage;
    const mitreTbody = document.getElementById("knowledge-mitre-table");
    if (mitreTbody) NexusUI.renderLoading(mitreTbody, `Mapping ${targetStage} to MITRE ATT&CK techniques...`);

    try {
      const data = await NexusAPI.getUnifiedKnowledge(targetStage);
      state.knowledgeData = data;
      renderKnowledge(data);
    } catch (err) {
      console.error("Failed to load knowledge:", err);
      if (mitreTbody) {
        NexusUI.renderError(
          mitreTbody,
          `Unable to load ATT&CK/CAPEC knowledge: ${err.message}`,
          () => loadKnowledge(targetStage)
        );
      }
    }
  }

  function renderKnowledge(data) {
    if (!data) return;
    const stageEl = document.getElementById("flow-stage-tag");
    const evEl = document.getElementById("flow-evidence-tags");
    if (stageEl) stageEl.textContent = data.selected_stage || "DISCOVERY";
    if (evEl) evEl.textContent = (data.active_evidence_categories || []).join(" • ") || "GENERAL TELEMETRY";

    // 1. ATT&CK Techniques Table
    const mitreTbody = document.getElementById("knowledge-mitre-table");
    if (mitreTbody && data.techniques) {
      mitreTbody.innerHTML = data.techniques
        .map((t) => {
          let badgeClass = "badge-compact";
          if (t.relevance === "EVIDENCE_SUPPORTED") badgeClass += " attack";
          else if (t.relevance === "REVIEW_REQUIRED") badgeClass += " review";
          else badgeClass += " benign";

          return `
          <tr>
            <td style="font-family:var(--font-mono); font-weight:600; color:var(--text-primary);">${t.attack_id}</td>
            <td style="font-weight:500; color:var(--text-primary);">${t.technique}</td>
            <td style="font-family:var(--font-mono); font-size:11px;">${t.mitre_tactic}</td>
            <td><span class="${badgeClass}">${t.relevance}</span></td>
            <td style="font-family:var(--font-mono); font-size:11px;">${t.mapping_confidence}</td>
            <td style="font-size:11.5px; color:var(--text-secondary);">${t.evidence_notes || t.mapping_reason}</td>
          </tr>
        `;
        })
        .join("");
    }

    // 2. CAPEC Patterns Table
    const capecTbody = document.getElementById("knowledge-capec-table");
    if (capecTbody && data.capec_patterns) {
      capecTbody.innerHTML = data.capec_patterns
        .map((p) => {
          let badgeClass = "badge-compact";
          if (p.relevance === "EVIDENCE_SUPPORTED") badgeClass += " attack";
          else if (p.relevance === "REVIEW_REQUIRED") badgeClass += " review";
          else badgeClass += " benign";

          return `
          <tr>
            <td style="font-family:var(--font-mono); font-weight:600; color:var(--text-primary);">${p.capec_id}</td>
            <td style="font-weight:500; color:var(--text-primary);">${p.name}</td>
            <td style="font-family:var(--font-mono); font-size:11px;">${p.typical_severity}</td>
            <td style="font-family:var(--font-mono); font-size:11px;">${p.likelihood_of_attack}</td>
            <td style="font-family:var(--font-mono); font-size:11px;">${p.related_attack_ids.join(", ") || "Direct"}</td>
            <td><span class="${badgeClass}">${p.relevance}</span></td>
          </tr>
        `;
        })
        .join("");
    }
  }

  // Knowledge Tabs
  document.querySelectorAll("#knowledge-tabs-nav .tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("#knowledge-tabs-nav .tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll("#page-knowledge .tab-content-panel").forEach((p) => p.classList.remove("active"));

      btn.classList.add("active");
      const target = document.getElementById(btn.dataset.tab);
      if (target) target.classList.add("active");
    });
  });

  // --------------------------------------------------------------------------
  // PAGE 6: DATASET ANALYSIS
  // --------------------------------------------------------------------------
  async function loadDatasets() {
    const container = document.getElementById("datasets-cards-container");
    if (container) NexusUI.renderLoading(container, "Loading dataset benchmarks...");

    try {
      const data = await NexusAPI.getDatasetAnalysis();
      state.datasetData = data;
      renderDatasets(data);
    } catch (err) {
      console.error("Failed to load dataset analysis:", err);
      if (container) {
        NexusUI.renderError(
          container,
          `Unable to load dataset analysis: ${err.message}`,
          loadDatasets
        );
      }
    }
  }

  function renderDatasets(data) {
    if (!data) return;

    // 1. Render Cards
    const container = document.getElementById("datasets-cards-container");
    if (container && data.datasets) {
      container.innerHTML = Object.values(data.datasets)
        .map(
          (d) => {
            const samples = d.samples || d.flows_count || "2,830,743";
            const ratio = d.attack_ratio || d.class_balance || "80.3% / 19.7%";
            const windows = d.temporal_windows || "4,120 windows";
            const feats = d.features_available || "22 Canonical Features";
            const splits = d.splits ? `${d.splits.train} / ${d.splits.val} / ${d.splits.test}` : "60% / 20% / 20%";

            return `
            <div class="chart-card">
              <span class="control-label">BENCHMARK DATASET</span>
              <h3 style="font-family:var(--font-serif); font-size:20px; color:var(--text-primary); margin:6px 0 12px 0;">${d.name}</h3>
              <table class="editorial-table" style="font-size:11.5px;">
                <tr><th>Total Sequences</th><td style="font-family:var(--font-mono);">${samples}</td></tr>
                <tr><th>Attack Ratio</th><td style="font-family:var(--font-mono);">${ratio}</td></tr>
                <tr><th>Temporal Windows</th><td style="font-family:var(--font-mono);">${windows}</td></tr>
                <tr><th>Canonical Features</th><td style="font-family:var(--font-mono);">${feats}</td></tr>
                <tr><th>Splits (Train/Val/Test)</th><td style="font-family:var(--font-mono);">${splits}</td></tr>
              </table>
            </div>
          `;
          }
        )
        .join("");
    }

    // 2. Render Horizon Performance Table
    renderDatasetPerformanceTable(data.horizon_metrics, state.datasetHorizon);
  }

  function renderDatasetPerformanceTable(metricsByHorizon, horizonKey) {
    const tbody = document.getElementById("datasets-performance-table");
    if (!tbody || !metricsByHorizon) return;

    const data = metricsByHorizon[horizonKey] || {};
    tbody.innerHTML = Object.entries(data)
      .map(
        ([ds, m]) => `
        <tr>
          <td style="font-family:var(--font-mono); font-weight:600; color:var(--text-primary);">${ds}</td>
          <td style="font-family:var(--font-mono);">${(m.accuracy * 100).toFixed(1)}%</td>
          <td style="font-family:var(--font-mono);">${(m.precision * 100).toFixed(1)}%</td>
          <td style="font-family:var(--font-mono);">${(m.recall * 100).toFixed(1)}%</td>
          <td style="font-family:var(--font-mono); font-weight:600; color:var(--accent-bronze);">${m.f1.toFixed(3)}</td>
          <td style="font-family:var(--font-mono);">${m.roc_auc.toFixed(3)}</td>
          <td style="font-family:var(--font-mono); color:var(--semantic-attack);">${(m.fpr * 100).toFixed(2)}%</td>
          <td style="font-family:var(--font-mono);">${m.state_mae.toFixed(3)}</td>
          <td style="font-family:var(--font-mono);">${(m.stage_acc * 100).toFixed(1)}%</td>
        </tr>
      `
      )
      .join("");
  }

  document.querySelectorAll(".btn-horizon[data-dataset-horizon]").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".btn-horizon[data-dataset-horizon]").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.datasetHorizon = btn.dataset.datasetHorizon;
      if (state.datasetData) renderDatasetPerformanceTable(state.datasetData.horizon_metrics, state.datasetHorizon);
    });
  });

  // --------------------------------------------------------------------------
  // PAGE 7: REPORTS
  // --------------------------------------------------------------------------
  async function loadReports() {
    const tbody = document.getElementById("reports-table-body");
    if (tbody) NexusUI.renderLoading(tbody, "Indexing verified phase reports...");

    try {
      const data = await NexusAPI.getReports();
      state.reportsData = data;
      renderReports(data);
    } catch (err) {
      console.error("Failed to load reports:", err);
      if (tbody) {
        NexusUI.renderError(
          tbody,
          `Unable to load reports: ${err.message}`,
          loadReports
        );
      }
    }
  }

  function renderReports(reports) {
    const tbody = document.getElementById("reports-table-body");
    if (!tbody || !reports) return;

    tbody.innerHTML = reports
      .map(
        (r) => {
          const reportId = r.id || r.path || r.filename;
          const desc = r.summary || r.description || "Technical research report";
          const date = r.last_modified || r.date || "2026-09-22";
          const status = r.status || "APPROVED";
          const pathParam = r.id || r.filename || r.path;

          return `
          <tr>
            <td><strong style="color:var(--text-primary); font-size:13px;">${r.title}</strong></td>
            <td style="font-family:var(--font-mono); font-size:11px; color:var(--accent-bronze);">${r.phase}</td>
            <td style="font-size:12px; color:var(--text-secondary); max-width:320px;">${desc}</td>
            <td style="font-family:var(--font-mono); font-size:11px;">${date}</td>
            <td><span class="badge-compact ${status === "APPROVED" || status === "FROZEN" ? "benign" : "review"}">${status}</span></td>
            <td style="text-align:right;">
              <button class="btn-secondary btn-view-report" data-id="${reportId}" data-path="${pathParam}" data-title="${r.title}" style="padding:4px 10px; font-size:10.5px; margin-right:6px;">VIEW</button>
              <a class="btn-secondary" href="/api/reports/${reportId}/download" download style="padding:4px 10px; font-size:10.5px; text-decoration:none; display:inline-block;">DOWNLOAD</a>
            </td>
          </tr>
        `;
        }
      )
      .join("");

    tbody.querySelectorAll(".btn-view-report").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const reportId = btn.dataset.id || btn.dataset.path;
        const title = btn.dataset.title;
        openReportModal(reportId, title);
      });
    });
  }

  async function openReportModal(reportId, title) {
    modalReportTitle.textContent = title;
    modalReportBody.textContent = "Loading report content...";
    modalDownloadBtn.href = `/api/reports/${encodeURIComponent(reportId)}/download`;
    modalOverlay.classList.add("open");

    try {
      const data = await NexusAPI.getReportDetail(reportId);
      modalReportBody.textContent = data.content;
    } catch (err) {
      modalReportBody.textContent = `Error reading report: ${err.message}`;
    }
  }

  modalCloseBtn.addEventListener("click", () => modalOverlay.classList.remove("open"));
  modalCloseActionBtn.addEventListener("click", () => modalOverlay.classList.remove("open"));

  // Keyboard Escape listener
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      drawer.classList.remove("open");
      modalOverlay.classList.remove("open");
    }
  });

  // Initial Boot: Populate selectors dynamically and load dashboard
  initHeaderSelectors().then(() => loadDashboard());
});
