// Recon6_Suite Enterprise Dashboard — lógica de front-end
// Consume window.RECON6_DATA (inyectado por index.html desde resumen_json)

(function () {
  const DATA = window.RECON6_DATA || {};
  const ACCENT = "#FACC15";
  const GRID_COLOR = "rgba(255,255,255,0.06)";
  const TEXT_MUTED = "#9CA3AF";

  if (typeof Chart !== "undefined") {
    Chart.defaults.color = TEXT_MUTED;
    Chart.defaults.font.family = "Segoe UI, Inter, sans-serif";
  }

  // ---------- Toasts ----------
  window.showToast = function (msg, type = "info") {
    const stack = document.getElementById("toast-stack");
    if (!stack) return;
    const el = document.createElement("div");
    el.className = `toast ${type}`;
    el.textContent = msg;
    stack.appendChild(el);
    setTimeout(() => el.remove(), 4500);
  };

  // ---------- KPI count-up ----------
  function animateValue(el, end) {
    const start = 0;
    const duration = 700;
    const startTime = performance.now();
    function tick(now) {
      const progress = Math.min((now - startTime) / duration, 1);
      const value = Math.floor(start + (end - start) * progress);
      el.textContent = value;
      if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  document.querySelectorAll("[data-kpi-value]").forEach((el) => {
    const end = parseInt(el.getAttribute("data-kpi-value"), 10) || 0;
    animateValue(el, end);
  });

  // ---------- Radar Chart: Attack Surface ----------
  const radarCtx = document.getElementById("radarChart");
  if (radarCtx && DATA.radar && typeof Chart !== "undefined") {
    const labels = Object.keys(DATA.radar);
    const values = Object.values(DATA.radar);
    new Chart(radarCtx, {
      type: "radar",
      data: {
        labels,
        datasets: [{
          label: "Attack Surface",
          data: values,
          backgroundColor: "rgba(250,204,21,0.18)",
          borderColor: ACCENT,
          pointBackgroundColor: ACCENT,
          borderWidth: 2,
        }],
      },
      options: {
        responsive: true,
        scales: {
          r: {
            angleLines: { color: GRID_COLOR },
            grid: { color: GRID_COLOR },
            pointLabels: { color: TEXT_MUTED, font: { size: 10 } },
            ticks: { display: false, backdropColor: "transparent" },
            suggestedMin: 0, suggestedMax: 100,
          },
        },
        plugins: { legend: { display: false } },
      },
    });
  }

  // ---------- Doughnut: Technology Distribution ----------
  const donutCtx = document.getElementById("techDoughnut");
  if (donutCtx && DATA.doughnut && typeof Chart !== "undefined") {
    const entries = Object.entries(DATA.doughnut).filter(([, v]) => v > 0);
    const hasData = entries.length > 0;
    new Chart(donutCtx, {
      type: "doughnut",
      data: {
        labels: hasData ? entries.map((e) => e[0]) : ["Sin datos"],
        datasets: [{
          data: hasData ? entries.map((e) => e[1]) : [1],
          backgroundColor: hasData
            ? ["#FACC15", "#38BDF8", "#A78BFA", "#34D399", "#F87171", "#9CA3AF"]
            : ["#1F2937"],
          borderColor: "#0B0F14",
          borderWidth: 3,
        }],
      },
      options: {
        responsive: true,
        cutout: "65%",
        plugins: { legend: { position: "bottom", labels: { boxWidth: 10, font: { size: 11 } } } },
      },
    });
  }

  // ---------- Line: Historical Risk ----------
  const lineCtx = document.getElementById("riskLine");
  if (lineCtx && typeof Chart !== "undefined") {
    const history = DATA.history || [];
    const labels = history.length
      ? history.map((h) => (h.timestamp || "").split("T")[1] || h.timestamp)
      : ["Sin historial"];
    const values = history.length ? history.map((h) => h.risk_score) : [0];
    new Chart(lineCtx, {
      type: "line",
      data: {
        labels,
        datasets: [{
          label: "Risk Score",
          data: values,
          borderColor: ACCENT,
          backgroundColor: "rgba(250,204,21,0.12)",
          tension: 0.35,
          fill: true,
          pointRadius: 3,
          pointBackgroundColor: ACCENT,
        }],
      },
      options: {
        responsive: true,
        scales: {
          x: { grid: { color: GRID_COLOR }, ticks: { maxRotation: 0, font: { size: 9 } } },
          y: { min: 0, max: 100, grid: { color: GRID_COLOR } },
        },
        plugins: { legend: { display: false } },
      },
    });
  }

  // ---------- vis-network: Attack Surface Graph ----------
  const graphContainer = document.getElementById("graph-container");
  if (graphContainer && DATA.graph && DATA.graph.nodes && DATA.graph.nodes.length && typeof vis !== "undefined") {
    const groupColors = {
      domain: { background: "#FACC15", border: "#b8860b", font: "#1a1400" },
      subdomain: { background: "#38BDF8", border: "#0369A1", font: "#031521" },
      port: { background: "#F87171", border: "#991B1B", font: "#2b0505" },
      technology: { background: "#A78BFA", border: "#5B21B6", font: "#160a2e" },
      info: { background: "#34D399", border: "#065F46", font: "#04140d" },
      vulnerable: { background: "#EF4444", border: "#7F1D1D", font: "#fff" },
    };
    const nodes = new vis.DataSet(
      DATA.graph.nodes.map((n) => {
        const c = groupColors[n.group] || groupColors.info;
        return {
          id: n.id, label: n.label,
          shape: n.group === "domain" ? "dot" : "dot",
          size: n.group === "domain" ? 26 : 14,
          color: { background: c.background, border: c.border, highlight: { background: c.background, border: "#fff" } },
          font: { color: "#F9FAFB", size: 11 },
          title: `${n.group.toUpperCase()}: ${n.label}`,
        };
      })
    );
    const edges = new vis.DataSet(
      DATA.graph.edges.map((e) => ({ from: e.from, to: e.to, color: { color: "#1F2937", highlight: ACCENT }, width: 1.2 }))
    );
    new vis.Network(graphContainer, { nodes, edges }, {
      physics: { solver: "forceAtlas2Based", forceAtlas2Based: { springLength: 90, gravitationalConstant: -60 }, stabilization: { iterations: 120 } },
      interaction: { hover: true, tooltipDelay: 80, dragNodes: true, zoomView: true },
      layout: { improvedLayout: true },
    });
  } else if (graphContainer) {
    graphContainer.innerHTML = '<div class="empty-state">Sin activos relacionados todavía. Ejecuta un escaneo (Nmap, Subdominios o Tecnologías) para construir el grafo.</div>';
  }

  // ---------- Technical table: search + sort + pagination ----------
  const tableData = DATA.table || [];
  const tbody = document.getElementById("tech-table-body");
  const searchInput = document.getElementById("table-search");
  const pagination = document.getElementById("table-pagination");
  const PAGE_SIZE = 6;
  let currentPage = 1;
  let sortKey = null;
  let sortDir = 1;

  function renderTable() {
    if (!tbody) return;
    let rows = [...tableData];
    const q = (searchInput?.value || "").toLowerCase();
    if (q) {
      rows = rows.filter((r) => Object.values(r).some((v) => String(v).toLowerCase().includes(q)));
    }
    if (sortKey) {
      rows.sort((a, b) => (a[sortKey] > b[sortKey] ? sortDir : a[sortKey] < b[sortKey] ? -sortDir : 0));
    }
    const totalPages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
    currentPage = Math.min(currentPage, totalPages);
    const start = (currentPage - 1) * PAGE_SIZE;
    const pageRows = rows.slice(start, start + PAGE_SIZE);

    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="8"><div class="empty-state">No hay activos que coincidan. Ejecuta un escaneo Nmap para poblar la tabla.</div></td></tr>`;
    } else {
      tbody.innerHTML = pageRows.map((r) => `
        <tr>
          <td>${r.host || "-"}</td>
          <td>${r.ip || "-"}</td>
          <td>${r.port}</td>
          <td>${r.service || "-"}</td>
          <td><span class="badge low">${r.state}</span></td>
          <td>${r.technology || "-"}</td>
          <td><span class="badge ${r.severity}">${r.severity}</span></td>
          <td>${(r.last_seen || "").replace("T", " ")}</td>
        </tr>
      `).join("");
    }

    if (pagination) {
      let html = "";
      for (let i = 1; i <= totalPages; i++) {
        html += `<button data-page="${i}" class="${i === currentPage ? "active" : ""}">${i}</button>`;
      }
      pagination.innerHTML = html;
      pagination.querySelectorAll("button").forEach((btn) => {
        btn.addEventListener("click", () => { currentPage = parseInt(btn.dataset.page, 10); renderTable(); });
      });
    }
  }

  if (tbody) {
    renderTable();
    searchInput?.addEventListener("input", () => { currentPage = 1; renderTable(); });
    document.querySelectorAll("th[data-sort]").forEach((th) => {
      th.addEventListener("click", () => {
        const key = th.getAttribute("data-sort");
        sortDir = sortKey === key ? -sortDir : 1;
        sortKey = key;
        renderTable();
      });
    });
  }

  // ---------- Scan form: loading state ----------
  const scanForm = document.getElementById("scan-form");
  if (scanForm) {
    scanForm.addEventListener("submit", () => {
      const btn = document.getElementById("scan-btn");
      if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Escaneando...';
      }
      document.querySelectorAll(".skeleton-target").forEach((el) => el.classList.add("skeleton"));
      window.showToast("Escaneo iniciado…", "info");
    });
  }

  // ---------- Mobile sidebar toggle ----------
  const mobileToggle = document.getElementById("mobile-toggle");
  const sidebar = document.getElementById("sidebar");
  let backdrop = document.getElementById("sidebar-backdrop");
  if (!backdrop && sidebar) {
    backdrop = document.createElement("div");
    backdrop.id = "sidebar-backdrop";
    document.body.appendChild(backdrop);
  }

  function openSidebar() {
    sidebar?.classList.add("open");
    backdrop?.classList.add("visible");
    if (mobileToggle) mobileToggle.textContent = "✕ Cerrar";
  }
  function closeSidebar() {
    sidebar?.classList.remove("open");
    backdrop?.classList.remove("visible");
    if (mobileToggle) mobileToggle.textContent = "☰ Menú";
  }

  mobileToggle?.addEventListener("click", () => {
    sidebar?.classList.contains("open") ? closeSidebar() : openSidebar();
  });
  backdrop?.addEventListener("click", closeSidebar);
  sidebar?.querySelectorAll(".nav-item").forEach((item) => {
    item.addEventListener("click", () => { if (window.innerWidth <= 980) closeSidebar(); });
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeSidebar(); });
  window.addEventListener("resize", () => { if (window.innerWidth > 980) closeSidebar(); });

  if (DATA.target) {
    window.showToast(`Dashboard actualizado para ${DATA.target}`, "success");
  }

  // ---------- Threat Intelligence buttons ----------
  const intelOutput = document.getElementById("intel-output");
  document.querySelectorAll(".intel-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const service = btn.dataset.service;
      const target = DATA.target;
      if (!target) { window.showToast("Ejecuta primero un escaneo para tener un target activo.", "error"); return; }
      intelOutput.style.display = "block";
      intelOutput.textContent = `Consultando ${service}…`;
      try {
        const resp = await fetch(`/intel/${service}?target=${encodeURIComponent(target)}`);
        const data = await resp.json();
        intelOutput.textContent = data.resultado || "Sin respuesta.";
      } catch (e) {
        intelOutput.textContent = `Error consultando ${service}: ${e}`;
      }
    });
  });

  // ---------- Screenshot button ----------
  const screenshotBtn = document.getElementById("screenshot-btn");
  const screenshotResult = document.getElementById("screenshot-result");
  screenshotBtn?.addEventListener("click", async () => {
    const target = DATA.target;
    if (!target) { window.showToast("Ejecuta primero un escaneo para tener un target activo.", "error"); return; }
    screenshotBtn.disabled = true;
    screenshotBtn.innerHTML = '<span class="spinner"></span> Capturando...';
    screenshotResult.innerHTML = "";
    try {
      const form = new FormData();
      form.append("target", target);
      const resp = await fetch("/screenshot", { method: "POST", body: form });
      const data = await resp.json();
      if (data.ok) {
        screenshotResult.innerHTML = `<img src="${data.url}" style="max-width:100%;border-radius:10px;border:1px solid var(--border-color);">`;
        window.showToast("Captura lista", "success");
      } else {
        screenshotResult.innerHTML = `<div class="console-output">${data.mensaje}</div>`;
        window.showToast("No se pudo capturar", "error");
      }
    } catch (e) {
      screenshotResult.innerHTML = `<div class="console-output">Error: ${e}</div>`;
    } finally {
      screenshotBtn.disabled = false;
      screenshotBtn.innerHTML = "📸 Capturar pantalla";
    }
  });
})();
