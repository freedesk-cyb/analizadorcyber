/**
 * AI Web Security Analyzer - Frontend Logic
 */

document.addEventListener("DOMContentLoaded", () => {
  // Estado de la aplicación
  let currentScanId = null;
  let eventSource = null;
  let currentScanData = null;
  let activeFindingsFilter = "ALL";

  // Elementos DOM Principales
  const scanForm = document.getElementById("scan-form");
  const targetUrlInput = document.getElementById("target-url-input");
  const checkAuthorized = document.getElementById("check-authorized");
  const checkEnableNmap = document.getElementById("check-enable-nmap");
  const checkEnableNse = document.getElementById("check-enable-nse");
  const checkEnableZap = document.getElementById("check-enable-zap");
  const btnStartScan = document.getElementById("btn-start-scan");
  const btnScanText = document.getElementById("btn-scan-text");

  // Secciones
  const scanningSection = document.getElementById("scanning-section");
  const resultsSection = document.getElementById("results-section");
  const scanCurrentStep = document.getElementById("scan-current-step");
  const scanTargetDisplay = document.getElementById("scan-target-display");
  const scanProgressBar = document.getElementById("scan-progress-bar");
  const scanProgressText = document.getElementById("scan-progress-text");
  const scanTimerText = document.getElementById("scan-timer-text");
  const terminalLogs = document.getElementById("terminal-logs");

  // Botones de acción
  const btnNewScan = document.getElementById("btn-new-scan");
  const btnPrintReport = document.getElementById("btn-print-report");
  const btnDownloadJson = document.getElementById("btn-download-json");
  const btnShowHistory = document.getElementById("btn-show-history");
  const modalHistory = document.getElementById("modal-history");
  const btnCloseModal = document.getElementById("btn-close-modal");
  const modalHistoryBody = document.getElementById("modal-history-body");

  // Pestañas
  const tabButtons = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");
  const filterButtons = document.querySelectorAll(".filter-btn");
  const severityPills = document.querySelectorAll(".severity-pill");
  const snippetTabButtons = document.querySelectorAll(".snippet-tab-btn");
  const snippetBoxes = document.querySelectorAll(".snippet-box");
  const presetButtons = document.querySelectorAll(".preset-btn");

  // Temporizador de escaneo
  let scanTimerInterval = null;
  let scanStartTime = null;

  // 1. Inicialización
  checkSystemStatus();

  // 2. Presets de objetivos
  presetButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      targetUrlInput.value = btn.dataset.url;
      targetUrlInput.focus();
    });
  });

  // 3. Manejo de Inicio de Escaneo
  scanForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = targetUrlInput.value.trim();
    if (!url) return;

    if (!checkAuthorized.checked) {
      alert("Por favor confirme la autorización de análisis para continuar.");
      return;
    }

    startScan(url);
  });

  async function startScan(targetUrl) {
    // Resetear vistas
    scanningSection.style.display = "block";
    resultsSection.style.display = "none";
    terminalLogs.innerHTML = "";
    scanProgressBar.style.width = "5%";
    scanProgressText.textContent = "5% Iniciando...";
    scanCurrentStep.textContent = "Iniciando pipeline de análisis...";
    scanTargetDisplay.textContent = `Objetivo: ${targetUrl}`;
    
    // Deshabilitar botón
    btnStartScan.disabled = true;
    btnScanText.textContent = "Analizando...";

    // Iniciar temporizador
    scanStartTime = Date.now();
    if (scanTimerInterval) clearInterval(scanTimerInterval);
    scanTimerInterval = setInterval(() => {
      const elapsed = ((Date.now() - scanStartTime) / 1000).toFixed(1);
      scanTimerText.textContent = `${elapsed}s`;
    }, 100);

    // Scroll suave hacia la sección de escaneo
    scanningSection.scrollIntoView({ behavior: "smooth" });

    try {
      const payload = {
        url: targetUrl,
        authorized: checkAuthorized.checked,
        enable_nmap: checkEnableNmap.checked,
        enable_nmap_nse: checkEnableNmap.checked && checkEnableNse.checked,
        enable_zap: checkEnableZap.checked,
      };

      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.detail || "Error al iniciar la auditoría.");
      }

      const data = await response.json();
      currentScanId = data.scan_id;
      addTerminalLog(`[+] Auditoría creada con éxito. ID de sesión: ${currentScanId}`, "info");

      // Escuchar flujo SSE en tiempo real
      initEventStream(currentScanId);

    } catch (err) {
      clearInterval(scanTimerInterval);
      addTerminalLog(`[-] Error: ${err.message}`, "error");
      btnStartScan.disabled = false;
      btnScanText.textContent = "Iniciar Auditoría";
      alert(`Error al iniciar análisis: ${err.message}`);
    }
  }

  // 4. Stream de Eventos en Vivo (SSE)
  function initEventStream(scanId) {
    if (eventSource) eventSource.close();

    eventSource = new EventSource(`/api/scan/${scanId}/stream`);

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);

        if (data.progress !== undefined) {
          scanProgressBar.style.width = `${data.progress}%`;
          scanProgressText.textContent = `${data.progress}% Completado`;
        }

        if (data.current_step) {
          scanCurrentStep.textContent = data.current_step;
        }

        if (data.log) {
          const logType = data.log.message.startsWith("[-]") ? "error" :
                          data.log.message.startsWith("[!]") ? "warn" :
                          data.log.message.startsWith("[+]") ? "success" : "info";
          addTerminalLog(`[${data.log.timestamp}] ${data.log.message}`, logType);
        }

        // Finalización
        if (data.completed || data.status === "COMPLETED" || data.status === "FAILED") {
          eventSource.close();
          clearInterval(scanTimerInterval);
          setTimeout(() => {
            fetchFullResults(scanId);
          }, 600);
        }
      } catch (e) {
        console.error("Error parseando SSE:", e);
      }
    };

    eventSource.onerror = () => {
      eventSource.close();
      // Polling de respaldo en caso de desconexión SSE
      pollFallback(scanId);
    };
  }

  async function pollFallback(scanId) {
    const interval = setInterval(async () => {
      try {
        const resp = await fetch(`/api/scan/${scanId}`);
        if (!resp.ok) return;
        const scan = await resp.json();
        
        scanProgressBar.style.width = `${scan.progress}%`;
        scanProgressText.textContent = `${scan.progress}%`;
        scanCurrentStep.textContent = scan.current_step;

        if (scan.status === "COMPLETED" || scan.status === "FAILED") {
          clearInterval(interval);
          clearInterval(scanTimerInterval);
          renderResults(scan);
        }
      } catch (e) {
        clearInterval(interval);
      }
    }, 1500);
  }

  async function fetchFullResults(scanId) {
    try {
      const resp = await fetch(`/api/scan/${scanId}`);
      if (!resp.ok) throw new Error("No se pudo obtener el reporte completo.");
      const scanData = await resp.json();
      renderResults(scanData);
    } catch (err) {
      alert(`Error obteniendo resultados: ${err.message}`);
    } finally {
      btnStartScan.disabled = false;
      btnScanText.textContent = "Iniciar Auditoría";
    }
  }

  // 5. Renderizado Completo del Dashboard
  function renderResults(scan) {
    currentScanData = scan;
    scanningSection.style.display = "none";
    resultsSection.style.display = "block";
    resultsSection.scrollIntoView({ behavior: "smooth" });

    // Notificar al chatbot IA sobre el reporte disponible
    if (typeof notifyChatScanReady === 'function') {
      notifyChatScanReady(scan.scan_id, scan.status);
    }

    // Barra superior
    document.getElementById("res-target-domain").textContent = scan.domain;
    document.getElementById("res-target-url").textContent = scan.normalized_url;
    document.getElementById("res-scan-duration").textContent = `${scan.scan_duration_seconds}s`;
    document.getElementById("res-scan-timestamp").textContent = new Date(scan.scan_timestamp).toLocaleString();

    const statusCodeEl = document.getElementById("res-target-status-code");
    if (scan.http_analysis && scan.http_analysis.status_code) {
      statusCodeEl.textContent = `HTTP ${scan.http_analysis.status_code}`;
      statusCodeEl.className = scan.http_analysis.status_code < 400 ? "badge badge-success" : "badge badge-warning";
    } else {
      statusCodeEl.textContent = "Sin Respuesta";
      statusCodeEl.className = "badge badge-danger";
    }

    // AI & Security Score Card
    const aiReport = scan.ai_report || {
      security_score: 50,
      security_grade: "C",
      risk_counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
      findings: [],
      executive_summary: "No se generó resumen.",
      priority_action_plan: [],
      configuration_snippets: {},
    };

    renderScoreGauge(aiReport.security_score, aiReport.security_grade);

    // Contadores de Severidad
    document.getElementById("count-critical").textContent = aiReport.risk_counts.CRITICAL || 0;
    document.getElementById("count-high").textContent = aiReport.risk_counts.HIGH || 0;
    document.getElementById("count-medium").textContent = aiReport.risk_counts.MEDIUM || 0;
    document.getElementById("count-low").textContent = aiReport.risk_counts.LOW || 0;
    document.getElementById("count-info").textContent = aiReport.risk_counts.INFO || 0;
    document.getElementById("res-total-findings-count").textContent = `${aiReport.findings.length} Hallazgos`;

    // Badges en pestañas
    document.getElementById("badge-headers-count").textContent = scan.http_analysis ? scan.http_analysis.security_headers.length : 0;
    document.getElementById("badge-cookies-count").textContent = scan.cookie_analysis ? scan.cookie_analysis.length : 0;
    document.getElementById("badge-ssl-grade").textContent = scan.ssl_analysis ? scan.ssl_analysis.grade : "N/A";
    document.getElementById("badge-ports-count").textContent = scan.network_analysis ? scan.network_analysis.open_ports.length : 0;

    // Resumen de Postura Rápido
    renderQuickPosture(scan);

    // Pestaña 1: AI Report
    renderAiReportTab(aiReport);

    // Pestaña 2: HTTP & Headers
    renderHttpTab(scan.http_analysis);

    // Pestaña 3: Cookies
    renderCookiesTab(scan.cookie_analysis);

    // Pestaña 4: SSL/TLS
    renderSslTab(scan.ssl_analysis);

    // Pestaña 5: Red & Puertos
    renderNetworkTab(scan.network_analysis);

    // Pestaña 6: Snippets de Configuración
    renderSnippetsTab(aiReport.configuration_snippets);

    // Pestaña 7: Raw JSON
    document.getElementById("raw-json-content").textContent = JSON.stringify(scan, null, 2);
  }

  // 6. Gauge Circular de Seguridad
  function renderScoreGauge(score, grade) {
    const scoreNumEl = document.getElementById("res-score-number");
    const scoreGradeEl = document.getElementById("res-score-grade");
    const gaugeCircle = document.getElementById("score-gauge-circle");
    const scoreInterp = document.getElementById("res-score-interpretation");

    scoreNumEl.textContent = score;
    scoreGradeEl.textContent = grade;

    // Circunferencia del círculo r=68 -> 2 * PI * 68 ≈ 427.25
    const circumference = 427.25;
    const offset = circumference - (score / 100) * circumference;
    gaugeCircle.style.strokeDashoffset = offset;

    // Colores dinámicos según el score
    let strokeColor = "var(--emerald)";
    let interpText = "Excelente Postura de Seguridad";

    if (score < 40) {
      strokeColor = "var(--crimson)";
      interpText = "Postura Crítica - Vulnerabilidades Graves";
    } else if (score < 60) {
      strokeColor = "#ff6b4a";
      interpText = "Postura Deficiente - Requiere Atención Urgente";
    } else if (score < 75) {
      strokeColor = "var(--amber)";
      interpText = "Postura Moderada - Varias Oportunidades de Mejora";
    } else if (score < 90) {
      strokeColor = "var(--cyan)";
      interpText = "Postura Satisfactoria - Controles Básicos Activos";
    }

    gaugeCircle.style.stroke = strokeColor;
    scoreInterp.textContent = interpText;
  }

  // 7. Controles de Postura Rápidos
  function renderQuickPosture(scan) {
    const list = document.getElementById("res-posture-quick-list");
    list.innerHTML = "";

    const items = [
      {
        label: "Cifrado HTTPS / TLS",
        ok: scan.ssl_analysis && scan.ssl_analysis.has_https && !scan.ssl_analysis.is_expired,
        text: scan.ssl_analysis && scan.ssl_analysis.has_https ? (scan.ssl_analysis.protocol_version || "Activo") : "Inactivo",
      },
      {
        label: "Cabecera HSTS",
        ok: scan.http_analysis && scan.http_analysis.security_headers.some(h => h.header === "Strict-Transport-Security" && h.present),
        text: scan.http_analysis && scan.http_analysis.security_headers.some(h => h.header === "Strict-Transport-Security" && h.present) ? "Protegido" : "Faltante",
      },
      {
        label: "Content-Security-Policy",
        ok: scan.http_analysis && scan.http_analysis.security_headers.some(h => h.header === "Content-Security-Policy" && h.present),
        text: scan.http_analysis && scan.http_analysis.security_headers.some(h => h.header === "Content-Security-Policy" && h.present) ? "Definida" : "Sin CSP",
      },
      {
        label: "Protección Clickjacking",
        ok: scan.http_analysis && scan.http_analysis.security_headers.some(h => h.header === "X-Frame-Options" && h.present),
        text: scan.http_analysis && scan.http_analysis.security_headers.some(h => h.header === "X-Frame-Options" && h.present) ? "Bloqueado" : "Vulnerable",
      },
      {
        label: "Seguridad DNS (SPF/DMARC)",
        ok: scan.network_analysis && (scan.network_analysis.spf_configured || scan.network_analysis.dmarc_configured),
        text: scan.network_analysis && scan.network_analysis.spf_configured && scan.network_analysis.dmarc_configured ? "Completo" : "Parcial / Ausente",
      },
    ];

    items.forEach(it => {
      const div = document.createElement("div");
      div.className = "posture-item";
      div.innerHTML = `
        <span class="posture-label"><i class="fa-solid fa-${it.ok ? 'shield-check' : 'shield-xmark'}"></i> ${it.label}</span>
        <span class="posture-status-badge ${it.ok ? 'ok' : 'bad'}">${it.text}</span>
      `;
      list.appendChild(div);
    });
  }

  // 8. Render Pestaña 1: IA Report & Findings
  function renderAiReportTab(aiReport) {
    // Markdown a HTML básico para el resumen
    const summaryBox = document.getElementById("res-ai-summary-text");
    summaryBox.innerHTML = formatMarkdown(aiReport.executive_summary);

    // Plan de acción prioritario
    const actionList = document.getElementById("res-priority-actions");
    actionList.innerHTML = "";
    (aiReport.priority_action_plan || []).forEach((act, idx) => {
      const card = document.createElement("div");
      card.className = "priority-action-card";
      card.innerHTML = `
        <div class="action-num">${idx + 1}</div>
        <div class="action-text">${act}</div>
      `;
      actionList.appendChild(card);
    });

    // Renderizar Hallazgos con filtro
    renderFindingsList(aiReport.findings);
  }

  function renderFindingsList(findings) {
    const container = document.getElementById("res-findings-accordion");
    container.innerHTML = "";

    const filtered = activeFindingsFilter === "ALL"
      ? findings
      : findings.filter(f => f.severity === activeFindingsFilter);

    if (filtered.length === 0) {
      container.innerHTML = `<div style="padding: 1.5rem; color: var(--text-dim); text-align: center;">No hay hallazgos en la categoría seleccionada (${activeFindingsFilter}).</div>`;
      return;
    }

    filtered.forEach((f, idx) => {
      const card = document.createElement("div");
      card.className = `finding-card ${f.severity.toLowerCase()} ${idx === 0 ? 'open' : ''}`;
      card.dataset.id = f.id;

      card.innerHTML = `
        <div class="finding-header">
          <div class="finding-header-left">
            <span class="finding-badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
            <span class="finding-category-tag">${f.category}</span>
            <span class="finding-title-text">${f.title}</span>
          </div>
          <i class="fa-solid fa-chevron-down finding-chevron"></i>
        </div>
        <div class="finding-body">
          <div class="finding-section">
            <div class="finding-sec-title"><i class="fa-solid fa-circle-info"></i> Descripción & Riesgo</div>
            <p style="color: #cbd5e1; margin-bottom: 0.5rem;">${f.description}</p>
            <p style="color: var(--amber); font-size: 0.85rem;"><strong>Impacto:</strong> ${f.impact}</p>
          </div>
          
          <div class="finding-section">
            <div class="finding-sec-title"><i class="fa-solid fa-magnifying-glass"></i> Evidencia Técnica Recopilada</div>
            <div class="finding-evidence-box">${escapeHtml(f.evidence)}</div>
          </div>

          <div class="finding-section">
            <div class="finding-sec-title"><i class="fa-solid fa-wrench"></i> Guía de Remediación Recomendada</div>
            <div class="finding-remediation-box">${escapeHtml(f.remediation)}</div>
          </div>

          <div class="finding-meta-tags">
            ${f.cwe_id ? `<span class="cwe-tag"><i class="fa-solid fa-bug"></i> ${f.cwe_id}</span>` : ''}
            ${f.owasp_category ? `<span class="owasp-tag"><i class="fa-solid fa-shield-halved"></i> ${f.owasp_category}</span>` : ''}
          </div>
        </div>
      `;

      // Evento de acordeón
      card.querySelector(".finding-header").addEventListener("click", () => {
        card.classList.toggle("open");
      });

      container.appendChild(card);
    });
  }

  // 9. Render Pestaña 2: HTTP & Headers
  function renderHttpTab(httpData) {
    if (!httpData) return;

    document.getElementById("http-status-val").textContent = `${httpData.status_code} ${httpData.status_code === 200 ? 'OK' : ''}`;
    document.getElementById("http-latency-val").textContent = `${httpData.response_time_ms} ms`;
    document.getElementById("http-redirects-val").textContent = `${httpData.redirect_chain.length} saltos`;
    document.getElementById("http-title-val").textContent = httpData.html_title || "Sin título declarado";

    // Tecnologías
    const techContainer = document.getElementById("res-detected-technologies");
    techContainer.innerHTML = "";
    if (httpData.detected_technologies && httpData.detected_technologies.length > 0) {
      httpData.detected_technologies.forEach(t => {
        const pill = document.createElement("div");
        pill.className = "tech-pill";
        pill.innerHTML = `
          <i class="fa-solid fa-microchip"></i>
          <span>${t.name}</span>
          <span class="tech-cat">${t.category}</span>
        `;
        techContainer.appendChild(pill);
      });
    } else {
      techContainer.innerHTML = `<span style="color: var(--text-dim); font-size: 0.85rem;">No se detectaron firmas evidentes de CMS o tecnologías públicas.</span>`;
    }

    // Leaks
    const leaksContainer = document.getElementById("res-server-leaks");
    leaksContainer.innerHTML = "";
    if (httpData.server_info_leaks && httpData.server_info_leaks.length > 0) {
      httpData.server_info_leaks.forEach(leak => {
        const item = document.createElement("div");
        item.className = "leak-item";
        item.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> ${escapeHtml(leak)}`;
        leaksContainer.appendChild(item);
      });
    } else {
      leaksContainer.innerHTML = `<span style="color: var(--emerald); font-size: 0.85rem;"><i class="fa-solid fa-check"></i> No se detectaron cabeceras reveladoras de versiones de servidor.</span>`;
    }

    // Tabla de Cabeceras
    const tbody = document.getElementById("headers-table-body");
    tbody.innerHTML = "";
    (httpData.security_headers || []).forEach(h => {
      const tr = document.createElement("tr");
      const statusClass = h.status === "GOOD" ? "good" : h.status === "WARNING" ? "warning" : "missing";
      const statusIcon = h.status === "GOOD" ? "fa-check" : h.status === "WARNING" ? "fa-triangle-exclamation" : "fa-xmark";

      tr.innerHTML = `
        <td><strong>${h.header}</strong></td>
        <td><span class="status-pill ${statusClass}"><i class="fa-solid ${statusIcon}"></i> ${h.status}</span></td>
        <td><span class="finding-badge badge-${h.severity.toLowerCase()}">${h.severity}</span></td>
        <td><span class="code-badge">${h.value ? escapeHtml(h.value.substring(0, 45) + (h.value.length > 45 ? '...' : '')) : 'No Configurado'}</span></td>
        <td style="font-size: 0.82rem; color: var(--text-muted);">${h.recommendation}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  // 10. Render Pestaña 3: Cookies
  function renderCookiesTab(cookies) {
    const tbody = document.getElementById("cookies-table-body");
    tbody.innerHTML = "";

    if (!cookies || cookies.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-dim); padding: 1.5rem;">No se detectaron cookies emitidas en la respuesta HTTP evaluada.</td></tr>`;
      return;
    }

    cookies.forEach(c => {
      const tr = document.createElement("tr");
      const isOk = c.risk_level === "SECURE";

      tr.innerHTML = `
        <td>
          <strong>${escapeHtml(c.name)}</strong>
          ${c.is_sensitive ? '<span class="tag-cyber" style="margin-left: 0.4rem; font-size: 0.68rem; color: var(--crimson); border-color: var(--crimson);">Sensible / Auth</span>' : ''}
        </td>
        <td><span class="code-badge">${escapeHtml(c.value_masked)}</span></td>
        <td>${c.secure ? '<span class="status-pill good">✓ Secure</span>' : '<span class="status-pill missing">✗ Falta</span>'}</td>
        <td>${c.httponly ? '<span class="status-pill good">✓ HttpOnly</span>' : '<span class="status-pill missing">✗ Falta</span>'}</td>
        <td><span class="code-badge">${c.samesite || 'No definido'}</span></td>
        <td><span class="finding-badge badge-${c.risk_level === 'SECURE' ? 'low' : c.risk_level.toLowerCase()}">${c.risk_level}</span></td>
        <td style="font-size: 0.82rem; color: var(--text-muted);">${c.explanation || '-'}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  // 11. Render Pestaña 4: SSL/TLS
  function renderSslTab(sslData) {
    if (!sslData) return;

    const gradeLarge = document.getElementById("ssl-grade-large");
    gradeLarge.textContent = sslData.grade;
    gradeLarge.className = `ssl-badge-large ${sslData.grade === 'F' ? 'grade-f' : ''}`;

    document.getElementById("ssl-common-name").textContent = sslData.common_name || "Desconocido";
    document.getElementById("ssl-issuer-text").textContent = `Emitido por: ${sslData.issuer.organizationName || sslData.issuer.commonName || 'CA de Confianza'}`;
    document.getElementById("ssl-valid-from").textContent = sslData.valid_from || "-";
    document.getElementById("ssl-valid-to").textContent = sslData.valid_to || "-";
    document.getElementById("ssl-days-left").textContent = `${sslData.days_left || 0} días`;
    document.getElementById("ssl-protocol").textContent = sslData.protocol_version || "N/A";
    document.getElementById("ssl-cipher").textContent = sslData.cipher_suite || "N/A";
    document.getElementById("ssl-has-https").textContent = sslData.has_https ? "Habilitado (Puerto 443)" : "No Disponible";

    // SANs
    const sansList = document.getElementById("ssl-sans-list");
    sansList.innerHTML = "";
    if (sslData.san_list && sslData.san_list.length > 0) {
      sslData.san_list.forEach(san => {
        const span = document.createElement("span");
        span.className = "san-pill";
        span.textContent = san;
        sansList.appendChild(span);
      });
    } else {
      sansList.innerHTML = `<span style="color: var(--text-dim); font-size: 0.85rem;">No se declararon SANs adicionales.</span>`;
    }

    // Warnings
    const warnBlock = document.getElementById("ssl-warnings-block");
    const warnList = document.getElementById("ssl-warnings-list");
    if (sslData.validation_errors && sslData.validation_errors.length > 0) {
      warnBlock.style.display = "block";
      warnList.innerHTML = "";
      sslData.validation_errors.forEach(w => {
        const item = document.createElement("div");
        item.className = "leak-item";
        item.style.borderColor = "var(--crimson)";
        item.style.color = "var(--crimson)";
        item.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> ${escapeHtml(w)}`;
        warnList.appendChild(item);
      });
    } else {
      warnBlock.style.display = "none";
    }
  }

  // 12. Render Pestaña 5: Red & Puertos
  function renderNetworkTab(netData) {
    if (!netData) return;

    // IPs
    const ipList = document.getElementById("res-ip-list");
    ipList.innerHTML = "";
    (netData.ip_addresses || []).forEach(ip => {
      const row = document.createElement("div");
      row.className = "ip-row";
      row.innerHTML = `<span><i class="fa-solid fa-server"></i> ${ip}</span><span class="code-badge">IPv4</span>`;
      ipList.appendChild(row);
    });
    (netData.ipv6_addresses || []).forEach(ip6 => {
      const row = document.createElement("div");
      row.className = "ip-row";
      row.innerHTML = `<span><i class="fa-solid fa-globe"></i> ${ip6}</span><span class="code-badge">IPv6</span>`;
      ipList.appendChild(row);
    });
    if (!netData.ip_addresses?.length && !netData.ipv6_addresses?.length) {
      ipList.innerHTML = `<span style="color: var(--text-dim); font-size: 0.85rem;">No se resolvieron direcciones IP públicas.</span>`;
    }

    // SPF & DMARC
    const dnsSec = document.getElementById("res-dns-sec-status");
    dnsSec.innerHTML = `
      <div class="dns-sec-item">
        <span><i class="fa-solid fa-envelope"></i> Registro SPF (Sender Policy Framework)</span>
        <span class="posture-status-badge ${netData.spf_configured ? 'ok' : 'bad'}">${netData.spf_configured ? 'Configurado' : 'Faltante'}</span>
      </div>
      <div class="dns-sec-item">
        <span><i class="fa-solid fa-shield-virus"></i> Registro DMARC (_dmarc)</span>
        <span class="posture-status-badge ${netData.dmarc_configured ? 'ok' : 'bad'}">${netData.dmarc_configured ? 'Configurado' : 'Faltante'}</span>
      </div>
    `;

    // Puertos Abiertos
    const tbody = document.getElementById("ports-table-body");
    tbody.innerHTML = "";
    if (netData.open_ports && netData.open_ports.length > 0) {
      netData.open_ports.forEach(p => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><strong>${p.port}</strong></td>
          <td><span class="code-badge">${p.protocol.toUpperCase()}</span></td>
          <td>${p.service}</td>
          <td><span class="code-badge">${p.banner ? escapeHtml(p.banner) : 'Servicio Abierto'}</span></td>
          <td><span class="finding-badge badge-${p.risk.toLowerCase()}">${p.risk}</span></td>
          <td style="font-size: 0.82rem; color: var(--text-muted);">${p.risk_reason || '-'}</td>
        `;
        tbody.appendChild(tr);
      });
    } else {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-dim); padding: 1.5rem;">No se detectaron puertos adicionales expuestos en los servicios evaluados.</td></tr>`;
    }

    // Hallazgos NSE (Nmap NSE)
    const nseList = document.getElementById("nse-findings-list");
    const nseBadge = document.getElementById("nse-scripts-badge");
    const nseFindings = netData.nse_findings || [];
    const nseScripts = netData.nse_scripts_executed || [];
    nseList.innerHTML = "";

    if (netData.nse_enabled) {
      nseBadge.textContent = `${nseScripts.length} scripts · ${nseFindings.length} hallazgos`;
      if (nseFindings.length === 0) {
        nseList.innerHTML = `
          <div class="nse-item nse-info">
            <div class="nse-item-head">
              <span class="finding-badge badge-info">OK</span>
              <span class="nse-script-id">Sin hallazgos relevantes</span>
            </div>
            <div class="nse-item-title">Los scripts NSE ejecutados no reportaron vulnerabilidades confirmadas en este objetivo.</div>
          </div>`;
      } else {
        nseFindings.forEach(f => {
          const sev = (f.severity || "INFO").toLowerCase();
          const cves = (f.cve_ids || []).map(c => `<span class="code-badge">${escapeHtml(c)}</span>`).join(" ");
          const item = document.createElement("div");
          item.className = `nse-item nse-${sev}`;
          item.innerHTML = `
            <div class="nse-item-head">
              <span class="finding-badge badge-${sev}">${escapeHtml(f.severity)}</span>
              <span class="nse-script-id">${escapeHtml(f.script_id)}</span>
              <span class="nse-port">${f.port ? `${f.port}/${(f.protocol || "tcp").toUpperCase()}` : "HOST"}</span>
              ${cves}
            </div>
            <div class="nse-item-title">${escapeHtml(f.title || "Sin título")}</div>
            <pre class="nse-item-output">${escapeHtml((f.output || "").slice(0, 900))}</pre>`;
          nseList.appendChild(item);
        });
      }
    } else {
      nseBadge.textContent = "NSE inactivo";
      nseList.innerHTML = `
        <div class="nse-empty">
          Escaneo NSE no ejecutado. Activa <strong>Scripts NSE</strong> en las opciones de escaneo
          (requiere Nmap instalado) para detectar vulnerabilidades con <code>vuln</code>, <code>vulners</code>
          y fingerprint web con <code>http-enum</code>, <code>http-title</code> y <code>ssl-cert</code>.
        </div>`;
    }

    // Registros DNS
    const dnsGrid = document.getElementById("res-dns-records-grid");
    dnsGrid.innerHTML = "";
    Object.entries(netData.dns_records || {}).forEach(([rtype, rvals]) => {
      const card = document.createElement("div");
      card.className = "dns-type-card";
      card.innerHTML = `
        <div class="dns-type-name">${rtype} (${rvals.length})</div>
        <div class="dns-type-vals">
          ${rvals.map(v => `<div>&bull; ${escapeHtml(v)}</div>`).join('')}
        </div>
      `;
      dnsGrid.appendChild(card);
    });
  }

  // 13. Render Pestaña 6: Snippets
  function renderSnippetsTab(snippets) {
    if (!snippets) return;
    document.getElementById("code-nginx").textContent = snippets["NGINX"] || "# Sin plantilla generada";
    document.getElementById("code-apache").textContent = snippets["Apache"] || "# Sin plantilla generada";
    document.getElementById("code-node").textContent = snippets["Node.js (Express & Helmet)"] || "// Sin plantilla generada";
  }

  // 14. Filtro de Severidades y Pestañas
  filterButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      filterButtons.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      activeFindingsFilter = btn.dataset.filter;
      if (currentScanData && currentScanData.ai_report) {
        renderFindingsList(currentScanData.ai_report.findings);
      }
    });
  });

  severityPills.forEach(pill => {
    pill.addEventListener("click", () => {
      const sev = pill.dataset.filter;
      const matchingFilterBtn = document.querySelector(`.filter-btn[data-filter="${sev}"]`);
      if (matchingFilterBtn) {
        matchingFilterBtn.click();
        // Cambiar a la pestaña de AI Report
        document.querySelector('.tab-btn[data-tab="tab-ai-report"]').click();
      }
    });
  });

  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      tabButtons.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const targetContent = document.getElementById(btn.dataset.tab);
      if (targetContent) targetContent.classList.add("active");
    });
  });

  snippetTabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      snippetTabButtons.forEach(b => b.classList.remove("active"));
      snippetBoxes.forEach(box => box.classList.remove("active"));

      btn.classList.add("active");
      const targetBox = document.getElementById(btn.dataset.target);
      if (targetBox) targetBox.classList.add("active");
    });
  });

  // 15. Copiar Código
  document.querySelectorAll(".btn-copy-code").forEach(btn => {
    btn.addEventListener("click", () => {
      const codeEl = document.getElementById(btn.dataset.codeId);
      if (codeEl) {
        navigator.clipboard.writeText(codeEl.textContent);
        const originalText = btn.innerHTML;
        btn.innerHTML = `<i class="fa-solid fa-check"></i> ¡Copiado!`;
        setTimeout(() => { btn.innerHTML = originalText; }, 2000);
      }
    });
  });

  document.getElementById("btn-copy-json").addEventListener("click", () => {
    const raw = document.getElementById("raw-json-content").textContent;
    navigator.clipboard.writeText(raw);
    alert("JSON copiado al portapapeles.");
  });

  // 16. Botones de Exportación
  btnNewScan.addEventListener("click", () => {
    resultsSection.style.display = "none";
    scanningSection.style.display = "none";
    window.scrollTo({ top: 0, behavior: "smooth" });
    targetUrlInput.focus();
  });

  btnPrintReport.addEventListener("click", () => {
    window.print();
  });

  btnDownloadJson.addEventListener("click", () => {
    if (currentScanId) {
      window.open(`/api/export/${currentScanId}/json`, "_blank");
    }
  });

  // 17. Historial de Auditorías
  btnShowHistory.addEventListener("click", async () => {
    modalHistory.style.display = "flex";
    modalHistoryBody.innerHTML = "<p>Cargando historial de escaneos...</p>";

    try {
      const resp = await fetch("/api/history");
      const data = await resp.json();
      
      if (!data.history || data.history.length === 0) {
        modalHistoryBody.innerHTML = "<p style='color: var(--text-dim);'>No hay auditorías previas en memoria.</p>";
        return;
      }

      modalHistoryBody.innerHTML = "";
      data.history.forEach(item => {
        const div = document.createElement("div");
        div.className = "history-item";
        div.innerHTML = `
          <div>
            <div class="history-host">${escapeHtml(item.domain)}</div>
            <div class="history-meta">${new Date(item.timestamp).toLocaleString()} &bull; Duración: ${item.duration}s</div>
          </div>
          <div>
            <span class="finding-badge badge-low" style="font-size: 0.85rem;">Score: ${item.score || 0}/100 (${item.grade || '-'})</span>
          </div>
        `;

        div.addEventListener("click", () => {
          modalHistory.style.display = "none";
          fetchFullResults(item.scan_id);
        });

        modalHistoryBody.appendChild(div);
      });
    } catch (e) {
      modalHistoryBody.innerHTML = `<p style="color: var(--crimson);">Error al cargar historial: ${e.message}</p>`;
    }
  });

  btnCloseModal.addEventListener("click", () => {
    modalHistory.style.display = "none";
  });

  modalHistory.addEventListener("click", (e) => {
    if (e.target === modalHistory) modalHistory.style.display = "none";
  });

  // 18. Chequeo de Estado del Sistema
  async function checkSystemStatus() {
    try {
      const resp = await fetch("/api/system-status");
      if (resp.ok) {
        const data = await resp.json();
        const nmapStatus = document.getElementById("nmap-status-text");
        const nseAvailable = Boolean(data.nmap_available && data.nmap_nse && data.nmap_nse.available);
        if (data.nmap_available) {
          nmapStatus.textContent = nseAvailable ? "Activo (CLI + NSE)" : "Activo (CLI)";
        } else {
          nmapStatus.textContent = "Socket Nativo";
        }

        if (checkEnableNse) {
          checkEnableNse.disabled = !nseAvailable;
          checkEnableNse.closest("label").title = nseAvailable
            ? `Scripts NSE instalados: ${data.nmap_nse.scripts_count ?? "N/D"}. Ejecuta vuln, vulners e http-*/ssl-*.`
            : "Requiere Nmap con la biblioteca de scripts NSE instalada en el sistema.";
          if (!nseAvailable) checkEnableNse.checked = false;
        }
      }
    } catch (e) {
      console.warn("No se pudo conectar al endpoint de estado.");
    }
  }

  // 19. Funciones Auxiliares
  function addTerminalLog(msg, type = "info") {
    const line = document.createElement("div");
    line.className = `term-line ${type}`;
    line.textContent = msg;
    terminalLogs.appendChild(line);
    terminalLogs.scrollTop = terminalLogs.scrollHeight;
  }

  function escapeHtml(text) {
    if (!text) return "";
    return text.toString().replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }


  function formatMarkdown(text) {
    if (!text) return "";
    let html = escapeHtml(text);
    // Negrita
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    // Salto de línea doble a párrafos
    const paras = html.split('\n\n');
    return paras.map(p => `<p>${p.replace(/\n/g, '<br>')}</p>`).join('');
  }

  // ================================================================
  // CHATBOT DE CIBERDEFENSA IA
  // ================================================================
  const chatBubble    = document.getElementById('chatbot-bubble');
  const chatPanel     = document.getElementById('chatbot-panel');
  const chatClose     = document.getElementById('chatbot-close');
  const chatMessages  = document.getElementById('chatbot-messages');
  const chatInput     = document.getElementById('chatbot-input');
  const chatSend      = document.getElementById('chatbot-send');
  const chatSuggest   = document.getElementById('chatbot-suggestions');

  let chatHistory = [];    // { role, content }[]
  let chatScanId  = null;  // se llena cuando termina un scan

  // Abrir / cerrar panel
  chatBubble.addEventListener('click', () => {
    chatPanel.style.display = chatPanel.style.display === 'none' ? 'flex' : 'none';
    if (chatPanel.style.display === 'flex') {
      if (!chatScanId) ensureChatContext();
      chatInput.focus();
    }
  });
  chatClose.addEventListener('click', () => { chatPanel.style.display = 'none'; });

  // Botón "Consultar IA" en la cabecera de resultados
  const btnAskAi = document.getElementById('btn-ask-ai');
  if (btnAskAi) {
    btnAskAi.addEventListener('click', () => {
      chatPanel.style.display = 'flex';
      if (!chatScanId) ensureChatContext();
      chatInput.focus();
      chatMessages.scrollTop = chatMessages.scrollHeight;
    });
  }

  // Sincronizar scan_id cuando se complete un análisis.
  // Se engancha desde renderResults() con el scan_id real del reporte.
  let chatTargetLabel = null;   // dominio del análisis activo
  let chatNotifiedFor = null;   // scan_id ya notificado (evita duplicar mensajes)

  function activateChat(scanId, label) {
    chatScanId = scanId;
    chatTargetLabel = label || chatTargetLabel;
    // Badge luminoso en la burbuja para indicar contexto disponible
    chatBubble.style.boxShadow = '0 0 36px rgba(0,255,157,0.7), 0 4px 20px rgba(0,0,0,0.4)';
    updateChatStatus();
  }

  function updateChatStatus() {
    const statusEl = document.querySelector('.chatbot-status');
    if (!statusEl) return;
    statusEl.innerHTML = chatScanId
      ? `<span class="status-dot green"></span> Contexto: ${escapeHtml(chatTargetLabel || 'análisis activo')}`
      : '<span class="status-dot green"></span> Groq · GPT-OSS 120B';
  }

  function notifyChatScanReady(scanId, status) {
    if (!scanId) return;
    activateChat(scanId, currentScanData ? currentScanData.domain : null);
    if (scanId === chatNotifiedFor) return;
    chatNotifiedFor = scanId;
    if (status === 'FAILED') {
      appendChatMsg('bot', '⚠️ El análisis **falló** antes de completarse. No hay reporte disponible para consultar.');
      return;
    }
    appendChatMsg('bot', `✅ **Análisis completado**${chatTargetLabel ? ` sobre **${chatTargetLabel}**` : ''}. Ya puedes preguntarme sobre los resultados: vulnerabilidades, prioridades, remediaciones o cualquier hallazgo del reporte.`);
  }

  // Exponer globalmente para que sea llamado cuando termina el pipeline
  window.notifyChatScanReady = notifyChatScanReady;

  // Restaura el contexto del chat desde /api/history (memoria + respaldos en disco).
  // force=true se usa cuando el scan_id guardado ya no existe (p.ej. reinicio del contenedor).
  async function ensureChatContext(force) {
    try {
      const resp = await fetch('/api/history');
      if (!resp.ok) return !!chatScanId;
      const data = await resp.json();
      const list = (data.history || []).filter(h => h.status === 'COMPLETED' && h.scan_id);
      if (!list.length) return !!chatScanId;

      const stillValid = list.some(h => h.scan_id === chatScanId);
      if (!chatScanId || (force && !stillValid)) {
        activateChat(list[0].scan_id, list[0].domain);
        if (!chatNotifiedFor) chatNotifiedFor = list[0].scan_id;
      }
      return true;
    } catch (e) {
      return !!chatScanId;
    }
  }

  // Contexto inicial al cargar la página
  ensureChatContext();

  // Enviar mensaje
  async function sendChatMessage(question) {
    if (!question.trim()) return;

    // Sin contexto: intenta restaurarlo desde el historial antes de rendirse
    if (!chatScanId) {
      const restored = await ensureChatContext();
      if (!restored) {
        appendChatMsg('bot', '⚠️ Aún no hay un análisis disponible. Realiza primero una auditoría de seguridad y luego podrás consultarme sobre los resultados.');
        return;
      }
    }

    // Historial previo (sin el mensaje actual: lo añade el backend)
    const priorHistory = chatHistory.slice(-10);

    appendChatMsg('user', question);
    chatHistory.push({ role: 'user', content: question });
    chatInput.value = '';
    chatSend.disabled = true;

    // Indicador de escritura
    const typingEl = document.createElement('div');
    typingEl.className = 'chat-msg bot';
    typingEl.innerHTML = '<div class="chat-typing"><span></span><span></span><span></span></div>';
    chatMessages.appendChild(typingEl);
    chatMessages.scrollTop = chatMessages.scrollHeight;

    let answer = null;
    let errorMsg = null;

    for (let attempt = 0; attempt < 2 && !answer && !errorMsg; attempt++) {
      let res;
      try {
        res = await fetch('/api/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            scan_id: chatScanId,
            question: question,
            history: priorHistory
          })
        });
      } catch (e) {
        errorMsg = '❌ No se pudo conectar con el servidor. Verifica que la aplicación esté corriendo.';
        break;
      }

      if (res.ok) {
        const data = await res.json();
        answer = data.answer;
        break;
      }

      const err = await res.json().catch(() => ({}));

      // El análisis ya no está en el servidor: se restaura el contexto y se reintenta una vez
      if (res.status === 404 && attempt === 0) {
        const restored = await ensureChatContext(true);
        if (restored) continue;
      }

      errorMsg = `❌ Error: ${err.detail || 'No se pudo obtener respuesta de la IA.'}`;
    }

    typingEl.remove();
    if (answer) {
      appendChatMsg('bot', answer);
      chatHistory.push({ role: 'assistant', content: answer });
    } else {
      appendChatMsg('bot', errorMsg || '❌ Error inesperado al consultar la IA.');
      chatHistory.pop();  // la pregunta no tuvo respuesta: no deja huella en el contexto
    }
    chatSend.disabled = false;
    chatInput.focus();
  }

  function appendChatMsg(role, text) {
    const msgEl = document.createElement('div');
    msgEl.className = `chat-msg ${role}`;
    const bubble = document.createElement('div');
    bubble.className = 'chat-bubble';
    // Render markdown básico sobre texto ya escapado
    bubble.innerHTML = escapeHtml(text)
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\n/g, '<br>');
    msgEl.appendChild(bubble);
    chatMessages.appendChild(msgEl);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

  // Enviar con botón
  chatSend.addEventListener('click', () => sendChatMessage(chatInput.value));

  // Enviar con Enter
  chatInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendChatMessage(chatInput.value);
    }
  });

  // Chips de sugerencias
  chatSuggest.querySelectorAll('.suggestion-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const q = chip.dataset.q;
      chatInput.value = q;
      chatPanel.style.display = 'flex';
      sendChatMessage(q);
    });
  });

}); // Fin DOMContentLoaded

