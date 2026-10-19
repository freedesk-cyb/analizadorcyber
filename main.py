import os
import uuid
import time
import json
import shutil
import asyncio
import platform
import subprocess
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

from fastapi import FastAPI, BackgroundTasks, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

from modules.models import ScanRequest, FullScanReport
from modules.web_analyzer import WebAnalyzer
from modules.cookie_analyzer import CookieAnalyzer
from modules.ssl_analyzer import SslAnalyzer
from modules.network_analyzer import NetworkAnalyzer
from modules.zap_analyzer import ZapAnalyzer
from modules.ai_analyzer import AiSecurityAnalyzer

app = FastAPI(
    title="AI Web Security Analyzer",
    description="Plataforma web de auditoría de ciberseguridad asistida por IA para análisis controlado de páginas y servidores web.",
    version="1.0.0",
)

# CORS habilitado
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def disable_browser_cache(request, call_next):
    """Evita que el navegador sirva HTML/JS/CSS obsoletos tras una actualización."""
    response = await call_next(request)
    path = request.url.path
    if path == "/" or path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

# Directorio para almacenamiento temporal
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "temp_reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# Almacenamiento en memoria volátil (SIN BASE DE DATOS)
SCANS_CACHE: Dict[str, FullScanReport] = {}
MAX_CACHED_SCANS = 50


def normalize_target_url(raw_url: str) -> str:
    """Normaliza y valida la URL de destino."""
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def extract_domain(url: str) -> str:
    """Extrae el dominio o host de la URL."""
    try:
        parsed = urlparse(url)
        return parsed.hostname or url
    except Exception:
        return url


async def run_security_pipeline(scan_id: str, request: ScanRequest):
    """Pipeline de análisis secuencial y controlado ejecutado en segundo plano."""
    report = SCANS_CACHE.get(scan_id)
    if not report:
        return

    start_time = time.perf_counter()

    def log_event(message: str, step: str, progress: int):
        timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        report.logs.append({"timestamp": timestamp, "message": message})
        report.current_step = step
        report.progress = progress

    try:
        url = report.normalized_url
        domain = report.domain

        # 1. Análisis HTTP / Headers / Tecnologías
        log_event(f"Iniciando escaneo HTTP/HTTPS sobre {url}", "Auditoría HTTP", 15)
        web_auditor = WebAnalyzer(timeout=10.0)
        # Ejecutar en thread pool para no bloquear el loop asíncrono
        http_result, web_logs = await asyncio.to_thread(web_auditor.analyze, url)
        for l in web_logs:
            log_event(l, "Auditoría HTTP", 25)
        report.http_analysis = http_result

        # 2. Análisis de Cookies
        log_event("Inspeccionando directivas Set-Cookie y banderas de seguridad", "Análisis de Cookies", 35)
        cookie_auditor = CookieAnalyzer(timeout=8.0)
        cookies_result, cookie_logs = await asyncio.to_thread(cookie_auditor.analyze, url)
        for l in cookie_logs:
            log_event(l, "Análisis de Cookies", 45)
        report.cookie_analysis = cookies_result

        # 3. Análisis SSL/TLS
        log_event(f"Verificando certificado X.509 y configuración TLS para {domain}:443", "Inspección SSL/TLS", 55)
        ssl_auditor = SslAnalyzer(timeout=8.0)
        ssl_result, ssl_logs = await asyncio.to_thread(ssl_auditor.analyze, url)
        for l in ssl_logs:
            log_event(l, "Inspección SSL/TLS", 65)
        report.ssl_analysis = ssl_result

        # 4. Análisis de Red, DNS y Puertos
        log_event(f"Consultando registros DNS y evaluando superficie de puertos de {domain}", "Reconocimiento de Red", 75)
        net_auditor = NetworkAnalyzer(socket_timeout=1.2)
        net_result, net_logs = await asyncio.to_thread(
            net_auditor.analyze,
            url,
            request.enable_nmap,
            request.enable_nmap_nse,
            request.nse_scripts,
        )
        for l in net_logs:
            log_event(l, "Reconocimiento de Red", 85)
        report.network_analysis = net_result

        # 5. Análisis OWASP ZAP (Opcional)
        zap_result = None
        if request.enable_zap:
            log_event("Consultando motor OWASP ZAP...", "Análisis ZAP", 88)
            zap_auditor = ZapAnalyzer()
            zap_result, zap_logs = await asyncio.to_thread(zap_auditor.analyze, url, request.enable_zap)
            for l in zap_logs:
                log_event(l, "Análisis ZAP", 90)
            report.zap_analysis = zap_result

        # 6. Motor de Inteligencia Artificial / Síntesis de Ciberseguridad
        model_name = request.ai_model or "openai/gpt-oss-120b"
        log_event(f"Motor IA Groq ({model_name}) interpretando hallazgos y correlacionando vectores de ataque...", "Análisis de Inteligencia Artificial", 95)
        ai_auditor = AiSecurityAnalyzer(api_key=request.ai_api_key, provider=request.ai_provider, model=model_name)
        ai_report = await asyncio.to_thread(
            ai_auditor.analyze,
            target_url=url,
            http_data=report.http_analysis,
            cookies_data=report.cookie_analysis,
            ssl_data=report.ssl_analysis,
            network_data=report.network_analysis,
            zap_data=zap_result,
        )
        report.ai_report = ai_report

        total_duration = round(time.perf_counter() - start_time, 2)
        report.scan_duration_seconds = total_duration
        report.status = "COMPLETED"
        report.progress = 100
        report.current_step = "Análisis Finalizado"
        log_event(f"Auditoría completada exitosamente en {total_duration}s. Score de Seguridad: {ai_report.security_score}/100 ({ai_report.security_grade})", "Completado", 100)

        # Guardar copia temporal en JSON
        save_temp_json_report(report)

    except Exception as exc:
        total_duration = round(time.perf_counter() - start_time, 2)
        report.scan_duration_seconds = total_duration
        report.status = "FAILED"
        report.error = str(exc)
        report.progress = 100
        report.current_step = "Fallo en el análisis"
        log_event(f"[-] Error crítico durante el escaneo: {str(exc)}", "Error", 100)


def save_temp_json_report(report: FullScanReport):
    """Guarda una copia en disco temporal del reporte para respaldo en caliente."""
    try:
        filepath = os.path.join(REPORTS_DIR, f"{report.scan_id}.json")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(report.model_dump_json(indent=2))
    except Exception:
        pass


NSE_KEY_SCRIPTS = ("vulners.nse", "ssl-heartbleed.nse", "http-enum.nse", "http-title.nse", "ssl-cert.nse")


def detect_nmap_nse_scripts(nmap_path: Optional[str]) -> Dict[str, Any]:
    """Localiza la biblioteca de scripts NSE en cualquier plataforma.

    Busca en las rutas habituales de Windows, Debian/Ubuntu (incluido el contenedor Docker),
    macOS (Homebrew) y compilaciones desde fuente. Si ninguna existe, se le pregunta al
    propio Nmap con --script-help como último recurso.
    """
    candidates = []
    if nmap_path:
        exe_dir = os.path.dirname(os.path.abspath(nmap_path))
        candidates += [
            os.path.join(exe_dir, "scripts"),
            os.path.join(os.path.dirname(exe_dir), "share", "nmap", "scripts"),
        ]
    nmapdir = os.getenv("NMAPDIR")
    if nmapdir:
        candidates += [os.path.join(nmapdir, "scripts"), nmapdir]
    candidates += [
        r"C:\Program Files (x86)\Nmap\scripts",
        r"C:\Program Files\Nmap\scripts",
        "/usr/share/nmap/scripts",
        "/usr/local/share/nmap/scripts",
        "/opt/homebrew/share/nmap/scripts",
    ]

    scripts_dir = next((d for d in candidates if d and os.path.isdir(d)), None)
    if scripts_dir:
        try:
            nse_files = {f for f in os.listdir(scripts_dir) if f.endswith(".nse")}
        except OSError:
            nse_files = set()
        if nse_files:
            return {
                "available": True,
                "scripts_dir": scripts_dir,
                "scripts_count": len(nse_files),
                "key_scripts": {name: name in nse_files for name in NSE_KEY_SCRIPTS},
            }

    if nmap_path:
        try:
            proc = subprocess.run(
                [nmap_path, "--script-help", "http-title"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
            combined = ((proc.stdout or "") + (proc.stderr or "")).lower()
            if proc.returncode == 0 and "http-title" in combined:
                return {
                    "available": True,
                    "scripts_dir": None,
                    "scripts_count": None,
                    "key_scripts": {name: None for name in NSE_KEY_SCRIPTS},
                }
        except Exception:
            pass

    return {"available": False, "scripts_dir": None, "scripts_count": 0, "key_scripts": {}}


# ==========================================
# RUTAS DE LA API REST
# ==========================================

@app.post("/api/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Inicia una nueva auditoría de seguridad en segundo plano."""
    if not request.url:
        raise HTTPException(status_code=400, detail="Debe proporcionar una URL válida.")

    normalized_url = normalize_target_url(request.url)
    domain = extract_domain(normalized_url)
    scan_id = str(uuid.uuid4())[:8]
    now_iso = datetime.now(timezone.utc).isoformat()

    # Instanciar reporte inicial en memoria
    new_report = FullScanReport(
        scan_id=scan_id,
        target_url=request.url,
        normalized_url=normalized_url,
        domain=domain,
        scan_timestamp=now_iso,
        scan_duration_seconds=0.0,
        status="SCANNING",
        progress=5,
        current_step="Validando objetivo...",
        logs=[{"timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"), "message": f"[*] Solicitud recibida para {normalized_url} (ID: {scan_id})"}],
    )

    # Mantener el límite de memoria
    if len(SCANS_CACHE) >= MAX_CACHED_SCANS:
        oldest_key = next(iter(SCANS_CACHE))
        del SCANS_CACHE[oldest_key]

    SCANS_CACHE[scan_id] = new_report

    # Lanzar pipeline asíncrono
    background_tasks.add_task(run_security_pipeline, scan_id, request)

    return {
        "status": "success",
        "scan_id": scan_id,
        "target_url": normalized_url,
        "domain": domain,
        "message": "Auditoría iniciada en segundo plano.",
    }


@app.get("/api/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    """Consulta el estado o resultado completo de una auditoría."""
    report = load_report(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="Auditoría no encontrada o expirada.")

    return report


@app.get("/api/scan/{scan_id}/stream")
async def stream_scan_logs(scan_id: str):
    """Transmite eventos y logs en tiempo real vía Server-Sent Events (SSE)."""
    async def event_generator():
        last_log_idx = 0
        while True:
            report = SCANS_CACHE.get(scan_id)
            if not report:
                yield f"data: {json.dumps({'error': 'Scan not found'})}\n\n"
                break

            current_logs = report.logs[last_log_idx:]
            if current_logs:
                for log_entry in current_logs:
                    payload = {
                        "progress": report.progress,
                        "current_step": report.current_step,
                        "status": report.status,
                        "log": log_entry,
                    }
                    yield f"data: {json.dumps(payload)}\n\n"
                last_log_idx = len(report.logs)

            if report.status in ["COMPLETED", "FAILED"]:
                # Notificar finalización
                yield f"data: {json.dumps({'progress': 100, 'status': report.status, 'completed': True})}\n\n"
                break

            await asyncio.sleep(0.4)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


def load_report(scan_id: str) -> Optional[FullScanReport]:
    """Carga un reporte desde la memoria volátil o, si ya no está, desde el JSON temporal en disco."""
    report = SCANS_CACHE.get(scan_id)
    if report:
        return report

    filepath = os.path.join(REPORTS_DIR, f"{scan_id}.json")
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            report = FullScanReport(**json.load(f))
    except Exception:
        return None

    if len(SCANS_CACHE) < MAX_CACHED_SCANS:
        SCANS_CACHE[scan_id] = report
    return report


def history_entry(rep: FullScanReport) -> Dict[str, Any]:
    """Normaliza un reporte a la fila usada por el historial de la interfaz."""
    return {
        "scan_id": rep.scan_id,
        "target_url": rep.target_url,
        "domain": rep.domain,
        "timestamp": rep.scan_timestamp,
        "status": rep.status,
        "score": rep.ai_report.security_score if rep.ai_report else None,
        "grade": rep.ai_report.security_grade if rep.ai_report else None,
        "duration": rep.scan_duration_seconds,
    }


@app.get("/api/history")
async def get_scan_history():
    """Retorna el historial de auditorías: memoria volátil + respaldos JSON en disco."""
    entries: Dict[str, Dict[str, Any]] = {}

    # Auditorías todavía vivas en memoria
    for rep in SCANS_CACHE.values():
        entries[rep.scan_id] = history_entry(rep)

    # Respaldos temporales (sobreviven a reinicios del contenedor / recargas)
    try:
        for filename in os.listdir(REPORTS_DIR):
            if not filename.endswith(".json"):
                continue
            scan_id = filename[:-5]
            if scan_id in entries:
                continue
            rep = load_report(scan_id)
            if rep:
                entries[scan_id] = history_entry(rep)
    except Exception:
        pass

    history = sorted(entries.values(), key=lambda e: e.get("timestamp") or "", reverse=True)
    return {"history": history[:20]}


class ChatRequest(BaseModel):
    scan_id: str
    question: str
    history: List[Dict[str, str]] = []


@app.post("/api/chat")
async def chat_with_ai(req: ChatRequest):
    """Chatbot contextual de ciberdefensa: responde preguntas sobre el análisis realizado usando Groq."""
    report = load_report(req.scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="Análisis no encontrado.")

    # Construir contexto técnico compacto del reporte para el LLM
    ai = report.ai_report
    context_parts = [
        f"URL analizada: {report.normalized_url}",
        f"Dominio: {report.domain}",
        f"Timestamp: {report.scan_timestamp}",
    ]
    if ai:
        context_parts += [
            f"Score de seguridad: {ai.security_score}/100 (Grado {ai.security_grade})",
            f"Distribución de riesgos: Críticos={ai.risk_counts.get('CRITICAL',0)}, Altos={ai.risk_counts.get('HIGH',0)}, Medios={ai.risk_counts.get('MEDIUM',0)}, Bajos={ai.risk_counts.get('LOW',0)}, Info={ai.risk_counts.get('INFO',0)}",
            f"Resumen ejecutivo:\n{ai.executive_summary}",
        ]
        if ai.findings:
            findings_txt = "\n".join(
                f"- [{f.severity}] {f.id}: {f.title} | Evidencia: {f.evidence} | Remediación: {f.remediation}"
                for f in ai.findings
            )
            context_parts.append(f"Hallazgos técnicos:\n{findings_txt}")
        if ai.key_strengths:
            context_parts.append("Fortalezas detectadas:\n" + "\n".join(f"- {s}" for s in ai.key_strengths))
        if ai.priority_action_plan:
            context_parts.append("Plan de acción prioritario:\n" + "\n".join(f"{i+1}. {a}" for i, a in enumerate(ai.priority_action_plan)))
        if ai.threat_intelligence_notes:
            context_parts.append(f"Notas de Threat Intelligence:\n{ai.threat_intelligence_notes}")

    if report.ssl_analysis:
        ssl = report.ssl_analysis
        context_parts.append(
            f"SSL/TLS: HTTPS={ssl.has_https}, Protocolo={ssl.protocol_version}, Expirado={ssl.is_expired}, Días restantes={ssl.days_left}, Grado={ssl.grade}"
        )
    if report.network_analysis:
        net = report.network_analysis
        context_parts.append(
            f"Red: IPs={net.ip_addresses}, SPF={net.spf_configured}, DMARC={net.dmarc_configured}, Puertos abiertos={[f'{p.port}/{p.protocol} ({p.service}) riesgo={p.risk}' for p in net.open_ports]}"
        )
        if net.nse_enabled:
            nse_lines = [
                f"{n.severity} {n.script_id} (puerto {n.port or 'host'}): {n.title} {','.join(n.cve_ids)}"
                for n in net.nse_findings
            ]
            context_parts.append(
                f"Nmap NSE: scripts ejecutados={net.nse_scripts_executed}, hallazgos={nse_lines or 'ninguno'}"
            )
    if report.http_analysis:
        http = report.http_analysis
        missing_headers = [h.header for h in http.security_headers if h.status == "MISSING"]
        bad_headers = [f"{h.header} ({h.status})" for h in http.security_headers if h.status in ("WARNING", "INFO_LEAK")]
        context_parts.append(
            f"HTTP: Estado={http.status_code}, Latencia={http.response_time_ms}ms, "
            f"URL final={http.final_url}, Cabeceras de seguridad ausentes={missing_headers or 'ninguna'}, "
            f"Cabeceras débiles/fugas={bad_headers or 'ninguna'}, Fugas en servidor={http.server_info_leaks or 'ninguna'}, "
            f"Tecnologías detectadas={[t.get('name') for t in http.detected_technologies]}, Título={http.html_title}"
        )
    if report.cookie_analysis:
        cookie_lines = []
        for c in report.cookie_analysis:
            flags = f"Secure={'S' if c.secure else 'NO'} HttpOnly={'S' if c.httponly else 'NO'} SameSite={c.samesite or 'no'}"
            cookie_lines.append(
                f"- {c.name} [{c.risk_level}] {flags} sensible={c.is_sensitive}"
                + (f" | Problemas: {'; '.join(c.issues)}" if c.issues else "")
            )
        context_parts.append(
            f"Cookies ({len(report.cookie_analysis)} auditadas):\n" + ("\n".join(cookie_lines) if cookie_lines else "ninguna")
        )
    if report.zap_analysis:
        context_parts.append(f"Resultados OWASP ZAP: {json.dumps(report.zap_analysis, ensure_ascii=False)[:3000]}")

    if report.status != "COMPLETED":
        context_parts.append(
            f"AVISO: este análisis está en estado {report.status}. "
            f"Posible error: {report.error or 'no registrado'}. Indícalo al analista."
        )

    system_prompt = (
        "Eres el Asistente Experto en Ciberseguridad y Auditoría Web del Centro de Ciberdefensa (CyberDefense AI). "
        "Tu función es ORIENTAR al analista sobre el análisis de seguridad que se te proporciona: "
        "explicar qué significa cada hallazgo, priorizar el trabajo, sugerir el siguiente paso y detallar cómo remediar. "
        "Reglas: \n"
        "1. Responde basándote EXCLUSIVAMENTE en los datos del análisis (no inventes hallazgos, puertos, cabeceras o fechas que no estén en el contexto). \n"
        "2. Responde siempre en español, con tono técnico y profesional, en Markdown (negritas, listas, bloques de código para configuraciones). \n"
        "3. Cita los hallazgos por su id y severidad cuando existan. \n"
        "4. Cuando pidan 'qué hago primero', entrega un plan ordenado por impacto/urgencia con acciones concretas y verificables. \n"
        "5. Si te preguntan por algo no cubierto en el análisis, dilo claramente y explica qué módulo lo obtendría. \n"
        "6. Si la pregunta es ajena a ciberseguridad o al análisis, indícalo amablemente y vuelve al contexto.\n\n"
        "=== CONTEXTO DEL ANÁLISIS DE SEGURIDAD ===\n"
        + "\n".join(context_parts)
    )

    groq_api_key = os.getenv("GROQ_API_KEY", "")
    groq_model = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")

    if not groq_api_key:
        raise HTTPException(status_code=503, detail="API Key de Groq no configurada.")

    # Historial saneado: se descarta la última entrada si duplica la pregunta actual
    history = [m for m in req.history if isinstance(m, dict) and m.get("content")]
    if (
        history
        and history[-1].get("role") == "user"
        and str(history[-1].get("content", "")).strip() == req.question.strip()
    ):
        history = history[:-1]

    messages = [{"role": "system", "content": system_prompt}]
    for msg in history[-8:]:  # Máximo 8 mensajes de historial
        messages.append({"role": msg.get("role", "user"), "content": msg.get("content", "")})
    messages.append({"role": "user", "content": req.question})

    try:
        import httpx as _httpx
        async with _httpx.AsyncClient(timeout=25.0) as client:
            resp = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {groq_api_key}", "Content-Type": "application/json"},
                json={"model": groq_model, "messages": messages, "temperature": 0.3},
            )
        if resp.status_code == 200:
            answer = resp.json()["choices"][0]["message"]["content"]
            return {"answer": answer, "model": groq_model}
        else:
            raise HTTPException(status_code=502, detail=f"Error de Groq API: {resp.text}")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error al contactar la IA: {str(exc)}")


@app.get("/api/export/{scan_id}/json")
async def export_json_report(scan_id: str):
    """Descarga el reporte de seguridad en formato JSON estructurado."""
    report = load_report(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="Informe no encontrado.")

    return JSONResponse(
        content=report.model_dump(),
        headers={"Content-Disposition": f"attachment; filename=security_report_{report.domain}_{scan_id}.json"}
    )


@app.get("/api/system-status")
async def get_system_status():
    """Informa el estado de dependencias del servidor (Nmap, ZAP, Python, Groq)."""
    nmap_path = shutil.which("nmap")
    groq_configured = bool(os.getenv("GROQ_API_KEY"))

    return {
        "python_version": platform.python_version(),
        "nmap_available": bool(nmap_path),
        "nmap_path": nmap_path,
        "nmap_nse": detect_nmap_nse_scripts(nmap_path),
        "database": "In-Memory / Zero-DB Architecture",
        "active_scans_in_memory": len(SCANS_CACHE),
        "ai_engine": "Groq Cloud (OpenAI GPT-OSS 120B / 20B) + Native Heuristics",
        "groq_configured": groq_configured,
        "groq_models": ["openai/gpt-oss-120b", "openai/gpt-oss-20b"],
    }


# Montar archivos estáticos
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    """Sirve la interfaz web principal del centro de comando de ciberseguridad."""
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>AI Web Security Analyzer</h1><p>Frontend cargando...</p>")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
