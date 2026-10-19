import os
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import httpx
from dotenv import load_dotenv

# Cargar variables de entorno desde .env
load_dotenv()

from modules.models import (
    AiAnalysisResult,
    RiskFinding,
    HttpAuditResult,
    CookieAuditItem,
    SslCertInfo,
    NetworkAuditResult,
)

logger = logging.getLogger(__name__)


class AiSecurityAnalyzer:
    """
    Capa de Inteligencia Artificial y Motor Experto de Ciberseguridad.
    Integra el motor de inferencia ultra-rápido de Groq con modelos OpenAI GPT-OSS (120B / 20B)
    y un sistema determinístico heurístico de no-alucinación.
    """

    GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
    DEFAULT_120B_MODEL = "openai/gpt-oss-120b"
    DEFAULT_20B_MODEL = "openai/gpt-oss-20b"

    def __init__(
        self,
        api_key: Optional[str] = None,
        provider: str = "auto",
        model: Optional[str] = None,
    ):
        self.groq_api_key = api_key or os.getenv("GROQ_API_KEY")
        self.gemini_api_key = os.getenv("GEMINI_API_KEY")
        self.openai_api_key = os.getenv("OPENAI_API_KEY")

        self.provider = provider.lower() if provider else "auto"
        self.requested_model = (
            model
            or os.getenv("GROQ_MODEL")
            or self.DEFAULT_120B_MODEL
        )
        self.fast_model = (
            os.getenv("GROQ_FAST_MODEL")
            or self.DEFAULT_20B_MODEL
        )

    def analyze(
        self,
        target_url: str,
        http_data: Optional[HttpAuditResult],
        cookies_data: List[CookieAuditItem],
        ssl_data: Optional[SslCertInfo],
        network_data: Optional[NetworkAuditResult],
        zap_data: Optional[Dict[str, Any]] = None,
    ) -> AiAnalysisResult:
        """Sintetiza todos los hallazgos técnicos reales y genera el informe de evaluación de ciberseguridad."""

        # 1. Extracción y catalogación estricta de evidencias técnicas determinísticas
        findings: List[RiskFinding] = []
        strengths: List[str] = []
        priority_actions: List[str] = []
        cve_correlations: List[Dict[str, Any]] = []

        # --- A. ANÁLISIS DE TRANSPORTE Y SSL/TLS ---
        if ssl_data:
            if not ssl_data.has_https:
                findings.append(RiskFinding(
                    id="SSL-01",
                    title="Sitio web sin soporte HTTPS o puerto 443 inaccesible",
                    severity="CRITICAL",
                    category="SSL/TLS",
                    description="El tráfico entre el usuario y el servidor viaja en texto plano sin cifrado criptográfico.",
                    evidence=f"No se pudo establecer handshake TLS. Errores: {', '.join(ssl_data.validation_errors) if ssl_data.validation_errors else 'Puerto 443 cerrado'}",
                    impact="Cualquier actor intermediario en la red (WiFi pública, ISP, routers) puede interceptar credenciales, tokens de sesión y modificar el tráfico (Ataques MitM / Inyección de scripts).",
                    remediation="Instalar un certificado SSL/TLS válido (ej. Let's Encrypt gratuito o comercial) y forzar la redirección permanente de HTTP a HTTPS.",
                    cwe_id="CWE-319: Cleartext Transmission of Sensitive Information",
                    owasp_category="A02:2021 - Cryptographic Failures",
                ))
                priority_actions.append("Habilitar urgentemente HTTPS con certificado TLS 1.2+ en el servidor web.")
            else:
                if ssl_data.is_expired:
                    findings.append(RiskFinding(
                        id="SSL-02",
                        title="Certificado SSL/TLS Expirado",
                        severity="HIGH",
                        category="SSL/TLS",
                        description="El certificado digital ha superado su fecha límite de validez, provocando alertas de seguridad críticas en los navegadores.",
                        evidence=f"Fecha de expiración: {ssl_data.valid_to} ({abs(ssl_data.days_left or 0)} días transcurridos)",
                        impact="Pérdida inmediata de confianza del usuario, bloqueo por parte de navegadores modernos y advertencias de seguridad.",
                        remediation="Renovar de inmediato el certificado mediante Certbot / Let's Encrypt o la entidad emisora (CA).",
                        cwe_id="CWE-298: Improper Validation of Certificate Expiration",
                        owasp_category="A02:2021 - Cryptographic Failures",
                    ))
                    priority_actions.append("Renovar el certificado SSL/TLS expirado.")
                elif ssl_data.is_expiring_soon:
                    findings.append(RiskFinding(
                        id="SSL-03",
                        title="Certificado SSL/TLS próximo a expirar",
                        severity="LOW",
                        category="SSL/TLS",
                        description=f"El certificado SSL caducará en {ssl_data.days_left} días.",
                        evidence=f"Válido hasta: {ssl_data.valid_to} ({ssl_data.days_left} días restantes).",
                        impact="Si no se renueva oportunamente, el sitio quedará inaccesible para los usuarios.",
                        remediation="Verificar que el proceso de renovación automática (cron/certbot) esté activo y operativo.",
                        cwe_id="CWE-298",
                        owasp_category="A02:2021 - Cryptographic Failures",
                    ))

                if any("Error de validación" in err for err in ssl_data.validation_errors):
                    findings.append(RiskFinding(
                        id="SSL-04",
                        title="Fallo en la cadena de confianza del certificado SSL",
                        severity="HIGH",
                        category="SSL/TLS",
                        description="El certificado no fue emitido por una Autoridad de Certificación (CA) de confianza reconocida o presenta discrepancias en el nombre común.",
                        evidence=f"Detalles: {'; '.join(ssl_data.validation_errors)}",
                        impact="Los navegadores mostrarán una advertencia de sitio no seguro a los visitantes.",
                        remediation="Instalar un certificado emitido por una CA reconocida y configurar la cadena intermedia completa (fullchain.pem).",
                        cwe_id="CWE-295: Improper Certificate Validation",
                        owasp_category="A02:2021 - Cryptographic Failures",
                    ))

                if ssl_data.protocol_version in ["TLSv1.3", "TLSv1.2"] and not ssl_data.is_expired and not ssl_data.validation_errors:
                    issuer_org = ssl_data.issuer.get('organizationName', ssl_data.issuer.get('commonName', 'CA Autorizada'))
                    strengths.append(f"Cifrado SSL/TLS robusto utilizando {ssl_data.protocol_version} emitido por {issuer_org}.")

        # --- B. ANÁLISIS DE CABECERAS HTTP DE SEGURIDAD ---
        if http_data:
            for item in http_data.security_headers:
                if item.status == "MISSING":
                    if item.header == "Strict-Transport-Security":
                        findings.append(RiskFinding(
                            id="HDR-HSTS",
                            title="Cabecera Strict-Transport-Security (HSTS) ausente",
                            severity="HIGH",
                            category="Headers",
                            description="HSTS no está habilitado, lo que permite que una conexión inicial sea interceptada o degradada a HTTP mediante ataques de SSL Stripping.",
                            evidence="Cabecera 'Strict-Transport-Security' no encontrada en la respuesta HTTP.",
                            impact="Vulnerabilidad a ataques Man-in-the-Middle y degradación de protocolo en redes hostiles.",
                            remediation="Configurar en el servidor: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
                            cwe_id="CWE-319",
                            owasp_category="A05:2021 - Security Misconfiguration",
                        ))
                        priority_actions.append("Agregar cabecera HSTS en la configuración del servidor web.")

                    elif item.header == "Content-Security-Policy":
                        findings.append(RiskFinding(
                            id="HDR-CSP",
                            title="Cabecera Content-Security-Policy (CSP) ausente",
                            severity="MEDIUM",
                            category="Headers",
                            description="No se han establecido restricciones de orígenes para la ejecución de scripts, hojas de estilo o recursos multimedia.",
                            evidence="Cabecera 'Content-Security-Policy' no encontrada.",
                            impact="Mayor exposición y riesgo ante ataques de Cross-Site Scripting (XSS) y Clickjacking.",
                            remediation="Definir una política CSP inicial: 'default-src \\'self\\'; script-src \\'self\\'; style-src \\'self\\' \\'unsafe-inline\\'; img-src \\'self\\' data:;'",
                            cwe_id="CWE-1021: Improper Restriction of Rendered UI Layers or Scripts",
                            owasp_category="A03:2021 - Injection",
                        ))
                        priority_actions.append("Implementar una política Content-Security-Policy (CSP) restrictiva.")

                    elif item.header == "X-Frame-Options":
                        findings.append(RiskFinding(
                            id="HDR-XFO",
                            title="Cabecera X-Frame-Options ausente (Riesgo de Clickjacking)",
                            severity="MEDIUM",
                            category="Headers",
                            description="El sitio permite ser cargado dentro de etiquetas <iframe> de dominios externos.",
                            evidence="Cabecera 'X-Frame-Options' no recibida y no se detectó directiva 'frame-ancestors' en CSP.",
                            impact="Un atacante puede crear un sitio malicioso con una capa invisible de esta página para engañar al usuario y capturar clics o acciones no deseadas.",
                            remediation="Configurar 'X-Frame-Options: SAMEORIGIN' o 'X-Frame-Options: DENY'.",
                            cwe_id="CWE-1021",
                            owasp_category="A05:2021 - Security Misconfiguration",
                        ))

                    elif item.header == "X-Content-Type-Options":
                        findings.append(RiskFinding(
                            id="HDR-XCTO",
                            title="Cabecera X-Content-Type-Options ausente",
                            severity="LOW",
                            category="Headers",
                            description="El navegador puede intentar adivinar (MIME sniffing) el tipo de contenido más allá de lo declarado por el servidor.",
                            evidence="Cabecera 'X-Content-Type-Options' ausente.",
                            impact="Potencial ejecución de código en archivos subidos por usuarios con extensiones no ejecutables.",
                            remediation="Configurar 'X-Content-Type-Options: nosniff'.",
                            cwe_id="CWE-79",
                            owasp_category="A05:2021 - Security Misconfiguration",
                        ))

                    elif item.header == "Referrer-Policy":
                        findings.append(RiskFinding(
                            id="HDR-REF",
                            title="Cabecera Referrer-Policy ausente",
                            severity="LOW",
                            category="Headers",
                            description="No se especifica qué información de URL se incluye en los encabezados Referer al navegar hacia enlaces externos.",
                            evidence="Cabecera 'Referrer-Policy' ausente.",
                            impact="Posible fuga de parámetros sensibles presentes en la URL hacia dominios de terceros.",
                            remediation="Configurar 'Referrer-Policy: strict-origin-when-cross-origin'.",
                            cwe_id="CWE-200: Exposure of Sensitive Information",
                            owasp_category="A01:2021 - Broken Access Control",
                        ))

                    elif item.header == "Permissions-Policy":
                        findings.append(RiskFinding(
                            id="HDR-PERM",
                            title="Cabecera Permissions-Policy no configurada",
                            severity="INFO",
                            category="Headers",
                            description="No se restringen explícitamente las APIs del navegador como cámara, micrófono o geolocalización.",
                            evidence="Cabecera 'Permissions-Policy' ausente.",
                            impact="Submarcos (iframes) de terceros podrían solicitar permisos si no están restringidos.",
                            remediation="Configurar 'Permissions-Policy: geolocation=(), microphone=(), camera=()'.",
                            cwe_id="CWE-693",
                            owasp_category="A05:2021 - Security Misconfiguration",
                        ))

                elif item.status == "WARNING":
                    findings.append(RiskFinding(
                        id=f"HDR-WARN-{item.header[:4]}",
                        title=f"Configuración subóptima en {item.header}",
                        severity=item.severity,
                        category="Headers",
                        description=item.recommendation,
                        evidence=f"Valor actual: '{item.value}'",
                        impact="Debilitamiento de las defensas del navegador frente a inyecciones o ataques de canal lateral.",
                        remediation=item.recommendation,
                        cwe_id="CWE-693",
                        owasp_category="A05:2021 - Security Misconfiguration",
                    ))
                elif item.status == "GOOD":
                    val_preview = item.value[:45] if item.value else "Activa"
                    strengths.append(f"Cabecera '{item.header}' correctamente implementada ({val_preview}...).")

            # Fugas de información en headers
            if http_data.server_info_leaks:
                for leak in http_data.server_info_leaks:
                    findings.append(RiskFinding(
                        id=f"LEAK-{hash(leak) % 1000}",
                        title="Divulgación de versiones o software del servidor (Banner Grabbing)",
                        severity="LOW",
                        category="Information Leak",
                        description="El servidor web incluye cabeceras que revelan la tecnología, versión del servidor o del framework en uso.",
                        evidence=f"Cabecera detectada: {leak}",
                        impact="Facilita a los atacantes identificar vulnerabilidades conocidas asociadas a versiones específicas de software durante la fase de reconocimiento.",
                        remediation="Ocultar la firma del servidor en la configuración (ej. 'server_tokens off;' en Nginx o 'ServerTokens Prod' en Apache).",
                        cwe_id="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
                        owasp_category="A05:2021 - Security Misconfiguration",
                    ))

        # --- C. ANÁLISIS DE COOKIES ---
        for cookie in cookies_data:
            if cookie.issues:
                for issue in cookie.issues:
                    severity = cookie.risk_level
                    findings.append(RiskFinding(
                        id=f"COOKIE-{cookie.name[:6]}",
                        title=f"Configuración insegura en Cookie '{cookie.name}'",
                        severity=severity,
                        category="Cookies",
                        description=issue,
                        evidence=f"Cookie: {cookie.name} | Secure: {cookie.secure} | HttpOnly: {cookie.httponly} | SameSite: {cookie.samesite or 'No definido'} | Sensible: {cookie.is_sensitive}",
                        impact=cookie.explanation or "Riesgo de robo de sesión (XSS), interceptación en red (MitM) o falsificación de petición (CSRF).",
                        remediation=f"Emitir la cookie '{cookie.name}' con atributos 'Secure; HttpOnly; SameSite=Lax; Path=/' en la cabecera Set-Cookie.",
                        cwe_id="CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
                        owasp_category="A05:2021 - Security Misconfiguration",
                    ))
                    if severity in ["HIGH", "CRITICAL"]:
                        priority_actions.append(f"Asegurar la cookie de sesión/autenticación '{cookie.name}' con flags Secure y HttpOnly.")
            else:
                strengths.append(f"Cookie '{cookie.name}' protegida con atributos Secure, HttpOnly y SameSite.")

        # --- D. ANÁLISIS DE RED Y PUERTOS ---
        if network_data:
            if not network_data.spf_configured:
                findings.append(RiskFinding(
                    id="DNS-SPF",
                    title="Registro SPF no configurado en DNS",
                    severity="LOW",
                    category="Network",
                    description="El dominio no cuenta con un registro TXT con directiva 'v=spf1' para autorizar servidores de correo electrónico legítimos.",
                    evidence="No se encontró registro SPF en la zona DNS del dominio.",
                    impact="Permite a terceros falsificar correos electrónicos en nombre de su dominio (Email Spoofing / Phishing).",
                    remediation="Publicar un registro TXT en el DNS con la política SPF adecuada, ej: 'v=spf1 mx -all'.",
                    cwe_id="CWE-345",
                    owasp_category="A05:2021 - Security Misconfiguration",
                ))

            if not network_data.dmarc_configured:
                findings.append(RiskFinding(
                    id="DNS-DMARC",
                    title="Registro DMARC ausente en DNS",
                    severity="LOW",
                    category="Network",
                    description="El dominio no cuenta con política DMARC publicada en '_dmarc.<dominio>'.",
                    evidence="No se localizó registro TXT en _dmarc.",
                    impact="Dificulta la protección de marca contra campañas de suplantación de identidad por correo.",
                    remediation="Añadir registro TXT en '_dmarc.<dominio>' con valor 'v=DMARC1; p=quarantine; rua=mailto:dmarc@dominio.com'.",
                    cwe_id="CWE-345",
                    owasp_category="A05:2021 - Security Misconfiguration",
                ))

            for open_port in network_data.open_ports:
                if open_port.risk in ["HIGH", "CRITICAL"]:
                    findings.append(RiskFinding(
                        id=f"PORT-{open_port.port}",
                        title=f"Puerto de alto riesgo expuesto a Internet: {open_port.port}/{open_port.protocol.upper()} ({open_port.service})",
                        severity=open_port.risk,
                        category="Network",
                        description=open_port.risk_reason or f"El servicio {open_port.service} está accesible públicamente.",
                        evidence=f"Puerto {open_port.port}/TCP abierto. Banner: {open_port.banner or 'No disponible'}",
                        impact="Exposición directa a ataques de fuerza bruta, escaneo de vulnerabilidades específicas de bases de datos y potencial acceso no autorizado.",
                        remediation=f"Bloquear el puerto {open_port.port} mediante firewall (iptables, UFW, AWS Security Group) o restringirlo únicamente a IPs internas autorizadas vía VPN.",
                        cwe_id="CWE-200 / CWE-284: Improper Access Control",
                        owasp_category="A05:2021 - Security Misconfiguration",
                    ))
                    priority_actions.append(f"Cerrar o filtrar con firewall el puerto expuesto {open_port.port} ({open_port.service}).")
                elif open_port.risk == "MEDIUM":
                    findings.append(RiskFinding(
                        id=f"PORT-{open_port.port}",
                        title=f"Puerto de servicio detectado: {open_port.port}/{open_port.protocol.upper()} ({open_port.service})",
                        severity="MEDIUM",
                        category="Network",
                        description=open_port.risk_reason or "Servicio de gestión o alternativo expuesto.",
                        evidence=f"Puerto {open_port.port} abierto.",
                        impact="Superficie de ataque ampliada.",
                        remediation=f"Evaluar si el puerto {open_port.port} requiere exposición pública o puede protegerse tras una pasarela de autenticación.",
                        cwe_id="CWE-284",
                        owasp_category="A05:2021 - Security Misconfiguration",
                    ))

            # Hallazgos NSE de Nmap (vulnerabilidades y configuración detectadas por scripts)
            nse_relevant = [
                n for n in network_data.nse_findings if n.severity in ("CRITICAL", "HIGH", "MEDIUM")
            ]
            for nse in nse_relevant:
                port_label = f"{nse.port}/{nse.protocol.upper()}" if nse.port else "nivel host"
                cve_txt = f" CVEs confirmadas: {', '.join(nse.cve_ids)}." if nse.cve_ids else ""
                findings.append(RiskFinding(
                    id=f"NSE-{nse.script_id}-{nse.port or 'host'}",
                    title=f"Vulnerabilidad detectada por Nmap NSE: {nse.title or nse.script_id}",
                    severity=nse.severity,
                    category="Network",
                    description=(
                        f"El script NSE '{nse.script_id}' reportó un hallazgo sobre {port_label}: "
                        f"{nse.title or 'sin descripción'}.{cve_txt}"
                    ),
                    evidence=f"nmap --script {nse.script_id} :: {nse.output[:600]}",
                    impact=(
                        "Explotación potencial del servicio afectado según el catálogo de vulnerabilidades "
                        "consultado por Nmap NSE. Requiere verificación manual para confirmar la explotabilidad."
                    ),
                    remediation=(
                        "Actualizar el servicio afectado a la versión corregida, aplicar el parche del fabricante "
                        "y restringir el acceso al puerto mediante firewall o lista de control de acceso."
                    ),
                    cwe_id="CWE-1035" if nse.cve_ids else "CWE-16",
                    owasp_category=(
                        "A06:2021 - Vulnerable and Outdated Components" if nse.cve_ids
                        else "A05:2021 - Security Misconfiguration"
                    ),
                ))
                priority_actions.append(
                    f"Verificar y corregir el hallazgo NSE '{nse.script_id}' en {port_label}"
                    + (f" ({', '.join(nse.cve_ids[:3])})." if nse.cve_ids else ".")
                )

            if network_data.nse_enabled and not nse_relevant:
                strengths.append(
                    f"Escaneo NSE de Nmap ejecutado ({len(network_data.nse_scripts_executed)} scripts) sin "
                    "vulnerabilidades confirmadas en los catálogos consultados."
                )

        # --- E. CÁLCULO DE SCORE DE SEGURIDAD (0-100) Y GRADO ---
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            risk_counts[f.severity] = risk_counts.get(f.severity, 0) + 1

        score = 100
        score -= risk_counts["CRITICAL"] * 30
        score -= risk_counts["HIGH"] * 15
        score -= risk_counts["MEDIUM"] * 6
        score -= risk_counts["LOW"] * 2
        score = max(5, min(100, score))

        if score >= 90:
            grade = "A+" if score >= 97 else "A"
        elif score >= 75:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 40:
            grade = "D"
        else:
            grade = "F"

        # --- F. BASE DETERMINÍSTICA DE SNIPPETS Y RESUMEN ---
        snippets = self._generate_remediation_snippets(findings, http_data)
        summary = self._generate_executive_summary(target_url, score, grade, risk_counts, findings, strengths)
        threat_intel_notes: Optional[str] = None
        ai_model_name = "Motor Experto Heurístico Nativo"

        # --- G. ENRIQUECIMIENTO CON GROQ (OpenAI GPT-OSS 120B / 20B) ---
        if self.groq_api_key and self.provider in ["auto", "groq", "openai-gpt-oss", "groq-120b", "groq-20b"]:
            groq_model_to_use = self.requested_model
            if self.provider == "groq-20b":
                groq_model_to_use = self.fast_model

            groq_result = self._call_groq_llm(
                target_url=target_url,
                score=score,
                grade=grade,
                risk_counts=risk_counts,
                findings=findings,
                strengths=strengths,
                http_data=http_data,
                ssl_data=ssl_data,
                network_data=network_data,
                model_name=groq_model_to_use,
            )

            if groq_result:
                if groq_result.get("executive_summary"):
                    summary = groq_result["executive_summary"]
                if groq_result.get("threat_intelligence_notes"):
                    threat_intel_notes = groq_result["threat_intelligence_notes"]
                if groq_result.get("priority_action_plan") and isinstance(groq_result["priority_action_plan"], list):
                    priority_actions = groq_result["priority_action_plan"]
                if groq_result.get("configuration_snippets") and isinstance(groq_result["configuration_snippets"], dict):
                    # Actualizar snippets con las versiones avanzadas generadas por el modelo
                    snippets.update(groq_result["configuration_snippets"])
                if groq_result.get("cve_correlations") and isinstance(groq_result["cve_correlations"], list):
                    cve_correlations = groq_result["cve_correlations"]

                ai_model_name = f"Groq Cloud • {groq_result.get('model_used', groq_model_to_use)}"

        return AiAnalysisResult(
            executive_summary=summary,
            security_score=score,
            security_grade=grade,
            risk_counts=risk_counts,
            findings=findings,
            key_strengths=strengths,
            priority_action_plan=priority_actions or ["El sitio presenta una postura de seguridad sólida. Mantener auditorías periódicas."],
            configuration_snippets=snippets,
            threat_intelligence_notes=threat_intel_notes,
            cve_correlations=cve_correlations,
            ai_model_used=ai_model_name,
        )

    def _call_groq_llm(
        self,
        target_url: str,
        score: int,
        grade: str,
        risk_counts: Dict[str, int],
        findings: List[RiskFinding],
        strengths: List[str],
        http_data: Optional[HttpAuditResult],
        ssl_data: Optional[SslCertInfo],
        network_data: Optional[NetworkAuditResult],
        model_name: str,
    ) -> Optional[Dict[str, Any]]:
        """Realiza la llamada a Groq API con OpenAI GPT-OSS (120B o 20B con fallback)."""
        models_to_try = [model_name]
        if model_name != self.fast_model:
            models_to_try.append(self.fast_model)

        # Preparar contexto técnico estructurado
        tech_list = []
        if http_data and http_data.detected_technologies:
            tech_list = [f"{t.get('name', '')} {t.get('version', '')}".strip() for t in http_data.detected_technologies]

        missing_headers = []
        if http_data:
            missing_headers = [h.header for h in http_data.security_headers if h.status == "MISSING"]

        open_ports_info = []
        if network_data:
            open_ports_info = [f"Port {p.port}/{p.protocol} ({p.service})" for p in network_data.open_ports]

        findings_summary = [
            {"id": f.id, "title": f.title, "severity": f.severity, "category": f.category, "evidence": f.evidence}
            for f in findings
        ]

        system_prompt = (
            "Eres un Auditor Principal de Ciberdefensa, Arquitecto de Seguridad Web y Especialista en Inteligencia de Amenazas (Threat Intelligence).\n"
            "Analiza los datos técnicos reales recopilados de un objetivo web y genera un informe de alta precisión profesional.\n"
            "REGLAS OBLIGATORIAS:\n"
            "1. NO inventes vulnerabilidades no sustentadas por las evidencias técnicas proporcionadas.\n"
            "2. Analiza las tecnologías y versiones detectadas en busca de vectores de ataque reales conocidos (CVEs o debilidades comunes).\n"
            "3. Devuelve SIEMPRE la respuesta en formato JSON estrictamente válido.\n"
            "4. Idioma: Español profesional y técnico.\n"
            "5. Si 'network_info.nse_findings' no está vacío, trata cada entrada como evidencia técnica de alta "
            "confianza generada por Nmap NSE e incorpórala a 'cve_correlations' y al plan de remediación.\n"
            "6. Estructura JSON requerida:\n"
            "   - 'executive_summary': (Texto Markdown) Resumen ejecutivo directivo y técnico con contexto de impacto real en el negocio.\n"
            "   - 'threat_intelligence_notes': (Texto Markdown) Análisis de inteligencia de amenazas sobre las tecnologías detectadas, posibles vectores de ataque y CVEs relevantes.\n"
            "   - 'priority_action_plan': (Array de Strings) Pasos ordenados por urgencia e impacto defensivo.\n"
            "   - 'configuration_snippets': (Objeto con claves 'NGINX', 'Apache', 'Node.js (Express & Helmet)', 'Cloudflare WAF') Código listo para producción adaptado a las cabeceras faltantes.\n"
            "   - 'cve_correlations': (Array de Objetos con 'technology', 'potential_cves', 'risk_description', 'mitigation')."
        )

        user_content = {
            "target_url": target_url,
            "calculated_score": score,
            "calculated_grade": grade,
            "risk_distribution": risk_counts,
            "detected_technologies": tech_list,
            "missing_security_headers": missing_headers,
            "server_leaks": http_data.server_info_leaks if http_data else [],
            "ssl_info": {
                "has_https": ssl_data.has_https if ssl_data else False,
                "protocol": ssl_data.protocol_version if ssl_data else None,
                "days_left": ssl_data.days_left if ssl_data else None,
                "is_expired": ssl_data.is_expired if ssl_data else False,
            } if ssl_data else None,
            "network_info": {
                "open_ports": open_ports_info,
                "spf": network_data.spf_configured if network_data else False,
                "dmarc": network_data.dmarc_configured if network_data else False,
                "nmap_nse_executed": network_data.nse_enabled if network_data else False,
                "nse_scripts_run": network_data.nse_scripts_executed if network_data else [],
                "nse_findings": [
                    {
                        "script": n.script_id,
                        "port": n.port,
                        "severity": n.severity,
                        "title": n.title,
                        "cves": n.cve_ids,
                    }
                    for n in network_data.nse_findings
                    if n.severity in ("CRITICAL", "HIGH", "MEDIUM")
                ] if network_data else [],
            } if network_data else None,
            "technical_findings": findings_summary,
            "strengths_detected": strengths,
        }

        headers = {
            "Authorization": f"Bearer {self.groq_api_key}",
            "Content-Type": "application/json",
        }

        for current_model in models_to_try:
            try:
                payload = {
                    "model": current_model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": json.dumps(user_content, ensure_ascii=False)},
                    ],
                    "temperature": 0.2,
                    "response_format": {"type": "json_object"},
                }

                with httpx.Client(timeout=25.0) as client:
                    response = client.post(self.GROQ_API_URL, headers=headers, json=payload)

                if response.status_code == 200:
                    data = response.json()
                    raw_content = data["choices"][0]["message"]["content"]
                    parsed = json.loads(raw_content)
                    parsed["model_used"] = current_model
                    return parsed
                else:
                    logger.warning(f"Groq API {current_model} returned status {response.status_code}: {response.text}")
            except Exception as e:
                logger.warning(f"Error calling Groq model {current_model}: {str(e)}")

        return None

    def _generate_executive_summary(
        self,
        url: str,
        score: int,
        grade: str,
        counts: Dict[str, int],
        findings: List[RiskFinding],
        strengths: List[str],
    ) -> str:
        """Construye un resumen ejecutivo profesional determinístico basado estrictamente en evidencias reales."""
        total_issues = len(findings)
        high_critical = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)

        status_desc = "EXCELENTE" if score >= 90 else "SATISFACTORIA" if score >= 75 else "MODERADA CON RIESGOS" if score >= 50 else "CRÍTICA / DEFICIENTE"

        summary = (
            f"El análisis automatizado de seguridad ejecutado sobre **{url}** determinó una calificación de **{score}/100 (Grado {grade})**, "
            f"clasificando la postura actual del objetivo como **{status_desc}**.\n\n"
            f"Se identificaron un total de **{total_issues} hallazgo(s) técnico(s)** distribuidos en: "
            f"**{counts.get('CRITICAL', 0)} Críticos**, **{counts.get('HIGH', 0)} Altos**, **{counts.get('MEDIUM', 0)} Medios**, "
            f"**{counts.get('LOW', 0)} Bajos** y **{counts.get('INFO', 0)} Informativos**.\n\n"
        )

        if high_critical > 0:
            summary += (
                f"⚠️ **Atención Prioritaria**: Se detectaron {high_critical} vulnerabilidad(es) de severidad Alta o Crítica "
                f"que requieren mitigación inmediata para evitar riesgos de interceptación de tráfico, secuestro de sesiones "
                f"o exposición no autorizada de servicios internos.\n\n"
            )
        else:
            summary += (
                "✅ **Sin Riesgos Críticos Inmediatos**: No se detectaron vulnerabilidades críticas de exposición masiva. "
                "Las oportunidades de mejora corresponden a robustecimiento defensivo (Hardening) de cabeceras HTTP y políticas DNS.\n\n"
            )

        if strengths:
            summary += f"🔒 **Fortalezas Detectadas**: Se verificó la implementación adecuada de {len(strengths)} control(es) de seguridad, incluyendo el cifrado de transporte y la configuración adecuada de parámetros defensivos."

        return summary

    def _generate_remediation_snippets(self, findings: List[RiskFinding], http_data: Optional[HttpAuditResult]) -> Dict[str, str]:
        """Genera plantillas de configuración listas para aplicar en Nginx, Apache y Node.js."""
        missing_hsts = any(f.id == "HDR-HSTS" for f in findings)
        missing_csp = any(f.id == "HDR-CSP" for f in findings)
        missing_xfo = any(f.id == "HDR-XFO" for f in findings)
        missing_xcto = any(f.id == "HDR-XCTO" for f in findings)
        missing_ref = any(f.id == "HDR-REF" for f in findings)
        missing_perm = any(f.id == "HDR-PERM" for f in findings)

        # Snippet NGINX
        nginx_lines = [
            "# --- Configuración de Seguridad Recomendada para NGINX ---",
            "server {",
            "    # Ocultar versión del servidor",
            "    server_tokens off;",
            "",
            "    # Cabeceras de Seguridad (Hardening)",
        ]
        if missing_hsts:
            nginx_lines.append("    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;")
        if missing_xcto:
            nginx_lines.append("    add_header X-Content-Type-Options \"nosniff\" always;")
        if missing_xfo:
            nginx_lines.append("    add_header X-Frame-Options \"SAMEORIGIN\" always;")
        if missing_ref:
            nginx_lines.append("    add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;")
        if missing_perm:
            nginx_lines.append("    add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;")
        if missing_csp:
            nginx_lines.append("    add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';\" always;")
        nginx_lines.extend([
            "",
            "    # Resto de su configuración...",
            "}",
        ])

        # Snippet Apache .htaccess / httpd.conf
        apache_lines = [
            "# --- Configuración de Seguridad Recomendada para Apache (.htaccess) ---",
            "<IfModule mod_headers.c>",
            "    # Ocultar versión de Apache",
            "    ServerSignature Off",
            "",
        ]
        if missing_hsts:
            apache_lines.append("    Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"")
        if missing_xcto:
            apache_lines.append("    Header always set X-Content-Type-Options \"nosniff\"")
        if missing_xfo:
            apache_lines.append("    Header always set X-Frame-Options \"SAMEORIGIN\"")
        if missing_ref:
            apache_lines.append("    Header always set Referrer-Policy \"strict-origin-when-cross-origin\"")
        if missing_perm:
            apache_lines.append("    Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\"")
        if missing_csp:
            apache_lines.append("    Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;\"")
        apache_lines.extend([
            "</IfModule>",
        ])

        # Snippet Express.js (Helmet)
        node_lines = [
            "// --- Configuración con Helmet para Node.js / Express ---",
            "const express = require('express');",
            "const helmet = require('helmet');",
            "",
            "const app = express();",
            "",
            "// Aplicar todas las cabeceras estándar de seguridad de una sola vez",
            "app.use(helmet({",
            "  contentSecurityPolicy: {",
            "    directives: {",
            "      defaultSrc: [\"'self'\"],",
            "      scriptSrc: [\"'self'\"],",
            "      styleSrc: [\"'self'\", \"'unsafe-inline'\"],",
            "      imgSrc: [\"'self'\", \"data:\"],",
            "    },",
            "  },",
            "  hsts: {",
            "    maxAge: 31536000,",
            "    includeSubDomains: true,",
            "    preload: true,",
            "  },",
            "  frameguard: { action: 'sameorigin' },",
            "  noSniff: true,",
            "  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },",
            "});",
        ]

        return {
            "NGINX": "\n".join(nginx_lines),
            "Apache": "\n".join(apache_lines),
            "Node.js (Express & Helmet)": "\n".join(node_lines),
        }
