import time
import re
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse
import httpx
from bs4 import BeautifulSoup

from modules.models import HttpAuditResult, HeaderAuditItem


SECURITY_HEADER_SPECS = {
    "Content-Security-Policy": {
        "description": "Previene ataques de inyección de código como Cross-Site Scripting (XSS) y Clickjacking al restringir los orígenes de contenido ejecutable.",
        "recommended": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';",
        "severity_if_missing": "MEDIUM",
        "category": "Inyección / XSS",
    },
    "Strict-Transport-Security": {
        "description": "Fuerza a los navegadores a comunicarse exclusivamente mediante HTTPS cifrado (HSTS), previniendo ataques Man-in-the-Middle y SSL Stripping.",
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "severity_if_missing": "HIGH",
        "category": "Cifrado / Transporte",
    },
    "X-Content-Type-Options": {
        "description": "Impide que el navegador interprete archivos con tipos MIME incorrectos (MIME sniffing), reduciendo riesgos de ejecución de scripts maliciosos.",
        "recommended": "nosniff",
        "severity_if_missing": "LOW",
        "category": "MIME Sniffing",
    },
    "X-Frame-Options": {
        "description": "Protege contra ataques de Clickjacking impidiendo que la página sea embebida en marcos (<frame>, <iframe> o <object>).",
        "recommended": "DENY o SAMEORIGIN",
        "severity_if_missing": "MEDIUM",
        "category": "Clickjacking",
    },
    "Referrer-Policy": {
        "description": "Controla cuánta información de referencia (URL anterior) se envía en la cabecera Referer al navegar a otros sitios.",
        "recommended": "strict-origin-when-cross-origin o no-referrer",
        "severity_if_missing": "LOW",
        "category": "Privacidad / Fuga de Datos",
    },
    "Permissions-Policy": {
        "description": "Permite restringir el acceso a APIs y funciones sensibles del navegador (cámara, micrófono, geolocalización, pago).",
        "recommended": "geolocation=(), microphone=(), camera=()",
        "severity_if_missing": "INFO",
        "category": "Control de Características",
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Aísla el contexto de navegación para prevenir ataques de canales laterales como Spectre y manipulación de ventanas emergentes.",
        "recommended": "same-origin",
        "severity_if_missing": "INFO",
        "category": "Aislamiento de Origen",
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Bloquea que otros sitios web lean recursos sensibles cargados desde este origen.",
        "recommended": "same-origin o same-site",
        "severity_if_missing": "INFO",
        "category": "Aislamiento de Recursos",
    },
}

INFO_LEAK_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime",
    "x-version",
    "x-drupal-cache",
    "x-varnish",
    "via",
]


class WebAnalyzer:
    """Módulo de análisis de protocolos HTTP/HTTPS, cabeceras y tecnologías."""

    def __init__(self, timeout: float = 12.0, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = (
            user_agent
            or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 AI-Web-Security-Auditor/1.0"
        )

    def analyze(self, target_url: str) -> Tuple[HttpAuditResult, List[str]]:
        """Realiza la solicitud HTTP/HTTPS completa, analiza cabeceras y detecta tecnologías."""
        logs = []
        logs.append(f"[+] Iniciando análisis HTTP/HTTPS sobre: {target_url}")

        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        headers_request = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

        redirect_chain = []
        start_time = time.perf_counter()

        try:
            with httpx.Client(
                follow_redirects=True,
                verify=False,  # Permite analizar sitios con certificados autofirmados
                timeout=self.timeout,
                headers=headers_request,
            ) as client:
                response = client.get(target_url)
                elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

                # Rastrear historial de redirecciones
                if response.history:
                    for resp in response.history:
                        redirect_chain.append({
                            "status_code": resp.status_code,
                            "url": str(resp.url),
                            "location": resp.headers.get("location", ""),
                        })
                    logs.append(f"[+] Detectadas {len(redirect_chain)} redirección(es) hacia {response.url}")

                final_url = str(response.url)
                status_code = response.status_code
                response_headers = {k: v for k, v in response.headers.items()}
                html_body = response.text

        except httpx.RequestError as exc:
            logs.append(f"[-] Error de conexión con {target_url}: {str(exc)}")
            # Devolver resultado mínimo de error
            return HttpAuditResult(
                target_url=target_url,
                final_url=target_url,
                status_code=0,
                response_time_ms=0.0,
                http_method="GET",
                redirect_chain=[],
                headers={},
                security_headers=[],
                server_info_leaks=[f"Fallo de conexión: {str(exc)}"],
                detected_technologies=[],
                html_title=None,
            ), logs

        # Evaluar cabeceras de seguridad
        security_headers_audit = self._audit_security_headers(response_headers, target_url)

        # Detectar fuga de información en cabeceras
        info_leaks = self._detect_info_leaks(response_headers)

        # Extraer tecnologías y metadatos HTML
        technologies, html_title = self._detect_technologies(response_headers, html_body)

        logs.append(f"[+] HTTP {status_code} ({elapsed_ms} ms) - {len(security_headers_audit)} cabeceras de seguridad evaluadas.")

        result = HttpAuditResult(
            target_url=target_url,
            final_url=final_url,
            status_code=status_code,
            response_time_ms=elapsed_ms,
            http_method="GET",
            redirect_chain=redirect_chain,
            headers=response_headers,
            security_headers=security_headers_audit,
            server_info_leaks=info_leaks,
            detected_technologies=technologies,
            html_title=html_title,
        )

        return result, logs

    def _audit_security_headers(self, headers: Dict[str, str], target_url: str) -> List[HeaderAuditItem]:
        """Evalúa minuciosamente las cabeceras de seguridad presentes y ausentes."""
        audit_items = []
        normalized_headers = {k.lower(): (k, v) for k, v in headers.items()}

        for header_name, spec in SECURITY_HEADER_SPECS.items():
            header_lower = header_name.lower()
            present = header_lower in normalized_headers

            if not present:
                # Regla especial: HSTS sólo aplica si es HTTPS
                is_https = target_url.startswith("https://")
                severity = spec["severity_if_missing"] if is_https or header_name != "Strict-Transport-Security" else "INFO"

                audit_items.append(HeaderAuditItem(
                    header=header_name,
                    present=False,
                    value=None,
                    status="MISSING",
                    severity=severity,
                    recommendation=f"Configurar la cabecera '{header_name}: {spec['recommended']}'",
                    description=spec["description"],
                ))
            else:
                orig_key, value = normalized_headers[header_lower]
                status, severity, recommendation = self._evaluate_header_value(header_name, value)
                audit_items.append(HeaderAuditItem(
                    header=header_name,
                    present=True,
                    value=value,
                    status=status,
                    severity=severity,
                    recommendation=recommendation,
                    description=spec["description"],
                ))

        return audit_items

    def _evaluate_header_value(self, header_name: str, value: str) -> Tuple[str, str, str]:
        """Analiza la fortaleza de los valores de cabeceras configuradas."""
        val_lower = value.lower()

        if header_name == "Content-Security-Policy":
            issues = []
            if "'unsafe-inline'" in val_lower and "nonce-" not in val_lower and "sha256-" not in val_lower:
                issues.append("permite 'unsafe-inline' (reduce protección XSS)")
            if "'unsafe-eval'" in val_lower:
                issues.append("permite 'unsafe-eval' (ejecución de strings como código)")
            if " *" in val_lower or "http:" in val_lower:
                issues.append("utiliza comodines o recursos HTTP inseguros")
            if "default-src" not in val_lower and "script-src" not in val_lower:
                issues.append("carece de directiva 'default-src' o 'script-src'")

            if issues:
                return (
                    "WARNING",
                    "MEDIUM",
                    f"Mejorar CSP: Se detectó {', '.join(issues)}. Considere implementar nonces o hashes estrictos."
                )
            return "GOOD", "INFO", "Content-Security-Policy configurada adecuadamente."

        elif header_name == "Strict-Transport-Security":
            max_age_match = re.search(r"max-age=(\d+)", val_lower)
            if not max_age_match:
                return "WARNING", "MEDIUM", "HSTS no contiene la directiva obligatoria max-age."

            max_age_val = int(max_age_match.group(1))
            if max_age_val < 15552000:  # Menos de 6 meses
                return (
                    "WARNING",
                    "LOW",
                    f"El valor de max-age ({max_age_val}s) es bajo. Se recomienda al menos 31536000 (1 año)."
                )
            if "includesubdomains" not in val_lower:
                return (
                    "GOOD",
                    "INFO",
                    "HSTS activo. Para máxima seguridad agregue 'includeSubDomains; preload'."
                )
            return "GOOD", "INFO", "HSTS implementado de forma robusta con max-age prolongado."

        elif header_name == "X-Content-Type-Options":
            if "nosniff" in val_lower:
                return "GOOD", "INFO", "Protección contra MIME-sniffing activa con valor 'nosniff'."
            return "WARNING", "LOW", "Valor no estándar en X-Content-Type-Options. Debe ser 'nosniff'."

        elif header_name == "X-Frame-Options":
            if "deny" in val_lower or "sameorigin" in val_lower:
                return "GOOD", "INFO", f"Protección Clickjacking activa con directiva '{value}'."
            return "WARNING", "LOW", "Valor de X-Frame-Options permisivo o no recomendado. Usar DENY o SAMEORIGIN."

        elif header_name == "Referrer-Policy":
            if any(safe in val_lower for safe in ["no-referrer", "strict-origin-when-cross-origin", "same-origin", "strict-origin"]):
                return "GOOD", "INFO", f"Política de Referrer adecuada ('{value}')."
            return "WARNING", "LOW", f"Política de Referrer '{value}' podría exponer URLs con tokens o datos sensibles a terceros."

        return "GOOD", "INFO", "Cabecera presente y reconocida."

    def _detect_info_leaks(self, headers: Dict[str, str]) -> List[str]:
        """Detecta cabeceras que revelan software del servidor, frameworks o versiones."""
        leaks = []
        for header, value in headers.items():
            if header.lower() in INFO_LEAK_HEADERS:
                leaks.append(f"{header}: {value}")
        return leaks

    def _detect_technologies(self, headers: Dict[str, str], html: str) -> Tuple[List[Dict[str, str]], str]:
        """Detecta software, CMS, bibliotecas y tecnologías presentes."""
        technologies = []
        title = None

        headers_str = " ".join([f"{k}:{v}" for k, v in headers.items()]).lower()

        # Detección por headers
        server = headers.get("server", "") or headers.get("Server", "")
        if server:
            technologies.append({"name": f"Servidor Web: {server}", "category": "Web Server"})

        powered_by = headers.get("x-powered-by", "") or headers.get("X-Powered-By", "")
        if powered_by:
            technologies.append({"name": f"Backend Runtime: {powered_by}", "category": "Backend"})

        if "cf-ray" in headers_str or "cloudflare" in headers_str:
            technologies.append({"name": "Cloudflare CDN / WAF", "category": "CDN / WAF"})
        if "x-amz-cf-id" in headers_str or "cloudfront" in headers_str:
            technologies.append({"name": "Amazon CloudFront CDN", "category": "CDN"})
        if "fastly" in headers_str:
            technologies.append({"name": "Fastly CDN", "category": "CDN"})

        # Análisis HTML con BeautifulSoup
        if html:
            try:
                soup = BeautifulSoup(html[:100000], "html.parser")
                if soup.title and soup.title.string:
                    title = soup.title.string.strip()

                # Meta tags
                meta_generator = soup.find("meta", attrs={"name": re.compile(r"generator", re.I)})
                if meta_generator and meta_generator.get("content"):
                    technologies.append({
                        "name": f"CMS / Generador: {meta_generator.get('content')}",
                        "category": "CMS / Generator"
                    })

                # Búsqueda de firmas comunes en HTML y scripts
                html_lower = html.lower()
                if "wp-content" in html_lower or "wp-includes" in html_lower:
                    technologies.append({"name": "WordPress CMS", "category": "CMS"})
                if "drupal" in html_lower:
                    technologies.append({"name": "Drupal CMS", "category": "CMS"})
                if "joomla" in html_lower:
                    technologies.append({"name": "Joomla CMS", "category": "CMS"})
                if "react" in html_lower or "__reactfiber" in html_lower or "react-dom" in html_lower:
                    technologies.append({"name": "React.js Framework", "category": "Frontend UI"})
                if "vue" in html_lower or "__vue__" in html_lower:
                    technologies.append({"name": "Vue.js Framework", "category": "Frontend UI"})
                if "angular" in html_lower or "ng-" in html_lower:
                    technologies.append({"name": "Angular Framework", "category": "Frontend UI"})
                if "_next" in html_lower:
                    technologies.append({"name": "Next.js (React)", "category": "Web Framework"})
                if "_nuxt" in html_lower:
                    technologies.append({"name": "Nuxt.js (Vue)", "category": "Web Framework"})
                if "bootstrap" in html_lower:
                    technologies.append({"name": "Bootstrap CSS", "category": "UI Library"})
                if "tailwind" in html_lower:
                    technologies.append({"name": "Tailwind CSS", "category": "UI Library"})
                if "jquery" in html_lower:
                    technologies.append({"name": "jQuery Library", "category": "JavaScript Library"})

            except Exception:
                pass

        # Desduplicar tecnologías por nombre
        unique_techs = []
        seen = set()
        for t in technologies:
            if t["name"] not in seen:
                seen.add(t["name"])
                unique_techs.append(t)

        return unique_techs, title
