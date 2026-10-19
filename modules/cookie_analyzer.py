import re
from typing import List, Tuple
from http.cookies import SimpleCookie
import httpx

from modules.models import CookieAuditItem

SENSITIVE_COOKIE_PATTERNS = [
    r"sess",
    r"session",
    r"token",
    r"auth",
    r"jwt",
    r"id",
    r"user",
    r"login",
    r"csrf",
    r"xsrf",
    r"phpsessid",
    r"jsessionid",
    r"aspsessionid",
    r"connect\.sid",
    r"remember",
    r"key",
    r"secret",
]


class CookieAnalyzer:
    """Módulo de análisis de seguridad de cookies HTTP."""

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def analyze(self, target_url: str) -> Tuple[List[CookieAuditItem], List[str]]:
        """Realiza una petición para capturar y auditar todas las cookies emitidas vía Set-Cookie."""
        logs = []
        logs.append(f"[+] Inspeccionando cookies para: {target_url}")

        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        cookie_items: List[CookieAuditItem] = []

        try:
            with httpx.Client(follow_redirects=True, verify=False, timeout=self.timeout) as client:
                response = client.get(target_url)

                # Extraer todas las cabeceras Set-Cookie individuales (HTTPX maneja múltiples headers Set-Cookie)
                raw_set_cookies = response.headers.get_list("set-cookie")

                # Si get_list no devuelve o no existe, intentar raw headers
                if not raw_set_cookies:
                    raw_cookie_header = response.headers.get("set-cookie")
                    if raw_cookie_header:
                        raw_set_cookies = [raw_cookie_header]

                if not raw_set_cookies:
                    logs.append("[i] No se recibieron cookies en la respuesta HTTP inicial.")
                    return [], logs

                for raw_cookie_str in raw_set_cookies:
                    audited_cookie = self._parse_and_audit_single_cookie(raw_cookie_str, target_url)
                    if audited_cookie:
                        cookie_items.append(audited_cookie)

                logs.append(f"[+] Total de cookies analizadas: {len(cookie_items)}")

        except Exception as exc:
            logs.append(f"[-] Error al analizar cookies: {str(exc)}")

        return cookie_items, logs

    def _parse_and_audit_single_cookie(self, raw_cookie_str: str, target_url: str) -> CookieAuditItem:
        """Parsea una directiva Set-Cookie y evalúa sus atributos de seguridad."""
        cookie_obj = SimpleCookie()
        try:
            cookie_obj.load(raw_cookie_str)
        except Exception:
            pass

        # Parseo manual robusto para asegurar banderas booleanas
        parts = [p.strip() for p in raw_cookie_str.split(";")]
        if not parts:
            return None

        # Primera parte: nombre=valor
        first_part = parts[0]
        if "=" in first_part:
            cookie_name, raw_val = first_part.split("=", 1)
        else:
            cookie_name, raw_val = first_part, ""

        cookie_name = cookie_name.strip()
        raw_val = raw_val.strip()

        # Enmascarar valor para el informe (mostrar solo primeros y últimos caracteres)
        if len(raw_val) > 8:
            masked_val = f"{raw_val[:3]}...{raw_val[-3:]} ({len(raw_val)} chars)"
        elif raw_val:
            masked_val = "***"
        else:
            masked_val = "[vacío]"

        # Atributos
        is_secure = False
        is_httponly = False
        samesite_val = None
        domain_val = None
        path_val = None
        expires_val = None

        for part in parts[1:]:
            part_lower = part.lower()
            if part_lower == "secure":
                is_secure = True
            elif part_lower == "httponly":
                is_httponly = True
            elif part_lower.startswith("samesite="):
                samesite_val = part.split("=", 1)[1].strip()
            elif part_lower.startswith("domain="):
                domain_val = part.split("=", 1)[1].strip()
            elif part_lower.startswith("path="):
                path_val = part.split("=", 1)[1].strip()
            elif part_lower.startswith("expires=") or part_lower.startswith("max-age="):
                expires_val = part.split("=", 1)[1].strip()

        # Detectar si el nombre de cookie sugiere información sensible / sesión
        is_sensitive = any(
            re.search(pat, cookie_name, re.IGNORECASE) for pat in SENSITIVE_COOKIE_PATTERNS
        )

        issues: List[str] = []
        risk_level = "SECURE"
        explanations: List[str] = []

        # Evaluación de Banderas
        is_https = target_url.startswith("https://")

        # 1. Flag Secure
        if not is_secure:
            if is_sensitive:
                issues.append("Falta flag 'Secure' en cookie de sesión/sensible.")
                explanations.append(
                    "Al no tener el atributo 'Secure', la cookie puede transmitirse en texto plano ante degradaciones HTTP, "
                    "permitiendo a un atacante en la misma red interceptar tokens de autenticación (Session Hijacking)."
                )
                risk_level = "HIGH"
            else:
                issues.append("Falta flag 'Secure'.")
                explanations.append(
                    "La cookie podría ser transmitida en conexiones no cifradas HTTP."
                )
                if risk_level != "HIGH":
                    risk_level = "MEDIUM"

        # 2. Flag HttpOnly
        if not is_httponly:
            if is_sensitive:
                issues.append("Falta flag 'HttpOnly' en cookie de autenticación.")
                explanations.append(
                    "Sin 'HttpOnly', cualquier script en el navegador (vía vulnerabilidad XSS) puede leer document.cookie "
                    "y exfiltrar la sesión del usuario inmediatamente."
                )
                risk_level = "HIGH"
            else:
                issues.append("Falta flag 'HttpOnly'.")
                explanations.append(
                    "Accesible por código JavaScript del lado cliente."
                )
                if risk_level == "SECURE":
                    risk_level = "LOW"

        # 3. SameSite
        if not samesite_val:
            issues.append("Atributo 'SameSite' ausente.")
            explanations.append(
                "La ausencia de SameSite expone a la aplicación a ataques de Cross-Site Request Forgery (CSRF). "
                "Se recomienda definir 'SameSite=Lax' o 'SameSite=Strict'."
            )
            if risk_level in ["SECURE", "LOW"]:
                risk_level = "MEDIUM"
        elif samesite_val.lower() == "none" and not is_secure:
            issues.append("SameSite=None sin flag 'Secure' (inseguro y rechazado por navegadores modernos).")
            explanations.append(
                "SameSite=None requiere obligatoriamente el atributo 'Secure' para evitar rechazos en navegadores."
            )
            risk_level = "HIGH"

        # 4. Prefijos __Host- y __Secure-
        if cookie_name.startswith("__Host-"):
            if not is_secure or path_val != "/" or domain_val is not None:
                issues.append("Violación del prefijo '__Host-': Requiere Secure, Path=/ y sin atributo Domain.")
                risk_level = "HIGH"
        elif cookie_name.startswith("__Secure-"):
            if not is_secure:
                issues.append("Violación del prefijo '__Secure-': Requiere la bandera 'Secure'.")
                risk_level = "HIGH"

        if not issues:
            risk_level = "SECURE"
            explanations.append("Cookie configurada con las mejores prácticas de seguridad (Secure, HttpOnly, SameSite).")

        return CookieAuditItem(
            name=cookie_name,
            value_masked=masked_val,
            domain=domain_val,
            path=path_val,
            secure=is_secure,
            httponly=is_httponly,
            samesite=samesite_val,
            expires=expires_val,
            is_sensitive=is_sensitive,
            risk_level=risk_level,
            issues=issues,
            explanation=" ".join(explanations),
        )
