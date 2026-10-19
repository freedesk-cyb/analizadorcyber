import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Tuple, List, Dict, Any, Optional

from modules.models import SslCertInfo


class SslAnalyzer:
    """Módulo de análisis pasivo y seguro de certificados SSL/TLS y versiones de protocolo."""

    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout

    def analyze(self, target_url: str) -> Tuple[SslCertInfo, List[str]]:
        """Extrae de forma segura el certificado X.509 y metadatos de la sesión TLS."""
        logs = []
        logs.append(f"[+] Iniciando auditoría SSL/TLS...")

        parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        hostname = parsed.hostname or target_url
        port = parsed.port or (80 if parsed.scheme == "http" else 443)

        # Si el usuario ingresó http:// explícito, comprobar si el puerto 443 tiene HTTPS disponible
        if parsed.scheme == "http" and port == 80:
            port = 443  # Probar si el host soporta HTTPS

        # Contexto SSL por defecto con validación estándar
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        cert_dict = None
        protocol_version = None
        cipher_used = None
        validation_errors = []

        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_dict = ssock.getpeercert()
                    protocol_version = ssock.version()
                    cipher_info = ssock.cipher()
                    cipher_used = f"{cipher_info[0]} ({cipher_info[1]}, {cipher_info[2]} bits)" if cipher_info else None
                    logs.append(f"[+] Conexión TLS exitosa con {hostname}:{port} usando {protocol_version}")

        except ssl.SSLCertVerificationError as exc:
            logs.append(f"[-] Error de validación de certificado SSL: {exc.verify_message}")
            validation_errors.append(f"Error de validación: {exc.verify_message} (Código: {exc.verify_code})")
            # Reintentar sin validación para extraer los datos del certificado autofirmado/inválido
            cert_dict, protocol_version, cipher_used = self._fallback_unverified_cert(hostname, port)

        except ssl.SSLError as exc:
            logs.append(f"[-] Error SSL/TLS: {str(exc)}")
            validation_errors.append(f"Error SSL: {str(exc)}")
            cert_dict, protocol_version, cipher_used = self._fallback_unverified_cert(hostname, port)

        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
            logs.append(f"[-] No se pudo establecer conexión SSL en {hostname}:{port} - {str(exc)}")
            return SslCertInfo(
                has_https=False,
                subject={},
                issuer={},
                common_name=None,
                san_list=[],
                valid_from=None,
                valid_to=None,
                days_left=None,
                is_expired=False,
                is_expiring_soon=False,
                protocol_version=None,
                cipher_suite=None,
                validation_errors=[f"HTTPS no disponible o puerto 443 cerrado ({str(exc)})"],
                grade="F",
            ), logs

        if not cert_dict:
            return SslCertInfo(
                has_https=False,
                subject={},
                issuer={},
                validation_errors=validation_errors or ["No se pudo obtener información del certificado."],
                grade="F",
            ), logs

        # Procesar certificado
        subject_dict = self._parse_x509_name(cert_dict.get("subject", ()))
        issuer_dict = self._parse_x509_name(cert_dict.get("issuer", ()))
        common_name = subject_dict.get("commonName")

        # SANs (Subject Alternative Names)
        sans = []
        for san_type, san_val in cert_dict.get("subjectAltName", ()):
            if san_type == "DNS":
                sans.append(san_val)

        # Fechas de validez
        not_before_str = cert_dict.get("notBefore")
        not_after_str = cert_dict.get("notAfter")
        valid_from = None
        valid_to = None
        days_left = None
        is_expired = False
        is_expiring_soon = False

        if not_before_str and not_after_str:
            try:
                # Formato OpenSSL estándar: 'May 10 00:00:00 2026 GMT'
                dt_format = "%b %d %H:%M:%S %Y %Z"
                dt_before = datetime.strptime(not_before_str, dt_format).replace(tzinfo=timezone.utc)
                dt_after = datetime.strptime(not_after_str, dt_format).replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)

                valid_from = dt_before.strftime("%Y-%m-%d %H:%M:%S UTC")
                valid_to = dt_after.strftime("%Y-%m-%d %H:%M:%S UTC")

                delta = dt_after - now
                days_left = delta.days

                if days_left < 0:
                    is_expired = True
                    validation_errors.append(f"El certificado SSL expiró hace {abs(days_left)} días.")
                elif days_left < 30:
                    is_expiring_soon = True
                    validation_errors.append(f"El certificado expirará pronto ({days_left} días restantes).")

            except Exception as e:
                logs.append(f"[-] No se pudo parsear fecha del certificado: {str(e)}")

        # Evaluar versión de TLS
        if protocol_version in ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]:
            validation_errors.append(f"Uso de protocolo inseguro u obsoleto ({protocol_version}). Se requiere TLSv1.2 o TLSv1.3.")

        # Calcular grado SSL
        grade = "A"
        if is_expired or any("Error de validación" in err for err in validation_errors):
            grade = "F"
        elif is_expiring_soon or (protocol_version and protocol_version in ["TLSv1", "TLSv1.1"]):
            grade = "C"
        elif validation_errors:
            grade = "B"
        elif protocol_version == "TLSv1.3":
            grade = "A+"

        logs.append(f"[+] Certificado emitido por: {issuer_dict.get('organizationName', issuer_dict.get('commonName', 'Desconocido'))} - Válido por {days_left} días.")

        return SslCertInfo(
            has_https=True,
            subject=subject_dict,
            issuer=issuer_dict,
            common_name=common_name,
            san_list=sans,
            valid_from=valid_from,
            valid_to=valid_to,
            days_left=days_left,
            is_expired=is_expired,
            is_expiring_soon=is_expiring_soon,
            protocol_version=protocol_version,
            cipher_suite=cipher_used,
            validation_errors=validation_errors,
            grade=grade,
        ), logs

    def _fallback_unverified_cert(self, hostname: str, port: int) -> Tuple[Optional[dict], Optional[str], Optional[str]]:
        """Intenta obtener el certificado en modo sin verificación para diagnosticar certificados autofirmados o caducados."""
        try:
            unverified_ctx = ssl.create_default_context()
            unverified_ctx.check_hostname = False
            unverified_ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with unverified_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=False)
                    version = ssock.version()
                    cipher_info = ssock.cipher()
                    cipher_str = f"{cipher_info[0]} ({cipher_info[1]}, {cipher_info[2]} bits)" if cipher_info else None
                    return cert_bin or {}, version, cipher_str
        except Exception:
            return None, None, None

    def _parse_x509_name(self, rdn_sequence) -> Dict[str, str]:
        """Convierte la tupla RDN de python ssl a un diccionario legible."""
        result = {}
        for rdn in rdn_sequence:
            for key, val in rdn:
                result[key] = val
        return result
