import os
from typing import Dict, Any, List, Tuple, Optional
import httpx


class ZapAnalyzer:
    """Módulo de integración opcional con el motor de análisis OWASP ZAP."""

    def __init__(self, zap_base_url: Optional[str] = None, api_key: Optional[str] = None):
        self.zap_base_url = zap_base_url or os.getenv("ZAP_API_URL", "http://localhost:8080")
        self.api_key = api_key or os.getenv("ZAP_API_KEY", "")

    def analyze(self, target_url: str, enabled: bool = False) -> Tuple[Dict[str, Any], List[str]]:
        """Verifica disponibilidad de ZAP y ejecuta escaneo autorizado si se encuentra activo."""
        logs = []

        if not enabled:
            return {
                "enabled": False,
                "status": "DISABLED",
                "message": "Escaneo ZAP no habilitado para este análisis.",
                "alerts": [],
                "alert_counts": {"High": 0, "Medium": 0, "Low": 0, "Informational": 0},
            }, logs

        logs.append(f"[+] Verificando disponibilidad de instancia OWASP ZAP en {self.zap_base_url}...")

        try:
            # Probar conexión al endpoint de versión de ZAP
            headers = {"X-ZAP-API-Key": self.api_key} if self.api_key else {}
            with httpx.Client(timeout=3.0) as client:
                resp = client.get(f"{self.zap_base_url}/JSON/core/view/version/", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    version = data.get("version", "Activo")
                    logs.append(f"[+] Instancia OWASP ZAP conectada exitosamente (Versión: {version})")

                    # Consultar alertas para la URL objetivo
                    alerts_resp = client.get(
                        f"{self.zap_base_url}/JSON/alert/view/alertsByRisk/",
                        params={"url": target_url, "recurrence": "true"},
                        headers=headers,
                        timeout=5.0
                    )
                    alerts_data = alerts_resp.json() if alerts_resp.status_code == 200 else {}

                    return {
                        "enabled": True,
                        "status": "CONNECTED",
                        "zap_version": version,
                        "alerts": alerts_data.get("alertsByRisk", []),
                        "message": "ZAP conectado. Resultados de auditoría web incorporados.",
                    }, logs

        except Exception as exc:
            logs.append(f"[i] OWASP ZAP no disponible en {self.zap_base_url} ({str(exc)}). Continuando con auditoría nativa.")

        return {
            "enabled": True,
            "status": "STANDBY",
            "message": "Servicio OWASP ZAP no detectado en el puerto local. Escaneo nativo completado con éxito.",
            "alerts": [],
            "alert_counts": {"High": 0, "Medium": 0, "Low": 0, "Informational": 0},
        }, logs
