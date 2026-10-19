import socket
import asyncio
import shutil
import subprocess
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional
import dns.resolver

from modules.models import NetworkAuditResult, PortServiceItem, NseScriptFinding


COMMON_SECURITY_PORTS = [
    (21, "FTP", "HIGH", "Servicio FTP en texto plano. Riesgo de interceptación de credenciales."),
    (22, "SSH", "INFO", "Servicio de administración remota SSH."),
    (23, "Telnet", "CRITICAL", "Protocolo Telnet sin cifrar. Extremadamente vulnerable a sniffing."),
    (25, "SMTP", "LOW", "Servidor de correo SMTP."),
    (53, "DNS", "LOW", "Servidor DNS."),
    (80, "HTTP", "INFO", "Servidor web HTTP estándar."),
    (110, "POP3", "LOW", "Servicio de correo POP3."),
    (143, "IMAP", "LOW", "Servicio de correo IMAP."),
    (443, "HTTPS", "INFO", "Servidor web HTTPS cifrado."),
    (465, "SMTPS", "INFO", "Servicio SMTP seguro sobre SSL/TLS."),
    (587, "SMTP-Submission", "LOW", "Envío de correo autenticado."),
    (993, "IMAPS", "INFO", "Servicio IMAP seguro sobre SSL/TLS."),
    (995, "POP3S", "INFO", "Servicio POP3 seguro sobre SSL/TLS."),
    (1433, "MSSQL", "HIGH", "Base de datos Microsoft SQL Server expuesta públicamente."),
    (1521, "Oracle DB", "HIGH", "Base de datos Oracle expuesta a la red pública."),
    (3306, "MySQL", "HIGH", "Base de datos MySQL/MariaDB expuesta a Internet. Riesgo de fuerza bruta y fuga."),
    (3389, "RDP", "HIGH", "Escritorio remoto de Windows (RDP) accesible directamente sin VPN."),
    (5432, "PostgreSQL", "HIGH", "Base de datos PostgreSQL accesible públicamente."),
    (6379, "Redis", "CRITICAL", "Instancia de caché/base de datos Redis expuesta sin autenticación obligatoria."),
    (8080, "HTTP-Proxy/Alt", "LOW", "Puerto web alternativo / Panel de administración."),
    (8443, "HTTPS-Alt", "INFO", "Puerto web HTTPS secundario."),
    (8888, "HTTP-Alt", "LOW", "Panel web secundario / Jupyter / Tomcat."),
    (9000, "SonarQube/PHP-FPM", "MEDIUM", "Servicio de administración o PHP-FPM expuesto."),
    (9200, "Elasticsearch", "CRITICAL", "Cluster Elasticsearch expuesto directamente a Internet."),
    (27017, "MongoDB", "CRITICAL", "Base de datos NoSQL MongoDB expuesta públicamente."),
]


# Puertos adicionales evaluados solo cuando se activa el escaneo NSE (superficie web/app ampliada).
NSE_EXTRA_PORTS = [
    (445, "SMB", "HIGH", "SMB/CIFS expuesto a Internet. Vector clásico de movilidad lateral y ransomware."),
    (135, "MS-RPC", "MEDIUM", "Endpoint Mapper de Windows expuesto públicamente."),
    (139, "NetBIOS", "HIGH", "NetBIOS sesion service expuesta. Filtrado de información y ataques locales."),
    (2049, "NFS", "HIGH", "Sistema de archivos NFS exportado a la red pública."),
    (2375, "Docker API", "CRITICAL", "API de Docker sin TLS. Control total del host si no requiere autenticación."),
    (2376, "Docker TLS", "MEDIUM", "API de Docker con TLS expuesta públicamente."),
    (3000, "HTTP-Dev", "LOW", "Servidor de desarrollo web (React, Django, Rails, Gitea)."),
    (4443, "HTTPS-Alt", "LOW", "Servicio web HTTPS alternativo."),
    (5000, "HTTP-Dev/API", "LOW", "API o servidor de desarrollo (Flask, Docker Registry)."),
    (5672, "AMQP", "MEDIUM", "Broker RabbitMQ expuesto. Posible acceso a colas de mensajes."),
    (5900, "VNC", "HIGH", "VNC sin cifrar accesible desde Internet."),
    (5985, "WinRM-HTTP", "HIGH", "WinRM HTTP expuesto. Ejecución remota de comandos en Windows."),
    (5986, "WinRM-HTTPS", "MEDIUM", "WinRM sobre TLS expuesto públicamente."),
    (6443, "K8s API", "HIGH", "API Server de Kubernetes expuesta a Internet."),
    (8000, "HTTP-Alt", "LOW", "Servidor web alternativo / API backend."),
    (8008, "HTTP-Alt", "LOW", "Servicio HTTP secundario."),
    (8081, "HTTP-Proxy/Alt", "LOW", "Puerto web alternativo / panel de administración."),
    (8082, "HTTP-Alt", "LOW", "Puerto web alternativo / consola de gestión."),
    (8088, "HTTP-Alt", "LOW", "Puerto web alternativo / proxy inverso."),
    (8090, "HTTP-Alt", "LOW", "Puerto web alternativo / aplicación interna."),
    (8161, "ActiveMQ-Console", "HIGH", "Consola de Apache ActiveMQ expuesta públicamente."),
    (8500, "Consul", "HIGH", "HashiCorp Consul expuesto. Descubrimiento de servicios y posible ejecución remota."),
    (8834, "Nessus-API", "HIGH", "API de Nessus expuesta públicamente."),
    (9001, "HTTP-Alt", "LOW", "Servicio web alternativo / Tor ORPort."),
    (9090, "HTTP-Alt/Monitor", "MEDIUM", "Consola de monitorización (Prometheus, Codiad) expuesta."),
    (9300, "Elastic-Transport", "HIGH", "Transporte interno de Elasticsearch expuesto."),
    (9443, "HTTPS-Alt/K8s", "MEDIUM", "Servicio web HTTPS alternativo o API de Kubernetes."),
    (10000, "Webmin", "HIGH", "Panel Webmin expuesto a Internet."),
    (10250, "Kubelet", "CRITICAL", "Kubelet API expuesto. Ejecución de contenedores y fuga de secretos."),
    (10443, "HTTPS-Alt", "LOW", "Puerto HTTPS alternativo."),
    (11211, "Memcached", "CRITICAL", "Memcached expuesto sin autenticación. Fuga y agotamiento de caché."),
    (15672, "RabbitMQ-UI", "HIGH", "Consola de administración de RabbitMQ expuesta."),
    (27018, "MongoDB-Secondary", "CRITICAL", "Réplica de MongoDB expuesta públicamente."),
]

NSE_PORT_SET = COMMON_SECURITY_PORTS + NSE_EXTRA_PORTS
PORT_RISK_MAP = {p: (svc, risk, reason) for p, svc, risk, reason in NSE_PORT_SET}

# Selección por defecto de scripts NSE: descubrimiento web/SSL + catálogos de vulnerabilidades.
DEFAULT_NSE_SCRIPTS = "default,vuln,vulners,http-enum,http-robots.txt,http-security-headers"
FALLBACK_NSE_SCRIPTS = "default,vuln"

# Salidas que solo declaran la ausencia de un problema y no aportan hallazgo.
NSE_NEGATIVE_MARKERS = (
    "COULDN'T FIND",
    "COULD NOT FIND",
    "NO ITEMS FOUND",
    "NO VULNERABILITIES",
    "NO EVIDENCE",
)


class NetworkAnalyzer:
    """Módulo de reconocimiento DNS, IPs y análisis controlado de puertos."""

    def __init__(self, socket_timeout: float = 1.5):
        self.socket_timeout = socket_timeout

    def analyze(
        self,
        target_url: str,
        enable_nmap: bool = True,
        enable_nse: bool = False,
        nse_scripts: Optional[str] = None,
    ) -> Tuple[NetworkAuditResult, List[str]]:
        """Realiza consultas DNS completas y análisis seguro de puertos."""
        logs = []
        parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        domain = parsed.hostname or target_url

        logs.append(f"[+] Iniciando reconocimiento de red y DNS para: {domain}")

        # 1. Resolución de IPs
        ip_addresses, ipv6_addresses = self._resolve_ips(domain, logs)

        # 2. Reverse DNS / PTR
        reverse_dns = self._get_reverse_dns(ip_addresses[0] if ip_addresses else None)

        # 3. Registros DNS (MX, TXT, NS, CNAME, SOA)
        dns_records, spf_configured, dmarc_configured = self._query_dns_records(domain, logs)

        # 4. Análisis de Puertos (Nmap si está disponible, o Socket Scanner integrado asíncrono)
        open_ports = []
        nmap_executed = False
        nmap_summary = None
        nse_findings: List[NseScriptFinding] = []
        nse_scripts_run: List[str] = []
        nse_enabled = False

        if enable_nmap and shutil.which("nmap"):
            if enable_nse:
                logs.append(
                    f"[+] Nmap detectado. Ejecutando escaneo de servicios + scripts NSE "
                    f"({nse_scripts or DEFAULT_NSE_SCRIPTS}) sobre {domain}..."
                )
            else:
                logs.append(f"[+] Nmap detectado en el sistema. Ejecutando escaneo controlado de servicios sobre {domain}...")
            open_ports, nmap_executed, nmap_summary, nse_findings, nse_scripts_run, nse_enabled = self._run_nmap_scan(
                domain, logs, enable_nse=enable_nse, nse_scripts=nse_scripts
            )
        else:
            if enable_nmap:
                logs.append("[i] Binario Nmap no encontrado en PATH. Utilizando Escáner Asíncrono Nativo de Python...")
                if enable_nse:
                    logs.append("[i] El escaneo NSE (vulnerabilidades / fingerprint web) requiere Nmap instalado y fue omitido.")
            open_ports = self._run_native_socket_scan(
                domain, logs, NSE_PORT_SET if enable_nse else COMMON_SECURITY_PORTS
            )

        if nse_enabled:
            logs.append(
                f"[+] NSE: {len(nse_scripts_run)} script(s) ejecutados, "
                f"{len(nse_findings)} hallazgo(s) reportado(s)."
            )

        logs.append(f"[+] Análisis de red completado. {len(open_ports)} puerto(s) abierto(s) identificado(s).")

        result = NetworkAuditResult(
            domain=domain,
            ip_addresses=ip_addresses,
            ipv6_addresses=ipv6_addresses,
            hostname=domain,
            reverse_dns=reverse_dns,
            dns_records=dns_records,
            spf_configured=spf_configured,
            dmarc_configured=dmarc_configured,
            open_ports=open_ports,
            nmap_executed=nmap_executed,
            nmap_output_summary=nmap_summary,
            nse_enabled=nse_enabled,
            nse_scripts_executed=nse_scripts_run,
            nse_findings=nse_findings,
        )

        return result, logs

    def _resolve_ips(self, domain: str, logs: List[str]) -> Tuple[List[str], List[str]]:
        """Resuelve direcciones IPv4 e IPv6."""
        ipv4_list = []
        ipv6_list = []

        try:
            # IPv4
            addr_info = socket.getaddrinfo(domain, None, socket.AF_INET)
            for item in addr_info:
                ip = item[4][0]
                if ip not in ipv4_list:
                    ipv4_list.append(ip)
            logs.append(f"[+] IPv4 resueltas: {', '.join(ipv4_list) if ipv4_list else 'Ninguna'}")
        except Exception as e:
            logs.append(f"[-] No se pudo resolver IPv4 para {domain}: {str(e)}")

        try:
            # IPv6
            addr_info_v6 = socket.getaddrinfo(domain, None, socket.AF_INET6)
            for item in addr_info_v6:
                ip = item[4][0]
                if ip not in ipv6_list:
                    ipv6_list.append(ip)
            if ipv6_list:
                logs.append(f"[+] IPv6 detectadas: {', '.join(ipv6_list)}")
        except Exception:
            # Es común que muchos hosts no tengan IPv6
            pass

        return ipv4_list, ipv6_list

    def _get_reverse_dns(self, ip: Optional[str]) -> Optional[str]:
        """Obtiene el nombre de host mediante PTR."""
        if not ip:
            return None
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except Exception:
            return None

    def _query_dns_records(self, domain: str, logs: List[str]) -> Tuple[Dict[str, List[str]], bool, bool]:
        """Consulta registros DNS esenciales usando dnspython."""
        dns_records = {}
        spf_found = False
        dmarc_found = False

        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0

        for record_type in ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]:
            try:
                answers = resolver.resolve(domain, record_type)
                vals = [str(rdata).strip('"') for rdata in answers]
                if vals:
                    dns_records[record_type] = vals
            except Exception:
                continue

        # Verificar DMARC específicamente en _dmarc.domain
        try:
            dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc_vals = [str(r).strip('"') for r in dmarc_answers]
            if dmarc_vals:
                dns_records["DMARC"] = dmarc_vals
                dmarc_found = any("v=DMARC1" in v for v in dmarc_vals)
        except Exception:
            pass

        # Evaluar SPF en registros TXT
        txt_records = dns_records.get("TXT", [])
        spf_found = any("v=spf1" in txt for txt in txt_records)

        logs.append(f"[+] Registros DNS encontrados: {list(dns_records.keys())} (SPF: {'Sí' if spf_found else 'No'}, DMARC: {'Sí' if dmarc_found else 'No'})")

        return dns_records, spf_found, dmarc_found

    def _run_native_socket_scan(self, domain: str, logs: List[str], ports=None) -> List[PortServiceItem]:
        """Escáner TCP multihilo ultrarrápido y seguro para el conjunto de puertos críticos."""
        from concurrent.futures import ThreadPoolExecutor

        open_ports: List[PortServiceItem] = []
        port_set = ports or COMMON_SECURITY_PORTS

        def check_port(port_info):
            port, service, risk_level, risk_reason = port_info
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.6)
                    result = s.connect_ex((domain, port))
                    if result == 0:
                        banner = None
                        try:
                            s.settimeout(0.4)
                            if port in [21, 22, 25, 110, 143]:
                                banner = s.recv(128).decode("utf-8", errors="ignore").strip()
                        except Exception:
                            pass

                        return PortServiceItem(
                            port=port,
                            service=service,
                            state="open",
                            protocol="tcp",
                            banner=banner,
                            risk=risk_level,
                            risk_reason=risk_reason,
                        )
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(check_port, port_set)
            for res in results:
                if res is not None:
                    open_ports.append(res)

        return open_ports

    def _build_port_spec(self, ports) -> str:
        """Construye la lista de puertos para el argumento -p de Nmap sin duplicados."""
        seen = []
        for p in ports:
            num = p[0] if isinstance(p, (tuple, list)) else int(p)
            if num not in seen:
                seen.append(num)
        return ",".join(str(n) for n in seen)

    def _run_nmap_scan(
        self,
        domain: str,
        logs: List[str],
        enable_nse: bool = False,
        nse_scripts: Optional[str] = None,
    ):
        """Ejecuta Nmap de forma controlada, opcionalmente con scripts NSE en salida XML."""
        port_set = NSE_PORT_SET if enable_nse else COMMON_SECURITY_PORTS

        if enable_nse:
            result = self._run_nmap_nse_scan(domain, logs, nse_scripts)
            if result is not None:
                return result
            logs.append("[i] Escaneo NSE no completado. Continuando con escaneo de servicios estándar (-sV)...")

        open_ports, executed, summary = self._run_nmap_service_scan(domain, logs, port_set)
        if open_ports is None:
            logs.append("[i] Recurriendo al Escáner Asíncrono Nativo de Python...")
            open_ports = self._run_native_socket_scan(domain, logs, port_set)
            executed, summary = False, None
        return open_ports, executed, summary, [], [], False

    def _run_nmap_service_scan(self, domain: str, logs: List[str], ports) -> Tuple[List[PortServiceItem], bool, Optional[str]]:
        """Ejecuta nmap -sV -Pn de forma controlada sobre los puertos definidos."""
        ports_str = self._build_port_spec(ports)
        # -T4 y --version-light mantienen el escaneo por debajo del timeout;
        # --host-timeout evita bloquear el pipeline si el destino filtra el tráfico.
        cmd = [
            "nmap", "-sV", "-Pn", "-T4", "--version-light",
            "--host-timeout", "35s", "--open", "-p", ports_str, domain,
        ]

        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=45,
            )
            output = proc.stdout
            logs.append("[+] Nmap ejecutado exitosamente.")

            open_ports = []
            for line in output.splitlines():
                # Ejemplo de línea: 80/tcp  open  http    Apache httpd 2.4.41
                match = re.match(r"^(\d+)/(\w+)\s+(\w+)\s+([\w.\-/]+)\s*(.*)$", line.strip())
                if match:
                    port_num = int(match.group(1))
                    proto = match.group(2)
                    state = match.group(3)
                    service_name = match.group(4)
                    version_info = match.group(5).strip()

                    risk_level = "LOW"
                    risk_reason = f"Servicio {service_name} expuesto."
                    if port_num in PORT_RISK_MAP:
                        _, risk_level, risk_reason = PORT_RISK_MAP[port_num]

                    open_ports.append(PortServiceItem(
                        port=port_num,
                        service=service_name,
                        state=state,
                        protocol=proto,
                        banner=version_info if version_info else None,
                        risk=risk_level,
                        risk_reason=risk_reason,
                    ))

            # Nmap abortó sin resultados utilizables: se recurre al escáner nativo
            if not open_ports and proc.returncode != 0:
                stderr_msg = (proc.stderr or "").strip()[:200]
                logs.append(f"[!] Nmap terminó con código {proc.returncode} ({stderr_msg}). Recurriendo al escáner nativo...")
                return None, False, None

            # Resumen breve de nmap
            summary_lines = [l for l in output.splitlines() if "Nmap done" in l or "PORT" in l or "/tcp" in l]
            return open_ports, True, "\n".join(summary_lines[:15])

        except (subprocess.TimeoutExpired, Exception) as exc:
            logs.append(f"[-] Nmap no pudo finalizar a tiempo ({str(exc)}). Recurriendo al escáner nativo...")
            return None, False, None

    def _run_nmap_nse_scan(
        self,
        domain: str,
        logs: List[str],
        nse_scripts: Optional[str] = None,
    ):
        """Ejecuta Nmap con scripts NSE en salida XML y parsea puertos + hallazgos.

        Devuelve una tupla de 6 elementos o None si NSE no pudo ejecutarse.
        """
        requested = [s.strip() for s in (nse_scripts or DEFAULT_NSE_SCRIPTS).split(",") if s.strip()]
        script_sets = [requested]
        if requested != [s.strip() for s in FALLBACK_NSE_SCRIPTS.split(",")]:
            script_sets.append([s.strip() for s in FALLBACK_NSE_SCRIPTS.split(",")])

        ports_str = self._build_port_spec(NSE_PORT_SET)

        for idx, scripts in enumerate(script_sets):
            cmd = [
                "nmap", "-sV", "-Pn", "-T4", "--version-light",
                "--host-timeout", "90s", "--script-timeout", "60s",
                "--open", "-p", ports_str,
                "--script", ",".join(scripts),
                "-oX", "-", domain,
            ]
            try:
                proc = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=120,
                )
            except subprocess.TimeoutExpired:
                logs.append("[-] El escaneo NSE superó el tiempo límite (120s).")
                continue
            except Exception as exc:
                logs.append(f"[-] No fue posible invocar Nmap NSE: {str(exc)}")
                continue

            xml_output = proc.stdout or ""
            if "<nmaprun" not in xml_output:
                stderr_msg = (proc.stderr or "").strip().replace("\n", " ")[:220]
                logs.append(
                    f"[!] NSE con scripts '{','.join(scripts)}' no produjo salida XML "
                    f"(código {proc.returncode}): {stderr_msg or 'sin detalle'}"
                )
                continue

            try:
                open_ports, nse_findings, scripts_run, summary = self._parse_nmap_xml(xml_output)
            except ET.ParseError as exc:
                logs.append(f"[-] Salida XML de Nmap ilegible: {str(exc)}")
                continue

            if idx > 0:
                logs.append(f"[i] Scripts no disponibles en esta instalación. NSE degradado a '{','.join(scripts)}'.")

            logs.append(
                f"[+] NSE completado: {len(open_ports)} puerto(s) abierto(s), "
                f"{len(scripts_run)} script(s) con salida, {len(nse_findings)} hallazgo(s)."
            )

            if not open_ports and proc.returncode != 0:
                logs.append(f"[!] Nmap NSE terminó con código {proc.returncode} sin resultados utilizables.")
                return None

            summary_lines = [l for l in summary.splitlines() if l.strip()]
            return open_ports, True, "\n".join(summary_lines[:15]), nse_findings, scripts_run, True

        return None

    def _parse_nmap_xml(self, xml_output: str) -> Tuple[List[PortServiceItem], List[NseScriptFinding], List[str], str]:
        """Parsea la salida XML de Nmap (-oX) extrayendo puertos, versiones y scripts NSE."""
        root = ET.fromstring(xml_output)

        open_ports: List[PortServiceItem] = []
        findings: List[NseScriptFinding] = []
        scripts_run: List[str] = []
        summary_lines: List[str] = []

        def parse_script(script_el, port_num: Optional[int], protocol: str):
            script_id = script_el.get("id") or "unknown"
            output = (script_el.get("output") or "").strip()
            if not output:
                return
            if script_id not in scripts_run:
                scripts_run.append(script_id)

            cves = self._extract_cves(output, script_el)
            severity = self._nse_severity(output, cves)
            if severity is None:
                return

            findings.append(NseScriptFinding(
                script_id=script_id,
                port=port_num,
                protocol=protocol,
                severity=severity,
                category=self._nse_category(script_id, severity),
                title=self._nse_title(output, script_id, cves),
                output=output,
                cve_ids=cves,
            ))

        for port_el in root.iter("port"):
            try:
                port_num = int(port_el.get("portid"))
            except (TypeError, ValueError):
                continue
            proto = port_el.get("protocol") or "tcp"
            state_el = port_el.find("state")
            state = state_el.get("state") if state_el is not None else "unknown"
            if state != "open":
                continue

            svc_el = port_el.find("service")
            service_name = (svc_el.get("name") if svc_el is not None else None) or "unknown"
            version_bits = []
            if svc_el is not None:
                for attr in ("product", "version", "extrainfo"):
                    val = svc_el.get(attr)
                    if val:
                        version_bits.append(val)
            banner = " ".join(version_bits) or None

            risk_level = "LOW"
            risk_reason = f"Servicio {service_name} expuesto."
            if port_num in PORT_RISK_MAP:
                _, risk_level, risk_reason = PORT_RISK_MAP[port_num]

            open_ports.append(PortServiceItem(
                port=port_num,
                service=service_name,
                state=state,
                protocol=proto,
                banner=banner,
                risk=risk_level,
                risk_reason=risk_reason,
            ))
            summary_lines.append(f"{port_num}/{proto:<4} open  {service_name:<14} {banner or ''}".rstrip())

            for script_el in port_el.findall("script"):
                parse_script(script_el, port_num, proto)

        for script_el in root.findall("./host/script"):
            parse_script(script_el, None, "tcp")

        finished = root.find("./runstats/finished")
        header = ""
        if finished is not None and finished.get("elapsed"):
            header = f"Nmap done: 1 IP address ({len(open_ports)} port(s) up) scanned in {finished.get('elapsed')} seconds"

        return open_ports, findings, scripts_run, "\n".join(([header] if header else []) + summary_lines)

    @staticmethod
    def _extract_cves(output: str, script_el) -> List[str]:
        """Extrae identificadores CVE del texto de salida y de los campos estructurados del script."""
        cves: List[str] = []
        for match in re.finditer(r"CVE-\d{4}-\d{4,7}", output, flags=re.IGNORECASE):
            cve = match.group(0).upper()
            if cve not in cves:
                cves.append(cve)
        for elem in script_el.iter("elem"):
            text = (elem.text or "").strip()
            if re.fullmatch(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE):
                cve = text.upper()
                if cve not in cves:
                    cves.append(cve)
        return cves

    @staticmethod
    def _nse_severity(output: str, cves: List[str]) -> Optional[str]:
        """Asigna severidad a un hallazgo NSE. Devuelve None si el resultado no aporta información."""
        upper = output.upper()
        if "NOT VULNERABLE" in upper:
            return None
        if "LIKELY VULNERABLE" in upper or "POTENTIALLY VULNERABLE" in upper:
            return "MEDIUM"
        if re.search(r"\bVULNERABLE\b", upper):
            return "CRITICAL" if cves and "REMOTE CODE EXECUTION" in upper else "HIGH"
        if cves:
            return "MEDIUM"
        if any(marker in upper for marker in NSE_NEGATIVE_MARKERS):
            return None
        return "INFO"

    @staticmethod
    def _nse_category(script_id: str, severity: str) -> str:
        if severity != "INFO":
            return "vuln"
        if script_id.startswith(("http-", "ssl-", "tls-")):
            return "web"
        return "discovery"

    @staticmethod
    def _nse_title(output: str, script_id: str, cves: List[str]) -> str:
        """Deriva un título legible a partir de la salida estructurada del script."""
        if script_id == "vulners" and cves:
            extra = f" (+{len(cves) - 1} más)" if len(cves) > 1 else ""
            return f"Coincidencia de versión con {cves[0]}{extra}"

        lines = [l.strip() for l in output.splitlines() if l.strip()]
        markers = ("vulnerable:", "likely vulnerable:", "potentially vulnerable:", "not vulnerable:")
        for idx, line in enumerate(lines):
            if line.lower() in markers:
                for nxt in lines[idx + 1:]:
                    low = nxt.lower()
                    if low.startswith(("cve:", "cvss:", "state:", "references:", "risk:", "ids:", "vector:")):
                        break
                    if len(nxt) > 3:
                        return nxt[:160]
                break
        first = lines[0] if lines else script_id
        return first[:160] if len(first) > 3 else script_id
