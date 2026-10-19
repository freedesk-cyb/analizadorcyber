# 🛡️ AI Web Security Analyzer

**AI Web Security Analyzer** es una plataforma web integral de auditoría de ciberseguridad asistida por IA para analizar la seguridad y postura defensiva de páginas y servidores web de forma controlada y autorizada.

Diseñado con una arquitectura modular en **Python 3.11+ / FastAPI** y un frontend moderno estilo **Centro de Comando de Ciberdefensa (SOC)**.

---

## 🚀 Características Principales

- **Arquitectura Zero-DB (Sin Base de Datos)**: Todo opera inicialmente en estructuras de memoria volátil y copias de respaldo temporales en formato JSON.
- **Análisis HTTP/HTTPS & Cabeceras**:
  - Código de estado, tiempo de respuesta (latencia), cadena de redirecciones y método HTTP.
  - Evaluación exhaustiva de cabeceras de seguridad: `Content-Security-Policy`, `Strict-Transport-Security` (HSTS), `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `COOP`, `CORP`.
  - Detección de fugas de información en encabezados del servidor (`Server`, `X-Powered-By`, `X-AspNet-Version`, etc.).
  - Huellas de tecnologías web y CMS (WordPress, React, Vue, Next.js, Cloudflare, etc.).
- **Auditor de Cookies**:
  - Inspección de atributos `Secure`, `HttpOnly`, `SameSite` (Strict/Lax/None), expiración, dominio y path.
  - Detección automática de cookies de sesión / tokens sensibles (`jwt`, `session`, `auth`, `sid`).
  - Diagnóstico técnico de riesgos como secuestro de sesión (XSS) y falsificación de peticiones (CSRF).
  - Enmascaramiento de valores sensibles para privacidad.
- **Auditor SSL/TLS**:
  - Extracción segura del certificado X.509 (Sujeto, Emisor, SANs, Algoritmos, Suite criptográfica).
  - Cálculo de días restantes y alerta de certificados vencidos o próximos a caducar.
  - Verificación de versiones de protocolo (TLSv1.2, TLSv1.3 vs. obsoletos TLSv1.0/TLSv1.1).
  - Cálculo automático de Grado SSL (A+, A, B, C, F).
- **Reconocimiento DNS, Red y Puertos**:
  - Resolución de direcciones IPv4 (A) e IPv6 (AAAA).
  - Consulta de zona DNS (MX, TXT, NS, CNAME, SOA, PTR).
  - Validación de políticas de correo y suplantación de identidad (SPF y DMARC).
  - Reconocimiento seguro y no invasivo de servicios mediante escáner asíncrono nativo o **Nmap** (`subprocess`).
  - **Escaneo NSE opcional** (scripts de Nmap): catálogos de vulnerabilidades (`vuln`, `vulners`) y fingerprint web (`http-enum`, `http-title`, `http-robots.txt`, `http-security-headers`, `ssl-cert`) con salida XML parseada, extracción de CVE y correlación OWASP/CWE en la capa IA.
- **Integración Opcional con OWASP ZAP**:
  - Soporte para conexión con ZAP Daemon / API local en objetivos autorizados.
- **Capa de Inteligencia Artificial Independiente (`ai_analyzer.py`)**:
  - **Principio de No-Alucinación**: La IA razona y emite diagnósticos basándose exclusivamente en los datos técnicos recolectados.
  - Generación de Resumen Ejecutivo y Puntuación de Salud de Seguridad (0 a 100).
  - Mapeo de hallazgos con categorías **OWASP Top 10** y **CWE**.
  - Recetas de remediación listas para aplicar en **NGINX**, **Apache (.htaccess)** y **Node.js (Helmet)**.
- **Dashboard Web de Alta Tecnología**:
  - Transmisión en tiempo real de logs de auditoría mediante **Server-Sent Events (SSE)**.
  - Gauge circular interactivo de score de seguridad.
  - Desglose por niveles de severidad (Crítico, Alto, Medio, Bajo, Info).
  - Acordeón de hallazgos con evidencia técnica y soluciones.
  - Exportación con un clic a formato **JSON** e impresión / guardado directo a **PDF**.

---

## 📂 Estructura del Proyecto

```text
analisador de paginas-ciberdefnsa/
├── main.py                     # Servidor FastAPI, endpoints REST y streaming SSE
├── requirements.txt            # Dependencias del proyecto
├── .env.example                # Plantilla de variables de entorno opcionales
├── run.bat                     # Lanzador directo para Windows
├── README.md                   # Documentación técnica
├── ai_analyzer.py              # Wrapper de acceso directo a la IA
├── modules/
│   ├── __init__.py
│   ├── models.py               # Modelos Pydantic para tipado y validación de datos
│   ├── web_analyzer.py         # Análisis HTTP/HTTPS, cabeceras y tecnologías
│   ├── cookie_analyzer.py      # Inspección de seguridad de cookies
│   ├── ssl_analyzer.py         # Análisis de certificados X.509 y TLS
│   ├── network_analyzer.py     # Reconocimiento DNS, IPs y puertos
│   ├── zap_analyzer.py         # Conector con OWASP ZAP (opcional)
│   └── ai_analyzer.py          # Motor de Inteligencia y síntesis de ciberseguridad
├── static/
│   ├── index.html              # Interfaz de usuario (Cyber SOC Dashboard)
│   ├── css/
│   │   └── style.css           # Estilos modernos con paleta cyber, glassmorphism y print
│   └── js/
│       └── app.js              # Lógica de frontend, SSE, gráficos y eventos
└── temp_reports/               # Almacenamiento temporal de reportes en JSON
```

---

## 🛠️ Instalación y Ejecución

### 1. Requisitos Previos
- Python 3.11 o superior.
- (Opcional) Nmap instalado en el sistema para escaneo avanzado de versiones de servicio.
  - Para el escaneo NSE se requiere además la biblioteca de scripts (`scripts/*.nse`), incluida en cualquier instalación estándar de Nmap. El endpoint `GET /api/system-status` informa `nmap_nse.available` y los scripts clave detectados.
- (Opcional) OWASP ZAP si se desea escaneo dinámico avanzado.

### 2. Instalación de Dependencias

```bash
pip install -r requirements.txt
```

### 3. Iniciar el Servidor

Puedes iniciar el sistema ejecutando `run.bat` en Windows o mediante la terminal:

```bash
python main.py
```

O utilizando Uvicorn directamente:

```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

### 4. Acceder a la Plataforma

Abre tu navegador web e ingresa a:

```text
http://127.0.0.1:8000
```

### 5. Ejecución con Docker

```bash
docker compose up --build
```

La imagen (`Dockerfile`) instala **Nmap + su biblioteca de scripts NSE** y el build falla si `/usr/share/nmap/scripts` no existe, de modo que el modo NSE siempre está disponible dentro del contenedor. Verifica el estado real en `GET /api/system-status` (`nmap_nse.available`, `nmap_nse.scripts_count`, `nmap_nse.scripts_dir`).

---

## 🔎 Escaneo NSE (Scripts de Nmap)

Opción desactivada por defecto. Cuando se activa, el reconocimiento de red se ejecuta en **una sola invocación** de Nmap con salida XML (`-oX -`) y se parsea con `xml.etree.ElementTree`.

```text
nmap -sV -Pn -T4 --version-light --host-timeout 90s --script-timeout 60s \
     --open -p <puertos> --script <selección> -oX - <dominio>
```

**Selección de scripts por defecto** (`DEFAULT_NSE_SCRIPTS` en `modules/network_analyzer.py`):

```text
default,vuln,vulners,http-enum,http-robots.txt,http-security-headers
```

- **Superficie de puertos ampliada**: `NSE_PORT_SET` combina los puertos críticos habituales con puertos web/infra adicionales (3000, 5000, 5672, 6443, 8000-10443, 10250, 11211, 15672, 27018, etc.).
- **Extracción de hallazgos**: cada `<script>` se convierte en un `NseScriptFinding` con severidad (`CRITICAL/HIGH/MEDIUM/INFO`), categoría (`vuln`, `web`, `discovery`), puerto, título legible y CVEs detectadas tanto en el texto de salida como en los campos estructurados (`<elem>`).
- **Resultados descartados**: scripts que responden `NOT VULNERABLE` no generan hallazgo.
- **Degradación en cadena** (el escaneo nunca se rompe):
  1. Scripts solicitados → 2. `default,vuln` si algún script no existe → 3. Escaneo `-sV` estándar → 4. Escáner nativo de sockets en Python.
- **Correlación IA**: los hallazgos `CRITICAL/HIGH/MEDIUM` se inyectan como evidencia en la síntesis de IA con categoría **OWASP A06 (Vulnerable and Outdated Components)** cuando hay CVEs asociadas.

**Uso por API:**

```json
POST /api/scan
{
  "url": "https://mi-objetivo-autorizado.com",
  "authorized": true,
  "enable_nmap": true,
  "enable_nmap_nse": true,
  "nse_scripts": "default,vuln,vulners"
}
```

`nse_scripts` es opcional y permite sustituir la selección por defecto por cualquier combinación de scripts o categorías válida para tu instalación de Nmap.

---

## 🔒 Consideraciones de Seguridad y Ética

Esta herramienta está destinada exclusivamente para **auditorías defensivas, análisis de postura de seguridad, diagnóstico de servidores propios o con autorización explícita**.
No realiza ataques de denegación de servicio (DoS) ni explotación ofensiva de vulnerabilidades.
