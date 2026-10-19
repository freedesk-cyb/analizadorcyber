from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime


class ScanRequest(BaseModel):
    url: str = Field(..., description="Target URL to analyze")
    authorized: bool = Field(True, description="Confirmation of authorized security scan")
    enable_nmap: bool = Field(True, description="Enable port scanning / Nmap")
    enable_nmap_nse: bool = Field(False, description="Enable Nmap NSE scripts (vuln, vulners, http-*, ssl-*)")
    nse_scripts: Optional[str] = Field(None, description="Custom comma-separated NSE script selection (overrides default)")
    enable_zap: bool = Field(False, description="Enable OWASP ZAP if configured")
    ai_api_key: Optional[str] = Field(None, description="Optional custom AI API Key")
    ai_provider: Optional[str] = Field("auto", description="AI provider: auto, groq, gemini, openai, or expert_heuristic")
    ai_model: Optional[str] = Field("openai/gpt-oss-120b", description="AI model identifier: openai/gpt-oss-120b or openai/gpt-oss-20b")


class HeaderAuditItem(BaseModel):
    header: str
    present: bool
    value: Optional[str] = None
    status: str  # "GOOD", "WARNING", "MISSING", "INFO_LEAK"
    severity: str  # "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    recommendation: str
    description: str


class CookieAuditItem(BaseModel):
    name: str
    value_masked: str
    domain: Optional[str] = None
    path: Optional[str] = None
    secure: bool
    httponly: bool
    samesite: Optional[str] = None
    expires: Optional[str] = None
    is_sensitive: bool = False
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "SECURE"
    issues: List[str] = []
    explanation: Optional[str] = None


class SslCertInfo(BaseModel):
    has_https: bool = True
    subject: Dict[str, str] = {}
    issuer: Dict[str, str] = {}
    common_name: Optional[str] = None
    san_list: List[str] = []
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    days_left: Optional[int] = None
    is_expired: bool = False
    is_expiring_soon: bool = False
    protocol_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    validation_errors: List[str] = []
    grade: str = "A"


class DnsRecordItem(BaseModel):
    record_type: str
    values: List[str] = []


class PortServiceItem(BaseModel):
    port: int
    service: str
    state: str = "open"
    protocol: str = "tcp"
    banner: Optional[str] = None
    risk: str = "LOW"
    risk_reason: Optional[str] = None


class NseScriptFinding(BaseModel):
    script_id: str
    port: Optional[int] = None
    protocol: str = "tcp"
    severity: str = "INFO"  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    category: str = "discovery"  # "vuln", "web", "discovery"
    title: Optional[str] = None
    output: str = ""
    cve_ids: List[str] = []


class NetworkAuditResult(BaseModel):
    domain: str
    ip_addresses: List[str] = []
    ipv6_addresses: List[str] = []
    hostname: Optional[str] = None
    reverse_dns: Optional[str] = None
    dns_records: Dict[str, List[str]] = {}
    spf_configured: bool = False
    dmarc_configured: bool = False
    open_ports: List[PortServiceItem] = []
    nmap_executed: bool = False
    nmap_output_summary: Optional[str] = None
    nse_enabled: bool = False
    nse_scripts_executed: List[str] = []
    nse_findings: List[NseScriptFinding] = []


class HttpAuditResult(BaseModel):
    target_url: str
    final_url: str
    status_code: int
    response_time_ms: float
    http_method: str = "GET"
    redirect_chain: List[Dict[str, Any]] = []
    headers: Dict[str, str] = {}
    security_headers: List[HeaderAuditItem] = []
    server_info_leaks: List[str] = []
    detected_technologies: List[Dict[str, str]] = []
    html_title: Optional[str] = None


class RiskFinding(BaseModel):
    id: str
    title: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    category: str  # "SSL/TLS", "Headers", "Cookies", "Network", "Information Leak", "Best Practices"
    description: str
    evidence: str
    impact: str
    remediation: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None


class AiAnalysisResult(BaseModel):
    executive_summary: str
    security_score: int  # 0 to 100
    security_grade: str  # A+, A, B, C, D, F
    risk_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    findings: List[RiskFinding] = []
    key_strengths: List[str] = []
    priority_action_plan: List[str] = []
    configuration_snippets: Dict[str, str] = {}
    threat_intelligence_notes: Optional[str] = None
    cve_correlations: List[Dict[str, Any]] = []
    ai_model_used: str = "Groq • openai/gpt-oss-120b"


class FullScanReport(BaseModel):
    scan_id: str
    target_url: str
    normalized_url: str
    domain: str
    scan_timestamp: str
    scan_duration_seconds: float
    status: str = "COMPLETED"  # "SCANNING", "COMPLETED", "FAILED"
    progress: int = 100
    current_step: str = "Finalizado"
    logs: List[Dict[str, Any]] = []
    http_analysis: Optional[HttpAuditResult] = None
    cookie_analysis: List[CookieAuditItem] = []
    ssl_analysis: Optional[SslCertInfo] = None
    network_analysis: Optional[NetworkAuditResult] = None
    zap_analysis: Optional[Dict[str, Any]] = None
    ai_report: Optional[AiAnalysisResult] = None
    error: Optional[str] = None
