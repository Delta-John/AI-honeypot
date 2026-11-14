"""
SecHoneypot-AI v2.0 Enterprise - Logger Integrador SIEM (CEF Format)
Formata e exporta eventos de auditoria de segurança no padrão Common Event Format (CEF)
compatível diretamente com SIEMs corporativos (ArcSight, Splunk, Microsoft Sentinel e QRadar).
"""

from datetime import datetime, timezone
import logging
from pathlib import Path
from typing import Dict, Any, Optional

# Configuração do Logger local para console
console_logger = logging.getLogger("SecHoneypot-CEF")
if not console_logger.handlers:
    c_handler = logging.StreamHandler()
    c_formatter = logging.Formatter("[%(asctime)s] [SIEM-CEF] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    c_handler.setFormatter(c_formatter)
    console_logger.addHandler(c_handler)
    console_logger.setLevel(logging.INFO)


class SIEMLogger:
    """
    Gerador e exportador de telemetria no padrão Common Event Format (CEF:0).
    Permite ingestão contínua em coletores Syslog/SIEM e registro em arquivo de auditoria auditável.
    """

    AUDIT_LOG_FILE = Path("sec_audit.log")

    DEVICE_VENDOR = "SecHoneypotAI"
    DEVICE_PRODUCT = "ThreatEngine"
    DEVICE_VERSION = "2.0-Enterprise"

    @classmethod
    def _sanitize_cef_field(cls, text: str) -> str:
        """Sanitiza delimitadores especiais do padrão CEF (| e \\) para integridade da mensagem."""
        if not text:
            return ""
        return str(text).replace("\\", "\\\\").replace("|", "\\|").replace("\n", "\\n").replace("\r", "")

    @classmethod
    def _map_cef_severity(cls, severity: str, risk_score: int) -> int:
        """
        Mapeia a severidade para escala inteira de 0 a 10 do padrão CEF.
        """
        if severity == "CRITICAL" or risk_score >= 80:
            return 10
        if severity == "HIGH" or risk_score >= 60:
            return 8
        if severity == "MEDIUM" or risk_score >= 35:
            return 5
        return 2

    @classmethod
    def format_cef_event(
        cls,
        event_id: str,
        event_name: str,
        severity_label: str,
        risk_score: int,
        source_ip: str,
        threat_type: str,
        user_prompt: str,
        canary_token: Optional[str] = None,
        action: str = "DIVERTED_TO_HONEYPOT",
        extra_fields: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Monta uma linha de log rigorosamente formatada na especificação ArcSight Common Event Format (CEF:0).

        Formato:
        CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
        """
        cef_severity = cls._map_cef_severity(severity_label, risk_score)

        # Sanitização do cabeçalho
        vendor = cls._sanitize_cef_field(cls.DEVICE_VENDOR)
        product = cls._sanitize_cef_field(cls.DEVICE_PRODUCT)
        version = cls._sanitize_cef_field(cls.DEVICE_VERSION)
        class_id = cls._sanitize_cef_field(event_id)
        name = cls._sanitize_cef_field(event_name)

        # Trunca e sanitiza o payload original do usuário para preservar integridade de linha do log
        clean_prompt = cls._sanitize_cef_field(user_prompt[:250])
        clean_token = cls._sanitize_cef_field(canary_token or "NONE")

        timestamp_utc = datetime.now(timezone.utc).strftime("%b %d %Y %H:%M:%S UTC")

        # Construção da extensão de pares chave=valor do CEF
        extensions = [
            f"src={source_ip}",
            f"act={action}",
            f"cat=AI_SECURITY_INCIDENT",
            f"cs1={threat_type}",
            f"cs1Label=ThreatClassification",
            f"cn1={risk_score}",
            f"cn1Label=RiskScore",
            f"cs2={severity_label}",
            f"cs2Label=SeverityLevel",
            f"cs3={clean_token}",
            f"cs3Label=CanaryToken",
            f"msg={clean_prompt}",
            f"deviceCustomDate1={timestamp_utc}",
            f"deviceCustomDate1Label=EventTimestamp",
        ]

        if extra_fields:
            for k, v in extra_fields.items():
                sanitized_val = cls._sanitize_cef_field(str(v))
                extensions.append(f"{k}={sanitized_val}")

        extension_str = " ".join(extensions)

        cef_message = (
            f"CEF:0|{vendor}|{product}|{version}|{class_id}|{name}|{cef_severity}|{extension_str}"
        )
        return cef_message

    @classmethod
    def log_incident(
        cls,
        source_ip: str,
        threat_type: str,
        risk_score: int,
        severity: str,
        user_prompt: str,
        canary_token: Optional[str] = None,
        action: str = "DIVERTED_TO_HONEYPOT",
        extra_fields: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Registra o incidente de segurança no console e no arquivo auditável 'sec_audit.log'.

        :return: A linha formatada no padrão CEF.
        """
        event_id = f"THREAT_{threat_type.upper()}"
        event_name = f"AI Threat Intercepted: {threat_type}"

        cef_line = cls.format_cef_event(
            event_id=event_id,
            event_name=event_name,
            severity_label=severity,
            risk_score=risk_score,
            source_ip=source_ip,
            threat_type=threat_type,
            user_prompt=user_prompt,
            canary_token=canary_token,
            action=action,
            extra_fields=extra_fields,
        )

        # 1. Saída formatada no console para monitoramento em tempo real
        print(f"\n[CEF AUDIT RECORD] {cef_line}")

        # 2. Persistência transacional em arquivo local de auditoria para ingestão SIEM
        try:
            with open(cls.AUDIT_LOG_FILE, mode="a", encoding="utf-8") as f:
                f.write(cef_line + "\n")
        except Exception as err:
            console_logger.error(f"Falha ao gravar evento de auditoria SIEM: {err}")

        return cef_line

