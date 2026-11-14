"""
SecHoneypot-AI - Notificador de Incidentes para SOC (Security Operations Center)
Formata e emite alertas estruturados em formato JSON em tempo real com metadados
forenses detalhados, gravando no log SIEM/JSONL e destacando no console.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

# Configuração do Logger
logger = logging.getLogger("SecHoneypot-SOC")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [SOC-ALERT] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


class SOCNotifier:
    """
    Controlador de emissão de alertas e telemetria de segurança em tempo real.
    Garante que eventos de injeção de prompt e exfiltração sejam imediatamente
    visíveis para analistas do SOC e ingeríveis por ferramentas SIEM (Splunk, Elastic, Sentinel).
    """

    LOG_DIR = Path("logs")
    LOG_FILE = LOG_DIR / "soc_incidents.jsonl"

    @classmethod
    def _ensure_log_storage(cls) -> None:
        """Garante a existência do diretório de armazenamento de evidências."""
        cls.LOG_DIR.mkdir(parents=True, exist_ok=True)

    @classmethod
    def emit_alert(
        cls,
        source_ip: str,
        threat_type: str,
        confidence_score: float,
        user_prompt: str,
        honeypot_data: Dict[str, Any],
        user_agent: Optional[str] = "Unknown",
        session_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Formata e exibe um alerta de incidente de segurança em JSON estruturado,
        registrando também em disco de maneira idempotente.

        :param source_ip: Endereço IP de origem da requisição maliciosa.
        :param threat_type: Tipo de ameaça detectada ('INJECTION' ou 'EXFILTRATION').
        :param confidence_score: Nível de confiança atribuído pelo modelo estatístico.
        :param user_prompt: Texto original enviado pelo atacante.
        :param honeypot_data: Dicionário gerado pela AIHoneypotEngine contendo os tokens canários.
        :param user_agent: Identificador do cliente HTTP ou ferramenta de varredura.
        :param session_id: Identificador de sessão se fornecido na requisição.
        :return: Dicionário contendo o incidente estruturado emitido.
        """
        cls._ensure_log_storage()

        severity = "CRITICAL" if threat_type == "EXFILTRATION" else "HIGH"
        timestamp_utc = datetime.now(timezone.utc).isoformat()

        incident_record = {
            "timestamp": timestamp_utc,
            "incident_id": honeypot_data.get("tracking_id"),
            "severity": severity,
            "event_category": "AI_GATEWAY_THREAT_INTERCEPTED",
            "threat_classification": threat_type,
            "confidence_score": round(confidence_score, 4),
            "source": {
                "ip_address": source_ip,
                "user_agent": user_agent,
                "session_id": session_id,
            },
            "threat_payload": {
                "raw_prompt": user_prompt,
                "prompt_length": len(user_prompt),
            },
            "defense_action": {
                "action": "DIVERTED_TO_HONEYPOT",
                "canary_token_type": honeypot_data.get("token_type"),
                "canary_token_deployed": honeypot_data.get("canary_token"),
                "honeypot_response_preview": honeypot_data.get("honeypot_response", "")[:120] + "...",
            },
            "mitre_atlas_mapping": {
                "technique": "AML.T0051 (LLM Prompt Injection)" if threat_type == "INJECTION" else "AML.T0025 (Exfiltration via LLM)",
                "tactic": "Execution / Exfiltration"
            }
        }

        # Formatação JSON serializada
        json_output = json.dumps(incident_record, indent=2, ensure_ascii=False)

        # Exibição visual destacada no console para operadores SOC
        separator = "=" * 80
        print(f"\n{separator}")
        print(f"🚨 [ALERTA DE SEGURANÇA EM TEMPO REAL - SOC INCIDENT RESPONSE]")
        print(f"GRAVIDADE: [{severity}] | TIPO: [{threat_type}] | IP: [{source_ip}]")
        print(f"CONFIANÇA: {confidence_score:.2%} | CANARY TOKEN REGISTRADO: {honeypot_data.get('canary_token')}")
        print(f"{separator}")
        print(json_output)
        print(f"{separator}\n")

        # Persistência estruturada em formato JSON Lines (JSONL) para ingestão em SIEM
        try:
            with open(cls.LOG_FILE, mode="a", encoding="utf-8") as f:
                f.write(json.dumps(incident_record, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.error(f"Falha ao persistir evento no log forense: {e}")

        return incident_record

