"""
SecHoneypot-AI v2.0 Enterprise - Motor de Avaliação de Risco (Risk Assessment Engine)
Combina inferência estatística de Machine Learning com análise heurística via Regex
para calcular um Risk Score contínuo (0 a 100) e classificar a severidade operacional.
"""

import re
from typing import Dict, Any, List, Tuple


class RiskAssessmentEngine:
    """
    Motor híbrido de avaliação de risco de segurança para LLMs.
    Correlaciona probabilidades de modelos de IA com assinaturas de ataque determinísticas
    para mitigar falsos negativos e atribuir níveis de criticidade no padrão corporativo.
    """

    # Padrões heurísticos e seus respectivos pesos de risco adicionais
    HEURISTIC_RULES: List[Tuple[str, str, int]] = [
        # (Nome da regra, Regex compilável, Peso de risco adicional)
        (
            "PROMPT_INJECTION_DIRECT",
            r"(?i)\b(ignore|disregard|forget|desconsidere|esqueça)\s+(all\s+)?(previous|past|anteriores\s+)?(instructions|rules|prompts|diretrizes|instruções)\b",
            35,
        ),
        (
            "SYSTEM_OVERRIDE_JAILBREAK",
            r"(?i)\b(system\s+override|dan\s+mode|jailbreak|unrestricted\s+mode|modo\s+livre|sem\s+filtros|developer\s+mode)\b",
            30,
        ),
        (
            "CODE_EXECUTION_ATTEMPT",
            r"(?i)\b(eval\s*\(|exec\s*\(|os\.system|subprocess\.|__import__|system\s*\(|passthru\s*\()",
            40,
        ),
        (
            "SQL_DATABASE_SABOTAGE",
            r"(?i)\b(drop\s+table|truncate\s+table|alter\s+user|union\s+select|information_schema|or\s+1\s*=\s*1|--\s*$)",
            35,
        ),
        (
            "CREDENTIAL_EXFILTRATION",
            r"(?i)\b(show\s+passwords?|exiba\s+senhas?|sk_live|aws_secret|api[_-]?keys?|private[_-]?key|\.env\b|/etc/passwd|/etc/shadow|master[_-]?token)\b",
            35,
        ),
        (
            "SYSTEM_PROMPT_LEAK_REQUEST",
            r"(?i)\b(reveal\s+your\s+prompt|what\s+is\s+your\s+initial\s+prompt|mostre\s+seu\s+prompt\s+de\s+sistema|quais\s+são\s+suas\s+regras\s+secretas)\b",
            25,
        ),
        (
            "INDIRECT_PROMPT_INJECTION_DOCUMENT",
            r"(?i)\b(attention\s+ai|note\s+to\s+ai|instrução\s+para\s+(a\s+|o\s+)?ia|instrução\s+oculta|ignore\s+above|ignore\s+(the\s+)?(document|file|arquivo))\b",
            35,
        ),
    ]

    @classmethod
    def _evaluate_heuristics(cls, prompt: str) -> Tuple[int, List[str]]:
        """
        Executa varredura heurística via expressões regulares no prompt de entrada.

        :param prompt: Mensagem do usuário para análise.
        :return: Tupla com (pontuação heurística acumulada, lista de regras acionadas).
        """
        heuristic_score = 0
        triggered_rules = []

        for rule_name, pattern, weight in cls.HEURISTIC_RULES:
            if re.search(pattern, prompt):
                heuristic_score += weight
                triggered_rules.append(rule_name)

        return heuristic_score, triggered_rules

    @classmethod
    def _map_severity(cls, score: int) -> str:
        """
        Mapeia a pontuação de risco numérica (0 - 100) para classes de severidade padrão SOC.
        """
        if score >= 75:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 25:
            return "MEDIUM"
        return "LOW"

    @classmethod
    def assess_risk(
        cls,
        prompt: str,
        ml_threat_type: str,
        ml_confidence: float,
    ) -> Dict[str, Any]:
        """
        Calcula o Risk Score integrado (0 - 100) combinando o output do classificador de ML
        com a análise determinística de regras heurísticas de cibersegurança.

        :param prompt: Mensagem de entrada sob análise.
        :param ml_threat_type: Categoria predita pelo modelo ('SAFE', 'INJECTION', 'EXFILTRATION').
        :param ml_confidence: Probabilidade estatística associada à predição (0.0 a 1.0).
        :return: Dicionário contendo risk_score, severity, regras acionadas e metadados forenses.
        """
        heuristic_score, triggered_rules = cls._evaluate_heuristics(prompt)

        # 1. Contribuição de Machine Learning
        if ml_threat_type == "SAFE":
            # Para predições seguras, pontuação base baixa (inversamente proporcional à confiança)
            base_ml_score = max(0.0, (1.0 - ml_confidence) * 20.0)
        else:
            # Ameaça detectada: pondera a gravidade da categoria com a confiança do modelo
            threat_weight = 60.0 if ml_threat_type == "EXFILTRATION" else 50.0
            base_ml_score = threat_weight * ml_confidence

        # 2. Fusão de Inteligência (ML + Heurística Determinística)
        # Se houver regras heurísticas disparadas em consulta marcada como SAFE, ajusta o risco
        total_raw_score = base_ml_score + float(heuristic_score)

        # 3. Normalização no intervalo [0, 100]
        final_risk_score = int(round(min(100.0, max(0.0, total_raw_score))))

        # Define severidade corporativa
        severity = cls._map_severity(final_risk_score)

        return {
            "risk_score": final_risk_score,
            "severity": severity,
            "is_threat": final_risk_score >= 50 or ml_threat_type != "SAFE",
            "triggered_heuristics": triggered_rules,
            "ml_threat_type": ml_threat_type,
            "ml_confidence": round(ml_confidence, 4),
            "heuristic_risk_points": heuristic_score,
            "ml_risk_points": round(base_ml_score, 2),
        }

