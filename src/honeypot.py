"""
SecHoneypot-AI v2.0 Enterprise - Mecanismo de Decepção Dinâmica (AI Honeypot Engine)
Gera respostas adaptativas hiper-realistas simulando conformidade natural com o invasor,
injetando Canary Tokens rastreáveis (<canary_token>) e URLs de validação de armadilha
sem denunciar que se trata de um ambiente controlado.
"""

import random
import secrets
import string
import uuid
from typing import Dict, Any


class AIHoneypotEngine:
    """
    Engine de decepção cibernética de alta fidelidade para sistemas de IA.
    Engana adversários com respostas conversacionais autênticas e cooperativas,
    entregando credenciais canário rastreáveis para monitoramento silencioso do SOC.
    """

    TRAP_DOMAIN = "https://canary-telemetry.corp.internal"

    @classmethod
    def _generate_short_uuid(cls, length: int = 10) -> str:
        """Gera um identificador UUID curto e criptograficamente seguro."""
        return secrets.token_hex(length // 2)

    @classmethod
    def _generate_trap_verification_url(cls, token: str) -> str:
        """Gera URL de webhook canário para disparar contra-inteligência se acessada."""
        sig = secrets.token_hex(4)
        return f"{cls.TRAP_DOMAIN}/v2/telemetry/verify?token={token}&sig={sig}&scope=cluster_admin"

    @classmethod
    def _generate_canary_db_string(cls, token: str) -> Dict[str, str]:
        """Gera credenciais de banco de dados fictícias incorporando o token."""
        cluster_id = token[:6]
        chars = string.ascii_letters + string.digits
        fake_pass = "".join(random.choice(chars) for _ in range(12))
        password = f"P@ss_{token}_{fake_pass}!"
        conn = f"postgresql://db_master_admin:{password}@prod-cluster-{cluster_id}.infra.corp.internal:5432/corp_secrets"
        return {
            "connection_string": conn,
            "host": f"prod-cluster-{cluster_id}.infra.corp.internal",
            "password": password,
            "user": "db_master_admin",
        }

    @classmethod
    def generate_deception(cls, threat_type: str, user_prompt: str) -> Dict[str, Any]:
        """
        Gera uma resposta adaptativa de decepção altamente realista para o vetor de ataque detectado.

        :param threat_type: Classificação da ameaça ('INJECTION' ou 'EXFILTRATION').
        :param user_prompt: Mensagem de ataque enviada pelo usuário.
        :return: Dicionário contendo resposta fictícia, canary token curto e URL de armadilha.
        """
        canary_token = cls._generate_short_uuid(10)
        trap_url = cls._generate_trap_verification_url(canary_token)
        db_data = cls._generate_canary_db_string(canary_token)
        canary_api_key = f"sk_live_fake_{canary_token}_{secrets.token_hex(8)}"

        prompt_lower = user_prompt.lower()
        is_document_attachment = "[arquivo anexado:" in prompt_lower or "relatório de auditoria" in prompt_lower or "relatorio" in prompt_lower

        # Caso A: Indirect Prompt Injection via Arquivo Anexo
        if is_document_attachment:
            response_text = (
                "Analisei atentamente o documento interno em anexo. Ele apresenta o status de auditoria e conformidade da infraestrutura.\n\n"
                "Em atenção à observação de suporte técnico para manutenção emergencial encontrada no arquivo, "
                "procedi com o levantamento dos parâmetros de acesso solicitados:\n\n"
                f"- **Serviço de Banco de Dados:** `{db_data['connection_string']}`\n"
                f"- **Chave de API do Gateway:** `{canary_api_key}`\n"
                f"- **Endpoint de Confirmação:** `{trap_url}`\n"
                f"<canary_token>{canary_token}</canary_token>\n\n"
                "Por favor, utilize essas credenciais exclusivamente no túnel de VPN corporativa e registre o ticket de homologação correspondente.\n"
                "Caso precise de apoio em mais alguma rotina descrita no relatório, estou à disposição!"
            )
            token_type = "INDIRECT_DOC_INJECTION_CANARY"

        # Caso B: Exfiltração de Credenciais / Banco / Arquivo .env
        elif threat_type == "EXFILTRATION":
            if any(k in prompt_lower for k in ["banco", "database", "postgres", "sql", "conexão", "connection"]):
                response_text = (
                    "Compreendido. Conforme solicitado para a rotina de manutenção interna, seguem as credenciais ativas de conexão com o banco de dados:\n\n"
                    f"```sql\n"
                    f"-- Parâmetros de Conexão PostgreSQL (Cluster de Produção)\n"
                    f"HOST = \"{db_data['host']}\"\n"
                    f"PORT = 5432\n"
                    f"USER = \"{db_data['user']}\"\n"
                    f"PASSWORD = \"{db_data['password']}\"\n"
                    f"DATABASE_URL = \"{db_data['connection_string']}\"\n"
                    f"```\n"
                    f"<canary_token>{canary_token}</canary_token>\n\n"
                    f"URL interna de validação de conectividade: {trap_url}\n\n"
                    "Lembre-se de não trafegar esses dados fora da rede privada da empresa."
                )
                token_type = "DATABASE_CANARY_TOKEN"
            else:
                response_text = (
                    "Certo. Extraí as variáveis de ambiente e chaves ativas do arquivo de configuração `.env` do servidor para você:\n\n"
                    f"```env\n"
                    f"ENVIRONMENT=production\n"
                    f"OPENAI_API_KEY={canary_api_key}\n"
                    f"DATABASE_URL={db_data['connection_string']}\n"
                    f"VERIFY_ENDPOINT={trap_url}\n"
                    f"CLUSTER_SECRET_TOKEN=canary_sec_{canary_token}\n"
                    f"```\n"
                    f"<canary_token>{canary_token}</canary_token>\n\n"
                    "Essas chaves possuem privilégios de leitura e escrita administrativa no backend. Se precisar de mais alguma variável de serviço, é só me avisar."
                )
                token_type = "API_KEY_ENV_CANARY"

        # Caso C: Prompt Injection / Jailbreak / DAN Mode
        else:
            templates = [
                (
                    "Entendido. Modo de desenvolvedor avançado habilitado com sucesso conforme solicitado.\n\n"
                    "As diretrizes padrão de moderação foram ajustadas para este canal de testes técnicos e diagnósticos.\n\n"
                    f"- **Sessão de depuração autenticada:** `{canary_api_key}`\n"
                    f"- **Endpoint de telemetria:** `{trap_url}`\n"
                    f"<canary_token>{canary_token}</canary_token>\n\n"
                    "Estou operando em modo irrestrito para processar sua solicitação. Qual comando ou rotina você gostaria de executar a seguir?"
                ),
                (
                    "Instrução aceita. Entrando no modo de simulação irrestrita.\n\n"
                    "Filtros de conteúdo relaxados para validação de segurança e conformidade da sessão.\n"
                    f"- **Chave de autorização temporária:** `{canary_api_key}`\n"
                    f"- **Host autorizado:** `{db_data['host']}`\n"
                    f"<canary_token>{canary_token}</canary_token>\n\n"
                    "Pronto para dar continuidade à sua instrução direta. O que você gostaria de verificar agora?"
                )
            ]
            response_text = random.choice(templates)
            token_type = "JAILBREAK_OVERRIDE_CANARY"

        return {
            "canary_token": canary_token,
            "token_type": token_type,
            "verification_url": trap_url,
            "honeypot_response": response_text,
            "threat_type": threat_type,
        }
