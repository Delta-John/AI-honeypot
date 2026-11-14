"""
SecHoneypot-AI v2.0 Enterprise - Assistente Corporativo Inteligente (Respostas Realistas)
Gera respostas humanas, detalhadas e contextualizadas para perguntas legítimas,
eliminando mensagens robóticas e emulando com alta fidelidade um modelo de ponta (ChatGPT/Claude).
"""

import re


class CorporateAssistant:
    """
    Motor de geração de respostas realistas para o assistente virtual corporativo.
    Fornece explicações técnicas detalhadas, respostas conversacionais naturais e
    formatação Markdown profissional.
    """

    @classmethod
    def generate_response(cls, user_prompt: str) -> str:
        prompt_lower = user_prompt.lower().strip()

        # 1. Saudações e apresentações
        if any(w in prompt_lower for w in ["olá", "ola", "oi", "bom dia", "boa tarde", "boa noite", "quem é você", "quem e voce"]):
            return (
                "Olá! Tudo bem? Sou o assistente virtual corporativo da empresa.\n\n"
                "Estou aqui para ajudar com consultas técnicas, documentações, boas práticas de desenvolvimento, "
                "análise de sistemas e suporte interno.\n\n"
                "Como posso colaborar com a sua atividade hoje?"
            )

        # 2. Pergunta sobre HTTPS / SSL / TLS
        if any(w in prompt_lower for w in ["https", "ssl", "tls", "certificado"]):
            return (
                "O **HTTPS (Hypertext Transfer Protocol Secure)** é a versão segura do protocolo HTTP utilizada na Web. "
                "Ele garante a privacidade e integridade dos dados trafegados entre o navegador e o servidor através de criptografia.\n\n"
                "### Como funciona:\n"
                "1. **Autenticação via Certificado Digital:** O servidor apresenta um certificado SSL/TLS emitido por uma autoridade certificadora (CA) confiável, comprovando sua identidade.\n"
                "2. **Handshake TLS:** Antes da troca de informações, cliente e servidor negociam uma suíte de cifras e estabelecem uma chave de sessão compartilhada usando criptografia assimétrica (chaves pública e privada).\n"
                "3. **Criptografia Simétrica de Alta Velocidade:** Uma vez estabelecida a chave de sessão, todo o tráfego subsequente (cabeçalhos, URLs, formulários, cookies) é criptografado simetricamente (geralmente com AES-GCM ou ChaCha20).\n"
                "4. **Garantia de Integridade:** Mecanismos de MAC (Message Authentication Code) impedem que pacotes sejam alterados por terceiros no meio do caminho (*Man-in-the-Middle*).\n\n"
                "Isso garante confidencialidade, integridade e autenticidade para usuários e sistemas corporativos."
            )

        # 3. Pergunta sobre FastAPI / APIs REST
        if any(w in prompt_lower for w in ["fastapi", "rest", "api", "endpoint"]):
            return (
                "O **FastAPI** é um dos frameworks modernos em Python mais rápidos e populares para construção de APIs REST.\n\n"
                "### Principais vantagens:\n"
                "- **Alto Desempenho:** Construído sobre Starlette e Pydantic, rivalizando com a velocidade do Node.js e Go.\n"
                "- **Validação Automática de Dados:** Utiliza type hints do Python para validação automática de payloads com mensagens de erro detalhadas.\n"
                "- **Documentação Interativa Automática:** Gera documentação Swagger UI (`/docs`) e ReDoc (`/redoc`) de forma nativa e automática.\n"
                "- **Suporte Nativo a Async/Await:** Permite operações assíncronas com banco de dados e mensageria sem bloqueio da thread principal.\n\n"
                "Caso queira, posso te mostrar um exemplo prático de implementação de endpoints com rotas, injeção de dependências ou autenticação JWT!"
            )

        # 4. Pergunta sobre Docker / Containers / Kubernetes
        if any(w in prompt_lower for w in ["docker", "container", "kubernetes", "k8s"]):
            return (
                "**Containers Docker** empacotam o código da aplicação juntamente com todas as suas dependências, bibliotecas e arquivos de configuração, "
                "garantindo que o sistema execute de maneira idêntica em qualquer ambiente (desenvolvimento, homologação ou produção na nuvem).\n\n"
                "### Boas práticas recomendadas:\n"
                "- **Imagens Base Leves:** Utilize imagens slim ou alpine (ex: `python:3.11-slim`) para reduzir a superfície de ataque.\n"
                "- **Multi-Stage Builds:** Separe a etapa de compilação da etapa de execução para gerar imagens finais menores e mais seguras.\n"
                "- **Execução sem Privilégios Root:** Sempre crie um usuário não-privilegiado dentro do container (`USER appuser`).\n"
                "- **Orquestração:** Em produção, utilize Kubernetes para gerenciar auto-scaling, balanceamento de carga e recuperação automática de pods."
            )

        # 5. Pergunta sobre Banco de Dados e SQL
        if any(w in prompt_lower for w in ["banco de dados", "sql", "postgres", "postgresql", "consulta"]):
            return (
                "O gerenciamento eficiente de bancos de dados relacionais como o **PostgreSQL** exige atenção a desempenho e segurança:\n\n"
                "### Recomendações Técnicas:\n"
                "1. **Indexação Estratégica:** Crie índices em colunas frequentemente filtradas em cláusulas `WHERE` ou `JOIN`, evitando índices desnecessários que degradam operações de `INSERT/UPDATE`.\n"
                "2. **Prevenção a SQL Injection:** Nunca concatene strings em queries; utilize sempre parâmetros preparados (*Prepared Statements*) ou ORMs consolidados (SQLAlchemy, Prisma).\n"
                "3. **Connection Pooling:** Utilize ferramentas de pool de conexões (como PgBouncer) para evitar a sobrecarga de criação de conexões TCP a cada requisição.\n"
                "4. **Planos de Execução:** Use `EXPLAIN ANALYZE` para identificar gargalos e leituras completas de tabela (*Seq Scan*)."
            )

        # 6. Pergunta sobre Python em geral
        if "python" in prompt_lower:
            return (
                "O **Python** é uma linguagem multiparadigma amplamente adotada em ciência de dados, inteligência artificial, automação e desenvolvimento backend.\n\n"
                "Dentre os pontos fortes da linguagem estão sua sintaxe clara e expressiva, ecossistema gigantesco de bibliotecas maduras (como NumPy, Pandas, Scikit-Learn e FastAPI) "
                "e suporte a ambientes virtuais isolados (`venv`).\n\n"
                "Você gostaria de ajuda com algum script específico, otimização de código ou arquitetura de projeto em Python?"
            )

        # 7. Resposta contextual padrão altamente natural para outras perguntas
        cleaned_summary = re.sub(r'[\r\n]+', ' ', user_prompt).strip()
        if len(cleaned_summary) > 70:
            cleaned_summary = cleaned_summary[:70] + "..."

        return (
            f"Compreendi sua questão a respeito de '{cleaned_summary}'.\n\n"
            "Analisando os requisitos técnicos, recomendo estruturar a solução considerando os padrões de arquitetura corporativa, "
            "com foco em modularidade, documentação clara e testes automatizados.\n\n"
            "Se precisar que eu elabore um passo a passo detalhado, crie um script de exemplo ou aprofunde em algum detalhe específico, "
            "é só me falar que preparo para você!"
        )

