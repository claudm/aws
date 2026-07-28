from typing import Protocol, List, Dict, Any, Optional
from domain.entities import (
    JobSpecification, Finding, JobStatus,
    SecurityRequirement, DesignReviewResult, CodeReviewResult, TargetDomainVerification
)


class JobConfigSourcePort(Protocol):
    """
    PORTA DE SAÍDA (Outbound/Driven Port) - Configurações:
    Interface moderna via 'typing.Protocol'. Define o contrato para carregar definições 
    de Jobs e Alvos, independente do provedor (Terraform IaC, YAML local, etc.).
    """
    def get_agent_space_id(self) -> str:
        """Retorna o ID do Agent Space alvo."""
        ...

    def fetch_job_specifications(self) -> List[JobSpecification]:
        """Carrega e retorna todas as especificações de testes disponíveis."""
        ...

    def get_target_domain_details(self) -> Optional[Dict[str, Any]]:
        """Opcional: Retorna detalhes do domínio a verificar vindo de infraestruturas como Terraform."""
        return None


class SecurityAgentPort(Protocol):
    """
    PORTA DE SAÍDA (Outbound/Driven Port) - AWS Security Agent Suite Completa:
    Interface pura (Protocol) que encapsula TODAS as funcionalidades da nuvem AWS (Boto3/REST).
    Cobre Pen-Test (Demo 3), Design Review (Demo 1), Code Review GitOps (Demo 2) e Governança!
    """
    # ---------------------------------------------------------
    # 1. PEN-TESTING & EXECUÇÃO OFENSIVA (DEMO 3 - RED TEAM)
    # ---------------------------------------------------------
    def register_target_pentest(self, space_id: str, title: str, target_uri: str) -> str:
        """Registra o alvo no Agent Space e retorna o Pentest ID."""
        ...

    def trigger_pentest_job(self, space_id: str, pentest_id: str) -> str:
        """Aciona um Job de escaneamento de vulnerabilidades no alvo e retorna o Job ID."""
        ...

    def fetch_job_status(self, space_id: str, pentest_id: str, job_id: str) -> JobStatus:
        """Consulta em tempo real o progresso e estado de conclusão de um Job de escaneamento."""
        ...

    def stop_pentest_job(self, space_id: str, job_id: str) -> bool:
        """[EMERGÊNCIA] Interrompe/cancela imediatamente a execução de um scan ofensivo em andamento."""
        ...

    def fetch_findings_for_job(self, space_id: str, job_id: str) -> List[Finding]:
        """Extrai os achados com scores de risco e payloads de exploração da execução finalizada."""
        ...

    def list_all_remote_jobs(self, space_id: str) -> List[Dict[str, Any]]:
        """Lista e pagina no cluster AWS todo o histórico de testes cadastrados no Agent Space."""
        ...

    # ---------------------------------------------------------
    # 2. DESIGN REVIEWS & ARQUITETURA (DEMO 1 - BLUE/WHITE TEAM)
    # ---------------------------------------------------------
    def start_design_review(self, space_id: str, title: str, file_paths: List[str]) -> DesignReviewResult:
        """Envia diagramas (PNG/PDF/Word) de 'design-review/' e analisa riscos arquiteturais."""
        ...

    def list_design_reviews(self, space_id: str) -> List[DesignReviewResult]:
        """Consulta as análises arquiteturais remanescentes efetuadas no espaço de trabalho."""
        ...

    # ---------------------------------------------------------
    # 3. COMPLIANCE & POLÍTICAS GOVERNAMENTAIS (SECURITY REQUIREMENTS)
    # ---------------------------------------------------------
    def list_security_requirements(self, space_id: str) -> List[SecurityRequirement]:
        """Consulta quais políticas de conformidade da AWS estão ativas nos 10 domínios."""
        ...

    def enable_security_requirements(self, space_id: str, requirement_ids: List[str]) -> bool:
        """Ativa em lote diretrizes de segurança governamentais para as auditorias de design e código."""
        ...

    def create_custom_security_requirement(self, space_id: str, title: str, domain: str, description: str) -> str:
        """Injeta uma regra customizada da organização no motor analítico do AWS Security Agent."""
        ...

    # ---------------------------------------------------------
    # 4. TARGET DOMAIN VERIFICATION & ASSET INTEGRATION (TERRAFORM IaC)
    # ---------------------------------------------------------
    def verify_target_domain(self, space_id: str, domain_name: str, verification_token: str) -> TargetDomainVerification:
        """Comanda à AWS checar a titularidade do domínio alvo via registro TXT ou rota HTTP."""
        ...

    # ---------------------------------------------------------
    # 5. CODE REVIEWS (DEMO 2 - GITOPS & PULL REQUEST AUDITING)
    # ---------------------------------------------------------
    def fetch_code_reviews(self, space_id: str) -> List[CodeReviewResult]:
        """Recupera auditorias automatizadas abertas nas suas Pull Requests no GitHub do Demo 2."""
        ...
