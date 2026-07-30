from typing import Protocol, List, Dict, Any, Optional
from domain.entities import (
    JobSpecification, PentestExecutionResult, SecurityRequirement, AgentSpace,
    DesignReviewResult, CodeReviewResult, TargetDomainVerification
)


class PentestUseCasePort(Protocol):
    """
    PORTA DE ENTRADA (Inbound/Primary Port):
    Implementado via 'typing.Protocol' (PEP-544) como uma pura INTERFACE PYTHONICA moderna.
    Contrato mestre da suite de segurança (Blue Team, Red Team & DevSecOps).
    Expõe aos adaptadores (CLI, APIs REST) todas as ações operacionais orquestradas.
    """
    # --- AGENT SPACES ---
    def list_agent_spaces(self) -> List[AgentSpace]:
        """Lista os Agent Spaces disponíveis na conta AWS."""
        ...

    # --- PAINEL & CONEXÕES BASIC ---
    def list_configured_jobs(self) -> List[JobSpecification]:
        """Lista especificações dos testes (carregadas via Terraform ou YAML)."""
        ...

    def list_remote_agent_jobs(self) -> List[Dict[str, Any]]:
        """Consulta os jobs processados ou ativos no cluster remota da AWS."""
        ...

    # --- EXECUÇÃO DE PEN-TEST (DEMO 3) ---
    def execute_pentest_for_target(self, target_uri: str, title: str) -> PentestExecutionResult:
        """Executa bateria ponta a ponta (Register -> Scan -> Polling -> Report)."""
        ...

    def execute_all_configured_jobs(self) -> List[PentestExecutionResult]:
        """Dispara na ordem e acompanha simultaneamente todos os alvos configurados."""
        ...

    def emergency_stop_job(self, job_id: str) -> bool:
        """[CIRCUIT BREAKER] Aborta imediatamente um teste que esteja em andamento (IN_PROGRESS)."""
        ...

    # --- DESIGN REVIEWS (DEMO 1) ---
    def run_architecture_design_review(self, design_files_dir: str) -> DesignReviewResult:
        """Analisa documentos de arquitetura no diretório (Ex: 'design-review/') contra regras AWS."""
        ...

    def list_past_design_reviews(self) -> List[DesignReviewResult]:
        """Resgata auditorias de design computadas pela inteligência artificial da AWS."""
        ...

    # --- GOVERNANCE & SECURITY REQUIREMENTS ---
    def audit_security_requirements(self) -> List[SecurityRequirement]:
        """Verifica o compliance do Agent Space mapeando as 10 categorias de proteção habilitadas."""
        ...

    def add_custom_compliance_rule(self, title: str, domain_category: str, rule_description: str) -> str:
        """Cria e vincula uma política personalizada de segurança organizacional na AWS."""
        ...

    # --- VERIFICAÇÃO DE TITULARIDADE DE DOMÍNIO (IaC TERRAFORM) ---
    def verify_terraform_target_domain(self) -> Optional[TargetDomainVerification]:
        """Inspeciona saídas do Terraform IaC e envia o challenge (TXT/HTTP) para validação de posse na AWS."""
        ...

    # --- CODE REVIEWS (DEMO 2 - GITOPS) ---
    def get_pull_request_code_reviews(self) -> List[CodeReviewResult]:
        """Exibe o veredicto de segurança do Security Agent para Pull Requests abertos no GitHub."""
        ...
