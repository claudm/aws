from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


class JobStatus(str, Enum):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    STOPPED = "STOPPED"
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    VERIFIED = "VERIFIED"
    UNKNOWN = "UNKNOWN"

    def is_terminal(self) -> bool:
        return self in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.STOPPED, JobStatus.VERIFIED)


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    UNKNOWN = "UNKNOWN"

    @property
    def severity_score(self) -> int:
        order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFORMATIONAL": 4,
            "UNKNOWN": 5
        }
        return order.get(self.value, 9)


@dataclass
class JobSpecification:
    """Entidade que representa a especificação de um teste de segurança (Alvo/Job)."""
    job_id: str
    target_uri: str
    title: str
    priority: str = "MEDIUM"
    agent_space_id: str = "pentest-demo-space"


@dataclass
class Finding:
    """Entidade que representa uma vulnerabilidade de segurança encontrada pelo agente."""
    finding_id: str
    name: str
    risk_level: RiskLevel
    risk_score: float
    risk_type: str
    description: str
    confidence: str
    attack_script: Optional[str] = None


@dataclass
class PentestExecutionResult:
    """Entidade que encapsula o resultado completo de uma execução de Pen-Test (Demo 3 - Red Team)."""
    pentest_id: str
    job_id: str
    target_uri: str
    status: JobStatus
    findings: List[Finding] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def get_sorted_findings(self) -> List[Finding]:
        """Retorna os findings ordenados da maior severidade (CRITICAL) para a menor."""
        return sorted(self.findings, key=lambda f: f.risk_level.severity_score)


# =====================================================================
# EXTENSÃO DO DOMÍNIO: COMPLIANCE, DESIGN REVIEW E TARGET VERIFICATION
# =====================================================================

@dataclass
class AgentSpace:
    """Representa um Agent Space: o espaço de trabalho que agrupa pentests, revisões e achados."""
    agent_space_id: str
    name: str
    description: Optional[str] = None
    target_domain_ids: List[str] = field(default_factory=list)
    kms_key_id: Optional[str] = None
    code_review_enabled: bool = False


@dataclass
class SecurityRequirement:
    """Representa uma política de compliance ou requisito de segurança (Ex: KMS obrigatório, CloudTrail, IAM)."""
    requirement_id: str
    title: str
    domain: str
    enabled: bool
    description: Optional[str] = None
    is_custom: bool = False


@dataclass
class DesignReviewResult:
    """Encapsula achados de auditoria arquitetural sobre documentos ou diagramas de Design (Demo 1)."""
    review_id: str
    title: str
    status: JobStatus
    findings: List[Finding] = field(default_factory=list)
    attached_files: List[str] = field(default_factory=list)


@dataclass
class CodeReviewResult:
    """Encapsula revisões automatizadas geradas em Pull Requests de IaC/Terraform no GitHub (Demo 2)."""
    pr_url: str
    commit_sha: str
    vulnerabilities_found: int
    findings: List[Finding] = field(default_factory=list)


@dataclass
class TargetDomainVerification:
    """Encapsula o status e o Token/Challenge de verificação de propriedade de domínio na AWS."""
    domain_id: str
    domain_name: str
    verification_method: str  # "DNS_TXT" ou "HTTP_ROUTE"
    verification_token: str
    status: JobStatus = JobStatus.PENDING_VERIFICATION
