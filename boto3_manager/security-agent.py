#!/usr/bin/env python3
"""
AWS SECURITY AGENT DEVSECOPS SUITE - CLI em arquivo único.

Consolidação do main.py e de toda a Arquitetura Hexagonal (domínio, portas,
adaptadores e serviço) num único módulo executável, sem dependência do pacote
boto3_manager. O wiring continua sendo feito no contexto do Click (ctx.obj).

Uso: python security-agent.py [OPÇÕES] COMANDO [ARGS]

EXEMPLOS DE COMANDOS:

1. Espaços de Trabalho (Agent Spaces)
  Criar um espaço:
  $ python security-agent.py create-agent-space --name "Pentest-Homolog" --description "Homolog" --role-arn "arn:aws:iam::123456789012:role/Role"
  Listar espaços:
  $ python security-agent.py agent-spaces

2. Catálogo e Automação de Alvos
  Listar os alvos mapeados do código:
  $ python security-agent.py jobs
  Consultar os testes executados na AWS:
  $ python security-agent.py remote-jobs
  Painel executivo com status e falhas:
  $ python security-agent.py dashboard

3. Red Team: Pen-Testing Ofensivo
  Registrar alvo para teste, sem iniciar o motor:
  $ python security-agent.py create-pentest --target "http://minha-api-vulneravel.com" --title "API" --service-role "arn:aws:iam::123456789012:role/Role"
  Executar varredura em um alvo único e ver resultado:
  $ python security-agent.py scan --target "http://minha-api-vulneravel.com" --title "API Test" --service-role "arn:aws:iam::123456789012:role/Role"
  Disparar scans automatizados para todos os alvos configurados:
  $ python security-agent.py run
  Abortar teste rodando (Circuit Breaker):
  $ python security-agent.py stop --job-id "job-f1a23b45-6789-abcd"

4. Blue Team: Design Review de Arquitetura
  Submeter uma pasta de diagramas para a IA auditar falhas:
  $ python security-agent.py design-review --dir "caminho/para/pasta"
  Ver histórico de revisões de arquitetura:
  $ python security-agent.py design-reviews

5. GitOps: Code Review
  Auditar as modificações de IaC no GitHub:
  $ python security-agent.py github-pr

6. Governança e Compliance
  Adicionar uma nova regra mandatória de segurança da organização:
  $ python security-agent.py add-rule --title "TLS-Restrito" --domain "Data Protection" --description "Obriga TLS 1.3"
  Listar as regras atuais mapeadas:
  $ python security-agent.py compliance

7. Gestão de Assets e Infraestrutura
  Validar titularidade programática do domínio do alvo:
  $ python security-agent.py verify-domain

Flags Globais podem ser usadas (antes do comando):
  $ python security-agent.py --region "sa-east-1" --profile "Profile" --agent-space "space-id" scan --target "http://alvo.com"

"""

import os
import json
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Protocol

import boto3
import click
import yaml
from botocore.config import Config as BotocoreConfig
from botocore.exceptions import BotoCoreError, ClientError


# =============================================================================
# DOMÍNIO: EXCEÇÕES
# =============================================================================

class DomainException(Exception):
    """Exceção base para todo o domínio da aplicação."""
    pass


class JobConfigurationError(DomainException):
    """Lançada quando a configuração do job ou arquivo de entrada é inválida ou inacessível."""
    pass


class SecurityAgentConnectionError(DomainException):
    """Lançada em caso de falhas na comunicação externa com o AWS Security Agent."""
    pass


class PentestExecutionTimeoutError(DomainException):
    """Lançada quando o Job de teste ultrapassa o limite de tempo para conclusão."""
    pass


# =============================================================================
# DOMÍNIO: ENTIDADES
# =============================================================================

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


# ---------------------------------------------------------------------
# EXTENSÃO DO DOMÍNIO: COMPLIANCE, DESIGN REVIEW E TARGET VERIFICATION
# ---------------------------------------------------------------------

@dataclass
class AgentSpace:
    """Representa um Agent Space: o espaço de trabalho que agrupa pentests, revisões e achados."""
    agent_space_id: str
    name: str
    description: Optional[str] = None
    target_domain_ids: List[str] = field(default_factory=list)
    kms_key_id: Optional[str] = None
    code_review_enabled: bool = False
    role_arn: Optional[str] = None


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


# =============================================================================
# PORTAS DE ENTRADA (INBOUND / PRIMARY PORTS)
# =============================================================================

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

    def create_agent_space(self, name: str, description: Optional[str] = None, role_arn: Optional[str] = None) -> str:
        """Cria um Agent Space na conta e devolve o novo id."""
        ...

    # --- PAINEL & CONEXÕES BASIC ---
    def list_configured_jobs(self) -> List[JobSpecification]:
        """Lista especificações dos testes (carregadas via Terraform ou YAML)."""
        ...

    def list_remote_agent_jobs(self) -> List[Dict[str, Any]]:
        """Consulta os jobs processados ou ativos no cluster remota da AWS."""
        ...

    # --- EXECUÇÃO DE PEN-TEST (DEMO 3) ---
    def create_pentest_target(self, target_uri: str, title: str, service_role: Optional[str] = None) -> str:
        """Registra o alvo (CreatePentest) e devolve o Pentest ID, sem disparar o Job de scan."""
        ...

    def execute_pentest_for_target(self, target_uri: str, title: str, service_role: Optional[str] = None) -> PentestExecutionResult:
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


# =============================================================================
# PORTAS DE SAÍDA (OUTBOUND / DRIVEN PORTS)
# =============================================================================

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
    # 0. AGENT SPACES (ESPAÇOS DE TRABALHO)
    # ---------------------------------------------------------
    def list_agent_spaces(self) -> List[AgentSpace]:
        """Lista todos os Agent Spaces existentes na conta."""
        ...

    def create_agent_space(self, name: str, description: Optional[str] = None, role_arn: Optional[str] = None) -> str:
        """Cria um Agent Space na conta e devolve o novo id."""
        ...

    # ---------------------------------------------------------
    # 1. PEN-TESTING & EXECUÇÃO OFENSIVA (DEMO 3 - RED TEAM)
    # ---------------------------------------------------------
    def register_target_pentest(self, space_id: str, title: str, target_uri: str, service_role: Optional[str] = None) -> str:
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


# =============================================================================
# ADAPTADOR DE SAÍDA: LEITOR YAML
# =============================================================================

class YamlJobConfigSourceAdapter(JobConfigSourcePort):
    """
    ADAPTADOR DE SAÍDA (Outbound Adapter) - Leitor YAML:
    Implementa o contrato JobConfigSourcePort, consumindo a biblioteca PyYAML
    para converter especificações em disco no modelo estruturado do Domínio.
    """
    def __init__(self, filepath: str):
        if not os.path.exists(filepath):
            raise JobConfigurationError(f"O arquivo de configuração '{filepath}' não foi localizado no sistema.")
        self.filepath = filepath
        self._data: Dict[str, Any] = self._parse_yaml()

    def _parse_yaml(self) -> Dict[str, Any]:
        with open(self.filepath, "r", encoding="utf-8") as file:
            try:
                content = yaml.safe_load(file)
                return content or {}
            except yaml.YAMLError as exc:
                raise JobConfigurationError(f"Erro ao processar sintaxe do YAML no arquivo '{self.filepath}': {exc}")

    def get_agent_space_id(self) -> str:
        """
        Agent Space declarado no YAML. Devolve string vazia quando o arquivo não
        declara nenhum: quem consome trata isso como 'não sei qual', e não como
        um espaço chamado 'pentest-demo-space' que provavelmente não existe.
        """
        return str(self._data.get("agent_space_id") or "")

    def fetch_job_specifications(self) -> List[JobSpecification]:
        raw_jobs = self._data.get("jobs", [])
        if not isinstance(raw_jobs, list):
            return []

        space_id = self.get_agent_space_id()
        specifications: List[JobSpecification] = []

        for item in raw_jobs:
            if not isinstance(item, dict):
                continue
            spec = JobSpecification(
                job_id=str(item.get("job_id", "unnamed-job")),
                target_uri=str(item.get("target_uri", "")),
                title=str(item.get("title", "Automated Scan Job")),
                priority=str(item.get("priority", "MEDIUM")),
                agent_space_id=space_id
            )
            specifications.append(spec)

        return specifications


# =============================================================================
# ADAPTADORES DE SAÍDA: TERRAFORM E HÍBRIDO
# =============================================================================

class TerraformJobConfigSourceAdapter(JobConfigSourcePort):
    """
    ADAPTADOR DE SAÍDA (Outbound Adapter) - Integração com Terraform:
    Implementa o contrato JobConfigSourcePort conversando diretamente com a stack de
    Infraestrutura como Código (IaC) em 'd:/aws/sample-security-agent-demo/terraform-aws-security-agent'.
    Extrai o `agent_space_id` e propriedades dinamicamente via `terraform output -json`.
    """
    def __init__(self, terraform_dir: str = r"d:\aws\sample-security-agent-demo\terraform-aws-security-agent"):
        if not os.path.exists(terraform_dir):
            raise JobConfigurationError(f"O diretório do Terraform '{terraform_dir}' não foi encontrado no sistema.")
        self.terraform_dir = terraform_dir
        self.outputs: Dict[str, Any] = self._load_terraform_outputs()

    def _load_terraform_outputs(self) -> Dict[str, Any]:
        """Executa 'terraform output -json' no diretório informado para capturar os outputs da stack."""
        try:
            result = subprocess.check_output(
                ["terraform", "output", "-json"],
                cwd=self.terraform_dir,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8"
            )
            data = json.loads(result)
            return data
        except subprocess.CalledProcessError as err:
            raise JobConfigurationError(
                f"Erro ao executar 'terraform output -json' no diretório '{self.terraform_dir}'. "
                f"Verifique se o 'terraform init/apply' foi realizado. Retorno: {err.stderr}"
            )
        except FileNotFoundError:
            raise JobConfigurationError(
                "O executável do 'terraform' não foi encontrado no PATH do sistema operacional."
            )
        except json.JSONDecodeError as exc:
            raise JobConfigurationError(f"Falha ao decodificar a saída JSON do Terraform: {exc}")

    def get_agent_space_id(self) -> str:
        space_output = self.outputs.get("agent_space_id", {}).get("value")
        if space_output and space_output != "null":
            return str(space_output)

        props_output = self.outputs.get("agent_space_properties", {}).get("value")
        if isinstance(props_output, dict) and "AgentSpaceId" in props_output:
            return str(props_output["AgentSpaceId"])

        # A stack não expôs nenhum Agent Space: melhor dizer que não sabe do que
        # devolver um id inventado que não existe na conta.
        return ""

    def get_service_role_arn(self) -> Optional[str]:
        return self.outputs.get("service_role_arn", {}).get("value")

    def get_app_role_arn(self) -> Optional[str]:
        return self.outputs.get("app_role_arn", {}).get("value")

    def get_terraform_pentest_id(self) -> Optional[str]:
        val = self.outputs.get("pentest_id", {}).get("value")
        return None if val == "null" else str(val) if val else None

    def get_target_domain_details(self) -> Optional[Dict[str, Any]]:
        """Extrai os tokens de verificação de domínio providos pela stack do Terraform para o Challenge na AWS."""
        domain_id = self.outputs.get("target_domain_id", {}).get("value")
        details = self.outputs.get("target_domain_verification_details", {}).get("value")

        if domain_id and domain_id != "null":
            return {
                "domain_id": str(domain_id),
                "domain_name": details.get("DomainName", str(domain_id)) if isinstance(details, dict) else str(domain_id),
                "token": details.get("VerificationToken", "aws-security-agent-challenge-tf-token") if isinstance(details, dict) else "aws-security-agent-challenge-tf-token"
            }
        # Sem domínio nos outputs não há o que verificar; quem chama trata None.
        return None

    def fetch_job_specifications(self) -> List[JobSpecification]:
        space_id = self.get_agent_space_id()
        domain_info = self.get_target_domain_details()

        # Sem domínio provisionado, a stack não criou alvo nenhum.
        if not domain_info:
            return []

        target_uri = f"http://{domain_info['domain_name']}"

        spec = JobSpecification(
            job_id="tf-stack-pentest-job",
            target_uri=target_uri,
            title="Scan Automático em Alvo Provisionado via Terraform",
            priority="CRITICAL",
            agent_space_id=space_id
        )
        return [spec]


class HybridTerraformYamlAdapter(JobConfigSourcePort):
    """
    ADAPTADOR COMPÓSITO / HÍBRIDO (Outbound Composite Adapter):
    Sincroniza o Agent Space ID e detalhes de verificação do TERRAFORM (IaC) com
    a lista pormenorizada de testes ofensivos definidos localmente em YAML!
    """
    def __init__(self, yaml_filepath: str, terraform_dir: str = r"d:\aws\sample-security-agent-demo\terraform-aws-security-agent"):
        # As duas fontes são opcionais: a wheel instalada não leva o
        # jobs_config.yaml, e uma máquina que só consulta não tem a stack do
        # Terraform. Sem nenhuma delas o adaptador continua válido e apenas não
        # sabe qual Agent Space usar — aí quem consome busca os ids na conta.
        self.yaml_adapter: Optional[Any] = None
        try:
            self.yaml_adapter = YamlJobConfigSourceAdapter(yaml_filepath)
        except Exception as exc:
            print(f"[Aviso YAML] Catálogo local indisponível ({exc}).")

        self.tf_adapter: Optional[TerraformJobConfigSourceAdapter] = None
        try:
            self.tf_adapter = TerraformJobConfigSourceAdapter(terraform_dir)
        except Exception as exc:
            print(f"[Aviso IaC] Saídas do Terraform indisponíveis ({exc}).")

    def get_agent_space_id(self) -> str:
        """Agent Space do Terraform; senão o do YAML; senão vazio (não sei qual)."""
        for fonte in (self.tf_adapter, self.yaml_adapter):
            if fonte is not None:
                space_id = fonte.get_agent_space_id()
                if space_id:
                    return space_id
        return ""

    def get_target_domain_details(self) -> Optional[Dict[str, Any]]:
        if self.tf_adapter is not None:
            return self.tf_adapter.get_target_domain_details()
        return None

    def get_service_role_arn(self) -> Optional[str]:
        return self.tf_adapter.get_service_role_arn() if self.tf_adapter else None

    def fetch_job_specifications(self) -> List[JobSpecification]:
        specs: List[JobSpecification] = []
        if self.yaml_adapter is not None:
            specs = self.yaml_adapter.fetch_job_specifications()
        elif self.tf_adapter is not None:
            specs = self.tf_adapter.fetch_job_specifications()

        real_space_id = self.get_agent_space_id()
        if real_space_id:
            for spec in specs:
                spec.agent_space_id = real_space_id
        return specs


# =============================================================================
# ADAPTADOR DE SAÍDA: AWS SECURITY AGENT VIA BOTO3
# =============================================================================

# Extensões aceitas pelo enum ArtifactType do AddArtifact.
_ARTIFACT_TYPES = {
    ".txt": "TXT",
    ".md": "MD",
    ".png": "PNG",
    ".jpg": "JPEG",
    ".jpeg": "JPEG",
    ".pdf": "PDF",
    ".docx": "DOCX",
    ".doc": "DOC",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
}

# Severidade de um Threat (CRITICAL/HIGH/MEDIUM/LOW/INFO) -> RiskLevel do domínio.
_THREAT_SEVERITY = {
    "CRITICAL": RiskLevel.CRITICAL,
    "HIGH": RiskLevel.HIGH,
    "MEDIUM": RiskLevel.MEDIUM,
    "LOW": RiskLevel.LOW,
    "INFO": RiskLevel.INFORMATIONAL,
}


class Boto3SecurityAgentAdapter(SecurityAgentPort):
    """
    ADAPTADOR DE SAÍDA (Outbound Adapter) - AWS Security Agent via Boto3.

    Todas as chamadas usam exclusivamente operações que existem na API real
    (service model securityagent 2025-09-06). Não há caminho simulado: quando a
    AWS não oferece uma operação equivalente, o método usa a operação real mais
    próxima e isso está documentado no próprio método.
    """

    def __init__(
        self,
        region_name: str = "us-east-1",
        service_role: Optional[str] = None,
        profile_name: Optional[str] = None,
    ):
        """
        :param region_name: Região AWS.
        :param service_role: ARN exigido por CreateThreatModel (Design Review).
        :param profile_name: Perfil do ~/.aws/credentials a usar na AWS real.
        """
        self.service_role = service_role or os.environ.get("SECURITY_AGENT_SERVICE_ROLE")

        session = boto3.Session(profile_name=profile_name) if profile_name else boto3.Session()
        client_kwargs: Dict[str, Any] = {"region_name": region_name}

        client_kwargs["config"] = BotocoreConfig(ignore_configured_endpoint_urls=True)

        self.client = session.client("securityagent", **client_kwargs)

    # =========================================================================
    # 0. AGENT SPACES (ESPAÇOS DE TRABALHO)
    # =========================================================================
    def list_agent_spaces(self) -> List[AgentSpace]:
        """
        Lista os Agent Spaces da conta. ListAgentSpaces devolve apenas resumos
        (id, nome e datas); descrição, domínios e KMS vêm de BatchGetAgentSpaces.
        """
        try:
            summaries = self._paginate(self.client.list_agent_spaces, "agentSpaceSummaries")
            space_ids = [str(s["agentSpaceId"]) for s in summaries if s.get("agentSpaceId")]
            if not space_ids:
                return []

            spaces = self.client.batch_get_agent_spaces(
                agentSpaceIds=space_ids
            ).get("agentSpaces", [])

            resultado: List[AgentSpace] = []
            for space in spaces:
                settings = space.get("codeReviewSettings") or {}
                resultado.append(AgentSpace(
                    agent_space_id=str(space["agentSpaceId"]),
                    name=str(space.get("name", "")),
                    description=space.get("description"),
                    target_domain_ids=list(space.get("targetDomainIds") or []),
                    kms_key_id=space.get("kmsKeyId"),
                    code_review_enabled=bool(
                        settings.get("controlsScanning") or settings.get("generalPurposeScanning")
                    ),
                    role_arn=space.get("awsResources", {}).get("iamRoles", [None])[0] if space.get("awsResources", {}).get("iamRoles") else None
                ))

            return resultado
        except (ClientError, BotoCoreError) as exc:
            raise SecurityAgentConnectionError(f"Erro ao listar Agent Spaces: {exc}")

    def create_agent_space(self, name: str, description: Optional[str] = None, role_arn: Optional[str] = None) -> str:
        """Cria um Agent Space (só 'name' é obrigatório) e devolve o novo id."""
        try:
            params: Dict[str, Any] = {"name": name}
            if description:
                params["description"] = description
            if role_arn:
                params["awsResources"] = {"iamRoles": [role_arn]}
            response = self.client.create_agent_space(**params)
            return str(response["agentSpaceId"])
        except (ClientError, BotoCoreError) as exc:
            raise SecurityAgentConnectionError(f"Erro na API AWS CreateAgentSpace para '{name}': {exc}")

    # =========================================================================
    # 1. PEN-TESTING (DEMO 3 - RED TEAM)
    # =========================================================================
    def register_target_pentest(self, space_id: str, title: str, target_uri: str, service_role: Optional[str] = None) -> str:
        try:
            params: Dict[str, Any] = {
                "agentSpaceId": space_id,
                "title": title,
                "assets": {"endpoints": [{"uri": target_uri}]}
            }
            if service_role:
                params["serviceRole"] = service_role
            response = self.client.create_pentest(**params)
            return str(response["pentestId"])
        except (ClientError, BotoCoreError) as exc:
            raise SecurityAgentConnectionError(f"Erro na API AWS CreatePentest para '{target_uri}': {exc}")

    def trigger_pentest_job(self, space_id: str, pentest_id: str) -> str:
        try:
            response = self.client.start_pentest_job(
                agentSpaceId=space_id,
                pentestId=pentest_id
            )
            return str(response["pentestJobId"])
        except (ClientError, BotoCoreError) as exc:
            raise SecurityAgentConnectionError(f"Erro ao disparar Job para Pentest '{pentest_id}': {exc}")

    def fetch_job_status(self, space_id: str, pentest_id: str, job_id: str) -> JobStatus:
        """Consulta o estado do Job. O status vive no PentestJob, não no Pentest."""
        try:
            response = self.client.batch_get_pentest_jobs(
                agentSpaceId=space_id,
                pentestJobIds=[job_id]
            )
            jobs = response.get("pentestJobs", [])
            if not jobs:
                return JobStatus.UNKNOWN

            try:
                return JobStatus(str(jobs[0].get("status", "")).upper())
            except ValueError:
                return JobStatus.UNKNOWN
        except (ClientError, BotoCoreError) as exc:
            raise SecurityAgentConnectionError(f"Erro ao consultar progresso do Job '{job_id}': {exc}")

    def stop_pentest_job(self, space_id: str, job_id: str) -> bool:
        """[EMERGÊNCIA] Interrompe o teste ofensivo em andamento."""
        try:
            self.client.stop_pentest_job(agentSpaceId=space_id, pentestJobId=job_id)
            return True
        except (ClientError, BotoCoreError) as exc:
            print(f"[!] Falha na API ao tentar abortar o Job '{job_id}': {exc}")
            return False

    def fetch_findings_for_job(self, space_id: str, job_id: str) -> List[Finding]:
        try:
            summaries = self._paginate(
                self.client.list_findings,
                "findingsSummaries",
                agentSpaceId=space_id,
                pentestJobId=job_id
            )
            return self._load_findings(space_id, summaries)
        except (ClientError, BotoCoreError) as exc:
            raise SecurityAgentConnectionError(f"Falha ao descarregar relatórios de vulnerabilidade (Job {job_id}): {exc}")

    def list_all_remote_jobs(self, space_id: str) -> List[Dict[str, Any]]:
        """
        Histórico de Jobs do Agent Space. A API lista Jobs por Pentest
        (ListPentestJobsForPentest), então o catálogo é percorrido por pentest.
        """
        try:
            all_jobs: List[Dict[str, Any]] = []
            pentests = self._paginate(self.client.list_pentests, "pentestSummaries", agentSpaceId=space_id)

            for pentest in pentests:
                pentest_id = pentest.get("pentestId")
                if not pentest_id:
                    continue

                all_jobs.extend(self._paginate(
                    self.client.list_pentest_jobs_for_pentest,
                    "pentestJobSummaries",
                    agentSpaceId=space_id,
                    pentestId=pentest_id
                ))

            return all_jobs
        except (ClientError, BotoCoreError) as exc:
            raise SecurityAgentConnectionError(f"Erro ao listar catálogo remotamente para space '{space_id}': {exc}")

    # =========================================================================
    # 2. DESIGN REVIEWS (DEMO 1 - ANÁLISE ARQUITETURAL)
    # =========================================================================
    def start_design_review(self, space_id: str, title: str, file_paths: List[str]) -> DesignReviewResult:
        """
        Design Review é o Threat Model da API: os documentos viram artefatos
        (AddArtifact), entram como assets.documents de um CreateThreatModel, e o
        StartThreatModelJob produz os Threats devolvidos como findings.
        """
        if not self.service_role:
            raise SecurityAgentConnectionError(
                "CreateThreatModel exige serviceRole. Informe service_role no adaptador "
                "ou defina SECURITY_AGENT_SERVICE_ROLE."
            )

        existing = [f for f in file_paths if os.path.exists(f)]
        file_names = [os.path.basename(f) for f in existing]

        try:
            documents = [{"artifactId": self._upload_artifact(space_id, path)} for path in existing]

            model = self.client.create_threat_model(
                agentSpaceId=space_id,
                title=title,
                serviceRole=self.service_role,
                assets={"documents": documents} if documents else {}
            )
            model_id = str(model["threatModelId"])

            job = self.client.start_threat_model_job(
                agentSpaceId=space_id,
                threatModelId=model_id
            )

            findings = self._fetch_threats(space_id, str(job["threatModelJobId"]))

            return DesignReviewResult(
                review_id=model_id,
                title=title,
                status=self._as_job_status(job.get("status")),
                findings=findings,
                attached_files=file_names
            )
        except (ClientError, BotoCoreError) as exc:
            raise SecurityAgentConnectionError(f"Erro ao iniciar Design Review na AWS para '{title}': {exc}")

    def list_design_reviews(self, space_id: str) -> List[DesignReviewResult]:
        """Lista os Threat Models do espaço, com o status do Job mais recente de cada um."""
        try:
            models = self._paginate(self.client.list_threat_models, "threatModelSummaries", agentSpaceId=space_id)

            reviews: List[DesignReviewResult] = []
            for model in models:
                model_id = str(model["threatModelId"])
                jobs = self._paginate(
                    self.client.list_threat_model_jobs,
                    "threatModelJobSummaries",
                    agentSpaceId=space_id,
                    threatModelId=model_id
                )

                reviews.append(DesignReviewResult(
                    review_id=model_id,
                    title=model.get("title", ""),
                    status=self._as_job_status(jobs[-1].get("status")) if jobs else JobStatus.UNKNOWN,
                    findings=[]
                ))

            return reviews
        except (ClientError, BotoCoreError) as exc:
            raise SecurityAgentConnectionError(f"Erro ao listar Design Reviews do espaço: {exc}")

    # =========================================================================
    # 3. COMPLIANCE & GOVERNANÇA (SECURITY REQUIREMENTS)
    # =========================================================================
    def list_security_requirements(self, space_id: str) -> List[SecurityRequirement]:
        """
        Requisitos de segurança na API real pertencem a um Pack, não ao Agent
        Space, então percorre todos os packs. O parâmetro space_id existe apenas
        para o contrato da porta.
        """
        try:
            requirements: List[SecurityRequirement] = []
            packs = self._paginate(
                self.client.list_security_requirement_packs,
                "securityRequirementPackSummaries"
            )

            for pack in packs:
                pack_id = str(pack["packId"])
                enabled = str(pack.get("status", "")).upper() == "ENABLED"
                is_custom = str(pack.get("managementType", "")).upper() == "CUSTOMER_MANAGED"

                summaries = self._paginate(
                    self.client.list_security_requirements,
                    "securityRequirementSummaries",
                    packId=pack_id
                )
                names = [str(s["name"]) for s in summaries if s.get("name")]
                if not names:
                    continue

                # O domínio de cada requisito só vem no BatchGet, não no List.
                detailed = self.client.batch_get_security_requirements(
                    packId=pack_id,
                    securityRequirementNames=names
                ).get("securityRequirements", [])

                for item in detailed:
                    requirements.append(SecurityRequirement(
                        requirement_id=str(item["name"]),
                        title=str(item["name"]),
                        domain=str(item.get("domain", "")),
                        enabled=enabled,
                        description=item.get("description"),
                        is_custom=is_custom
                    ))

            return requirements
        except (ClientError, BotoCoreError) as exc:
            raise SecurityAgentConnectionError(f"Erro ao consultar requisitos de segurança: {exc}")

    def enable_security_requirements(self, space_id: str, requirement_ids: List[str]) -> bool:
        """
        A API real não habilita requisitos individualmente: o status ENABLED/DISABLED
        é do Pack. Cada id recebido é tratado como packId em
        UpdateSecurityRequirementPack.
        """
        try:
            for pack_id in requirement_ids:
                self.client.update_security_requirement_pack(packId=pack_id, status="ENABLED")
            return True
        except (ClientError, BotoCoreError) as exc:
            print(f"[-] Erro ao reconfigurar regras de segurança na AWS: {exc}")
            return False

    def create_custom_security_requirement(self, space_id: str, title: str, domain: str, description: str) -> str:
        """
        Cria o requisito via BatchCreateSecurityRequirements dentro de um pack
        gerenciado pelo cliente, criando o pack se ainda não existir. A API
        identifica requisitos pelo nome, então o retorno é o nome criado.
        """
        try:
            pack_id = self._customer_pack_id()

            response = self.client.batch_create_security_requirements(
                packId=pack_id,
                securityRequirements=[{
                    "name": title,
                    "description": description,
                    "domain": domain,
                    "evaluation": description,
                }]
            )

            errors = response.get("errors", [])
            if errors:
                raise SecurityAgentConnectionError(
                    f"AWS recusou o requisito '{title}': {errors[0].get('code')} - {errors[0].get('message')}"
                )

            created = response.get("securityRequirements", [])
            return str(created[0]["name"]) if created else title
        except (ClientError, BotoCoreError) as exc:
            raise SecurityAgentConnectionError(f"Erro ao cadastrar requisito customizado '{title}': {exc}")

    # =========================================================================
    # 4. TARGET DOMAIN VERIFICATION (INTEGRAÇÃO TERRAFORM IaC)
    # =========================================================================
    def verify_target_domain(self, space_id: str, domain_name: str, verification_token: str) -> TargetDomainVerification:
        """
        VerifyTargetDomain recebe targetDomainId, então o domínio é localizado
        pelo nome em ListTargetDomains. O token de verificação é emitido pela AWS
        (verificationDetails) — o argumento verification_token existe apenas para
        o contrato da porta e não é enviado.
        """
        try:
            domain_id = self._target_domain_id(domain_name)
            if not domain_id:
                raise SecurityAgentConnectionError(
                    f"Domínio '{domain_name}' não está registrado no Security Agent. "
                    "Registre-o (CreateTargetDomain / Terraform) antes de verificar."
                )

            details = self._target_domain_details(domain_id)
            response = self.client.verify_target_domain(targetDomainId=domain_id)

            return TargetDomainVerification(
                domain_id=domain_id,
                domain_name=str(response.get("domainName", domain_name)),
                verification_method=str(details.get("method", "")),
                verification_token=str(details.get("token", "")),
                status=self._as_job_status(response.get("status"))
            )
        except (ClientError, BotoCoreError) as exc:
            raise SecurityAgentConnectionError(f"Falha de verificação de domínio AWS para '{domain_name}': {exc}")

    # =========================================================================
    # 5. CODE REVIEWS (DEMO 2 - AUDITANDO PRs NO GITHUB)
    # =========================================================================
    def fetch_code_reviews(self, space_id: str) -> List[CodeReviewResult]:
        """
        Revisões de código do Agent Space. O CodeReviewSummary da API não traz URL
        de Pull Request nem commit, então pr_url recebe o título da revisão e
        commit_sha fica vazio; os findings vêm do Job mais recente de cada revisão.
        """
        try:
            reviews = self._paginate(self.client.list_code_reviews, "codeReviewSummaries", agentSpaceId=space_id)

            results: List[CodeReviewResult] = []
            for review in reviews:
                review_id = str(review["codeReviewId"])
                jobs = self._paginate(
                    self.client.list_code_review_jobs_for_code_review,
                    "codeReviewJobSummaries",
                    agentSpaceId=space_id,
                    codeReviewId=review_id
                )

                findings: List[Finding] = []
                if jobs:
                    summaries = self._paginate(
                        self.client.list_findings,
                        "findingsSummaries",
                        agentSpaceId=space_id,
                        codeReviewJobId=str(jobs[-1]["codeReviewJobId"])
                    )
                    findings = self._load_findings(space_id, summaries)

                results.append(CodeReviewResult(
                    pr_url=str(review.get("title", "")),
                    commit_sha="",
                    vulnerabilities_found=len(findings),
                    findings=findings
                ))

            return results
        except (ClientError, BotoCoreError) as exc:
            raise SecurityAgentConnectionError(f"Erro ao consultar Code Reviews do espaço: {exc}")

    # =========================================================================
    # AUXILIARES INTERNOS
    # =========================================================================
    @staticmethod
    def _paginate(operation: Callable[..., Dict[str, Any]], key: str, **kwargs: Any) -> List[Dict[str, Any]]:
        """Percorre todas as páginas de uma operação e devolve os itens de 'key'."""
        items: List[Dict[str, Any]] = []
        next_token = None

        while True:
            params = dict(kwargs)
            if next_token:
                params["nextToken"] = next_token

            response = operation(**params)
            items.extend(response.get(key, []))

            next_token = response.get("nextToken")
            if not next_token:
                return items

    def _load_findings(self, space_id: str, summaries: List[Dict[str, Any]]) -> List[Finding]:
        """Resolve os findings completos a partir dos resumos devolvidos por ListFindings."""
        finding_ids = [str(s["findingId"]) for s in summaries if s.get("findingId")]
        if not finding_ids:
            return []

        raw = self.client.batch_get_findings(
            agentSpaceId=space_id,
            findingIds=finding_ids
        ).get("findings", [])

        return [self._convert_raw_finding(rf) for rf in raw]

    def _upload_artifact(self, space_id: str, path: str) -> str:
        """Envia um documento como artefato e devolve o artifactId."""
        extension = os.path.splitext(path)[1].lower()
        artifact_type = _ARTIFACT_TYPES.get(extension)
        if not artifact_type:
            raise SecurityAgentConnectionError(
                f"AddArtifact não aceita a extensão '{extension}' ({os.path.basename(path)}). "
                f"Tipos suportados: {', '.join(sorted(set(_ARTIFACT_TYPES.values())))}."
            )

        with open(path, "rb") as handle:
            content = handle.read()

        response = self.client.add_artifact(
            agentSpaceId=space_id,
            artifactContent=content,
            artifactType=artifact_type,
            fileName=os.path.basename(path)
        )
        return str(response["artifactId"])

    def _fetch_threats(self, space_id: str, threat_job_id: str) -> List[Finding]:
        """Carrega os Threats produzidos por um Job de Threat Model."""
        summaries = self._paginate(
            self.client.list_threats,
            "threats",
            agentSpaceId=space_id,
            threatJobId=threat_job_id
        )
        threat_ids = [str(s["threatId"]) for s in summaries if s.get("threatId")]
        if not threat_ids:
            return []

        threats = self.client.batch_get_threats(
            agentSpaceId=space_id,
            threatIds=threat_ids
        ).get("threats", [])

        return [self._convert_threat(t) for t in threats]

    def _customer_pack_id(self) -> str:
        """Devolve o pack gerenciado pelo cliente, criando-o se necessário."""
        packs = self._paginate(
            self.client.list_security_requirement_packs,
            "securityRequirementPackSummaries"
        )

        for pack in packs:
            if str(pack.get("managementType", "")).upper() == "CUSTOMER_MANAGED":
                return str(pack["packId"])

        created = self.client.create_security_requirement_pack(
            name="Corporate Custom Rules",
            description="Requisitos de segurança próprios da organização.",
            status="ENABLED"
        )
        return str(created["packId"])

    def _target_domain_id(self, domain_name: str) -> Optional[str]:
        """Localiza o id de um domínio registrado pelo nome."""
        for domain in self._paginate(self.client.list_target_domains, "targetDomainSummaries"):
            if domain.get("domainName") == domain_name:
                return str(domain["targetDomainId"])
        return None

    def _target_domain_details(self, domain_id: str) -> Dict[str, Any]:
        """Lê o desafio de verificação emitido pela AWS para um domínio."""
        domains = self.client.batch_get_target_domains(
            targetDomainIds=[domain_id]
        ).get("targetDomains", [])
        if not domains:
            return {}

        details = domains[0].get("verificationDetails", {})
        method = str(details.get("method", ""))
        challenge = details.get("dnsTxt") or details.get("httpRoute") or {}

        return {"method": method, "token": challenge.get("token", "")}

    @staticmethod
    def _as_job_status(value: Any) -> JobStatus:
        try:
            return JobStatus(str(value or "").upper())
        except ValueError:
            return JobStatus.UNKNOWN

    @staticmethod
    def _convert_threat(threat: Dict[str, Any]) -> Finding:
        """
        Converte um Threat em Finding. A API de Threat Model não atribui score
        nem confiança a um Threat, ao contrário dos findings de pentest.
        """
        stride = threat.get("stride") or []

        return Finding(
            finding_id=str(threat.get("threatId", "N/A")),
            name=str(threat.get("title", "(Sem Título)")),
            risk_level=_THREAT_SEVERITY.get(str(threat.get("severity", "")).upper(), RiskLevel.UNKNOWN),
            risk_score=0.0,
            risk_type=", ".join(stride) if stride else "Threat Model",
            description=str(threat.get("statement", "")),
            confidence="",
            attack_script=None
        )

    @staticmethod
    def _convert_raw_finding(rf: Dict[str, Any]) -> Finding:
        risk_str = rf.get("riskLevel", "UNKNOWN").upper()
        try:
            risk_enum = RiskLevel(risk_str)
        except ValueError:
            risk_enum = RiskLevel.UNKNOWN

        return Finding(
            finding_id=str(rf.get("findingId", "N/A")),
            name=str(rf.get("name", "(Sem Título)")),
            risk_level=risk_enum,
            risk_score=float(rf.get("riskScore", 0.0)),
            risk_type=str(rf.get("riskType", "Genérica")),
            description=str(rf.get("description", "Sem descrição.")),
            confidence=str(rf.get("confidence", "Médio")),
            attack_script=rf.get("attackScript")
        )


# =============================================================================
# NÚCLEO: SERVIÇO DE ORQUESTRAÇÃO (USE CASES)
# =============================================================================

class PentestService(PentestUseCasePort):
    """
    NÚCLEO E ORQUESTRAÇÃO DO SISTEMA DEVSECOPS (Hexagon Core / Use Case Orchestration):
    Implementa a Porta Primaria de Casos de Uso com absoluta autonomia tecnológica.
    Agrega as 5 vertentes de segurança AWS: Pen-Test (Demo 3), Design Review (Demo 1),
    Code Review GitOps (Demo 2), Verificação IaC (Terraform) e Compliance Operacional!
    """
    def __init__(
        self,
        config_source: JobConfigSourcePort,
        security_agent: SecurityAgentPort,
        max_wait_seconds: int = 300,
        poll_interval_sec: int = 5,
        agent_space_override: Optional[str] = None,
    ):
        """
        :param max_wait_seconds: Tolerância total de espera por um Job. O padrão
            (5 min) atende um emulador, onde os jobs concluem na hora; contra a
            AWS real um pen-test leva bem mais que isso e o valor precisa subir.
        :param poll_interval_sec: Intervalo entre consultas de status.
        :param agent_space_override: Se informado, ignora o Agent Space da fonte
            de configuração (ex.: o 'pentest-demo-space' fixo do jobs_config.yaml,
            que não existe na conta real) e usa este id em todas as operações.
        """
        self.config_source = config_source
        self.security_agent = security_agent
        self.agent_space_override = agent_space_override or None
        self.poll_interval_sec = max(1, poll_interval_sec)
        self.max_retries = max(1, int(max_wait_seconds / self.poll_interval_sec))

    # =========================================================================
    # RESOLUÇÃO DE ESCOPO (QUAIS AGENT SPACES CONSULTAR)
    # =========================================================================
    def _scope_space_ids(self) -> List[str]:
        """
        Agent Spaces a consultar.

        Quando a fonte de configuração sabe qual é (jobs_config.yaml ou output do
        Terraform), o escopo é só esse. Quando não sabe — pacote instalado sem
        jobs_config.yaml, máquina sem a stack — os ids vêm da própria conta via
        ListAgentSpaces, e a consulta cobre todos.
        """
        if self.agent_space_override:
            return [self.agent_space_override]

        configurado = self._configured_space_id()
        if configurado:
            return [configurado]

        return [space.agent_space_id for space in self.security_agent.list_agent_spaces()]

    def _configured_space_id(self) -> str:
        """Space da fonte de configuração, com o override tendo precedência."""
        return self.agent_space_override or self.config_source.get_agent_space_id()

    def _single_space_id(self, operacao: str) -> str:
        """
        Agent Space único para operações que escrevem. Diferente das consultas,
        criar um pentest ou uma regra exige saber exatamente onde.
        """
        espacos = self._scope_space_ids()

        if len(espacos) == 1:
            return espacos[0]

        if not espacos:
            raise SecurityAgentConnectionError(
                f"{operacao}: nenhum Agent Space configurado nem encontrado na conta. "
                "Declare 'agent_space_id' no jobs_config.yaml ou crie um Agent Space."
            )

        raise SecurityAgentConnectionError(
            f"{operacao}: a conta tem {len(espacos)} Agent Spaces e nenhum foi escolhido. "
            "Declare 'agent_space_id' no jobs_config.yaml para definir o alvo."
        )

    # =========================================================================
    # PAINEL NATIVO & CONSULTAS GERAIS
    # =========================================================================
    def list_agent_spaces(self) -> List[AgentSpace]:
        """Lista os Agent Spaces existentes na conta."""
        return self.security_agent.list_agent_spaces()

    def create_agent_space(self, name: str, description: Optional[str] = None, role_arn: Optional[str] = None) -> str:
        """Cria um Agent Space na conta e devolve o novo id."""
        print(f"    [Agent Space] Criando Agent Space '{name}'...")
        space_id = self.security_agent.create_agent_space(name, description, role_arn)
        print(f"    [Agent Space] Agent Space criado. ID: {space_id}")
        return space_id

    def list_configured_jobs(self) -> List[JobSpecification]:
        return self.config_source.fetch_job_specifications()

    def list_remote_agent_jobs(self) -> List[Dict[str, Any]]:
        jobs: List[Dict[str, Any]] = []
        for space_id in self._scope_space_ids():
            jobs.extend(self.security_agent.list_all_remote_jobs(space_id))
        return jobs

    # =========================================================================
    # PILAR 1: EXECUÇÃO DE PEN-TESTING (DEMO 3 - RED TEAM)
    # =========================================================================
    def create_pentest_target(self, target_uri: str, title: str, service_role: Optional[str] = None) -> str:
        """Registra o alvo (CreatePentest) e devolve o Pentest ID, sem disparar o Job de scan."""
        space_id = self._single_space_id("Criação de pen-test")

        print(f"    [Sistemas Red Team] Registrando alvo '{target_uri}' (Space: {space_id})...")
        pentest_id = self.security_agent.register_target_pentest(space_id, title, target_uri, service_role)
        print(f"    [Sistemas Red Team] Pentest criado. ID: {pentest_id}")
        return pentest_id

    def execute_pentest_for_target(self, target_uri: str, title: str, service_role: Optional[str] = None) -> PentestExecutionResult:
        space_id = self._single_space_id("Registro de pen-test")

        print(f"    [Sistemas Red Team] Registrando alvo '{target_uri}' (Space: {space_id})...")
        pentest_id = self.security_agent.register_target_pentest(space_id, title, target_uri, service_role)

        print(f"    [Sistemas Red Team] Acionando motor ofensivo no pentest ID: {pentest_id}...")
        job_id = self.security_agent.trigger_pentest_job(space_id, pentest_id)

        print(f"    [Sistemas Red Team] Job {job_id} disparado. Mantendo polling inteligente...")
        current_status = JobStatus.IN_PROGRESS

        for attempt in range(1, self.max_retries + 1):
            try:
                current_status = self.security_agent.fetch_job_status(space_id, pentest_id, job_id)
                print(f"      -> [{attempt * self.poll_interval_sec}s] Estado Operacional: {current_status.value}")

                if current_status.is_terminal():
                    break

                time.sleep(self.poll_interval_sec)
            except SecurityAgentConnectionError as err:
                print(f"      [!] Aviso na comunicação AWS neste ciclo: {err}. Realizando retry...")
                time.sleep(self.poll_interval_sec)
        else:
            raise PentestExecutionTimeoutError(f"O Job '{job_id}' esgotou a tolerância máxima de polling ({self.max_retries * self.poll_interval_sec}s).")

        print(f"    [Sistemas Red Team] Consolidação finalizada. Coletando falhas e evidências confirmadas...")
        findings = self.security_agent.fetch_findings_for_job(space_id, job_id)

        return PentestExecutionResult(
            pentest_id=pentest_id,
            job_id=job_id,
            target_uri=target_uri,
            status=current_status,
            findings=findings
        )

    def execute_all_configured_jobs(self) -> List[PentestExecutionResult]:
        specs = self.list_configured_jobs()
        results = []
        for index, spec in enumerate(specs, start=1):
            print(f"\n[*] ENGATILHANDO PEN-TEST (#{index}/{len(specs)}): {spec.title} [{spec.target_uri}]")
            try:
                res = self.execute_pentest_for_target(spec.target_uri, spec.title)
                results.append(res)
            except Exception as err:
                print(f"[-] O processamento do Job '{spec.job_id}' resultou em falha operacional: {err}")
        return results

    def emergency_stop_job(self, job_id: str) -> bool:
        """[CIRCUIT BREAKER] Parada instantânea de segurança para testes excessivamente pesados no ambiente."""
        space_id = self._single_space_id("Parada de Job")
        print(f"\n[EMERGÊNCIA OPERACIONAL] Comandando parada forçada imediata (HALT) no Job '{job_id}'...")
        return self.security_agent.stop_pentest_job(space_id, job_id)

    # =========================================================================
    # PILAR 2: DESIGN REVIEWS & ARQUITETURAS (DEMO 1 - BLUE TEAM)
    # =========================================================================
    def run_architecture_design_review(self, design_files_dir: str = r"d:\aws\sample-security-agent-demo\design-review") -> DesignReviewResult:
        space_id = self._single_space_id("Design Review")
        print(f"\n[*] DISPARANDO DESIGN REVIEW (DEMO 1) CONTRA ARQUIVOS DE '{design_files_dir}'...")

        target_files = []
        if os.path.exists(design_files_dir):
            for fname in os.listdir(design_files_dir):
                full_p = os.path.join(design_files_dir, fname)
                if os.path.isfile(full_p) and fname.endswith((".docx", ".pdf", ".png", ".md")):
                    target_files.append(full_p)

        title = "AnyBank Digital Portal - Comprehensive Design & Architecture Review"
        result = self.security_agent.start_design_review(space_id, title, target_files)
        print(f"[+] Design Review processado com sucesso! ID: {result.review_id}")
        return result

    def list_past_design_reviews(self) -> List[DesignReviewResult]:
        reviews: List[DesignReviewResult] = []
        for space_id in self._scope_space_ids():
            reviews.extend(self.security_agent.list_design_reviews(space_id))
        return reviews

    # =========================================================================
    # PILAR 3: GOVERNANÇA & POLÍTICAS DE COMPLIANCE (SECURITY REQUIREMENTS)
    # =========================================================================
    def audit_security_requirements(self) -> List[SecurityRequirement]:
        # Requisitos pertencem a um Pack, não a um Agent Space: uma chamada só
        # já cobre a conta inteira, independente de quantos espaços existam.
        return self.security_agent.list_security_requirements(self._configured_space_id())

    def add_custom_compliance_rule(self, title: str, domain_category: str, rule_description: str) -> str:
        space_id = self._single_space_id("Cadastro de regra de compliance")
        return self.security_agent.create_custom_security_requirement(space_id, title, domain_category, rule_description)

    # =========================================================================
    # PILAR 4: VERIFICAÇÃO AUTOMÁTICA DE TITULARIDADE DE DOMÍNIO (IaC TERRAFORM)
    # =========================================================================
    def verify_terraform_target_domain(self) -> Optional[TargetDomainVerification]:
        space_id = self._configured_space_id()
        info = self.config_source.get_target_domain_details()
        if not info:
            print("[-] Não foi possível capturar metadados do domínio para verificação no Terraform/YAML.")
            return None

        domain_name = info.get("domain_name", "")
        token = info.get("token", "")
        if not domain_name:
            print("[-] A fonte de configuração não informou o nome do domínio a verificar.")
            return None

        print(f"\n[*] TRANSMITINDO CHALLENGE DE VERIFICAÇÃO DE PROPRIEDADE DE DOMÍNIO PARA '{domain_name}'...")
        print(f"    Token IaC associado: {token}")
        result = self.security_agent.verify_target_domain(space_id, domain_name, token)
        print(f"[+] Domínio '{result.domain_name}' conferido na nuvem AWS. Status: {result.status.value}")
        return result

    # =========================================================================
    # PILAR 5: CODE REVIEWS EM PULL REQUESTS NO GITHUB (DEMO 2 - GITOPS)
    # =========================================================================
    def get_pull_request_code_reviews(self) -> List[CodeReviewResult]:
        reviews: List[CodeReviewResult] = []
        for space_id in self._scope_space_ids():
            reviews.extend(self.security_agent.fetch_code_reviews(space_id))
        return reviews


# =============================================================================
# ADAPTADOR DE ENTRADA: APRESENTAÇÃO NO TERMINAL
# =============================================================================

class CommandLineAdapter:
    """
    ADAPTADOR DE ENTRADA (Inbound/Driving Adapter) - Interface Terminal com CLICK:
    Apresenta ao operador um console rico, formatado e colorido com a biblioteca Click,
    cobrindo todas as frentes da suíte DevSecOps (Red Team, Blue Team, GitOps e Compliance).
    """
    def __init__(self, use_case: PentestUseCasePort):
        self.use_case = use_case

    @staticmethod
    def _get_risk_style(level: RiskLevel) -> dict:
        mapping = {
            RiskLevel.CRITICAL: {"fg": "bright_red", "bold": True},
            RiskLevel.HIGH: {"fg": "red", "bold": True},
            RiskLevel.MEDIUM: {"fg": "yellow", "bold": False},
            RiskLevel.LOW: {"fg": "cyan", "bold": False},
            RiskLevel.INFORMATIONAL: {"fg": "blue", "bold": False},
        }
        return mapping.get(level, {"fg": "white"})

    def show_dashboard(self):
        click.echo("")
        click.secho("="*78, fg="bright_blue")
        click.secho("    AWS SECURITY AGENT SUITE - ARQUITETURA HEXAGONAL (DEVSECOPS CONSOLE)", fg="bright_cyan", bold=True)
        click.secho("="*78, fg="bright_blue")

        # 1. Alvos do Pen-test
        jobs_locais = self.use_case.list_configured_jobs()
        click.secho(f"\n[*] Escopo do Red Team (Pen-Test Jobs Mapeados: {len(jobs_locais)}):", fg="bright_white", bold=True)
        for j in jobs_locais:
            priority_styled = click.style(f"[{j.priority:^8}]", fg="magenta" if j.priority == "CRITICAL" else "yellow", bold=True)
            click.echo(f"    - {priority_styled} {j.title:36} -> " + click.style(j.target_uri, fg="bright_cyan"))

        # 2. Status no Agent Space
        click.secho("\n[*] Comunicando com Agent Space na AWS para checar execuções remanescentes...", fg="yellow")
        try:
            remote_jobs = self.use_case.list_remote_agent_jobs()
            click.secho(f"    [+] Total de tarefas ativas/concluídas no servidor AWS: {len(remote_jobs)}", fg="green")
        except Exception as err:
            click.secho(f"    [!] Aviso de roteamento ao consultar API remota/simulada: {err}", fg="bright_red")

        # 3. Auditoria de Compliance
        try:
            reqs = self.use_case.audit_security_requirements()
            ativos = sum(1 for r in reqs if r.enabled)
            click.secho(f"\n[*] Motor de Compliance da AWS (Security Requirements):", fg="bright_white", bold=True)
            click.secho(f"    [+] {ativos} de {len(reqs)} categorias de conformidade governamental ativas no espaço.", fg="green")
        except Exception:
            pass

        click.echo("")
        click.secho("="*78, fg="bright_blue")

    def run_automated_scans(self):
        click.echo("")
        click.secho("[*] INICIANDO PROTOCOLO RED TEAM: PEN-TEST EM LOTE CONTRA ALVOS", fg="bright_red", bold=True, reverse=True)
        click.secho("-" * 78, fg="red")
        results = self.use_case.execute_all_configured_jobs()
        self.render_execution_report(results)

    @staticmethod
    def render_execution_report(results: List[PentestExecutionResult]):
        click.echo("\n")
        click.secho("#"*78, fg="bright_red")
        click.secho("                 RELATÓRIO CONSOLIDADO DE EXECUÇÕES OFENSIVAS", fg="bright_white", bold=True)
        click.secho("#"*78, fg="bright_red")

        if not results:
            click.secho("[i] Nenhuma bateria foi processada nesta sessão.", fg="yellow")
            return

        for idx, res in enumerate(results, start=1):
            click.echo("")
            click.secho(f"> TESTE #{idx} | ALVO: ", nl=False, fg="bright_white", bold=True)
            click.secho(res.target_uri, fg="bright_cyan", bold=True, underline=True)
            click.echo(f"  ID do Pentest: " + click.style(res.pentest_id, fg="green"))
            click.echo(f"  ID do Job    : " + click.style(res.job_id, fg="green"))
            click.echo(f"  Status Final : " + click.style(res.status.value, fg="bright_green", bold=True))
            click.echo(f"  Descobertas  : " + click.style(str(res.total_findings), fg="bright_yellow", bold=True))
            click.secho("-" * 78, fg="bright_black")

            findings_sorted = res.get_sorted_findings()
            if not findings_sorted:
                click.secho("  (Nenhum vetor vulnerável foi provado no alvo especificamente)", fg="green")
                continue

            for f_idx, finding in enumerate(findings_sorted, start=1):
                style_kwargs = CommandLineAdapter._get_risk_style(finding.risk_level)
                tag_risco = click.style(f"[{finding.risk_level.value}]", **style_kwargs)
                click.echo(f"  [{f_idx}] {tag_risco} {click.style(finding.name, fg='bright_white', bold=True)} (Score: {finding.risk_score})")
                click.echo(f"      Tipo      : " + click.style(finding.risk_type, fg="yellow"))
                click.echo(f"      Confiança : " + click.style(finding.confidence, fg="cyan"))
                click.echo(f"      Descrição : {finding.description}")
                if finding.attack_script:
                    click.secho(f"      Exploit/Script de Comprovação:", fg="red", bold=True)
                    for line in finding.attack_script.splitlines():
                        click.secho(f"          > {line}", fg="bright_red")
                click.secho("  " + ". "*38, fg="bright_black")

    # =========================================================================
    # RELATÓRIOS DO BLUETEAM: DESIGN REVIEWS & COMPLIANCE
    # =========================================================================
    def run_design_review_report(self, design_dir: str = r"d:\aws\sample-security-agent-demo\design-review"):
        result = self.use_case.run_architecture_design_review(design_files_dir=design_dir)
        click.echo("")
        click.secho("="*78, fg="cyan")
        click.secho("              RELATÓRIO DE ANÁLISE DE DESIGN ARQUITETURAL (DEMO 1)", fg="bright_cyan", bold=True)
        click.secho("="*78, fg="cyan")
        click.echo(f"Review ID  : " + click.style(result.review_id, fg="green"))
        click.echo(f"Título     : " + click.style(result.title, fg="bright_white", bold=True))
        click.echo(f"Status     : " + click.style(result.status.value, fg="bright_green", bold=True))
        click.echo(f"Arquivos   : " + click.style(', '.join(result.attached_files) if result.attached_files else 'Nenhum', fg="yellow"))
        click.secho("-" * 78, fg="bright_black")

        for idx, f in enumerate(result.findings, start=1):
            style_kwargs = CommandLineAdapter._get_risk_style(f.risk_level)
            tag_risco = click.style(f"[{f.risk_level.value}]", **style_kwargs)
            click.echo(f"[{idx}] {tag_risco} {click.style(f.name, fg='bright_white', bold=True)} (Score: {f.risk_score})")
            click.echo(f"    Categoria  : " + click.style(f.risk_type, fg="yellow"))
            click.echo(f"    Diagnóstico: {f.description}")
            click.secho("    " + "- "*36, fg="bright_black")

    def print_compliance_requirements_table(self):
        reqs = self.use_case.audit_security_requirements()
        click.echo("")
        click.secho("="*78, fg="green")
        click.secho("          CATEGORIAS E DE MANDATOS DE CONFORMIDADE NO AGENT SPACE", fg="bright_green", bold=True)
        click.secho("="*78, fg="green")
        header = f" {'ID':<10} | {'STATUS':<8} | {'DOMÍNIO':<24} | {'TÍTULO DA DIRETRIZ'}"
        click.secho(header, fg="bright_white", bold=True)
        click.secho("-" * 78, fg="green")
        for r in reqs:
            st = click.style("ATIVO   ", fg="bright_green", bold=True) if r.enabled else click.style("INATIVO ", fg="red")
            dom_str = click.style(f"{r.domain:<24}", fg="cyan")
            click.echo(f" {r.requirement_id:<10} | {st} | {dom_str} | {r.title}")
        click.secho("="*78, fg="green")

    def print_github_pr_audits(self):
        reviews = self.use_case.get_pull_request_code_reviews()
        click.echo("")
        click.secho("="*78, fg="bright_magenta")
        click.secho("        AUDITORIAS DE PULL REQUEST EM REPOSITÓRIOS GITHUB (DEMO 2 - GITOPS)", fg="bright_white", bold=True)
        click.secho("="*78, fg="bright_magenta")
        if not reviews:
            click.secho("[i] Nenhuma vulnerabilidade pendente nos seus Pull Requests gerados no GitHub.", fg="green")
            return

        for rev in reviews:
            click.echo(f"URL do PR   : " + click.style(rev.pr_url, fg="bright_cyan", underline=True))
            click.echo(f"Commit SHA  : " + click.style(rev.commit_sha, fg="yellow"))
            click.echo(f"Ocorrencias : " + click.style(f"{rev.vulnerabilities_found} problemas sinalizados no Code Review", fg="bright_red", bold=True))
            click.secho("-" * 78, fg="bright_black")
            for idx, f in enumerate(rev.findings, start=1):
                style_kwargs = CommandLineAdapter._get_risk_style(f.risk_level)
                tag = click.style(f"[{f.risk_level.value}]", **style_kwargs)
                click.echo(f"[{idx}] {tag} {click.style(f.name, fg='bright_white', bold=True)}")
                click.echo(f"    Tipo      : " + click.style(f.risk_type, fg="yellow"))
                click.echo(f"    Comentário: {f.description}")
                click.secho("    " + ". "*36, fg="bright_black")

    def verify_domain_ownership(self):
        res = self.use_case.verify_terraform_target_domain()
        if res:
            click.echo("")
            click.secho(f"[SUCESSO] Titularidade verificada via {res.verification_method} com token '{res.verification_token}'.", fg="bright_green", bold=True)

    def emergency_halt(self, job_id: str):
        self.use_case.emergency_stop_job(job_id)
        click.secho(f"\n[CIRCUIT BREAKER] Parada engatilhada no cluster para {job_id}.", fg="bright_red", bold=True)

    # =========================================================================
    # AGENT SPACES, CATÁLOGOS E AÇÕES PONTUAIS
    # =========================================================================
    def print_agent_spaces_table(self):
        """Tabela com todos os Agent Spaces da conta."""
        spaces = self.use_case.list_agent_spaces()
        click.echo("")
        click.secho("=" * 78, fg="bright_blue")
        click.secho("                    AGENT SPACES DISPONÍVEIS NA CONTA AWS", fg="bright_cyan", bold=True)
        click.secho("=" * 78, fg="bright_blue")

        if not spaces:
            click.secho("[i] Nenhum Agent Space encontrado nesta conta/endpoint.", fg="yellow")
            return

        header = f" {'AGENT SPACE ID':<38} | {'CODE REVIEW':<11} | {'NOME'}"
        click.secho(header, fg="bright_white", bold=True)
        click.secho("-" * 78, fg="bright_blue")

        for space in spaces:
            cr = click.style("ATIVO      ", fg="bright_green", bold=True) if space.code_review_enabled \
                else click.style("INATIVO    ", fg="bright_black")
            click.echo(f" {click.style(space.agent_space_id, fg='green'):<38} | {cr} | "
                       + click.style(space.name, fg="bright_white", bold=True))

            if space.description:
                click.secho(f"   {space.description}", fg="bright_black")
            if space.target_domain_ids:
                click.echo("   Domínios: " + click.style(", ".join(space.target_domain_ids), fg="cyan"))
            if space.kms_key_id:
                click.echo("   KMS     : " + click.style(space.kms_key_id, fg="yellow"))
            if space.role_arn:
                click.echo("   Role ARN: " + click.style(space.role_arn, fg="magenta"))

        click.secho("=" * 78, fg="bright_blue")
        click.secho(f"Total: {len(spaces)} Agent Space(s).", fg="bright_white", bold=True)

    def print_configured_jobs(self):
        """Escopo de alvos declarado no Terraform/YAML."""
        jobs = self.use_case.list_configured_jobs()
        click.echo("")
        click.secho("=" * 78, fg="bright_yellow")
        click.secho("               ESCOPO DE ALVOS CONFIGURADOS (TERRAFORM / YAML)", fg="bright_yellow", bold=True)
        click.secho("=" * 78, fg="bright_yellow")

        if not jobs:
            click.secho("[i] Nenhum alvo configurado na fonte selecionada.", fg="yellow")
            return

        for job in jobs:
            prioridade = click.style(f"[{job.priority:^8}]", fg="magenta" if job.priority == "CRITICAL" else "yellow", bold=True)
            click.echo(f" {prioridade} {job.job_id:<16} {job.title:<34} -> " + click.style(job.target_uri, fg="bright_cyan"))

        click.secho("-" * 78, fg="bright_yellow")
        click.secho(f"Total: {len(jobs)} alvo(s) mapeado(s).", fg="bright_white", bold=True)

    def print_remote_jobs(self):
        """Histórico de Jobs já executados no Agent Space."""
        jobs = self.use_case.list_remote_agent_jobs()
        click.echo("")
        click.secho("=" * 78, fg="bright_magenta")
        click.secho("             HISTÓRICO DE JOBS EXECUTADOS NO AGENT SPACE (AWS)", fg="bright_white", bold=True)
        click.secho("=" * 78, fg="bright_magenta")

        if not jobs:
            click.secho("[i] Nenhum job registrado remotamente para este Agent Space.", fg="yellow")
            return

        header = f" {'JOB ID':<38} | {'STATUS':<12} | {'TÍTULO'}"
        click.secho(header, fg="bright_white", bold=True)
        click.secho("-" * 78, fg="bright_magenta")

        for job in jobs:
            status = str(job.get("status", "-"))
            cor = "bright_green" if status == "COMPLETED" else "yellow" if status == "IN_PROGRESS" else "red"
            click.echo(f" {job.get('pentestJobId', '-'):<38} | "
                       + click.style(f"{status:<12}", fg=cor, bold=True) + f" | {job.get('title', '')}")

        click.secho("-" * 78, fg="bright_magenta")
        click.secho(f"Total: {len(jobs)} job(s).", fg="bright_white", bold=True)

    def print_past_design_reviews(self):
        """Design Reviews (Threat Models) já registrados no Agent Space."""
        reviews = self.use_case.list_past_design_reviews()
        click.echo("")
        click.secho("=" * 78, fg="cyan")
        click.secho("             DESIGN REVIEWS REGISTRADOS NO AGENT SPACE (DEMO 1)", fg="bright_cyan", bold=True)
        click.secho("=" * 78, fg="cyan")

        if not reviews:
            click.secho("[i] Nenhum Design Review registrado neste Agent Space.", fg="yellow")
            return

        header = f" {'REVIEW ID':<38} | {'STATUS':<12} | {'TÍTULO'}"
        click.secho(header, fg="bright_white", bold=True)
        click.secho("-" * 78, fg="cyan")

        for rev in reviews:
            cor = "bright_green" if rev.status.is_terminal() else "yellow"
            click.echo(f" {click.style(rev.review_id, fg='green'):<38} | "
                       + click.style(f"{rev.status.value:<12}", fg=cor, bold=True) + f" | {rev.title}")

        click.secho("-" * 78, fg="cyan")
        click.secho(f"Total: {len(reviews)} revisão(ões).", fg="bright_white", bold=True)

    def add_compliance_rule(self, title: str, domain: str, description: str):
        """Cadastra uma regra de compliance própria da organização."""
        requirement_id = self.use_case.add_custom_compliance_rule(title, domain, description)
        click.echo("")
        click.secho(f"[SUCESSO] Regra corporativa registrada no motor de compliance da AWS.", fg="bright_green", bold=True)
        click.echo("  Identificador: " + click.style(requirement_id, fg="green", bold=True))
        click.echo("  Domínio      : " + click.style(domain, fg="cyan"))
        click.echo("  Descrição    : " + description)

    def create_agent_space(self, name: str, description: str = None, role_arn: str = None):
        """Cria um Agent Space na conta AWS e exibe o novo Agent Space ID."""
        click.echo("")
        click.secho(f"[*] CRIANDO AGENT SPACE '{name}'", fg="bright_blue", bold=True, reverse=True)
        click.secho("-" * 78, fg="blue")
        space_id = self.use_case.create_agent_space(name, description, role_arn)
        click.echo("")
        click.secho(f"[SUCESSO] Agent Space criado na conta AWS.", fg="bright_green", bold=True)
        click.echo("  Agent Space ID: " + click.style(space_id, fg="green", bold=True))
        click.echo("  Nome          : " + click.style(name, fg="bright_cyan"))
        if description:
            click.echo("  Descrição     : " + click.style(description, fg="yellow"))
        if role_arn:
            click.echo("  Role ARN      : " + click.style(role_arn, fg="magenta"))
        click.secho("  Use-o nas próximas ações com: ", nl=False, fg="bright_black")
        click.secho(f"--agent-space {space_id}", fg="bright_black", italic=True)

    def create_pentest(self, target_uri: str, title: str, service_role: str = None):
        """Cria (registra) um Pen-Test no Agent Space sem disparar o scan, exibindo o Pentest ID."""
        click.echo("")
        click.secho(f"[*] CRIANDO PEN-TEST PARA '{target_uri}' (SEM DISPARAR SCAN)", fg="bright_red", bold=True, reverse=True)
        click.secho("-" * 78, fg="red")
        pentest_id = self.use_case.create_pentest_target(target_uri, title, service_role)
        click.echo("")
        click.secho(f"[SUCESSO] Pen-Test registrado no Agent Space da AWS.", fg="bright_green", bold=True)
        click.echo("  Pentest ID: " + click.style(pentest_id, fg="green", bold=True))
        click.echo("  Alvo      : " + click.style(target_uri, fg="bright_cyan"))
        click.echo("  Título    : " + click.style(title, fg="yellow"))
        if service_role:
            click.echo("  ServiceRole: " + click.style(service_role, fg="magenta"))
        click.secho("  Dispare o scan depois com: ", nl=False, fg="bright_black")
        click.secho(f"scan --target {target_uri}", fg="bright_black", italic=True)

    def run_single_scan(self, target_uri: str, title: str, service_role: str = None):
        """Dispara um Pen-Test pontual contra um alvo informado na linha de comando."""
        click.echo("")
        click.secho(f"[*] PEN-TEST PONTUAL CONTRA '{target_uri}'", fg="bright_red", bold=True, reverse=True)
        click.secho("-" * 78, fg="red")
        resultado = self.use_case.execute_pentest_for_target(target_uri, title, service_role)
        self.render_execution_report([resultado])


# =============================================================================
# BOOTSTRAP / WIRING: CLI COM CLICK
# =============================================================================

class SuiteGroup(click.Group):
    """
    Grupo que traduz falhas do domínio em erro de CLI.

    Sem isso, uma máquina sem credenciais AWS (ou com o kumo fora do ar) despeja
    um traceback do botocore no terminal em vez de dizer o que aconteceu.
    """
    def invoke(self, ctx):
        try:
            return super().invoke(ctx)
        except DomainException as exc:
            raise click.ClickException(str(exc)) from exc


@click.group(cls=SuiteGroup, context_settings=dict(help_option_names=['-h', '--help']))
@click.option(
    "--source", "-s",
    type=click.Choice(["yaml", "terraform", "hybrid"], case_sensitive=False),
    default="hybrid",
    show_default=True,
    help="Provedor para extração de Agent Space ID e especificações de Alvos"
)
@click.option(
    "--tf-dir",
    default=r"d:\aws\sample-security-agent-demo\terraform-aws-security-agent",
    show_default=True,
    help="Caminho do módulo Terraform de infraestrutura (IaC)"
)
@click.option(
    "--agent-space", "-a", "agent_space_id",
    default=None,
    envvar="AGENT_SPACE_ID",
    help="Sobrescreve o Agent Space da config"
)
@click.option(
    "--region", "-r",
    default=lambda: os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1",
    show_default="AWS_REGION, senão us-east-1",
    help="Região AWS usada nas chamadas"
)
@click.option(
    "--profile", "-p", "profile_name",
    default=None,
    envvar="AWS_PROFILE",
    help="Perfil do ~/.aws/credentials a usar"
)
@click.option(
    "--timeout",
    type=int,
    default=3600,
    show_default=True,
    help="Tolerância total de espera por um Job de pen-test, em segundos"
)
@click.option(
    "--poll-interval",
    type=int,
    default=30,
    show_default=True,
    help="Intervalo entre consultas de status do Job, em segundos"
)
@click.pass_context
def cli(ctx, source, tf_dir, agent_space_id, region, profile_name, timeout, poll_interval):
    """
    AWS SECURITY AGENT DEVSECOPS SUITE (Arquitetura Hexagonal + Click CLI)

    Orquestrador unificado cobrendo Red Team (Pen-Test), Blue Team (Design Review),
    GitOps (Code Review de IaC no GitHub) e Governança Organizacional.
    """
    click.secho("[INIT] Inicializando Controlador Hexagonal via Click...", fg="cyan", bold=True)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    yaml_config = os.path.join(base_dir, "jobs_config.yaml")

    if source.lower() == "terraform":
        config_adapter = TerraformJobConfigSourceAdapter(terraform_dir=tf_dir)
    elif source.lower() == "yaml":
        config_adapter = YamlJobConfigSourceAdapter(filepath=yaml_config)
    else:  # hybrid
        config_adapter = HybridTerraformYamlAdapter(yaml_filepath=yaml_config, terraform_dir=tf_dir)

    espera = timeout
    intervalo = poll_interval

    alvo = f"AWS ({region})"
    click.secho(f"[INIT] Alvo: {alvo} | espera máxima por job: {espera}s", fg="cyan")

    # CreateThreatModel (Design Review) exige serviceRole; o Terraform já expõe o ARN.
    get_role = getattr(config_adapter, "get_service_role_arn", None)
    boto3_adapter = Boto3SecurityAgentAdapter(
        region_name=region,
        service_role=get_role() if callable(get_role) else None,
        profile_name=profile_name
    )

    pentest_service = PentestService(
        config_source=config_adapter,
        security_agent=boto3_adapter,
        max_wait_seconds=espera,
        poll_interval_sec=intervalo,
        agent_space_override=agent_space_id
    )

    # Armazena a instância do Adaptador de Entrada (CLI) no contexto do Click
    ctx.ensure_object(dict)
    ctx.obj["adapter"] = CommandLineAdapter(use_case=pentest_service)
    ctx.obj["source"] = source


@cli.command("dashboard", short_help="Exibe o painel consolidado com status do Agent Space e alvos")
@click.pass_context
def cmd_dashboard(ctx):
    """Exibe o painel de controle executivo no terminal."""
    adapter = ctx.obj["adapter"]
    adapter.show_dashboard()


@cli.command("agent-spaces", short_help="[ESPAÇOS] Lista todos os Agent Spaces existentes na conta AWS")
@click.pass_context
def cmd_agent_spaces(ctx):
    """Lista os Agent Spaces da conta, com Code Review, domínios associados e chave KMS."""
    adapter = ctx.obj["adapter"]
    adapter.print_agent_spaces_table()


@cli.command("create-agent-space", short_help="[ESPAÇOS] Cria um novo Agent Space na conta AWS")
@click.option("--name", "-n", required=True, help="Nome do Agent Space a criar")
@click.option("--description", "-D", default=None, help="Descrição opcional do Agent Space")
@click.option("--role-arn", "-R", default=None, help="Role ARN a ser associada ao Agent Space")
@click.pass_context
def cmd_create_agent_space(ctx, name, description, role_arn):
    """Cria um Agent Space via CreateAgentSpace e devolve o Agent Space ID para usar com --agent-space."""
    adapter = ctx.obj["adapter"]
    adapter.create_agent_space(name=name, description=description, role_arn=role_arn)


@cli.command("jobs", short_help="[CATÁLOGO] Lista os alvos configurados no Terraform/YAML")
@click.pass_context
def cmd_jobs(ctx):
    """Exibe o escopo de alvos declarado na fonte de configuração selecionada."""
    adapter = ctx.obj["adapter"]
    adapter.print_configured_jobs()


@cli.command("remote-jobs", short_help="[CATÁLOGO] Lista os Jobs já executados no Agent Space")
@click.pass_context
def cmd_remote_jobs(ctx):
    """Consulta no cluster AWS o histórico de execuções do Agent Space."""
    adapter = ctx.obj["adapter"]
    adapter.print_remote_jobs()


@cli.command("run", short_help="[DEMO 3] Dispara bateria de escaneamento ofensivo (Pen-Test / Red Team)")
@click.pass_context
def cmd_run(ctx):
    """Executa na ordem e acompanha simultaneamente todos os Pen-Tests na nuvem AWS."""
    adapter = ctx.obj["adapter"]
    adapter.run_automated_scans()


@cli.command("scan", short_help="[DEMO 3] Dispara um Pen-Test pontual contra um alvo informado")
@click.option("--target", "-t", "target_uri", required=True, help="URI do alvo (ex: http://vulnerable-app.pentest.svc)")
@click.option("--title", default="Pen-Test-sob-demanda", show_default=True, help="Título do teste (só letras, números, hífen e underscore; máx. 100)")
@click.option("--service-role", "-S", default=None, help="Service Role ARN para o pentest")
@click.pass_context
def cmd_scan(ctx, target_uri, title, service_role):
    """Registra, dispara e acompanha um único alvo, sem depender do catálogo configurado."""
    adapter = ctx.obj["adapter"]
    adapter.run_single_scan(target_uri=target_uri, title=title, service_role=service_role)


@cli.command("create-pentest", short_help="[DEMO 3] Cria (registra) um Pen-Test contra um alvo, sem disparar o scan")
@click.option("--target", "-t", "target_uri", required=True, help="URI do alvo (ex: http://vulnerable-app.pentest.svc)")
@click.option("--title", default="Pen-Test-sob-demanda", show_default=True, help="Título do teste (só letras, números, hífen e underscore; máx. 100)")
@click.option("--service-role", "-S", default=None, help="Service Role ARN para o pentest")
@click.pass_context
def cmd_create_pentest(ctx, target_uri, title, service_role):
    """Registra o alvo no Agent Space via CreatePentest e devolve o Pentest ID, sem acionar o motor ofensivo."""
    adapter = ctx.obj["adapter"]
    adapter.create_pentest(target_uri=target_uri, title=title, service_role=service_role)


@cli.command("design-review", short_help="[DEMO 1] Audita diagramas e documentos de arquitetura (Blue Team)")
@click.option(
    "--dir", "-d", "design_dir",
    default=r"d:\aws\sample-security-agent-demo\design-review",
    show_default=True,
    help="Caminho para a pasta contendo as arquiteturas em DOCX, PDF, PNG ou MD"
)
@click.pass_context
def cmd_design_review(ctx, design_dir):
    """Submete diagramas arquiteturais à IA do AWS Security Agent em busca de falhas estruturais."""
    adapter = ctx.obj["adapter"]
    adapter.run_design_review_report(design_dir=design_dir)


@cli.command("design-reviews", short_help="[DEMO 1] Lista os Design Reviews já registrados no Agent Space")
@click.pass_context
def cmd_design_reviews(ctx):
    """Consulta as análises arquiteturais (Threat Models) existentes no espaço de trabalho."""
    adapter = ctx.obj["adapter"]
    adapter.print_past_design_reviews()


@cli.command("github-pr", short_help="[DEMO 2] Fiscaliza Pull Requests abertos com código IaC no GitHub")
@click.pass_context
def cmd_github_pr(ctx):
    """Apresenta o Code Review automatizado de segurança emitido sobre seus Pull Requests Terraform no GitHub."""
    adapter = ctx.obj["adapter"]
    adapter.print_github_pr_audits()


@cli.command("compliance", short_help="[GOVERNANÇA] Lista a tabela oficial de Mandatos e Regras no cluster")
@click.pass_context
def cmd_compliance(ctx):
    """Inspeciona as 10 categorias oficiais de governança, auditoria de IAM e proteção de dados."""
    adapter = ctx.obj["adapter"]
    adapter.print_compliance_requirements_table()


@cli.command("add-rule", short_help="[GOVERNANÇA] Cadastra uma regra de compliance própria da organização")
@click.option("--title", "-t", required=True, help="Nome da regra (identificador do requisito na AWS)")
@click.option("--domain", "-d", required=True, help="Domínio de compliance (ex: Secret Protection)")
@click.option("--description", "-D", required=True, help="Descrição do que a regra exige")
@click.pass_context
def cmd_add_rule(ctx, title, domain, description):
    """Injeta uma política customizada no motor de compliance do AWS Security Agent."""
    adapter = ctx.obj["adapter"]
    adapter.add_compliance_rule(title=title, domain=domain, description=description)


@cli.command("verify-domain", short_help="[ASSETS] Aciona a verificação programática de titularidade de domínio")
@click.pass_context
def cmd_verify_domain(ctx):
    """Lê os outputs do seu módulo Terraform e emite o challenge provando titularidade sobre o domínio de teste."""
    adapter = ctx.obj["adapter"]
    adapter.verify_domain_ownership()


@cli.command("stop", short_help="[EMERGÊNCIA] Aborta imediatamente uma execução ofensiva no meio do processo")
@click.option("--job-id", "-j", required=True, help="ID do pentest ou job em execução a ser interceptado")
@click.pass_context
def cmd_stop(ctx, job_id):
    """Aciona o Circuit Breaker no cluster AWS/LocalStack parando testes excessivamente pesados."""
    adapter = ctx.obj["adapter"]
    adapter.emergency_halt(job_id=job_id)


if __name__ == "__main__":
    cli(obj={})
