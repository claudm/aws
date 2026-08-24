import os
import boto3
from typing import List, Dict, Any, Optional, Callable
from botocore.config import Config as BotocoreConfig
from botocore.exceptions import BotoCoreError, ClientError
from domain.entities import (
    JobStatus, RiskLevel, Finding, SecurityRequirement, AgentSpace,
    DesignReviewResult, CodeReviewResult, TargetDomainVerification
)
from domain.exceptions import SecurityAgentConnectionError
from ports.outbound import SecurityAgentPort


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
        endpoint_url: Optional[str] = None,
        service_role: Optional[str] = None,
        profile_name: Optional[str] = None,
    ):
        """
        :param region_name: Região AWS.
        :param endpoint_url: None para a AWS real; URL do emulador (kumo) caso
            contrário.
        :param service_role: ARN exigido por CreateThreatModel (Design Review).
        :param profile_name: Perfil do ~/.aws/credentials a usar na AWS real.
        """
        self.endpoint_url = endpoint_url
        # CreateThreatModel exige serviceRole. Vem do output do Terraform
        # (service_role_arn) ou da variável de ambiente.
        self.service_role = service_role or os.environ.get("SECURITY_AGENT_SERVICE_ROLE")

        session = boto3.Session(profile_name=profile_name) if profile_name else boto3.Session()
        client_kwargs: Dict[str, Any] = {"region_name": region_name, "endpoint_url": endpoint_url}

        if endpoint_url:
            # Contra um emulador não há credencial real para resolver, e o
            # botocore recusa assinar sem nenhuma (NoCredentialsError). Só nesse
            # caso entram credenciais de fachada.
            if session.get_credentials() is None:
                client_kwargs["aws_access_key_id"] = "kumo"
                client_kwargs["aws_secret_access_key"] = "kumo"
        else:
            # Sem endpoint explícito o destino é a AWS real — e aí um
            # AWS_ENDPOINT_URL no ambiente (comum em quem usa emulador) não pode
            # sequestrar a chamada. ignore_configured_endpoint_urls desliga esse
            # override vindo de variável de ambiente e do ~/.aws/config.
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
                    )
                ))

            return resultado
        except (ClientError, BotoCoreError) as exc:
            raise SecurityAgentConnectionError(f"Erro ao listar Agent Spaces: {exc}")

    def create_agent_space(self, name: str, description: Optional[str] = None) -> str:
        """Cria um Agent Space (só 'name' é obrigatório) e devolve o novo id."""
        try:
            params: Dict[str, Any] = {"name": name}
            if description:
                params["description"] = description
            response = self.client.create_agent_space(**params)
            return str(response["agentSpaceId"])
        except (ClientError, BotoCoreError) as exc:
            raise SecurityAgentConnectionError(f"Erro na API AWS CreateAgentSpace para '{name}': {exc}")

    # =========================================================================
    # 1. PEN-TESTING (DEMO 3 - RED TEAM)
    # =========================================================================
    def register_target_pentest(self, space_id: str, title: str, target_uri: str) -> str:
        try:
            response = self.client.create_pentest(
                agentSpaceId=space_id,
                title=title,
                assets={"endpoints": [{"uri": target_uri}]}
            )
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
