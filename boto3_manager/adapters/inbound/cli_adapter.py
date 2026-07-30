import click
from typing import List
from domain.entities import (
    PentestExecutionResult, SecurityRequirement, DesignReviewResult,
    CodeReviewResult, TargetDomainVerification, RiskLevel
)
from ports.inbound import PentestUseCasePort


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

    def run_single_scan(self, target_uri: str, title: str):
        """Dispara um Pen-Test pontual contra um alvo informado na linha de comando."""
        click.echo("")
        click.secho(f"[*] PEN-TEST PONTUAL CONTRA '{target_uri}'", fg="bright_red", bold=True, reverse=True)
        click.secho("-" * 78, fg="red")
        resultado = self.use_case.execute_pentest_for_target(target_uri, title)
        self.render_execution_report([resultado])
