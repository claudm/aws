#!/usr/bin/env python3
"""
Ponto de entrada (Bootstrap / Wiring) do Controlador DEV-SEC-OPS com CLICK CLI.
Monta a Arquitetura Hexagonal com injeção de dependências nativa no contexto (ctx.obj).
"""

import os
import sys
import click

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from domain.exceptions import DomainException
from adapters.outbound.yaml_adapter import YamlJobConfigSourceAdapter
from adapters.outbound.terraform_adapter import TerraformJobConfigSourceAdapter, HybridTerraformYamlAdapter
from adapters.outbound.boto3_adapter import Boto3SecurityAgentAdapter
from service.pentest_service import PentestService
from adapters.inbound.cli_adapter import CommandLineAdapter


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
    "--cloud",
    is_flag=True,
    default=False,
    help="Conecta no serviço real da AWS (em vez do emulador kumo)"
)
@click.option(
    "--agent-space", "-a", "agent_space_id",
    default=None,
    envvar="AGENT_SPACE_ID",
    help="Sobrescreve o Agent Space da config (o 'pentest-demo-space' fixo não existe na conta real)"
)
@click.option(
    "--endpoint", "-e", "endpoint_url",
    default=None,
    envvar="KUMO_ENDPOINT",
    help="URL do emulador kumo. [padrão: http://kumo.127.0.0.1.nip.io; ignorado com --cloud]"
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
    help="Perfil do ~/.aws/credentials (somente com --cloud)"
)
@click.option(
    "--timeout",
    type=int,
    default=None,
    show_default="300s no kumo, 3600s com --cloud",
    help="Tolerância total de espera por um Job de pen-test, em segundos"
)
@click.option(
    "--poll-interval",
    type=int,
    default=None,
    show_default="5s no kumo, 30s com --cloud",
    help="Intervalo entre consultas de status do Job, em segundos"
)
@click.pass_context
def cli(ctx, source, tf_dir, cloud, agent_space_id, endpoint_url, region, profile_name, timeout, poll_interval):
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

    # Alvo das chamadas: AWS real com --cloud, senão o emulador kumo.
    endpoint = None if cloud else (endpoint_url or "http://kumo.127.0.0.1.nip.io")

    # Um pen-test na AWS leva bem mais que num emulador, onde o job conclui na
    # hora: por isso a espera padrão é maior no modo cloud.
    espera = timeout if timeout is not None else (3600 if cloud else 300)
    intervalo = poll_interval if poll_interval is not None else (30 if cloud else 5)

    alvo = f"AWS ({region})" if cloud else f"kumo em {endpoint}"
    click.secho(f"[INIT] Alvo: {alvo} | espera máxima por job: {espera}s", fg="cyan")

    # CreateThreatModel (Design Review) exige serviceRole; o Terraform já expõe o ARN.
    get_role = getattr(config_adapter, "get_service_role_arn", None)
    boto3_adapter = Boto3SecurityAgentAdapter(
        region_name=region,
        endpoint_url=endpoint,
        service_role=get_role() if callable(get_role) else None,
        profile_name=profile_name if cloud else None
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
    ctx.obj["cloud"] = cloud


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
@click.pass_context
def cmd_create_agent_space(ctx, name, description):
    """Cria um Agent Space via CreateAgentSpace e devolve o Agent Space ID para usar com --agent-space."""
    adapter = ctx.obj["adapter"]
    adapter.create_agent_space(name=name, description=description)


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
@click.pass_context
def cmd_scan(ctx, target_uri, title):
    """Registra, dispara e acompanha um único alvo, sem depender do catálogo configurado."""
    adapter = ctx.obj["adapter"]
    adapter.run_single_scan(target_uri=target_uri, title=title)


@cli.command("create-pentest", short_help="[DEMO 3] Cria (registra) um Pen-Test contra um alvo, sem disparar o scan")
@click.option("--target", "-t", "target_uri", required=True, help="URI do alvo (ex: http://vulnerable-app.pentest.svc)")
@click.option("--title", default="Pen-Test-sob-demanda", show_default=True, help="Título do teste (só letras, números, hífen e underscore; máx. 100)")
@click.pass_context
def cmd_create_pentest(ctx, target_uri, title):
    """Registra o alvo no Agent Space via CreatePentest e devolve o Pentest ID, sem acionar o motor ofensivo."""
    adapter = ctx.obj["adapter"]
    adapter.create_pentest(target_uri=target_uri, title=title)


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
