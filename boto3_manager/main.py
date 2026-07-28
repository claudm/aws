#!/usr/bin/env python3
"""
Ponto de entrada (Bootstrap / Wiring) do Controlador DEV-SEC-OPS com CLICK CLI.
Monta a Arquitetura Hexagonal com injeção de dependências nativa no contexto (ctx.obj).
"""

import os
import sys
import click

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from adapters.outbound.yaml_adapter import YamlJobConfigSourceAdapter
from adapters.outbound.terraform_adapter import TerraformJobConfigSourceAdapter, HybridTerraformYamlAdapter
from adapters.outbound.boto3_adapter import Boto3SecurityAgentAdapter
from service.pentest_service import PentestService
from adapters.inbound.cli_adapter import CommandLineAdapter


@click.group(context_settings=dict(help_option_names=['-h', '--help']))
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
    help="Conecta no serviço real da AWS (ignora emuladores locais da porta 4566)"
)
@click.pass_context
def cli(ctx, source, tf_dir, cloud):
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

    endpoint = None if cloud else "http://localhost:4566"
    boto3_adapter = Boto3SecurityAgentAdapter(region_name="us-east-1", endpoint_url=endpoint)
    
    pentest_service = PentestService(
        config_source=config_adapter,
        security_agent=boto3_adapter
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


@cli.command("run", short_help="[DEMO 3] Dispara bateria de escaneamento ofensivo (Pen-Test / Red Team)")
@click.pass_context
def cmd_run(ctx):
    """Executa na ordem e acompanha simultaneamente todos os Pen-Tests na nuvem AWS."""
    adapter = ctx.obj["adapter"]
    adapter.run_automated_scans()


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
