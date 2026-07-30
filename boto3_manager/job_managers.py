#!/usr/bin/env python3
"""
Gerenciamento de Jobs de Pen-Test no AWS Security Agent.

Este módulo não fala com a AWS nem lê YAML por conta própria: ele compõe os
adaptadores hexagonais do projeto. Quem conhece PyYAML é o
YamlJobConfigSourceAdapter; quem conhece boto3 é o Boto3SecurityAgentAdapter.
Aqui ficam apenas as regras de composição e comparação entre os dois.
"""

import os
from typing import List, Dict, Any, Optional

from adapters.outbound.yaml_adapter import YamlJobConfigSourceAdapter
from adapters.outbound.boto3_adapter import Boto3SecurityAgentAdapter
from domain.entities import JobSpecification
from domain.exceptions import DomainException
from ports.outbound import SecurityAgentPort


# =====================================================================
# CLASSE 1: LEITOR DE JOBS VIA YAML (delega ao adaptador de configuração)
# =====================================================================

class YamlJobLoader:
    """
    Carrega e consulta definições de jobs declaradas em YAML.

    A leitura em si é do YamlJobConfigSourceAdapter, que já devolve as
    especificações no modelo do domínio (JobSpecification).
    """
    def __init__(self, yaml_filepath: str, config_source: Optional[YamlJobConfigSourceAdapter] = None):
        """
        :param yaml_filepath: Caminho do arquivo de definições de jobs.
        :param config_source: Adaptador já construído (útil em testes).
        """
        self.yaml_filepath = yaml_filepath
        self._config_source = config_source or YamlJobConfigSourceAdapter(filepath=yaml_filepath)

    @property
    def agent_space_id(self) -> str:
        """Agent Space ID declarado no cabeçalho do YAML."""
        return self._config_source.get_agent_space_id()

    def get_all_jobs(self) -> List[JobSpecification]:
        """Especificações de todos os jobs configurados no arquivo."""
        return self._config_source.fetch_job_specifications()

    def get_job_by_id(self, job_id: str) -> Optional[JobSpecification]:
        """Busca a especificação de um job pelo seu ID único."""
        for job in self.get_all_jobs():
            if job.job_id == job_id:
                return job
        return None

    def filter_by_priority(self, priority: str) -> List[JobSpecification]:
        """Filtra jobs pela prioridade atribuída (ex: HIGH, CRITICAL)."""
        alvo = priority.upper()
        return [job for job in self.get_all_jobs() if job.priority.upper() == alvo]


# =====================================================================
# CLASSE 2: BUSCADOR DE JOBS NO AGENT SPACE (delega ao adaptador boto3)
# =====================================================================

class AgentSpaceJobManager:
    """
    Consulta os jobs que rodaram ou estão rodando dentro de um Agent Space.

    Depende da porta SecurityAgentPort, não de boto3: a chamada à AWS e a
    paginação ficam no Boto3SecurityAgentAdapter.
    """
    def __init__(
        self,
        region_name: str = "us-east-1",
        endpoint_url: Optional[str] = None,
        security_agent: Optional[SecurityAgentPort] = None,
    ):
        """
        :param region_name: Região AWS (ex: 'us-east-1').
        :param endpoint_url: Uso em emuladores como Kumo (ex: 'http://localhost:4566').
        :param security_agent: Adaptador já construído (útil em testes ou para
            reaproveitar a instância usada pelo resto da aplicação).
        """
        self._security_agent = security_agent or Boto3SecurityAgentAdapter(
            region_name=region_name,
            endpoint_url=endpoint_url
        )

    def fetch_all_jobs(self, agent_space_id: str) -> List[Dict[str, Any]]:
        """Todos os jobs do Agent Space, já paginados pelo adaptador."""
        try:
            return self._security_agent.list_all_remote_jobs(agent_space_id)
        except DomainException as exc:
            print(f"[!] Erro ao listar jobs do Agent Space '{agent_space_id}': {exc}")
            return []

    def fetch_jobs_by_status(self, agent_space_id: str, status: str) -> List[Dict[str, Any]]:
        """
        Retorna todos os jobs cujos estados equivalem ao solicitado
        (Ex: 'COMPLETED', 'IN_PROGRESS', 'FAILED').
        """
        alvo = status.upper()
        return [
            job for job in self.fetch_all_jobs(agent_space_id)
            if str(job.get("status", "")).upper() == alvo
        ]

    def check_jobs_difference(
        self,
        yaml_jobs: List[JobSpecification],
        aws_jobs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Compara os alvos declarados no YAML com os alvos executados no Agent Space.

        Atenção: os resumos devolvidos por fetch_all_jobs (PentestJobSummary) não
        carregam endpoints — só id, título e status. Para a comparação valer,
        aws_jobs precisa vir de BatchGetPentestJobs, que devolve o job completo.
        """
        uris_yaml = {job.target_uri for job in yaml_jobs if job.target_uri}

        uris_aws = set()
        for job in aws_jobs:
            endpoints = job.get("endpoints") or job.get("assets", {}).get("endpoints", [])
            for endpoint in endpoints:
                if endpoint.get("uri"):
                    uris_aws.add(endpoint["uri"])

        return {
            "apenas_no_yaml": list(uris_yaml - uris_aws),
            "ja_executados": list(uris_yaml.intersection(uris_aws)),
            "apenas_na_aws": list(uris_aws - uris_yaml)
        }


if __name__ == "__main__":
    import sys

    config_path = os.path.join(os.path.dirname(__file__), "jobs_config.yaml")
    if not os.path.exists(config_path):
        print("[!] jobs_config.yaml não encontrado no diretório atual.")
        sys.exit(0)

    loader = YamlJobLoader(config_path)
    print(f"[*] Lendo configuração do arquivo: {config_path}")
    print(f"    -> Agent Space ID: {loader.agent_space_id}")
    print(f"    -> Total de Jobs configurados no YAML: {len(loader.get_all_jobs())}")
    for spec in loader.get_all_jobs():
        print(f"       - [{spec.priority}] {spec.title} -> {spec.target_uri}")

    print("\n[*] Conectando ao AWS Security Agent...")
    manager = AgentSpaceJobManager(region_name="us-east-1", endpoint_url="http://kumo.127.0.0.1.nip.io")
    try:
        jobs = manager.fetch_all_jobs(loader.agent_space_id)
        print(f"[+] Total de jobs encontrados na AWS para o espaço '{loader.agent_space_id}': {len(jobs)}")
    except Exception as exc:
        print(f"[!] Aviso ao contatar o Security Agent: {exc}")
