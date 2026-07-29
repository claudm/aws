#!/usr/bin/env python3
"""
Classes de gerenciamento de Jobs de Pen-Test no AWS Security Agent via YAML e Boto3.
Requer: pip install boto3 pyyaml
"""

import os
import yaml
import boto3
from typing import List, Dict, Any, Optional
from botocore.exceptions import ClientError


# =====================================================================
# CLASSE 1: LEITOR DE JOBS VIA YAML
# =====================================================================

class YamlJobLoader:
    """
    Classe responsável por carregar e gerenciar definições de jobs a partir de arquivos YAML.
    """
    def __init__(self, yaml_filepath: str):
        if not os.path.exists(yaml_filepath):
            raise FileNotFoundError(f"Arquivo YAML não encontrado: {yaml_filepath}")
        self.yaml_filepath = yaml_filepath
        self.config: Dict[str, Any] = self._load_yaml()

    def _load_yaml(self) -> Dict[str, Any]:
        """Lê o arquivo YAML de forma segura usando SafeLoader."""
        with open(self.yaml_filepath, "r", encoding="utf-8") as file:
            try:
                data = yaml.safe_load(file)
                return data or {}
            except yaml.YAMLError as exc:
                raise ValueError(f"Erro ao converter formato YAML no arquivo {self.yaml_filepath}: {exc}")

    @property
    def agent_space_id(self) -> Optional[str]:
        """Retorna o Agent Space ID declarado no cabeçalho do YAML (se existente)."""
        return self.config.get("agent_space_id")

    def get_all_jobs(self) -> List[Dict[str, Any]]:
        """Retorna a lista completa de jobs configurados no arquivo YAML."""
        jobs = self.config.get("jobs", [])
        if not isinstance(jobs, list):
            return []
        return jobs

    def get_job_by_id(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Busca as especificações de um job no YAML a partir do seu ID único."""
        for job in self.get_all_jobs():
            if job.get("job_id") == job_id:
                return job
        return None

    def filter_by_priority(self, priority: str) -> List[Dict[str, Any]]:
        """Filtra jobs no YAML pela prioridade atribuída (ex: HIGH, CRITICAL)."""
        priority = priority.upper()
        return [
            j for j in self.get_all_jobs()
            if str(j.get("priority", "")).upper() == priority
        ]


# =====================================================================
# CLASSE 2: BUSCADOR DE JOBS NO AGENT SPACE (VIA BOTO3)
# =====================================================================

class AgentSpaceJobManager:
    """
    Classe responsável por buscar e gerenciar todos os jobs remotos que rodaram 
    ou estão rodando dentro de um Agent Space no AWS Security Agent via boto3.
    """
    def __init__(self, region_name: str = "us-east-1", endpoint_url: Optional[str] = None):
        """
        :param region_name: Região AWS (ex: 'us-east-1').
        :param endpoint_url: Uso em emuladores como LocalStack / Kumo (ex: 'http://localhost:4566').
        """
        self.client = boto3.client(
            "security-agent",
            region_name=region_name,
            endpoint_url=endpoint_url
        )

    def fetch_all_jobs(self, agent_space_id: str) -> List[Dict[str, Any]]:
        """
        Busca TODOS os jobs/pentests vinculados ao Agent Space especificado,
        realizando paginação automática através de nextToken caso haja muitos cadastros.
        """
        todos_jobs: List[Dict[str, Any]] = []
        next_token = None

        try:
            while True:
                kwargs = {"agentSpaceId": agent_space_id}
                if next_token:
                    kwargs["nextToken"] = next_token

                if hasattr(self.client, "list_pentest_jobs"):
                    response = self.client.list_pentest_jobs(**kwargs)
                    itens = response.get("pentestJobSummaries", response.get("jobs", []))
                else:
                    response = self.client.list_pentests(**kwargs)
                    itens = response.get("pentestSummaries", response.get("pentests", []))

                todos_jobs.extend(itens)

                next_token = response.get("nextToken")
                if not next_token:
                    break

        except ClientError as exc:
            print(f"[!] Erro ao listar jobs do Agent Space '{agent_space_id}': {exc}")

        return todos_jobs

    def fetch_jobs_by_status(self, agent_space_id: str, status: str) -> List[Dict[str, Any]]:
        """
        Retorna todos os jobs cujos estados equivalem ao solicitado
        (Ex: 'COMPLETED', 'IN_PROGRESS', 'FAILED').
        """
        jobs = self.fetch_all_jobs(agent_space_id)
        status_target = status.upper()
        return [
            j for j in jobs
            if str(j.get("status", "")).upper() == status_target
        ]

    def check_jobs_difference(self, yaml_jobs: List[Dict[str, Any]], aws_jobs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Compara os alvos que existem no arquivo YAML com os alvos que foram executados no Agent Space.
        """
        uris_yaml = {j.get("target_uri") for j in yaml_jobs if j.get("target_uri")}

        uris_aws = set()
        for j in aws_jobs:
            assets = j.get("assets", {}).get("endpoints", [])
            for a in assets:
                if a.get("uri"):
                    uris_aws.add(a["uri"])

        return {
            "apenas_no_yaml": list(uris_yaml - uris_aws),
            "ja_executados": list(uris_yaml.intersection(uris_aws)),
            "apenas_na_aws": list(uris_aws - uris_yaml)
        }


if __name__ == "__main__":
    import sys
    config_path = os.path.join(os.path.dirname(__file__), "jobs_config.yaml")
    if os.path.exists(config_path):
        loader = YamlJobLoader(config_path)
        print(f"[*] Lendo configuração do arquivo: {config_path}")
        print(f"    -> Agent Space ID: {loader.agent_space_id}")
        print(f"    -> Total de Jobs configurados no YAML: {len(loader.get_all_jobs())}")
        for j in loader.get_all_jobs():
            print(f"       - [{j.get('priority')}] {j.get('title')} -> {j.get('target_uri')}")
    else:
        print("[!] jobs_config.yaml não encontrado no diretório atual.")
        sys.exit(0)

    print("\n[*] Conectando ao AWS Security Agent...")
    manager = AgentSpaceJobManager(region_name="us-east-1", endpoint_url="http://localhost:4566")
    space_id = loader.agent_space_id if os.path.exists(config_path) else "pentest-demo-space"
    try:
        jobs = manager.fetch_all_jobs(space_id)
        print(f"[+] Total de jobs encontrados na AWS para o espaço '{space_id}': {len(jobs)}")
    except Exception as e:
        print(f"[!] Aviso ao contatar serviço na porta 4566: {e}")

