import os
import yaml
from typing import List, Dict, Any
from domain.entities import JobSpecification
from domain.exceptions import JobConfigurationError
from ports.outbound import JobConfigSourcePort


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
