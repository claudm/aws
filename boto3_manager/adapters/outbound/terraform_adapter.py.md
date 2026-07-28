import os
import json
import subprocess
from typing import List, Dict, Any, Optional
from domain.entities import JobSpecification
from domain.exceptions import JobConfigurationError
from ports.outbound import JobConfigSourcePort


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

        return "pentest-demo-space-from-terraform"

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
        # Fallback ilustrativo caso o output não tenha domínio configurado
        return {
            "domain_id": "tf-dom-vulnerable-svc",
            "domain_name": "vulnerable-app.pentest.svc",
            "token": "aws-verification-token-from-terraform"
        }

    def fetch_job_specifications(self) -> List[JobSpecification]:
        space_id = self.get_agent_space_id()
        domain_info = self.get_target_domain_details()
        
        target_uri = f"http://{domain_info['domain_name']}" if domain_info else "http://vulnerable-app.pentest.svc"

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
        from adapters.outbound.yaml_adapter import YamlJobConfigSourceAdapter
        self.yaml_adapter = YamlJobConfigSourceAdapter(yaml_filepath)
        
        try:
            self.tf_adapter = TerraformJobConfigSourceAdapter(terraform_dir)
            self._tf_available = True
        except Exception as exc:
            print(f"[Aviso IaC] Não foi possível carregar saídas ao vivo do Terraform ({exc}). Usando fallback do YAML.")
            self._tf_available = False

    def get_agent_space_id(self) -> str:
        if self._tf_available:
            return self.tf_adapter.get_agent_space_id()
        return self.yaml_adapter.get_agent_space_id()

    def get_target_domain_details(self) -> Optional[Dict[str, Any]]:
        if self._tf_available:
            return self.tf_adapter.get_target_domain_details()
        return {
            "domain_id": "yaml-domain-01",
            "domain_name": "vulnerable-app.pentest.svc",
            "token": "verification-token-from-yaml-environment"
        }

    def fetch_job_specifications(self) -> List[JobSpecification]:
        yaml_specs = self.yaml_adapter.fetch_job_specifications()
        real_space_id = self.get_agent_space_id()
        for spec in yaml_specs:
            spec.agent_space_id = real_space_id
        return yaml_specs
