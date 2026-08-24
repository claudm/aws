from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    store_backend: Literal["memory", "dynamodb"] = "memory"
    # Fonte de Spaces/Pentests/Endpoints:
    #   securityagent -> API real AWS Security Agent (boto3)
    #   memory        -> dados de exemplo (dev/local, sem AWS)
    sa_backend: Literal["securityagent", "memory"] = "memory"

    aws_region: str = "sa-east-1"
    expected_account_id: str | None = None
    assume_role_arn: str | None = None
    # Nome da role assumida em contas diferentes de expected_account_id
    # (arn:aws:iam::<conta informada>:role/<este nome>). Precisa existir e
    # confiar neste backend em cada conta que o usuário queira acessar.
    cross_account_role_name: str = "role-security-agent-pentest"

    ddb_spaces_table: str = "security-agent-spaces"
    ddb_pentests_table: str = "security-agent-pentests"

    s3_artifacts_bucket: str = "uploads-uva-dev"
    s3_artifacts_prefix: str = "security-agent-artifacts"

    # As operacoes de tag (TagResource/ListTagsForResource) exigem o ARN do
    # agent space, que NENHUMA operacao do servico devolve e que o modelo do
    # botocore nao documenta. O formato abaixo segue a convencao da AWS; se a
    # sua conta usar outro, ajuste por AGENT_SPACE_ARN_TEMPLATE em vez de mexer
    # no codigo. Placeholders: {region}, {account_id}, {space_id}.
    agent_space_arn_template: str = (
        "arn:aws:securityagent:{region}:{account_id}:agent-space/{space_id}"
    )

    secrets_prefix: str = "security-agent/pentests"
    role_name_filter: str = "security-agent"

    cors_origins: str = ""
    flask_secret_key: str = "change-me"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
