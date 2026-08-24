from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


# ---- Contexto / Spaces ----
class LoadContextRequest(BaseModel):
    account_id: str
    region: str


class VerifiedEndpoint(BaseModel):
    url: str
    # SEM STATUS | VERIFYING | VERIFIED | FAILED | PENDING | UNREACHABLE
    status: str = "SEM STATUS"
    verified_at: datetime | None = None
    detail: str | None = None
    id: str | None = None  # targetDomainId (modo securityagent)


class Space(BaseModel):
    space_id: str
    name: str
    description: str | None = None
    account_id: str
    region: str
    endpoints: list[VerifiedEndpoint] = Field(default_factory=list)
    target_domain_ids: list[str] = Field(default_factory=list)
    # awsResources do serviço (vpcs/iamRoles/...); usado para pré-preencher a edição
    aws_resources: dict | None = None


class CreateSpaceRequest(BaseModel):
    name: str = Field(..., min_length=1)
    description: str | None = None
    aws_resources: dict | None = None
    target_domain_ids: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)  # modo memory: URLs criadas antes do Space existir
    code_review_settings: dict | None = None
    kms_key_id: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)


class UpdateSpaceRequest(BaseModel):
    """Edição de Agent Space (PATCH): só os campos enviados são alterados.

    `kms_key_id` e `tags` ficam de fora porque UpdateAgentSpace não os aceita.
    """
    name: str | None = Field(None, min_length=1)
    description: str | None = None
    aws_resources: dict | None = None
    target_domain_ids: list[str] | None = None
    endpoints: list[str] | None = None  # modo mock: URLs do Space
    code_review_settings: dict | None = None


# ---- Rede (EC2) ----
class VpcOut(BaseModel):
    vpc_id: str
    name: str | None = None
    cidr_block: str | None = None
    is_default: bool = False


class SubnetOut(BaseModel):
    subnet_id: str
    name: str | None = None
    vpc_id: str
    cidr_block: str | None = None
    availability_zone: str | None = None


class SecurityGroupOut(BaseModel):
    group_id: str
    name: str | None = None
    vpc_id: str | None = None
    description: str | None = None


class RoleOut(BaseModel):
    role_name: str
    arn: str
    path: str | None = None


# ---- Endpoints ----
class VerifyEndpointRequest(BaseModel):
    space_id: str
    url: str
    target_domain_id: str | None = None


class CreateEndpointRequest(BaseModel):
    # space_id é opcional: um alvo pode ser criado antes de o Space existir
    # (ex.: no modal "Criar Agent Space"), bastando informar region.
    space_id: str | None = None
    region: str | None = None
    url: str = Field(..., min_length=1)
    verification_method: Literal["DNS_TXT", "HTTP_ROUTE", "PRIVATE_VPC"] = "DNS_TXT"


# ---- Pentest ----
class PentestStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    FAILED = "FAILED"
    COMPLETED = "COMPLETED"


class NetworkConfig(BaseModel):
    vpc_id: str | None = None
    subnet_id: str | None = None
    security_group_id: str | None = None


class TargetConfig(BaseModel):
    endpoints: list[str] = Field(default_factory=list)
    service_role_arn: str | None = None


class CredentialInput(BaseModel):
    actor_identifier: str
    mode: Literal["input", "advanced"] = "input"
    username: str | None = None
    password: str | None = None      # sensível
    totp_secret: str | None = None   # sensível
    access_url: str | None = None
    login_prompt: str | None = None
    secret_arn: str | None = None    # modo avançado: referencia secret já existente


class ConnectedResource(BaseModel):
    name: str
    type: str
    s3_uri: str


class PentestCreate(BaseModel):
    space_id: str
    title: str = Field(..., min_length=1)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    target: TargetConfig = Field(default_factory=TargetConfig)
    credentials: list[CredentialInput] = Field(default_factory=list)
    resources: list[ConnectedResource] = Field(default_factory=list)


class CredentialRef(BaseModel):
    actor_identifier: str
    secret_arn: str | None = None
    access_url: str | None = None
    has_2fa: bool = False


class Pentest(BaseModel):
    id: str
    space_id: str
    title: str
    status: PentestStatus = PentestStatus.PENDING
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    target: TargetConfig = Field(default_factory=TargetConfig)
    credentials: list[CredentialRef] = Field(default_factory=list)
    resources: list[ConnectedResource] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class PentestUpdate(BaseModel):
    # Necessário no modo securityagent: o pentest não fica no store local, então
    # precisamos do space (region/account) para chamar a API real.
    space_id: str | None = None
    title: str | None = None
    status: PentestStatus | None = None
    network: NetworkConfig | None = None
    target: TargetConfig | None = None
    resources: list[ConnectedResource] | None = None


# ---- Artefatos / S3 ----
class PresignUploadRequest(BaseModel):
    space_id: str
    filename: str
    content_type: str | None = None


class PresignUploadResponse(BaseModel):
    url: str
    content_type: str | None = None
    key: str
    s3_uri: str


class ResourceObject(BaseModel):
    name: str
    key: str
    s3_uri: str
    size: int
    last_modified: datetime | None = None
