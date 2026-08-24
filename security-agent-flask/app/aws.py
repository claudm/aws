"""Wrappers boto3. Traduz erros da AWS em ApiError (vira JSON no handler)."""
from __future__ import annotations

import json
import logging
import os
from datetime import date
from uuid import uuid4

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from .config import get_settings
from .errors import ApiError
from .mock_aws import get_mock_aws_client
from .schemas import (
    PresignUploadResponse,
    ResourceObject,
    RoleOut,
    SecurityGroupOut,
    SubnetOut,
    VpcOut,
)


def _mock() -> bool:
    return get_settings().sa_backend == "memory"

logger = logging.getLogger("security-agent.aws")


def _has_explicit_credentials() -> bool:
    # Credenciais estáticas via variável de ambiente (AWS_ACCESS_KEY_ID é a
    # que boto3 já lê nativamente): se presente, usa direto e ignora qualquer
    # assume-role (estático ou cross-account) — quem configurou uma access
    # key quer aquela identidade, não uma role assumida por cima dela.
    return bool(os.environ.get("AWS_ACCESS_KEY_ID"))


def _session(region: str | None = None, account_id: str | None = None) -> boto3.session.Session:
    settings = get_settings()
    region = region or settings.aws_region

    role_arn = None
    if _has_explicit_credentials():
        role_arn = None
    elif account_id and account_id != settings.expected_account_id:
        # Conta diferente da padrão: assume a role cross-account nela, em vez
        # de rejeitar. A role precisa existir e confiar neste backend na conta
        # informada — se a assume-role falhar, o erro real da AWS propaga.
        role_arn = f"arn:aws:iam::{account_id}:role/{settings.cross_account_role_name}"
    elif settings.assume_role_arn:
        role_arn = settings.assume_role_arn

    if role_arn:
        sts = boto3.client("sts", region_name=region)
        try:
            creds = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="security-agent-flask",
            )["Credentials"]
        except (ClientError, BotoCoreError) as exc:
            ctx = f"Falha ao assumir role na conta {account_id}" if account_id else "Falha ao assumir a role configurada"
            raise _aws_error(exc, ctx)
        return boto3.session.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=region,
        )
    return boto3.session.Session(region_name=region)


def _client(service: str, region: str | None = None, account_id: str | None = None):
    return _session(region, account_id).client(service)


def _aws_error(exc: Exception, ctx: str) -> ApiError:
    if isinstance(exc, NoCredentialsError):
        return ApiError(502, f"{ctx}: credenciais AWS não configuradas no backend.")
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        msg = exc.response.get("Error", {}).get("Message", str(exc))
        return ApiError(502, f"{ctx}: [{code}] {msg}")
    return ApiError(502, f"{ctx}: {exc}")


def _tag_name(tags: list[dict] | None) -> str | None:
    for t in tags or []:
        if t.get("Key") == "Name":
            return t.get("Value")
    return None


# ---- STS ----
def caller_account(region: str | None = None, account_id: str | None = None) -> str:
    try:
        return _client("sts", region, account_id).get_caller_identity()["Account"]
    except (ClientError, BotoCoreError) as exc:
        raise _aws_error(exc, "Falha ao consultar identidade AWS")


def assume_cross_account(account_id: str, region: str | None = None) -> None:
    """Garante acesso à conta informada: se for diferente da conta padrão,
    assume a role cross-account nela (ver _session) e confirma a identidade
    resultante. Não rejeita só por a conta diferir da esperada — só levanta
    ApiError se a própria assume-role falhar (role inexistente, trust policy
    não permite, etc.), com o erro real da AWS.
    """
    caller_account(region, account_id)


def validate_role_arn_account(account_id: str, role_arn: str | None) -> None:
    """Recusa uma role ARN de outra conta AWS (ex.: arn:...::123456789012:role/... != account_id)."""
    if not role_arn:
        return
    parts = role_arn.split(":")
    if len(parts) < 6 or parts[0] != "arn" or parts[2] != "iam":
        raise ApiError(400, f"ARN de role inválido: {role_arn}")
    arn_account = parts[4]
    if arn_account and arn_account != account_id:
        raise ApiError(
            400,
            f"A role '{role_arn}' pertence à conta {arn_account}, diferente da conta do Space ({account_id}).",
        )


# ---- EC2 ----
def list_vpcs(region: str, q: str | None = None) -> list[VpcOut]:
    if _mock():
        return get_mock_aws_client().list_vpcs(q)
    try:
        resp = _client("ec2", region).describe_vpcs()
    except (ClientError, BotoCoreError) as exc:
        raise _aws_error(exc, "Falha ao listar VPCs")
    out: list[VpcOut] = []
    for v in resp.get("Vpcs", []):
        name = _tag_name(v.get("Tags"))
        if q and q.lower() not in (name or "").lower() and q.lower() not in v["VpcId"].lower():
            continue
        out.append(
            VpcOut(
                vpc_id=v["VpcId"],
                name=name,
                cidr_block=v.get("CidrBlock"),
                is_default=v.get("IsDefault", False),
            )
        )
    return out


def list_subnets(region: str, vpc_id: str) -> list[SubnetOut]:
    if _mock():
        return get_mock_aws_client().list_subnets(vpc_id)
    try:
        resp = _client("ec2", region).describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )
    except (ClientError, BotoCoreError) as exc:
        raise _aws_error(exc, "Falha ao listar subnets")
    return [
        SubnetOut(
            subnet_id=s["SubnetId"],
            name=_tag_name(s.get("Tags")),
            vpc_id=s["VpcId"],
            cidr_block=s.get("CidrBlock"),
            availability_zone=s.get("AvailabilityZone"),
        )
        for s in resp.get("Subnets", [])
    ]


def list_security_groups(
    region: str, vpc_id: str | None = None, q: str | None = None
) -> list[SecurityGroupOut]:
    if _mock():
        return get_mock_aws_client().list_security_groups(vpc_id, q)
    filters = [{"Name": "vpc-id", "Values": [vpc_id]}] if vpc_id else []
    try:
        resp = _client("ec2", region).describe_security_groups(Filters=filters)
    except (ClientError, BotoCoreError) as exc:
        raise _aws_error(exc, "Falha ao listar Security Groups")
    out: list[SecurityGroupOut] = []
    for sg in resp.get("SecurityGroups", []):
        name = sg.get("GroupName")
        if q and q.lower() not in (name or "").lower() and q.lower() not in sg["GroupId"].lower():
            continue
        out.append(
            SecurityGroupOut(
                group_id=sg["GroupId"],
                name=name,
                vpc_id=sg.get("VpcId"),
                description=sg.get("Description"),
            )
        )
    return out


# ---- IAM ----
def list_roles(region: str, q: str | None = None) -> list[RoleOut]:
    if _mock():
        return get_mock_aws_client().list_roles(q)
    settings = get_settings()
    needle = (q or settings.role_name_filter or "").lower()
    out: list[RoleOut] = []
    try:
        paginator = _client("iam", region).get_paginator("list_roles")
        for page in paginator.paginate():
            for r in page.get("Roles", []):
                haystack = f"{r['RoleName']} {r.get('Path','')}".lower()
                if needle and needle not in haystack:
                    continue
                out.append(RoleOut(role_name=r["RoleName"], arn=r["Arn"], path=r.get("Path")))
    except (ClientError, BotoCoreError) as exc:
        raise _aws_error(exc, "Falha ao listar roles IAM")
    return out


# ---- Secrets Manager ----
def store_credential(
    region: str, space_id: str, pentest_id: str, actor_identifier: str, payload: dict
) -> str:
    settings = get_settings()
    if settings.store_backend != "dynamodb":
        # Modo mock: ARN fake, a credencial não sai do processo.
        return get_mock_aws_client().store_credential(region, space_id, pentest_id, actor_identifier)
    safe_actor = actor_identifier.replace("/", "_").replace(" ", "-")
    name = f"{settings.secrets_prefix}/{space_id}/{pentest_id}/{safe_actor}"
    client = _client("secretsmanager", region)
    secret_string = json.dumps(payload)
    try:
        resp = client.create_secret(
            Name=name,
            SecretString=secret_string,
            Tags=[
                {"Key": "app", "Value": "security-agent"},
                {"Key": "space_id", "Value": space_id},
                {"Key": "pentest_id", "Value": pentest_id},
            ],
        )
        return resp["ARN"]
    except client.exceptions.ResourceExistsException:
        return client.put_secret_value(SecretId=name, SecretString=secret_string)["ARN"]
    except (ClientError, BotoCoreError) as exc:
        raise _aws_error(exc, "Falha ao gravar credencial no Secrets Manager")


# ---- S3 ----
def _artifact_key(account_id: str, space_id: str, filename: str) -> str:
    settings = get_settings()
    return (
        f"{settings.s3_artifacts_prefix}/{account_id}/{space_id}/"
        f"{date.today().isoformat()}/{uuid4()}/{filename}"
    )


def presign_upload(
    region: str, account_id: str, space_id: str, filename: str, content_type: str | None
) -> PresignUploadResponse:
    if _mock():
        return get_mock_aws_client().presign_upload(space_id, filename, content_type)
    settings = get_settings()
    bucket = settings.s3_artifacts_bucket
    key = _artifact_key(account_id, space_id, filename)
    params = {"Bucket": bucket, "Key": key}
    if content_type:
        params["ContentType"] = content_type
    try:
        url = _client("s3", region).generate_presigned_url("put_object", Params=params, ExpiresIn=3600)
    except (ClientError, BotoCoreError) as exc:
        raise _aws_error(exc, "Falha ao gerar URL de upload S3")
    return PresignUploadResponse(
        url=url, content_type=content_type, key=key, s3_uri=f"s3://{bucket}/{key}"
    )


def list_resources(region: str, space_id: str) -> list[ResourceObject]:
    if _mock():
        return get_mock_aws_client().list_resources(space_id)
    settings = get_settings()
    bucket = settings.s3_artifacts_bucket
    prefix = f"{settings.s3_artifacts_prefix}/"
    out: list[ResourceObject] = []
    try:
        paginator = _client("s3", region).get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if f"/{space_id}/" not in key:
                    continue
                out.append(
                    ResourceObject(
                        name=key.rsplit("/", 1)[-1],
                        key=key,
                        s3_uri=f"s3://{bucket}/{key}",
                        size=obj.get("Size", 0),
                        last_modified=obj.get("LastModified"),
                    )
                )
    except (ClientError, BotoCoreError) as exc:
        raise _aws_error(exc, "Falha ao listar recursos no S3")
    return out
