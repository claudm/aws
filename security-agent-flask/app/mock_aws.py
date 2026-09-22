"""AWS de mentira para desenvolvimento: moto interceptando o botocore.

Em vez de duplicar as chamadas de EC2/IAM/S3/Secrets num backend de mock, o
processo liga o moto e semeia o estado a partir do `mock_data.json`. As funções
de `aws.py` rodam então o **código real** — paginação, filtros, extração da tag
`Name` — contra essa AWS falsa. Não existe segunda implementação delas.

O serviço `securityagent` não é coberto pelo moto, então o domínio
(Spaces/Pentests/Endpoints) continua com backend próprio em
`backends/memory.py`.

Os ids de VPC/subnet/SG do `mock_data.json` são placeholders: quem gera os ids
de verdade é o moto. `id_map()` devolve o de-para, aplicado em `mock.py` sobre
as referências que os Spaces e Pentests fazem a eles.
"""
from __future__ import annotations

import logging
import os

import boto3

from .config import get_settings
from .schemas import ResourceObject

logger = logging.getLogger("security-agent.mock_aws")

_started = False
_id_map: dict[str, str] = {}


def id_map() -> dict[str, str]:
    """De-para {id do mock_data: id gerado pelo moto}. Vazio antes do `start()`."""
    return _id_map


def start() -> dict[str, str]:
    """Liga o moto no processo e semeia EC2/IAM/S3. Idempotente."""
    global _started
    if _started:
        return _id_map
    _started = True

    settings = get_settings()
    # Precisa valer antes de o moto criar qualquer backend: os ARNs que ele
    # gera (roles, secrets) carregam esta conta, e `validate_role_arn_account`
    # compara com a conta do Space.
    os.environ["MOTO_ACCOUNT_ID"] = settings.expected_account_id or "000000000000"
    _isolate_environment()

    from moto import mock_aws

    mock_aws().start()
    logger.info("moto ligado: chamadas AWS deste processo não saem para a rede")

    from .mock import load_raw_mock_data

    _id_map.update(_seed(load_raw_mock_data(), settings))
    return _id_map


def _isolate_environment() -> None:
    """Tira do ambiente o que faria a chamada escapar do moto.

    O moto casa a requisição pela URL padrão do serviço; um `AWS_ENDPOINT_URL`
    apontando para outro lugar (um S3 local, um LocalStack, o kumo) faz a
    chamada sair de verdade — em silêncio, e possivelmente com credenciais
    reais do ambiente. Em modo dev o endpoint é o moto, ponto.
    """
    for var in [k for k in os.environ if k.startswith("AWS_ENDPOINT_URL")]:
        removed = os.environ.pop(var)
        logger.warning("%s=%s ignorado: em modo dev quem responde é o moto", var, removed)

    # Credenciais de mentira, para o caso de as reais estarem no ambiente.
    os.environ.update(
        AWS_ACCESS_KEY_ID="moto",
        AWS_SECRET_ACCESS_KEY="moto",
        AWS_SESSION_TOKEN="moto",
        AWS_SECURITY_TOKEN="moto",
    )


def _seed(data: dict, settings) -> dict[str, str]:
    region = settings.aws_region
    ids: dict[str, str] = {}

    ec2 = boto3.client("ec2", region_name=region)
    # O moto cria uma VPC default por região; some com ela para a listagem
    # mostrar exatamente o que o mock_data descreve.
    for v in ec2.describe_vpcs().get("Vpcs", []):
        for sn in ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [v["VpcId"]]}]
        ).get("Subnets", []):
            ec2.delete_subnet(SubnetId=sn["SubnetId"])
        ec2.delete_vpc(VpcId=v["VpcId"])

    for v in data.get("vpcs", []):
        vpc_id = ec2.create_vpc(CidrBlock=v["cidr_block"])["Vpc"]["VpcId"]
        ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": v["name"]}])
        ids[v["vpc_id"]] = vpc_id

    for s in data.get("subnets", []):
        subnet_id = ec2.create_subnet(
            VpcId=ids[s["vpc_id"]],
            CidrBlock=s["cidr_block"],
            AvailabilityZone=s["availability_zone"],
        )["Subnet"]["SubnetId"]
        ec2.create_tags(Resources=[subnet_id], Tags=[{"Key": "Name", "Value": s["name"]}])
        ids[s["subnet_id"]] = subnet_id

    for sg in data.get("security_groups", []):
        group_id = ec2.create_security_group(
            GroupName=sg["name"], Description=sg["description"], VpcId=ids[sg["vpc_id"]]
        )["GroupId"]
        ids[sg["group_id"]] = group_id

    # Cada VPC nova ganha um SG "default" do moto; some com eles pelo mesmo
    # motivo da VPC default acima — a listagem mostra só o que o arquivo descreve.
    for sg in ec2.describe_security_groups().get("SecurityGroups", []):
        if sg["GroupName"] == "default":
            ec2.delete_security_group(GroupId=sg["GroupId"])

    iam = boto3.client("iam", region_name=region)
    for r in data.get("roles", []):
        iam.create_role(
            RoleName=r["role_name"],
            Path=r.get("path") or "/",
            AssumeRolePolicyDocument="{}",
        )

    s3 = boto3.client("s3", region_name=region)
    bucket = settings.s3_artifacts_bucket
    kw = {"Bucket": bucket}
    if region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**kw)
    account_id = settings.expected_account_id or "000000000000"
    for r in data.get("resources", []):
        key = f"{settings.s3_artifacts_prefix}/{account_id}/{r['space_id']}/{r['name']}"
        s3.put_object(Bucket=bucket, Key=key, Body=b"\0" * r["size"])

    logger.info(
        "moto semeado: %d VPCs, %d subnets, %d SGs, %d roles, %d objetos em s3://%s",
        len(data.get("vpcs", [])), len(data.get("subnets", [])),
        len(data.get("security_groups", [])), len(data.get("roles", [])),
        len(data.get("resources", [])), bucket,
    )
    return ids


def store_artifact(region: str, key: str, size: int) -> ResourceObject:
    """Destino do PUT da URL de upload local: grava o objeto no S3 do moto.

    A partir daí ele aparece em `aws.list_resources` como qualquer outro — a
    listagem em dev roda o mesmo código de produção.
    """
    settings = get_settings()
    bucket = settings.s3_artifacts_bucket
    s3 = boto3.client("s3", region_name=region)
    s3.put_object(Bucket=bucket, Key=key, Body=b"\0" * size)
    head = s3.head_object(Bucket=bucket, Key=key)
    return ResourceObject(
        name=key.rsplit("/", 1)[-1], key=key, s3_uri=f"s3://{bucket}/{key}",
        size=head["ContentLength"], last_modified=head["LastModified"],
    )
