"""Integração com o serviço real AWS Security Agent (boto3 client 'securityagent').

Mapeia as respostas da API para os modelos do app (Space, Pentest,
VerifiedEndpoint). Operações usadas:
  - list_agent_spaces / batch_get_agent_spaces / create_agent_space / update_agent_space
  - list_pentests / batch_get_pentests / create_pentest
  - list_pentest_jobs_for_pentest (status de execução, best-effort)
  - list_target_domains / batch_get_target_domains / verify_target_domain
"""
from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse

from botocore.exceptions import BotoCoreError, ClientError

from .aws import _aws_error, _session  # reutiliza sessão/erro da camada AWS
from .schemas import (
    ConnectedResource,
    NetworkConfig,
    Pentest,
    PentestStatus,
    Space,
    TargetConfig,
    VerifiedEndpoint,
)


def _client(region: str, account_id: str | None = None):
    return _session(region, account_id).client("securityagent")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _first_list(resp: dict, *hints: str) -> list:
    # Sem fallback "primeira lista que aparecer": respostas de BatchGet* também
    # trazem um campo "notFound" (lista de IDs) que não deve ser confundido com
    # o campo de resultado quando nenhum dos IDs pedidos existe.
    for h in hints:
        v = resp.get(h)
        if isinstance(v, list):
            return v
    return []


# ---------------------------------------------------------------------------
# Agent Spaces
# ---------------------------------------------------------------------------
def list_agent_spaces(region: str, account_id: str) -> list[Space]:
    client = _client(region, account_id)
    out: list[Space] = []
    token = None
    try:
        while True:
            kw = {"maxResults": 100}
            if token:
                kw["nextToken"] = token
            resp = client.list_agent_spaces(**kw)
            for s in _first_list(resp, "agentSpaceSummaries"):
                out.append(
                    Space(
                        space_id=s["agentSpaceId"],
                        name=s.get("name", ""),
                        description=s.get("description"),
                        account_id=account_id,
                        region=region,
                    )
                )
            token = resp.get("nextToken")
            if not token:
                break
    except (ClientError, BotoCoreError) as exc:
        raise _aws_error(exc, "Falha ao listar agent spaces")
    return out


def get_agent_space(region: str, space_id: str, account_id: str) -> Space | None:
    client = _client(region)
    try:
        resp = client.batch_get_agent_spaces(agentSpaceIds=[space_id])
    except (ClientError, BotoCoreError) as exc:
        raise _aws_error(exc, "Falha ao obter agent space")
    items = _first_list(resp, "agentSpaces")
    if not items:
        return None
    s = items[0]
    return Space(
        space_id=s.get("agentSpaceId", space_id),
        name=s.get("name", ""),
        description=s.get("description"),
        account_id=account_id,
        region=region,
        target_domain_ids=s.get("targetDomainIds", []) or [],
        aws_resources=s.get("awsResources") or None,
    )


def create_agent_space(
    region: str,
    account_id: str,
    name: str,
    description: str | None = None,
    aws_resources: dict | None = None,
    target_domain_ids: list[str] | None = None,
    code_review_settings: dict | None = None,
    kms_key_id: str | None = None,
    tags: dict | None = None,
) -> Space:
    kw: dict = {"name": name}
    if description:
        kw["description"] = description
    if aws_resources:
        kw["awsResources"] = aws_resources
    if target_domain_ids:
        kw["targetDomainIds"] = target_domain_ids
    if code_review_settings:
        kw["codeReviewSettings"] = code_review_settings
    if kms_key_id:
        kw["kmsKeyId"] = kms_key_id
    if tags:
        kw["tags"] = tags
    try:
        resp = _client(region).create_agent_space(**kw)
    except (ClientError, BotoCoreError) as exc:
        raise _aws_error(exc, "Falha ao criar agent space")
    return Space(
        space_id=resp["agentSpaceId"],
        name=resp.get("name", name),
        description=resp.get("description", description),
        account_id=account_id,
        region=region,
        target_domain_ids=resp.get("targetDomainIds", []) or [],
        aws_resources=resp.get("awsResources") or aws_resources,
    )


def update_agent_space(
    region: str,
    account_id: str,
    space_id: str,
    name: str | None = None,
    description: str | None = None,
    aws_resources: dict | None = None,
    target_domain_ids: list[str] | None = None,
    code_review_settings: dict | None = None,
) -> Space:
    """UpdateAgentSpace: só manda o que veio preenchido (None = não mexe).

    A API não aceita kmsKeyId nem tags nesta operação — ambos são definidos
    apenas na criação.
    """
    kw: dict = {"agentSpaceId": space_id}
    if name is not None:
        kw["name"] = name
    if description is not None:
        kw["description"] = description
    if aws_resources is not None:
        kw["awsResources"] = aws_resources
    if target_domain_ids is not None:
        kw["targetDomainIds"] = target_domain_ids
    if code_review_settings is not None:
        kw["codeReviewSettings"] = code_review_settings
    try:
        resp = _client(region).update_agent_space(**kw)
    except (ClientError, BotoCoreError) as exc:
        raise _aws_error(exc, "Falha ao atualizar agent space")
    return Space(
        space_id=resp.get("agentSpaceId", space_id),
        name=resp.get("name", name or ""),
        description=resp.get("description", description),
        account_id=account_id,
        region=region,
        target_domain_ids=resp.get("targetDomainIds", []) or (target_domain_ids or []),
        aws_resources=resp.get("awsResources") or aws_resources,
    )


# ---------------------------------------------------------------------------
# Target domains (os "endpoints" da tela)
# ---------------------------------------------------------------------------
def _verification_detail(d: dict) -> str | None:
    details = (d.get("verificationDetails") or {})
    method = details.get("method")
    if method == "DNS_TXT":
        dns = details.get("dnsTxt") or {}
        if dns.get("dnsRecordName") and dns.get("token"):
            return f"Crie um registro DNS TXT em {dns['dnsRecordName']} com o valor: {dns['token']}"
    elif method == "HTTP_ROUTE":
        http = details.get("httpRoute") or {}
        if http.get("routePath") and http.get("token"):
            return f"Publique o token '{http['token']}' em {http['routePath']}"
    return d.get("verificationStatusReason")


def _endpoint_from(d: dict) -> VerifiedEndpoint:
    return VerifiedEndpoint(
        id=d.get("targetDomainId"),
        url=d.get("domainName", ""),
        status=d.get("verificationStatus") or d.get("status") or "PENDING",
        detail=_verification_detail(d),
    )


def list_target_domains(region: str) -> list[VerifiedEndpoint]:
    client = _client(region)
    out: list[VerifiedEndpoint] = []
    token = None
    try:
        while True:
            kw = {"maxResults": 100}
            if token:
                kw["nextToken"] = token
            resp = client.list_target_domains(**kw)
            for d in _first_list(resp, "targetDomainSummaries"):
                out.append(_endpoint_from(d))
            token = resp.get("nextToken")
            if not token:
                break
    except (ClientError, BotoCoreError) as exc:
        raise _aws_error(exc, "Falha ao listar target domains")
    return out


def list_endpoints_for_space(space: Space) -> list[VerifiedEndpoint]:
    if not space.target_domain_ids:
        return list_target_domains(space.region)
    try:
        resp = _client(space.region).batch_get_target_domains(
            targetDomainIds=space.target_domain_ids
        )
    except (ClientError, BotoCoreError) as exc:
        raise _aws_error(exc, "Falha ao obter target domains do space")
    return [_endpoint_from(d) for d in _first_list(resp, "targetDomains")]


def resolve_target_domain(region: str, url: str) -> str | None:
    host = urlparse(url).netloc or url
    for ep in list_target_domains(region):
        if ep.url and (ep.url == host or ep.url in url):
            return ep.id
    return None


def create_target_domain(
    region: str, domain_name: str, verification_method: str = "DNS_TXT"
) -> VerifiedEndpoint:
    try:
        resp = _client(region).create_target_domain(
            targetDomainName=domain_name, verificationMethod=verification_method
        )
    except (ClientError, BotoCoreError) as exc:
        raise _aws_error(exc, "Falha ao criar target domain")
    return _endpoint_from(resp)


def verify_target_domain(region: str, target_domain_id: str) -> VerifiedEndpoint:
    try:
        resp = _client(region).verify_target_domain(targetDomainId=target_domain_id)
    except (ClientError, BotoCoreError) as exc:
        raise _aws_error(exc, "Falha ao verificar target domain")
    return VerifiedEndpoint(
        id=resp.get("targetDomainId", target_domain_id),
        url=resp.get("domainName", ""),
        status=resp.get("status", "PENDING"),
        verified_at=resp.get("verifiedAt"),
    )


# ---------------------------------------------------------------------------
# Pentests
# ---------------------------------------------------------------------------
_JOB_STATUS = {
    "IN_PROGRESS": PentestStatus.RUNNING,
    "COMPLETED": PentestStatus.COMPLETED,
    "FAILED": PentestStatus.FAILED,
    "STOPPED": PentestStatus.FAILED,
    "STOPPING": PentestStatus.RUNNING,
}


def _latest_pentest_status(region: str, space_id: str, pentest_id: str) -> PentestStatus:
    """Status de execução vem dos jobs; best-effort (não quebra se o modelo diferir)."""
    try:
        resp = _client(region).list_pentest_jobs_for_pentest(
            agentSpaceId=space_id, pentestId=pentest_id, maxResults=1
        )
        for v in resp.values():
            if isinstance(v, list) and v and isinstance(v[0], dict) and "status" in v[0]:
                return _JOB_STATUS.get((v[0]["status"] or "").upper(), PentestStatus.PENDING)
    except Exception:  # noqa: BLE001 — status é acessório
        pass
    return PentestStatus.PENDING


def _network_from_vpc(cfg: dict | None) -> NetworkConfig:
    cfg = cfg or {}
    def _tail(arn):  # aceita ARN ou ID
        return arn.rsplit("/", 1)[-1] if arn else None
    sgs = cfg.get("securityGroupArns") or []
    subs = cfg.get("subnetArns") or []
    return NetworkConfig(
        vpc_id=_tail(cfg.get("vpcArn")),
        subnet_id=_tail(subs[0]) if subs else None,
        security_group_id=_tail(sgs[0]) if sgs else None,
    )


def _endpoints_and_resources_from_assets(assets: dict | None) -> tuple[list[str], list[ConnectedResource]]:
    assets = assets or {}
    endpoints = [e["uri"] for e in (assets.get("endpoints") or []) if e.get("uri")]
    resources = [
        ConnectedResource(name=d["s3Location"].rsplit("/", 1)[-1], type="s3", s3_uri=d["s3Location"])
        for d in (assets.get("documents") or []) if d.get("s3Location")
    ]
    return endpoints, resources


def list_pentests(region: str, space_id: str) -> list[Pentest]:
    client = _client(region)
    summaries: list[dict] = []
    token = None
    try:
        while True:
            kw = {"agentSpaceId": space_id, "maxResults": 100}
            if token:
                kw["nextToken"] = token
            resp = client.list_pentests(**kw)
            summaries += _first_list(resp, "pentestSummaries")
            token = resp.get("nextToken")
            if not token:
                break
    except (ClientError, BotoCoreError) as exc:
        raise _aws_error(exc, "Falha ao listar pentests")

    ids = [s["pentestId"] for s in summaries]
    details: dict[str, dict] = {}
    if ids:
        try:
            bg = client.batch_get_pentests(agentSpaceId=space_id, pentestIds=ids)
            for p in _first_list(bg, "pentests"):
                details[p["pentestId"]] = p
        except (ClientError, BotoCoreError):
            details = {}

    out: list[Pentest] = []
    for s in summaries:
        pid = s["pentestId"]
        p = details.get(pid, {})
        endpoints, resources = _endpoints_and_resources_from_assets(p.get("assets"))
        out.append(
            Pentest(
                id=pid,
                space_id=space_id,
                title=s.get("title", ""),
                status=_latest_pentest_status(region, space_id, pid),
                network=_network_from_vpc(p.get("vpcConfig")),
                target=TargetConfig(endpoints=endpoints, service_role_arn=p.get("serviceRole")),
                resources=resources,
                created_at=s.get("createdAt") or _now(),
                updated_at=s.get("updatedAt") or s.get("createdAt") or _now(),
            )
        )
    # ListPentests não garante ordem estável entre chamadas (kumo devolve em
    # ordem diferente a cada request) — ordena aqui para a tabela não "embaralhar".
    return sorted(out, key=lambda p: p.created_at, reverse=True)


def _vpc_config(region: str, account_id: str, net: NetworkConfig) -> dict | None:
    if not (net.vpc_id or net.subnet_id or net.security_group_id):
        return None
    cfg: dict = {}
    if net.vpc_id:
        cfg["vpcArn"] = (
            net.vpc_id if net.vpc_id.startswith("arn:")
            else f"arn:aws:ec2:{region}:{account_id}:vpc/{net.vpc_id}"
        )
    if net.security_group_id:
        cfg["securityGroupArns"] = [net.security_group_id]  # serviço aceita ID
    if net.subnet_id:
        cfg["subnetArns"] = [net.subnet_id]
    return cfg


def create_pentest(
    region: str, account_id: str, space_id: str, title: str,
    endpoints: list[str], net: NetworkConfig, service_role: str | None,
    resources: list[ConnectedResource] | None = None,
) -> Pentest:
    resources = resources or []
    kw: dict = {"agentSpaceId": space_id, "title": title}
    assets: dict = {}
    if endpoints:
        assets["endpoints"] = [{"uri": e} for e in endpoints]
    if resources:
        assets["documents"] = [{"s3Location": r.s3_uri} for r in resources]
    if assets:
        kw["assets"] = assets
    if service_role:
        kw["serviceRole"] = service_role
    vpc = _vpc_config(region, account_id, net)
    if vpc:
        kw["vpcConfig"] = vpc
    # NOTA: credenciais (assets.actors[].authentication) não são enviadas aqui —
    # o esquema de authentication depende do provider; ligue conforme sua política.
    try:
        resp = _client(region).create_pentest(**kw)
    except (ClientError, BotoCoreError) as exc:
        raise _aws_error(exc, "Falha ao criar pentest")
    return Pentest(
        id=resp["pentestId"],
        space_id=space_id,
        title=resp.get("title", title),
        status=PentestStatus.PENDING,
        network=net,
        target=TargetConfig(endpoints=endpoints, service_role_arn=service_role),
        resources=resources,
        created_at=resp.get("createdAt") or _now(),
        updated_at=resp.get("updatedAt") or _now(),
    )


def update_pentest(
    region: str, account_id: str, space_id: str, pentest_id: str,
    title: str | None, endpoints: list[str] | None, net: NetworkConfig | None,
    service_role: str | None, resources: list[ConnectedResource] | None,
) -> Pentest:
    kw: dict = {"pentestId": pentest_id, "agentSpaceId": space_id}
    if title is not None:
        kw["title"] = title
    assets: dict = {}
    if endpoints is not None:
        assets["endpoints"] = [{"uri": e} for e in endpoints]
    if resources is not None:
        assets["documents"] = [{"s3Location": r.s3_uri} for r in resources]
    if assets:
        kw["assets"] = assets
    if service_role is not None:
        kw["serviceRole"] = service_role
    if net is not None:
        vpc = _vpc_config(region, account_id, net)
        if vpc:
            kw["vpcConfig"] = vpc
    try:
        resp = _client(region).update_pentest(**kw)
    except (ClientError, BotoCoreError) as exc:
        raise _aws_error(exc, "Falha ao atualizar pentest")
    resp_endpoints, resp_resources = _endpoints_and_resources_from_assets(resp.get("assets"))
    return Pentest(
        id=resp.get("pentestId", pentest_id),
        space_id=space_id,
        title=resp.get("title", title or ""),
        status=_latest_pentest_status(region, space_id, pentest_id),
        network=net or _network_from_vpc(resp.get("vpcConfig")),
        target=TargetConfig(endpoints=resp_endpoints, service_role_arn=resp.get("serviceRole", service_role)),
        resources=resp_resources,
        created_at=resp.get("createdAt") or _now(),
        updated_at=resp.get("updatedAt") or _now(),
    )


def start_pentest_job(region: str, space_id: str, pentest_id: str) -> PentestStatus:
    """Inicia a execução do pentest (CreatePentest só registra o recurso)."""
    try:
        resp = _client(region).start_pentest_job(agentSpaceId=space_id, pentestId=pentest_id)
    except (ClientError, BotoCoreError) as exc:
        raise _aws_error(exc, "Falha ao iniciar pentest job")
    return _JOB_STATUS.get((resp.get("status") or "").upper(), PentestStatus.PENDING)
