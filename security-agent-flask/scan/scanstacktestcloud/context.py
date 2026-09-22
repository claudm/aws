"""Contexto de execução: sessões boto3, clients cacheados e helpers de coleta.

Regras do projeto:
  * somente chamadas READ-ONLY (Describe/Get/List) — nada de mutação;
  * uma sessão boto3 por thread (Session não é thread-safe para criar clients);
  * credenciais nunca são persistidas: apenas sessão temporária em memória.
"""

from __future__ import annotations

import datetime as dt
import logging
import threading
from typing import Any, Callable, Dict, Iterable, List, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from .models import Finding, Pillar, Severity

log = logging.getLogger("scanstacktestcloud")

# Erros que significam "não tenho permissão" ou "serviço não habilitado" —
# viram avisos no relatório, não quebram o scan.
SOFT_ERRORS = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthorizationError",
    "InvalidAccessException",
    "OptInRequired",
    "SubscriptionRequiredException",
    "UnrecognizedClientException",
    "InvalidClientTokenId",
    "BadRequestException",
    "ResourceNotFoundException",
    "InvalidAction",
}

BOTO_CONFIG = Config(
    retries={"max_attempts": 10, "mode": "adaptive"},
    connect_timeout=10,
    read_timeout=60,
    user_agent_extra="scanstacktestcloud-clone/1.0",
)


class SessionFactory:
    """Cria sessões boto3 (opcionalmente via AssumeRole com ExternalId)."""

    def __init__(
        self,
        profile: Optional[str] = None,
        role_arn: Optional[str] = None,
        external_id: Optional[str] = None,
        session_name: str = "scanstacktestcloud-scan",
        duration_seconds: int = 3600,
    ):
        self.profile = profile
        self.role_arn = role_arn
        self.external_id = external_id
        self.session_name = session_name
        self.duration_seconds = duration_seconds
        self._creds: Optional[Dict[str, Any]] = None
        self._lock = threading.Lock()

    def _base_session(self) -> boto3.Session:
        return boto3.Session(profile_name=self.profile) if self.profile else boto3.Session()

    def _assume(self) -> Dict[str, Any]:
        with self._lock:
            if self._creds:
                return self._creds
            sts = self._base_session().client("sts", config=BOTO_CONFIG)
            params: Dict[str, Any] = {
                "RoleArn": self.role_arn,
                "RoleSessionName": self.session_name,
                "DurationSeconds": self.duration_seconds,
            }
            if self.external_id:
                params["ExternalId"] = self.external_id
            resp = sts.assume_role(**params)["Credentials"]
            self._creds = {
                "aws_access_key_id": resp["AccessKeyId"],
                "aws_secret_access_key": resp["SecretAccessKey"],
                "aws_session_token": resp["SessionToken"],
            }
            return self._creds

    def new_session(self, region: Optional[str] = None) -> boto3.Session:
        """Sessão nova (uma por thread)."""
        if self.role_arn:
            return boto3.Session(region_name=region, **self._assume())
        if self.profile:
            return boto3.Session(profile_name=self.profile, region_name=region)
        return boto3.Session(region_name=region)


class ScanContext:
    """Um contexto por região (ou um global). Não é compartilhado entre threads."""

    def __init__(
        self,
        factory: SessionFactory,
        account_id: str,
        region: str,
        partition: str = "aws",
        account_alias: str = "",
        all_regions: Optional[List[str]] = None,
    ):
        self.factory = factory
        self.account_id = account_id
        self.region = region
        self.partition = partition
        self.account_alias = account_alias
        self.all_regions = all_regions or [region]
        self.session = factory.new_session(region)
        self._clients: Dict[str, Any] = {}
        self._cache: Dict[str, Any] = {}
        self.resources_seen = 0
        self.current_check = None  # preenchido pelo engine

    # ---------------------------------------------------------------- clients
    def client(self, service: str, region: Optional[str] = None):
        key = f"{service}:{region or self.region}"
        if key not in self._clients:
            self._clients[key] = self.session.client(
                service, region_name=region or self.region, config=BOTO_CONFIG
            )
        return self._clients[key]

    # ------------------------------------------------------------------ cache
    def cached(self, key: str, producer: Callable[[], Any]) -> Any:
        """Memoiza coletas caras (ex.: describe_instances) entre checks da mesma região."""
        if key not in self._cache:
            self._cache[key] = producer()
        return self._cache[key]

    # ------------------------------------------------------------- paginação
    def paginate(self, service: str, operation: str, result_key: str, **kwargs) -> List[Any]:
        client = self.client(service)
        items: List[Any] = []
        try:
            paginator = client.get_paginator(operation)
            for page in paginator.paginate(**kwargs):
                items.extend(page.get(result_key, []) or [])
        except (ClientError, BotoCoreError) as exc:
            if isinstance(exc, ClientError) and self.is_soft(exc):
                raise
            raise
        self.resources_seen += len(items)
        return items

    @staticmethod
    def is_soft(exc: Exception) -> bool:
        if isinstance(exc, ClientError):
            return exc.response.get("Error", {}).get("Code", "") in SOFT_ERRORS
        return False

    def call(
        self,
        service: str,
        operation: str,
        ignore: Iterable[str] = (),
        region: Optional[str] = None,
        **kwargs,
    ):
        """Chamada única tolerante: devolve None se o erro estiver em `ignore`."""
        client = self.client(service, region=region)
        try:
            return getattr(client, operation)(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in set(ignore) | SOFT_ERRORS:
                log.debug("%s.%s ignorado (%s) em %s", service, operation, code, self.region)
                return None
            raise

    # ------------------------------------------------------------------- ARNs
    def arn(self, service: str, resource: str, region: Optional[str] = None, account: bool = True) -> str:
        reg = "" if region == "" else (region or self.region)
        acct = self.account_id if account else ""
        return f"arn:{self.partition}:{service}:{reg}:{acct}:{resource}"

    # --------------------------------------------------------------- findings
    def finding(
        self,
        title: str,
        severity: Severity,
        pillar: Pillar,
        resource_id: str,
        description: str,
        remediation: str,
        resource_arn: str = "",
        well_architected: str = "",
        doc_url: str = "",
        evidence: Optional[Dict[str, Any]] = None,
        exposure: Optional[List[str]] = None,
        monthly_waste_usd: float = 0.0,
        region: Optional[str] = None,
    ) -> Finding:
        chk = self.current_check
        return Finding(
            check_id=chk.id if chk else "UNKNOWN",
            title=title,
            pillar=pillar,
            severity=severity,
            resource_id=resource_id,
            resource_arn=resource_arn,
            region=region or self.region,
            account_id=self.account_id,
            service=chk.service if chk else "",
            description=description,
            remediation=remediation,
            well_architected=well_architected or (chk.well_architected if chk else ""),
            doc_url=doc_url,
            evidence=evidence or {},
            exposure=exposure or [],
            monthly_waste_usd=round(monthly_waste_usd, 2),
        )


# --------------------------------------------------------------------- utils
def tags_to_dict(tags: Optional[Iterable[Dict[str, str]]], key="Key", value="Value") -> Dict[str, str]:
    return {t.get(key, ""): t.get(value, "") for t in (tags or [])}


def env_exposure(tags: Dict[str, str]) -> List[str]:
    """Deriva fator de exposição a partir de tags de ambiente."""
    env = (tags.get("Environment") or tags.get("environment") or tags.get("env") or "").lower()
    if env in {"prod", "production", "prd", "producao", "produção"}:
        return ["production_tag"]
    if env in {"dev", "test", "staging", "sandbox", "qa", "hml", "homolog"}:
        return ["non_production_tag"]
    return []


def days_since(value: Optional[dt.datetime]) -> Optional[int]:
    if not value:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return (dt.datetime.now(dt.timezone.utc) - value).days


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)
