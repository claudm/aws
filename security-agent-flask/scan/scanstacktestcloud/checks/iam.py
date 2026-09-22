"""Checks de identidade (IAM). Escopo global — rodam uma única vez."""

from __future__ import annotations

import csv
import datetime as dt
import io
import json
import time
from typing import Any, Dict, List, Optional
from urllib.parse import unquote

from ..context import ScanContext, days_since
from ..models import Pillar, Severity
from ..registry import check

KEY_MAX_AGE_DAYS = 90
IDLE_DAYS = 90


def _parse_dt(value: str) -> Optional[dt.datetime]:
    if not value or value in ("N/A", "no_information", "not_supported"):
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def credential_report(ctx: ScanContext) -> List[Dict[str, str]]:
    """Gera (se preciso) e lê o credential report do IAM — 1 chamada por scan."""

    def _load() -> List[Dict[str, str]]:
        iam = ctx.client("iam", region="us-east-1")
        for _ in range(12):
            state = iam.generate_credential_report()["State"]
            if state == "COMPLETE":
                break
            time.sleep(2)
        content = iam.get_credential_report()["Content"].decode("utf-8")
        return list(csv.DictReader(io.StringIO(content)))

    return ctx.cached("iam:credential_report", _load)


def _policy_is_wildcard_admin(doc: Any) -> bool:
    """Detecta Allow com Action '*' e Resource '*' sem Condition."""
    if isinstance(doc, str):
        doc = json.loads(unquote(doc))
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for st in statements:
        if st.get("Effect") != "Allow" or st.get("Condition"):
            continue
        actions = st.get("Action", [])
        resources = st.get("Resource", [])
        actions = [actions] if isinstance(actions, str) else actions
        resources = [resources] if isinstance(resources, str) else resources
        if "*" in actions and "*" in resources:
            return True
    return False


@check(
    "IAM.ROOT_MFA_DISABLED",
    "Conta root sem MFA",
    Pillar.SECURITY,
    "iam",
    scope="global",
    well_architected="SEC02-BP01",
    permissions=["iam:GetAccountSummary"],
)
def root_mfa(ctx: ScanContext):
    summary = ctx.call("iam", "get_account_summary")
    if not summary:
        return
    if summary["SummaryMap"].get("AccountMFAEnabled", 0) != 1:
        yield ctx.finding(
            title="Conta root sem MFA habilitado",
            severity=Severity.CRITICAL,
            pillar=Pillar.SECURITY,
            resource_id=f"root:{ctx.account_id}",
            resource_arn=f"arn:{ctx.partition}:iam::{ctx.account_id}:root",
            region="global",
            description=(
                "O usuário root tem acesso irrestrito à conta e não pode ter suas permissões "
                "limitadas por policy. Sem MFA, o comprometimento da senha do root entrega a "
                "conta inteira."
            ),
            remediation=(
                "Console > Security credentials (logado como root) > Assign MFA device. "
                "Use uma chave de hardware (FIDO2) ou app TOTP guardado em cofre corporativo."
            ),
            exposure=["privileged_identity", "internet_facing"],
            doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html",
        )


@check(
    "IAM.ROOT_ACCESS_KEYS",
    "Access keys na conta root",
    Pillar.SECURITY,
    "iam",
    scope="global",
    well_architected="SEC02-BP04",
    permissions=["iam:GetAccountSummary"],
)
def root_keys(ctx: ScanContext):
    summary = ctx.call("iam", "get_account_summary")
    if not summary:
        return
    if summary["SummaryMap"].get("AccountAccessKeysPresent", 0) == 1:
        yield ctx.finding(
            title="Conta root possui access keys ativas",
            severity=Severity.CRITICAL,
            pillar=Pillar.SECURITY,
            resource_id=f"root:{ctx.account_id}",
            resource_arn=f"arn:{ctx.partition}:iam::{ctx.account_id}:root",
            region="global",
            description=(
                "Access keys do root permitem acesso programático total e não são rastreáveis "
                "por identidade. Não há caso de uso legítimo em contas modernas."
            ),
            remediation="Delete as chaves em Security credentials do root e migre automações para IAM Roles.",
            exposure=["privileged_identity"],
        )


@check(
    "IAM.USER_MFA_DISABLED",
    "Usuário com console sem MFA",
    Pillar.SECURITY,
    "iam",
    scope="global",
    well_architected="SEC02-BP01",
    permissions=["iam:GenerateCredentialReport", "iam:GetCredentialReport"],
)
def user_mfa(ctx: ScanContext):
    for row in credential_report(ctx):
        if row["user"] == "<root_account>":
            continue
        if row.get("password_enabled") == "true" and row.get("mfa_active") != "true":
            yield ctx.finding(
                title=f"Usuário IAM '{row['user']}' tem senha de console sem MFA",
                severity=Severity.HIGH,
                pillar=Pillar.SECURITY,
                resource_id=row["user"],
                resource_arn=row["arn"],
                region="global",
                description="Login de console protegido apenas por senha é vulnerável a phishing e credential stuffing.",
                remediation=(
                    "Exija MFA via SCP/policy com condição aws:MultiFactorAuthPresent, ou "
                    "elimine usuários de console migrando para IAM Identity Center (SSO)."
                ),
                evidence={"password_last_used": row.get("password_last_used")},
                exposure=["internet_facing"],
            )


@check(
    "IAM.ACCESS_KEY_ROTATION",
    "Access key sem rotação",
    Pillar.SECURITY,
    "iam",
    scope="global",
    well_architected="SEC02-BP05",
    permissions=["iam:GetCredentialReport"],
)
def key_rotation(ctx: ScanContext):
    for row in credential_report(ctx):
        for idx in ("1", "2"):
            if row.get(f"access_key_{idx}_active") != "true":
                continue
            rotated = _parse_dt(row.get(f"access_key_{idx}_last_rotated", ""))
            age = days_since(rotated)
            if age is not None and age > KEY_MAX_AGE_DAYS:
                is_root = row["user"] == "<root_account>"
                yield ctx.finding(
                    title=f"Access key {idx} de '{row['user']}' com {age} dias sem rotação",
                    severity=Severity.HIGH if is_root else Severity.MEDIUM,
                    pillar=Pillar.SECURITY,
                    resource_id=f"{row['user']}#key{idx}",
                    resource_arn=row["arn"],
                    region="global",
                    description=(
                        f"A chave foi criada/rotacionada há {age} dias. Chaves de longa duração "
                        "aumentam a janela de exploração em caso de vazamento em repositório, log ou imagem."
                    ),
                    remediation=(
                        "Crie a segunda chave, atualize os consumidores, desative a antiga por alguns dias "
                        "e só então remova. Prefira roles (IRSA, instance profile, OIDC do GitHub Actions)."
                    ),
                    evidence={"age_days": age, "last_used": row.get(f"access_key_{idx}_last_used_date")},
                    exposure=["privileged_identity"] if is_root else [],
                )


@check(
    "IAM.ACCESS_KEY_UNUSED",
    "Access key ativa e sem uso",
    Pillar.SECURITY,
    "iam",
    scope="global",
    well_architected="SEC03-BP04",
    permissions=["iam:GetCredentialReport"],
)
def key_unused(ctx: ScanContext):
    for row in credential_report(ctx):
        for idx in ("1", "2"):
            if row.get(f"access_key_{idx}_active") != "true":
                continue
            last_used = _parse_dt(row.get(f"access_key_{idx}_last_used_date", ""))
            idle = days_since(last_used)
            if last_used is None:
                created = days_since(_parse_dt(row.get(f"access_key_{idx}_last_rotated", "")))
                if created is not None and created > 30:
                    yield ctx.finding(
                        title=f"Access key {idx} de '{row['user']}' nunca foi usada",
                        severity=Severity.MEDIUM,
                        pillar=Pillar.SECURITY,
                        resource_id=f"{row['user']}#key{idx}",
                        resource_arn=row["arn"],
                        region="global",
                        description=f"Chave ativa criada há {created} dias sem nenhum uso registrado.",
                        remediation="Desative e remova. Credencial não usada é só superfície de ataque.",
                        evidence={"created_days_ago": created},
                    )
            elif idle is not None and idle > IDLE_DAYS:
                yield ctx.finding(
                    title=f"Access key {idx} de '{row['user']}' sem uso há {idle} dias",
                    severity=Severity.LOW,
                    pillar=Pillar.SECURITY,
                    resource_id=f"{row['user']}#key{idx}",
                    resource_arn=row["arn"],
                    region="global",
                    description=f"Último uso registrado há {idle} dias.",
                    remediation="Desative a chave; se ninguém reclamar em 2 semanas, remova.",
                    evidence={"idle_days": idle},
                )


@check(
    "IAM.PASSWORD_POLICY",
    "Política de senha fraca ou ausente",
    Pillar.SECURITY,
    "iam",
    scope="global",
    well_architected="SEC02-BP02",
    permissions=["iam:GetAccountPasswordPolicy"],
)
def password_policy(ctx: ScanContext):
    resp = ctx.call("iam", "get_account_password_policy", ignore=["NoSuchEntity"])
    if resp is None:
        yield ctx.finding(
            title="Conta sem política de senha customizada",
            severity=Severity.MEDIUM,
            pillar=Pillar.SECURITY,
            resource_id=f"password-policy:{ctx.account_id}",
            region="global",
            description="A política padrão aceita senhas de 8 caracteres sem exigir complexidade nem expiração.",
            remediation="Defina mínimo de 14 caracteres, complexidade e reuso bloqueado (ou adote SSO e elimine senhas IAM).",
        )
        return

    policy = resp["PasswordPolicy"]
    problems = []
    if policy.get("MinimumPasswordLength", 0) < 14:
        problems.append(f"comprimento mínimo {policy.get('MinimumPasswordLength')}")
    for flag, label in (
        ("RequireSymbols", "símbolos"),
        ("RequireNumbers", "números"),
        ("RequireUppercaseCharacters", "maiúsculas"),
        ("RequireLowercaseCharacters", "minúsculas"),
    ):
        if not policy.get(flag):
            problems.append(f"não exige {label}")
    if policy.get("PasswordReusePrevention", 0) < 5:
        problems.append("permite reuso de senha recente")

    if problems:
        yield ctx.finding(
            title="Política de senha abaixo do recomendado",
            severity=Severity.LOW,
            pillar=Pillar.SECURITY,
            resource_id=f"password-policy:{ctx.account_id}",
            region="global",
            description="Desvios encontrados: " + "; ".join(problems) + ".",
            remediation="Ajuste em IAM > Account settings para 14+ caracteres, complexidade completa e reuso ≥ 5.",
            evidence=policy,
        )


@check(
    "IAM.WILDCARD_ADMIN_POLICY",
    "Policy customizada com Allow *:*",
    Pillar.SECURITY,
    "iam",
    scope="global",
    well_architected="SEC03-BP02",
    permissions=["iam:ListPolicies", "iam:GetPolicyVersion"],
)
def wildcard_policy(ctx: ScanContext):
    policies = ctx.paginate(
        "iam", "list_policies", "Policies", Scope="Local", OnlyAttached=True
    )
    iam = ctx.client("iam", region="us-east-1")
    for pol in policies:
        version = iam.get_policy_version(
            PolicyArn=pol["Arn"], VersionId=pol["DefaultVersionId"]
        )["PolicyVersion"]["Document"]
        if _policy_is_wildcard_admin(version):
            yield ctx.finding(
                title=f"Policy '{pol['PolicyName']}' concede Action:* em Resource:*",
                severity=Severity.HIGH,
                pillar=Pillar.SECURITY,
                resource_id=pol["PolicyName"],
                resource_arn=pol["Arn"],
                region="global",
                description=(
                    f"A policy está anexada a {pol.get('AttachmentCount', 0)} entidade(s) e "
                    "equivale a AdministratorAccess, violando menor privilégio."
                ),
                remediation=(
                    "Use IAM Access Analyzer (policy generation) para gerar uma policy a partir "
                    "do CloudTrail dos últimos 90 dias e substitua o wildcard."
                ),
                evidence={"attachment_count": pol.get("AttachmentCount", 0)},
                exposure=["privileged_identity"],
            )


@check(
    "IAM.INACTIVE_USER",
    "Usuário IAM inativo",
    Pillar.SECURITY,
    "iam",
    scope="global",
    well_architected="SEC03-BP04",
    permissions=["iam:GetCredentialReport"],
)
def inactive_user(ctx: ScanContext):
    for row in credential_report(ctx):
        if row["user"] == "<root_account>":
            continue
        candidates = [
            _parse_dt(row.get("password_last_used", "")),
            _parse_dt(row.get("access_key_1_last_used_date", "")),
            _parse_dt(row.get("access_key_2_last_used_date", "")),
        ]
        used = [d for d in candidates if d]
        created = _parse_dt(row.get("user_creation_time", ""))
        if not used:
            age = days_since(created)
            if age is not None and age > IDLE_DAYS:
                yield ctx.finding(
                    title=f"Usuário '{row['user']}' nunca autenticou",
                    severity=Severity.LOW,
                    pillar=Pillar.SECURITY,
                    resource_id=row["user"],
                    resource_arn=row["arn"],
                    region="global",
                    description=f"Criado há {age} dias sem nenhum uso de senha ou chave.",
                    remediation="Remova o usuário ou documente o motivo de mantê-lo.",
                )
            continue
        idle = days_since(max(used))
        if idle is not None and idle > IDLE_DAYS:
            yield ctx.finding(
                title=f"Usuário '{row['user']}' inativo há {idle} dias",
                severity=Severity.LOW,
                pillar=Pillar.SECURITY,
                resource_id=row["user"],
                resource_arn=row["arn"],
                region="global",
                description="Identidades órfãs costumam sobreviver a offboarding e viram porta de entrada.",
                remediation="Revogue credenciais e remova o usuário após confirmar com o time responsável.",
                evidence={"idle_days": idle},
            )
