"""Contexto de execução: sessões boto3, clients cacheados e helpers de coleta.

Regras do projeto:
  * somente chamadas READ-ONLY (Describe/Get/List) — nada de mutação;
  * uma sessão boto3 por thread (Session não é thread-safe para criar clients);
  * credenciais nunca são persistidas: apenas sessão temporária em memória.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import re
import threading
from typing import Any, Callable, Dict, Iterable, List, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from .models import Finding, Pillar, Severity

log = logging.getLogger("testcloud")

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
    user_agent_extra="testcloud-clone/1.0",
)


class SessionFactory:
    """Cria sessões boto3 (opcionalmente via AssumeRole com ExternalId)."""

    def __init__(
        self,
        profile: Optional[str] = None,
        role_arn: Optional[str] = None,
        external_id: Optional[str] = None,
        session_name: str = "testcloud-scan",
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
        resource_id: str,
        title: str = "",
        severity: Optional[Severity] = None,
        pillar: Optional[Pillar] = None,
        description: str = "",
        remediation: str = "",
        resource_arn: str = "",
        well_architected: str = "",
        doc_url: str = "",
        evidence: Optional[Dict[str, Any]] = None,
        exposure: Optional[List[str]] = None,
        monthly_waste_usd: float = 0.0,
        region: Optional[str] = None,
        variables: Optional[List[str]] = None,
        meta_override: Optional[Dict[str, Any]] = None,
    ) -> Finding:
        chk = self.current_check
        check_id = chk.id if chk else "UNKNOWN"
        check_pillar = pillar or (chk.pillar if chk else Pillar.SECURITY)
        
        from .catalog import get_rule_metadata
        meta = {**get_rule_metadata(check_pillar, check_id), **(meta_override or {})}
        
        def format_text(text: str) -> str:
            if not text or not variables: return text
            for v in variables:
                text = text.replace("{var}", str(v), 1)
            return text
            
        final_title = format_text(meta.get("title", "")) or title
        final_desc = format_text(meta.get("description", "")) or description
        final_rem = format_text(meta.get("remediation", "")) or remediation
        sev_str = meta.get("severity")
        final_severity = Severity(sev_str) if sev_str else (severity or Severity.LOW)

        return Finding(
            check_id=check_id,
            title=final_title,
            pillar=check_pillar,
            severity=final_severity,
            resource_id=resource_id,
            resource_arn=resource_arn,
            region=region or self.region,
            account_id=self.account_id,
            service=chk.service if chk else "",
            description=final_desc,
            remediation=final_rem,
            well_architected=well_architected or (chk.well_architected if chk else ""),
            doc_url=doc_url,
            evidence=evidence or {},
            exposure=exposure or [],
            monthly_waste_usd=round(monthly_waste_usd, 2),
        )

    def _prefetch_metrics(self, specs: List[tuple]) -> None:
        """Busca em lote as chamadas get_metric_data de vários recursos e grava cada uma no cache.

        `specs` são (service, região, params, erros ignorados, chave de cache) por recurso. Os Ids
        das queries recebem um prefixo por recurso (inclusive dentro das expressões); o resultado
        volta separado por recurso no mesmo formato da chamada individual. Falhas não são
        gravadas: o recurso cai na chamada individual.
        """
        no_batch = self._cache.setdefault("eval:no-batch", set())
        pending = [sp for sp in specs if sp[4] not in self._cache and sp[4] not in no_batch]
        groups: Dict[str, List[tuple]] = {}
        for sp in pending:
            group = json.dumps([sp[0], sp[1], sp[2].get("StartTime"), sp[2].get("EndTime")], default=str)
            groups.setdefault(group, []).append(sp)
        for group in groups.values():
            per_resource = max(1, 500 // max(1, len(group[0][2]["MetricDataQueries"])))
            for start in range(0, len(group), per_resource):
                chunk = group[start: start + per_resource]
                queries, owners = [], {}
                for i, (_, _, cp, _, key) in enumerate(chunk):
                    ids = [q["Id"] for q in cp["MetricDataQueries"]]
                    pattern = re.compile(r"\b(" + "|".join(map(re.escape, ids)) + r")\b")
                    for q in cp["MetricDataQueries"]:
                        q2 = dict(q, Id=f"r{i}_{q['Id']}")
                        if "Expression" in q2:
                            q2["Expression"] = pattern.sub(lambda m, i=i: f"r{i}_{m.group(1)}", q["Expression"])
                        queries.append(q2)
                        owners[q2["Id"]] = (key, q["Id"])
                service, reg, cp0 = chunk[0][0], chunk[0][1], chunk[0][2]
                values: Dict[str, List[Any]] = {}
                try:
                    token = None
                    while True:
                        kwargs = {"MetricDataQueries": queries, "StartTime": cp0["StartTime"], "EndTime": cp0["EndTime"]}
                        if token:
                            kwargs["NextToken"] = token
                        resp = self.call(service, "get_metric_data", region=reg, **kwargs) or {}
                        for res in resp.get("MetricDataResults", []):
                            values.setdefault(res["Id"], []).extend(res.get("Values", []))
                        token = resp.get("NextToken")
                        if not token:
                            break
                except Exception as exc:
                    # Não tenta o lote de novo para estes recursos: cada um faz a chamada individual.
                    log.debug("get_metric_data em lote falhou (%s); seguindo por recurso", exc)
                    no_batch.update(sp[4] for sp in chunk)
                    continue
                results: Dict[str, List[Dict[str, Any]]] = {sp[4]: [] for sp in chunk}
                for qid, (key, orig) in owners.items():
                    if qid in values:
                        results[key].append({"Id": orig, "Values": values[qid]})
                for key, res in results.items():
                    self._cache[key] = ("ok", {"MetricDataResults": res})

    def evaluate_dynamic_rule(
        self,
        resource_id: str = "",
        region: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        arn: str = "",
        vars: Optional[List[str]] = None,
        evaluate: Optional[Dict[str, Any]] = None,
        siblings: Optional[List[Dict[str, Any]]] = None,
    ) -> Iterable[Finding]:
        """Avalia um bloco `evaluate` do catálogo contra um recurso de um provider.

        O bloco é uma condição folha ou um nó {"operator": "and"|"or", "conditions": [...]},
        aninhável. Uma folha com `operation` avalia a resposta da chamada; com `capture`,
        um valor capturado; sem nenhum dos dois, o item corrente de um `any_item`/`none_item`
        (cuja árvore `where` roda em cada item da lista, podendo chamar APIs com `{item.X}`).

        Chaves opcionais do bloco: `overrides` (severidade/texto/exposure/vars quando `when`
        casa; a exposure do override substitui a do bloco), `env_tags` (exposure derivada das
        tags de ambiente), `vars` (valores para os {var} dos textos), `join`, `waste` (custo
        mensal via função do módulo pricing; None = não estimado), `evidence` e title/
        description/remediation/severity/exposure, que substituem os do catálogo.

        Folhas de get_metric_data com `"batch": true` são buscadas de uma vez para todos os
        `siblings` (params dos demais recursos do mesmo provider) e ficam no cache.
        """
        chk = self.current_check
        if not chk: return

        from . import pricing
        from .catalog import get_rule_metadata
        meta = get_rule_metadata(chk.pillar, chk.id)
        evaluate = evaluate or meta.get("evaluate")
        if not evaluate: return
        captures: Dict[str, Dict[str, Any]] = {}

        def resolve(v, item=None, prm=None):
            prm = params if prm is None else prm
            if isinstance(v, list):
                return [resolve(x, item, prm) for x in v]
            if isinstance(v, dict):
                return {k: resolve(x, item, prm) for k, x in v.items()}
            if not (isinstance(v, str) and v.startswith("{") and v.endswith("}")):
                return v
            key = v[1:-1]
            if key == "account_id":
                return self.account_id
            if key == "region":
                return self.region
            # Truncado na hora: chamadas iguais dentro do scan compartilham o cache.
            now = utcnow().replace(minute=0, second=0, microsecond=0)
            if key == "now":
                return now
            if key.startswith("now-") and key.endswith("d") and key[4:-1].isdigit():
                return now - dt.timedelta(days=int(key[4:-1]))
            if key.startswith("item."):
                return _dig(item, key[5:])
            if prm and key.split(".")[0] in prm:
                return _dig(prm, key)
            return v

        def call_spec(cond, item=None, prm=None):
            """(service, região, params resolvidos, erros ignorados, chave de cache) da chamada."""
            prm = params if prm is None else prm
            service = cond.get("service") or evaluate.get("service")
            req_region = resolve(cond.get("region") or evaluate.get("region") or region, item, prm)
            # Folha aninhada com params próprios usa só eles; senão herda os do bloco + provider.
            if cond is not evaluate and "params" in cond:
                raw = dict(cond["params"])
            else:
                raw = {**evaluate.get("params", {}), **(prm or {})}
            call_params = resolve(raw, item, prm)
            ignore = cond.get("ignore_errors") or evaluate.get("ignore_errors", [])
            key = "eval:" + json.dumps(
                [service, cond.get("operation"), req_region, call_params, sorted(ignore)], sort_keys=True, default=str
            )
            return service, req_region, call_params, ignore, key

        def response(cond, item=None):
            """Resposta da chamada da condição: ("ok", resp) ou ("err", None). Cacheada por contexto."""
            service, req_region, call_params, ignore, key = call_spec(cond, item)
            if (key not in self._cache and cond.get("batch") and siblings and item is None
                    and key not in self._cache.get("eval:no-batch", ())):
                self._prefetch_metrics([call_spec(cond, None, sib) for sib in siblings])
            if key not in self._cache:
                try:
                    self._cache[key] = ("ok", self.call(service, cond.get("operation"), ignore=ignore, region=req_region, **call_params))
                except Exception:
                    self._cache[key] = ("err", None)
            status, resp = self._cache[key]
            for path in cond.get("json_parse", []):
                _parse_json_field(resp, path)
            return status, resp

        def source(cond, item):
            """Objeto que a folha avalia. (False, None) quando a folha deve falhar direto."""
            if "operation" in cond:
                status, resp = response(cond, item)
                if status == "err":
                    return False, None
                if resp is None and cond.get("skip_if_none", evaluate.get("skip_if_none")):
                    return False, None
                return True, resp
            if "capture" in cond:
                return True, captures.get(cond["capture"])
            return True, item

        def leaf(cond, item=None):
            ok, resp = source(cond, item)
            if not ok:
                return False, []
            op = cond.get("operator")

            if op in ("any_item", "none_item"):
                matched, labels = [], []
                for it in _as_list(_dig(resp, cond.get("extract", "")), cond.get("as_items")):
                    hit, ext = node(cond["where"], it)
                    if hit:
                        matched.append(it)
                        labels += ext
                if "id" in cond:
                    captures[cond["id"]] = {
                        "count": len(matched),
                        "values": [_dig(it, cond["collect"]) for it in matched] if "collect" in cond else [],
                        "sum": sum(_dig(it, cond["sum"]) or 0 for it in matched) if "sum" in cond else 0,
                        "labels": labels,
                    }
                passed = len(matched) >= cond.get("min", 1) if op == "any_item" else not matched
                return passed, ([cond["label"]] if passed and cond.get("label") else [])

            if op == "aggregate":
                items = _as_list(_dig(resp, cond.get("extract", "")))
                values = [v for v in (_dig(it, cond.get("field", "")) for it in items) if isinstance(v, (int, float))]
                if len(values) < cond.get("min_count", 1):
                    return False, []
                agg = {"avg": sum(values) / len(values), "max": max(values), "min": min(values),
                       "sum": sum(values), "count": len(values)}[cond.get("fn", "avg")]
                if "id" in cond:
                    captures[cond["id"]] = {"value": agg, "count": len(values)}
                # Limite fixo (`value`) ou relativo a outro valor (`value_from` × `factor`).
                limit = value_of(cond["value_from"]) if "value_from" in cond else cond.get("value")
                if limit is None:
                    return False, []
                limit = limit * cond.get("factor", 1)
                return _match({"operator": cond.get("compare", "lt"), "value": limit}, agg)[0], []

            if "value" in cond:
                cond = {**cond, "value": resolve(cond["value"], item)}
            passed, extracted = _match(cond, resp)
            if passed and cond.get("label"):
                extracted = [cond["label"]]
            return passed, extracted

        def node(n, item=None):
            if "conditions" not in n:
                return leaf(n, item)
            is_and = n.get("operator", "or").lower() == "and"
            results, extracted = [], []
            for c in n["conditions"]:
                ok, ext = node(c, item)
                results.append(ok)
                if ok:
                    extracted += ext
                elif is_and:
                    return False, []
            final = all(results) if is_and else any(results)
            return final, (extracted if final else [])

        def value_of(spec):
            """Valor de um spec de `vars`/`evidence`/argumento de `waste`."""
            if not isinstance(spec, dict):
                return spec
            if "const" in spec:
                val = getattr(pricing, spec["const"])
            elif "value" in spec:
                val = resolve(spec["value"])
            elif "capture" in spec:
                val = (captures.get(spec["capture"]) or {}).get(spec.get("field", "value"))
            else:
                cond = spec if "operation" in spec else {**spec, "operation": evaluate.get("operation")}
                _, resp = response(cond)
                val = _dig(resp, spec.get("extract", ""))
            return _transform(val, spec)

        passed, extracted = node(evaluate)
        if not passed:
            return

        waste, estimated = 0.0, None
        if "waste" in evaluate:
            w = evaluate["waste"]
            args = [value_of(a) for a in w.get("args", [])]
            raw = getattr(pricing, w["fn"])(*([self] if w.get("ctx") else []), *args)
            # None: a função não conseguiu estimar (sem preço/dado) — diferente de "economia zero".
            estimated = raw is not None
            waste = round(raw * w.get("factor", 1), 2) if estimated else 0.0
            captures["waste"] = {"value": waste if estimated else None}

        override = {k: evaluate[k] for k in ("title", "description", "remediation", "severity") if k in evaluate}
        exposure = list(evaluate.get("exposure", meta.get("exposure", ["internet_facing", "data_store"])))
        var_specs = evaluate.get("vars", [])
        for o in evaluate.get("overrides", []):
            if node(o["when"])[0]:
                override.update({k: o[k] for k in ("title", "description", "remediation", "severity") if k in o})
                if "exposure" in o:
                    exposure = list(o["exposure"])
                var_specs = o.get("vars", var_specs)
        env = evaluate.get("env_tags")
        if env:
            _, resp = response(env)
            env_exp = env_exposure(_tags(_dig(resp, env.get("extract", ""))))
            exposure = env_exp if (env.get("replace") and env_exp) else exposure + env_exp

        joined = evaluate.get("join", " e ").join(str(v) for v in extracted if v)
        variables = [str(v) for v in list(vars or []) + [value_of(s) for s in var_specs]]
        if joined:
            variables.append(joined)
        if not variables:
            variables = [resource_id]

        evidence = {"evaluated": True}
        if estimated is not None:
            evidence["waste_estimated"] = estimated
        evidence.update({k: value_of(s) for k, s in evaluate.get("evidence", {}).items()})

        service_name = evaluate.get("service") or "aws"
        yield self.finding(
            resource_id=resource_id or f"{service_name}-{chk.id.split('.')[-1].lower()}:{self.account_id}",
            resource_arn=arn or self.arn(service_name, resource_id or f"account-pab:{self.account_id}"),
            evidence=evidence,
            exposure=list(dict.fromkeys(exposure)),
            variables=variables,
            region=region or "global",
            meta_override=override,
            monthly_waste_usd=waste,
        )


# --------------------------------------------------------------------- utils
def _match(cond: Dict[str, Any], resp: Any):
    """Aplica o operador de uma condição folha à resposta. Devolve (passou, variáveis extraídas)."""
    op = cond.get("operator")
    extract = cond.get("extract", "")
    value = cond.get("value")
    variables: List[str] = []
    passed = False

    if op == "missing_keys":
        cfg = _dig(resp, extract) if extract else (resp or {})
        cfg = cfg if isinstance(cfg, dict) else {}
        missing = [k for k in cond.get("keys", []) if not cfg.get(k)]
        if missing:
            passed = True
            variables.append(", ".join(missing))

    elif op == "is_true":
        if _dig(resp or {}, extract) is True:
            passed = True
            variables.append("bucket policy")

    elif op == "jsonpath":
        from jsonpath_ng.ext import parse

        try:
            matches = parse(cond.get("expression", "")).find(resp or {})
        except Exception:
            matches = []

        expected = cond.get("expected", "not_empty")
        first = matches[0].value if matches else None
        if expected == "empty" and not matches:
            passed = True
        elif expected == "not_empty" and matches:
            passed = True
            if isinstance(first, str):
                variables.append(first)
        elif expected == "not_contains":
            targets = [value] if isinstance(value, str) else (value or [])
            if not any(m.value in targets for m in matches):
                passed = True
                if isinstance(first, str):
                    variables.append(first)
        elif expected == "missing_any":
            found = {m.value for m in matches if isinstance(m.value, (str, int, float, bool))}
            missing = [v for v in (value or []) if v not in found]
            if missing:
                passed = True
                variables.append(", ".join(sorted(missing)))

    elif op == "range_hits":
        # Faixa [from, to] do objeto contra um mapa {número: rótulo}; emite "rótulo (número)".
        lo, hi = _dig(resp, cond.get("from", "")), _dig(resp, cond.get("to", ""))
        all_if = cond.get("all_if")
        if all_if and _dig(resp, all_if["field"]) == all_if["equals"]:
            lo, hi = 0, 65535
        lo = 0 if lo is None else lo
        hi = 65535 if hi is None else hi
        hits = sorted(int(p) for p in (value or {}) if lo <= int(p) <= hi)
        if hits:
            passed = True
            variables.append(", ".join(f"{value[str(p)]} ({p})" for p in hits[: cond.get("limit", 6)]))

    else:
        val = _dig(resp, extract)
        if op == "not_equals":
            passed = val != value
        elif op == "equals":
            passed = val == value
        elif op == "in":
            passed = val in (value or [])
        elif op == "not_in":
            passed = val not in (value or [])
        elif op == "contains":
            passed = value in ([val] if isinstance(val, str) else (val or []))
        elif op == "falsy":
            passed = not val
        elif op == "truthy":
            passed = bool(val)
        elif op in ("lt", "lte", "gt", "gte"):
            num = val or 0
            passed = {"lt": num < value, "lte": num <= value, "gt": num > value, "gte": num >= value}[op]
        elif op == "len_lt":
            passed = len(val or []) < value
        elif op == "len_gt":
            passed = len(val or []) > value
        elif op in ("regex", "not_regex"):
            found = isinstance(val, str) and re.search(value, val, re.IGNORECASE) is not None
            passed = found if op == "regex" else not found
        elif op == "age_days_gt":
            age = days_since(val)
            passed = age is None or age > value
        elif op == "age_days_lte":
            age = days_since(val)
            passed = age is not None and age <= value
        elif op == "days_until_between":
            left = days_until(val)
            passed = left is not None and value[0] <= left <= value[1]
        elif op == "env_is":
            passed = value in env_exposure(_tags(val))

    return passed, variables


_SIZES = ["nano", "micro", "small", "medium", "large", "xlarge", "2xlarge", "3xlarge", "4xlarge", "6xlarge",
          "8xlarge", "9xlarge", "10xlarge", "12xlarge", "16xlarge", "18xlarge", "24xlarge", "32xlarge", "48xlarge"]


def _as_list(val: Any, as_items: bool = False) -> List[Any]:
    """Normaliza o alvo de any_item: lista como está, dict vira [dict] (ou pares Key/Value)."""
    if val is None:
        return []
    if isinstance(val, dict):
        return [{"Key": k, "Value": v} for k, v in val.items()] if as_items else [val]
    return val if isinstance(val, list) else [val]


def _parse_json_field(obj: Any, path: str) -> None:
    """Troca, in place, o campo string em `path` pelo JSON decodificado (aceita URL-encoding)."""
    from urllib.parse import unquote

    parent_path, _, key = path.rpartition(".")
    parent = _dig(obj, parent_path)
    if isinstance(parent, dict) and isinstance(parent.get(key), str):
        try:
            parent[key] = json.loads(unquote(parent[key]))
        except Exception:
            pass


def _transform(val: Any, spec: Dict[str, Any]) -> Any:
    if val is None and "default" in spec:
        val = spec["default"]
    t = spec.get("transform")
    if not t:
        return val
    if t in ("days_since", "days_until", "first") and isinstance(val, list):
        val = val[0] if val else None
    if t == "days_since":
        return days_since(val)
    if t == "days_until":
        return days_until(val)
    if t == "first":
        return val
    if t == "count":
        return len(val or [])
    if t == "join":
        items = sorted(val or []) if spec.get("sort") else list(val or [])
        return ", ".join(str(x) for x in items[: spec.get("limit", len(items))])
    if t == "sorted":
        return sorted(val or [])
    if t == "sum":
        return sum(_dig(x, spec.get("field", "")) or 0 for x in (val or []))
    if t == "mb":
        return round((val or 0) / 1048576, 1)
    if t == "round":
        digits = spec.get("digits", 1)
        return int(round(val or 0)) if digits == 0 else round(val or 0, digits)
    if t == "family_map" and isinstance(val, str):
        # "m4.large" / "db.m4.large": troca a família conforme spec["map"]. A entrada pode ser
        # "m6i" ou {"family": "m6i", "min_size": "large", "size_map": {"10xlarge": "12xlarge"}}
        # para não sugerir um tamanho que não existe na família nova.
        parts = val.split(".")
        idx = 1 if parts[0] == "db" else 0
        if len(parts) > idx + 1:
            entry = spec.get("map", {}).get(parts[idx])
            if isinstance(entry, str):
                entry = {"family": entry}
            if entry:
                parts[idx] = entry["family"]
                size = entry.get("size_map", {}).get(parts[idx + 1], parts[idx + 1])
                minimum = entry.get("min_size")
                if minimum in _SIZES and size in _SIZES and _SIZES.index(size) < _SIZES.index(minimum):
                    size = minimum
                parts[idx + 1] = size
        return ".".join(parts)
    return val


def _tags(tags: Any) -> Dict[str, str]:
    """Aceita tags como dict ({k: v}) ou lista de {Key, Value}."""
    return tags if isinstance(tags, dict) else tags_to_dict(tags)


def _dig(obj: Any, path: str) -> Any:
    """Segue um caminho pontilhado ("A.B.0.C"); índices numéricos acessam listas."""
    if not path:
        return obj
    for key in path.split("."):
        if isinstance(obj, dict):
            obj = obj.get(key)
        elif isinstance(obj, list) and key.isdigit() and int(key) < len(obj):
            obj = obj[int(key)]
        else:
            return None
    return obj


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


def days_until(value: Optional[dt.datetime]) -> Optional[int]:
    if not value:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return (value - dt.datetime.now(dt.timezone.utc)).days
