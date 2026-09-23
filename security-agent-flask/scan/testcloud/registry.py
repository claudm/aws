"""Registro de checks. Cada check é uma função pura que recebe um ScanContext
e devolve (ou gera) findings."""

from __future__ import annotations

import dataclasses
from typing import Callable, Iterable, List, Optional

from .models import Finding, Pillar

CheckFunc = Callable[..., Iterable[Finding]]


@dataclasses.dataclass(slots=True)
class Check:
    id: str
    title: str
    pillar: Pillar
    service: str
    func: CheckFunc
    scope: str = "regional"  # "regional" | "global"
    well_architected: str = ""
    permissions: tuple = ()

    def run(self, ctx) -> List[Finding]:
        out = self.func(ctx)
        return list(out) if out else []


_REGISTRY: List[Check] = []


def check(
    check_id: str,
    title: str = "",
    pillar: Pillar = Pillar.SECURITY,
    service: str = "",
    scope: str = "regional",
    well_architected: str = "",
    permissions: Iterable[str] = (),
):
    """Decorator de registro.

    @check("EC2.SG_OPEN_SSH", "SSH aberto para a internet", Pillar.SECURITY, "ec2")
    def ssh_aberto(ctx): ...
    """

    def wrapper(func: CheckFunc) -> CheckFunc:
        _REGISTRY.append(
            Check(
                id=check_id,
                title=title,
                pillar=pillar,
                service=service,
                func=func,
                scope=scope,
                well_architected=well_architected,
                permissions=tuple(permissions),
            )
        )
        return func

    return wrapper


def all_checks() -> List[Check]:
    return list(_REGISTRY)


def select(
    pillars: Optional[Iterable[str]] = None,
    services: Optional[Iterable[str]] = None,
    include: Optional[Iterable[str]] = None,
    exclude: Optional[Iterable[str]] = None,
) -> List[Check]:
    checks = all_checks()
    if pillars:
        wanted = {p.lower() for p in pillars}
        checks = [c for c in checks if c.pillar.value in wanted]
    if services:
        wanted = {s.lower() for s in services}
        checks = [c for c in checks if c.service.lower() in wanted]
    if include:
        wanted = {i.upper() for i in include}
        checks = [c for c in checks if c.id.upper() in wanted]
    if exclude:
        unwanted = {e.upper() for e in exclude}
        checks = [c for c in checks if c.id.upper() not in unwanted]
    return checks

_PROVIDERS = {}

def resource_provider(service: str, resource_type: str):
    def wrapper(func):
        _PROVIDERS[f"{service}.{resource_type}"] = func
        return func
    return wrapper

def autoload_dynamic_checks():
    from .models import Pillar
    
    # Check what is already registered manually
    registered_ids = {c.id for c in _REGISTRY}
    
    import json
    import os
    rules_dir = os.path.join(os.path.dirname(__file__), "catalog", "rules")
    
    if not os.path.exists(rules_dir):
        return
        
    for filename in os.listdir(rules_dir):
        if not filename.endswith(".json"): continue
        
        path = os.path.join(rules_dir, filename)
        with open(path, "r", encoding="utf-8") as f:
            catalog = json.load(f)
            
        for rule_id, meta in catalog.items():
            if rule_id in registered_ids: continue
            
            evaluate = meta.get("evaluate")
            if not evaluate: continue
            
            # `evaluate` pode ser uma lista de blocos: um por tipo de recurso avaliado.
            blocks = evaluate if isinstance(evaluate, list) else [evaluate]
            if not all(b.get("resource") in _PROVIDERS for b in blocks):
                continue
            
            # This rule is fully dynamic and has a provider
            def make_func(blocks=blocks):
                def func(ctx):
                    for block in blocks:
                        resources = list(_PROVIDERS[block["resource"]](ctx))
                        # params de todos os recursos: permitem buscar métricas em lote
                        siblings = [r.get("params") or {} for r in resources]
                        for resource in resources:
                            yield from ctx.evaluate_dynamic_rule(
                                resource_id=resource.get("resource_id", ""),
                                region=resource.get("region"),
                                params=resource.get("params"),
                                arn=resource.get("arn", ""),
                                vars=resource.get("vars"),
                                evaluate=block,
                                siblings=siblings,
                            )
                return func
                
            service_name = blocks[0]["resource"].split(".")[0]
            
            # Map string pillar back to Enum
            pillar_name = meta.get("pillar", "security").lower()
            pillar_enum = Pillar.SECURITY
            for p in Pillar:
                # Aceita o valor ("cost_optimization") ou o nome ("cost") do pilar.
                if pillar_name in (p.value.lower(), p.name.lower()):
                    pillar_enum = p
                    break
                    
            _REGISTRY.append(Check(
                id=rule_id,
                title=meta.get("title", ""),
                pillar=pillar_enum,
                service=service_name,
                func=make_func(),
                scope=meta.get("scope", "global" if service_name in ["s3", "iam", "cloudfront", "route53", "wafv2", "shield"] else "regional"),
                well_architected=meta.get("well_architected", ""),
                permissions=tuple(meta.get("permissions", ())),
            ))
