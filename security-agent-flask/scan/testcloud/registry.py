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
    title: str,
    pillar: Pillar,
    service: str,
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
