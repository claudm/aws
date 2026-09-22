"""Modelos de dominio: pilares, severidades e achados (findings)."""

from __future__ import annotations

import dataclasses
import enum
from typing import Any, Dict, List, Optional


class Pillar(str, enum.Enum):
    """Pilares avaliados, alinhados ao AWS Well-Architected Framework."""

    SECURITY = "security"
    RELIABILITY = "reliability"
    COST = "cost_optimization"

    @property
    def label(self) -> str:
        return {
            Pillar.SECURITY: "Segurança",
            Pillar.RELIABILITY: "Confiabilidade",
            Pillar.COST: "Otimização de Custo",
        }[self]


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {
            Severity.CRITICAL: 100,
            Severity.HIGH: 70,
            Severity.MEDIUM: 40,
            Severity.LOW: 15,
            Severity.INFO: 5,
        }[self]

    @property
    def label(self) -> str:
        return {
            Severity.CRITICAL: "CRÍTICO",
            Severity.HIGH: "ALTO",
            Severity.MEDIUM: "MÉDIO",
            Severity.LOW: "BAIXO",
            Severity.INFO: "INFO",
        }[self]

    def __lt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.weight < other.weight


# Fatores de exposição: o ranking é por risco real, não só por severidade nominal.
EXPOSURE_MULTIPLIERS = {
    "internet_facing": 1.45,
    "cross_account": 1.25,
    "data_store": 1.20,
    "production_tag": 1.20,
    "privileged_identity": 1.35,
    "non_production_tag": 0.75,
    "empty_resource": 0.70,
}


@dataclasses.dataclass(slots=True)
class Finding:
    """Um achado individual, sempre amarrado a um recurso concreto."""

    check_id: str
    title: str
    pillar: Pillar
    severity: Severity
    resource_id: str
    region: str
    description: str
    remediation: str
    account_id: str = ""
    resource_arn: str = ""
    service: str = ""
    well_architected: str = ""
    doc_url: str = ""
    evidence: Dict[str, Any] = dataclasses.field(default_factory=dict)
    exposure: List[str] = dataclasses.field(default_factory=list)
    monthly_waste_usd: float = 0.0

    @property
    def risk_score(self) -> float:
        """Severidade base ajustada pelo contexto de exposição (0-100).

        O ajuste é limitado à banda da severidade: um achado ALTO muito exposto
        chega perto de um CRÍTICO, mas nunca o ultrapassa — a severidade continua
        sendo a informação principal, e o contexto só ordena dentro dela.
        """
        ladder = [0] + [s.weight for s in reversed(list(Severity))]  # [0, 5, 15, 40, 70, 100]
        base = float(self.severity.weight)
        idx = ladder.index(self.severity.weight)
        prev_w, next_w = ladder[idx - 1], ladder[idx + 1] if idx + 1 < len(ladder) else 100
        ceiling = base + 0.85 * (next_w - base)
        floor = base - 0.85 * (base - prev_w)

        score = base
        for factor in self.exposure:
            score *= EXPOSURE_MULTIPLIERS.get(factor, 1.0)
        return round(max(floor, min(score, ceiling, 100.0)), 1)

    @property
    def sort_key(self) -> tuple:
        return (-self.risk_score, -self.monthly_waste_usd, self.check_id, self.resource_id)

    def to_dict(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["pillar"] = self.pillar.value
        data["severity"] = self.severity.value
        data["risk_score"] = self.risk_score
        return data


@dataclasses.dataclass(slots=True)
class CheckError:
    """Falha na execução de um check (permissão faltando, serviço indisponível, etc.)."""

    check_id: str
    region: str
    error_code: str
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(slots=True)
class ScanResult:
    account_id: str
    account_alias: str
    partition: str
    regions: List[str]
    started_at: str
    finished_at: str
    duration_seconds: float
    checks_executed: int
    resources_evaluated: int
    findings: List[Finding] = dataclasses.field(default_factory=list)
    errors: List[CheckError] = dataclasses.field(default_factory=list)
    checks_run: List[str] = dataclasses.field(default_factory=list)

    def by_pillar(self, pillar: Pillar) -> List[Finding]:
        return [f for f in self.findings if f.pillar is pillar]

    def counts_by_severity(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def estimated_monthly_waste(self) -> float:
        return round(sum(f.monthly_waste_usd for f in self.findings), 2)

    @property
    def posture_score(self) -> int:
        """0-100. 100 = nenhum achado relevante. Penaliza pelo risco acumulado."""
        if not self.findings:
            return 100
        penalty = sum(f.risk_score for f in self.findings) ** 0.62
        return max(0, int(round(100 - penalty)))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": "1.0",
            "account_id": self.account_id,
            "account_alias": self.account_alias,
            "partition": self.partition,
            "regions": self.regions,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "checks_executed": self.checks_executed,
            "checks_run": sorted(self.checks_run),
            "resources_evaluated": self.resources_evaluated,
            "posture_score": self.posture_score,
            "estimated_monthly_waste_usd": self.estimated_monthly_waste,
            "counts_by_severity": self.counts_by_severity(),
            "findings": [f.to_dict() for f in sorted(self.findings, key=lambda x: x.sort_key)],
            "errors": [e.to_dict() for e in self.errors],
        }
