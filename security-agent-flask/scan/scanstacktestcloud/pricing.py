"""Estimativas de custo.

Os valores servem para *priorizar* achados, não para fechar fatura. Quando a
permissão `pricing:GetProducts` existe, o preço on-demand real é buscado na
Price List API (endpoint global em us-east-1). Caso contrário, caímos em uma
tabela estática de us-east-1.
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Dict, Optional

log = logging.getLogger("scanstacktestcloud.pricing")

HOURS_PER_MONTH = 730.0

# US$/GB-mês (us-east-1). Fallback quando a Price List API não está disponível.
EBS_GB_MONTH: Dict[str, float] = {
    "gp2": 0.10,
    "gp3": 0.08,
    "io1": 0.125,
    "io2": 0.125,
    "st1": 0.045,
    "sc1": 0.015,
    "standard": 0.05,
}
SNAPSHOT_GB_MONTH = 0.05
EIP_IDLE_HOUR = 0.005          # IPv4 público ocioso
NAT_GATEWAY_HOUR = 0.045
ALB_HOUR = 0.0225
NLB_HOUR = 0.0225

_cache: Dict[str, Optional[float]] = {}
_lock = threading.Lock()


def ebs_monthly(volume_type: str, size_gb: int, iops: int = 0, throughput: int = 0) -> float:
    base = EBS_GB_MONTH.get(volume_type, 0.10) * size_gb
    if volume_type == "gp3":
        base += max(0, iops - 3000) * 0.005
        base += max(0, throughput - 125) * 0.04
    elif volume_type in ("io1", "io2"):
        base += iops * 0.065
    return round(base, 2)


def gp2_to_gp3_saving(size_gb: int) -> float:
    """Economia mensal ao migrar gp2 -> gp3 mantendo a performance de baseline."""
    return round((EBS_GB_MONTH["gp2"] - EBS_GB_MONTH["gp3"]) * size_gb, 2)


def snapshot_monthly(size_gb: int) -> float:
    # Snapshots são incrementais: assumimos ~40% do tamanho do volume como custo efetivo.
    return round(SNAPSHOT_GB_MONTH * size_gb * 0.4, 2)


def ec2_hourly(ctx, instance_type: str) -> Optional[float]:
    """Preço on-demand Linux/shared. None quando não foi possível determinar."""
    key = f"ec2:{ctx.region}:{instance_type}"
    with _lock:
        if key in _cache:
            return _cache[key]
    price = _query_price_list(ctx, instance_type)
    with _lock:
        _cache[key] = price
    return price


def ec2_monthly(ctx, instance_type: str) -> float:
    hourly = ec2_hourly(ctx, instance_type)
    return round(hourly * HOURS_PER_MONTH, 2) if hourly else 0.0


def _query_price_list(ctx, instance_type: str) -> Optional[float]:
    try:
        pricing = ctx.client("pricing", region="us-east-1")
        resp = pricing.get_products(
            ServiceCode="AmazonEC2",
            MaxResults=1,
            Filters=[
                {"Type": "TERM_MATCH", "Field": "instanceType", "Value": instance_type},
                {"Type": "TERM_MATCH", "Field": "regionCode", "Value": ctx.region},
                {"Type": "TERM_MATCH", "Field": "operatingSystem", "Value": "Linux"},
                {"Type": "TERM_MATCH", "Field": "tenancy", "Value": "Shared"},
                {"Type": "TERM_MATCH", "Field": "preInstalledSw", "Value": "NA"},
                {"Type": "TERM_MATCH", "Field": "capacitystatus", "Value": "Used"},
                {"Type": "TERM_MATCH", "Field": "licenseModel", "Value": "No License required"},
            ],
        )
        for raw in resp.get("PriceList", []):
            product = json.loads(raw) if isinstance(raw, str) else raw
            for term in product.get("terms", {}).get("OnDemand", {}).values():
                for dim in term.get("priceDimensions", {}).values():
                    usd = float(dim.get("pricePerUnit", {}).get("USD", 0))
                    if usd > 0:
                        return usd
    except Exception as exc:  # pricing é best-effort: nunca deve quebrar o scan
        log.debug("Price List indisponível para %s: %s", instance_type, exc)
    return None
