"""Estimativas de custo.

Os valores servem para *priorizar* achados, não para fechar fatura. Quando a
permissão `pricing:GetProducts` existe, o preço on-demand real é buscado na
Price List API (endpoint global em us-east-1). Caso contrário, caímos em uma
tabela estática de us-east-1.
"""

from __future__ import annotations

import json
import logging
import math
import threading
from typing import Dict, Optional

log = logging.getLogger("testcloud.pricing")

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
RDS_GP3_GB_MONTH = 0.115
RDS_IO1_GB_MONTH = 0.125
RDS_IO1_IOPS_MONTH = 0.10
DDB_RCU_HOUR = 0.00013
DDB_WCU_HOUR = 0.00065
LAMBDA_GB_SECOND = 0.0000166667

# Engine do RDS -> (databaseEngine, databaseEdition) da Price List.
RDS_ENGINES = {
    "postgres": ("PostgreSQL", None),
    "mysql": ("MySQL", None),
    "mariadb": ("MariaDB", None),
    "aurora-postgresql": ("Aurora PostgreSQL", None),
    "aurora-mysql": ("Aurora MySQL", None),
    "oracle-ee": ("Oracle", "Enterprise"),
    "oracle-ee-cdb": ("Oracle", "Enterprise"),
    "oracle-se2": ("Oracle", "Standard Two"),
    "oracle-se2-cdb": ("Oracle", "Standard Two"),
    "sqlserver-ee": ("SQL Server", "Enterprise"),
    "sqlserver-se": ("SQL Server", "Standard"),
    "sqlserver-ex": ("SQL Server", "Express"),
    "sqlserver-web": ("SQL Server", "Web"),
}
# LicenseModel do describe_db_instances -> licenseModel da Price List.
RDS_LICENSES = {
    "license-included": "License included",
    "bring-your-own-license": "Bring your own license",
}

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


def ebs_monthly_total(volumes) -> float:
    """Soma de ebs_monthly para uma lista de volumes (shape do describe_volumes)."""
    return round(sum(ebs_monthly(v.get("VolumeType", "gp2"), v.get("Size", 0)) for v in (volumes or [])), 2)


def hourly_monthly(hourly: float) -> float:
    return round(hourly * HOURS_PER_MONTH, 2)


def lb_monthly(lb_type: str) -> float:
    return hourly_monthly(ALB_HOUR if lb_type == "application" else NLB_HOUR)


def gp2_to_gp3_saving(size_gb: int) -> float:
    """Economia mensal ao migrar gp2 -> gp3 mantendo a performance de baseline."""
    return round((EBS_GB_MONTH["gp2"] - EBS_GB_MONTH["gp3"]) * size_gb, 2)


def piops_to_gp3_saving(volume_type: str, size_gb: int, iops: int) -> float:
    """Economia ao trocar um volume io1/io2 por gp3 no baseline (3.000 IOPS / 125 MB/s)."""
    return round(max(0.0, ebs_monthly(volume_type, size_gb, iops) - ebs_monthly("gp3", size_gb)), 2)


def gp3_extra_monthly(iops: int, throughput: int) -> float:
    """Custo mensal do IOPS/throughput provisionado acima do baseline do gp3."""
    return round(max(0, iops - 3000) * 0.005 + max(0, throughput - 125) * 0.04, 2)


def rds_piops_saving(size_gb: int, iops: int) -> float:
    """Economia ao trocar storage io1/io2 do RDS por gp3 no baseline."""
    io1 = RDS_IO1_GB_MONTH * size_gb + RDS_IO1_IOPS_MONTH * iops
    return round(max(0.0, io1 - RDS_GP3_GB_MONTH * size_gb), 2)


def ddb_provisioned_saving(rcu: float, wcu: float, peak_rcu: float, peak_wcu: float) -> float:
    """Economia ao reduzir a capacidade provisionada para o pico observado + 30% de folga."""
    extra_r = max(0.0, rcu - peak_rcu * 1.3)
    extra_w = max(0.0, wcu - peak_wcu * 1.3)
    return round((extra_r * DDB_RCU_HOUR + extra_w * DDB_WCU_HOUR) * HOURS_PER_MONTH, 2)


def lambda_target_memory(used_max_mb: Optional[float]) -> Optional[int]:
    """Memória sugerida: pico usado + 30% de folga, em múltiplos de 64 MB (mínimo 128)."""
    if not used_max_mb:
        return None
    return max(128, int(math.ceil(used_max_mb * 1.3 / 64.0)) * 64)


def lambda_memory_saving(memory_mb: int, avg_duration_ms: float, invocations: float,
                         used_max_mb: Optional[float], days: int = 14) -> Optional[float]:
    """Economia mensal ao reduzir a memória para o pico usado (Lambda Insights) + folga.

    Sem o pico de memória não há base para estimar: devolve None. A duração é mantida,
    o que vale para funções curtas/IO-bound (as únicas que este check sinaliza).
    """
    target = lambda_target_memory(used_max_mb)
    if target is None:
        return None
    gb_seconds = invocations * (avg_duration_ms / 1000) * max(0, memory_mb - target) / 1024
    return round(gb_seconds * LAMBDA_GB_SECOND * 30 / days, 2)


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


def ec2_monthly(ctx, instance_type: str) -> Optional[float]:
    """Preço mensal on-demand. None quando o preço não pôde ser obtido."""
    hourly = ec2_hourly(ctx, instance_type)
    return round(hourly * HOURS_PER_MONTH, 2) if hourly else None


def ec2_upgrade_saving(ctx, current_type: str, suggested_type: str) -> Optional[float]:
    """Diferença mensal entre o tipo atual e o sugerido. None quando algum preço é desconhecido."""
    old, new = ec2_monthly(ctx, current_type), ec2_monthly(ctx, suggested_type)
    return round(max(0.0, old - new), 2) if old and new else None


def rds_monthly(ctx, instance_class: str, engine: str, multi_az: bool = False,
                license_model: Optional[str] = None) -> Optional[float]:
    """Preço on-demand mensal da instância RDS (sem storage). None quando indisponível."""
    engine_info = RDS_ENGINES.get(engine or "")
    if not engine_info:
        return None
    db_engine, edition = engine_info
    fields = {
        "instanceType": instance_class,
        "regionCode": ctx.region,
        "databaseEngine": db_engine,
        "deploymentOption": "Multi-AZ" if multi_az else "Single-AZ",
    }
    if edition:
        fields["databaseEdition"] = edition
    if license_model in RDS_LICENSES and db_engine in ("Oracle", "SQL Server"):
        fields["licenseModel"] = RDS_LICENSES[license_model]
    key = "rds:" + json.dumps(fields, sort_keys=True)
    with _lock:
        cached = _cache.get(key, False)
    if cached is False:
        cached = _price_list_hourly(ctx, "AmazonRDS", fields)
        with _lock:
            _cache[key] = cached
    return round(cached * HOURS_PER_MONTH, 2) if cached else None


def rds_upgrade_saving(ctx, current_class: str, suggested_class: str, engine: str, multi_az: bool = False,
                       license_model: Optional[str] = None) -> Optional[float]:
    old = rds_monthly(ctx, current_class, engine, multi_az, license_model)
    new = rds_monthly(ctx, suggested_class, engine, multi_az, license_model)
    return round(max(0.0, old - new), 2) if old and new else None


def _query_price_list(ctx, instance_type: str) -> Optional[float]:
    return _price_list_hourly(ctx, "AmazonEC2", {
        "instanceType": instance_type,
        "regionCode": ctx.region,
        "operatingSystem": "Linux",
        "tenancy": "Shared",
        "preInstalledSw": "NA",
        "capacitystatus": "Used",
        "licenseModel": "No License required",
    })


def _price_list_hourly(ctx, service_code: str, fields: Dict[str, str]) -> Optional[float]:
    """Primeiro preço on-demand > 0 da Price List para os filtros dados."""
    try:
        pricing = ctx.client("pricing", region="us-east-1")
        resp = pricing.get_products(
            ServiceCode=service_code,
            MaxResults=1,
            Filters=[{"Type": "TERM_MATCH", "Field": k, "Value": v} for k, v in fields.items()],
        )
        for raw in resp.get("PriceList", []):
            product = json.loads(raw) if isinstance(raw, str) else raw
            for term in product.get("terms", {}).get("OnDemand", {}).values():
                for dim in term.get("priceDimensions", {}).values():
                    usd = float(dim.get("pricePerUnit", {}).get("USD", 0))
                    if usd > 0:
                        return usd
    except Exception as exc:  # pricing é best-effort: nunca deve quebrar o scan
        log.debug("Price List indisponível para %s %s: %s", service_code, fields, exc)
    return None
