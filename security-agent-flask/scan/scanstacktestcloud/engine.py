"""Motor de execução do scan."""

from __future__ import annotations

import datetime as dt
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Optional

from botocore.exceptions import BotoCoreError, ClientError
from botocore.parsers import ResponseParserError

from . import checks  # noqa: F401  (popula o registry)
from .context import ScanContext, SessionFactory
from .models import CheckError, Finding, ScanResult
from .registry import Check

log = logging.getLogger("scanstacktestcloud")

ProgressCb = Callable[[str, str, int, int], None]


class Scanner:
    def __init__(
        self,
        factory: SessionFactory,
        checks_to_run: List[Check],
        regions: Optional[List[str]] = None,
        max_workers: int = 8,
        progress: Optional[ProgressCb] = None,
    ):
        self.factory = factory
        self.checks = checks_to_run
        self.requested_regions = regions
        self.max_workers = max_workers
        self.progress = progress
        self._done = 0
        self._total = 0

    # ------------------------------------------------------------- identidade
    def identity(self):
        session = self.factory.new_session("us-east-1")
        sts = session.client("sts")
        ident = sts.get_caller_identity()
        partition = ident["Arn"].split(":")[1]
        alias = ""
        try:
            aliases = session.client("iam").list_account_aliases().get("AccountAliases", [])
            alias = aliases[0] if aliases else ""
        except (ClientError, BotoCoreError, ResponseParserError):
            pass
        return ident["Account"], alias, partition

    def discover_regions(self) -> List[str]:
        if self.requested_regions:
            return list(self.requested_regions)
        session = self.factory.new_session("us-east-1")
        try:
            resp = session.client("ec2").describe_regions(AllRegions=False)
            return sorted(r["RegionName"] for r in resp["Regions"])
        except (ClientError, BotoCoreError, ResponseParserError) as exc:
            log.warning("describe_regions falhou (%s); usando lista estática do botocore", exc)
            return sorted(session.get_available_regions("ec2"))

    # ------------------------------------------------------------------- run
    def run(self) -> ScanResult:
        started = dt.datetime.now(dt.timezone.utc)
        t0 = time.monotonic()
        account_id, alias, partition = self.identity()
        regions = self.discover_regions()

        global_checks = [c for c in self.checks if c.scope == "global"]
        regional_checks = [c for c in self.checks if c.scope != "global"]
        self._total = len(global_checks) + len(regional_checks) * len(regions)

        findings: List[Finding] = []
        errors: List[CheckError] = []
        resources = 0
        checks_run: List[str] = []

        units = [("global", global_checks)] + [(r, regional_checks) for r in regions]

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(
                    self._run_unit, account_id, alias, partition, regions, region, unit_checks
                ): region
                for region, unit_checks in units
                if unit_checks
            }
            for fut in as_completed(futures):
                f, e, seen, run = fut.result()
                findings.extend(f)
                errors.extend(e)
                resources += seen
                checks_run.extend(run)

        finished = dt.datetime.now(dt.timezone.utc)
        return ScanResult(
            account_id=account_id,
            account_alias=alias,
            partition=partition,
            regions=regions,
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            duration_seconds=round(time.monotonic() - t0, 1),
            checks_executed=self._total,
            resources_evaluated=resources,
            findings=findings,
            errors=errors,
            checks_run=checks_run,
        )

    def _run_unit(self, account_id, alias, partition, all_regions, region, unit_checks):
        """Executa todos os checks de uma região (sequencial), compartilhando cache."""
        api_region = "us-east-1" if region == "global" else region
        ctx = ScanContext(
            factory=self.factory,
            account_id=account_id,
            region=api_region,
            partition=partition,
            account_alias=alias,
            all_regions=all_regions,
        )
        findings: List[Finding] = []
        errors: List[CheckError] = []
        run: List[str] = []

        for chk in unit_checks:
            ctx.current_check = chk
            run.append(chk.id)
            try:
                findings.extend(chk.run(ctx))
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                errors.append(
                    CheckError(chk.id, region, code, exc.response.get("Error", {}).get("Message", ""))
                )
                log.debug("%s falhou em %s: %s", chk.id, region, code)
            except (BotoCoreError, ResponseParserError) as exc:
                errors.append(CheckError(chk.id, region, "BotoCoreError", str(exc)))
            except Exception as exc:  # noqa: BLE001 - um check ruim não derruba o scan
                errors.append(CheckError(chk.id, region, "UnexpectedError", repr(exc)))
                log.exception("Erro inesperado em %s (%s)", chk.id, region)
            finally:
                self._done += 1
                if self.progress:
                    self.progress(chk.id, region, self._done, self._total)

        return findings, errors, ctx.resources_seen, run
