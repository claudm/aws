"""Interface de linha de comando."""

from __future__ import annotations

import argparse
import logging
import sys
from typing import List

from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from .context import SessionFactory
from .engine import Scanner
from .models import Severity
from .registry import all_checks, select
from .report import render_console, write_csv, write_html, write_json, write_split_json

SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="testcloud",
        description="Scanner read-only de postura AWS: segurança, confiabilidade e custo.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="executa o scan na conta")
    scan.add_argument("--profile", help="perfil do ~/.aws/config")
    scan.add_argument("--role-arn", help="role a assumir (modo multi-conta)")
    scan.add_argument("--external-id", help="ExternalId exigido pela trust policy")
    scan.add_argument("--regions", nargs="+", help="regiões (padrão: todas as habilitadas)")
    scan.add_argument("--pillars", nargs="+", choices=["security", "reliability", "cost_optimization"])
    scan.add_argument("--services", nargs="+", help="filtra por serviço: ec2 s3 rds ...")
    scan.add_argument("--check", nargs="+", dest="include", help="executa apenas estes check ids")
    scan.add_argument("--skip", nargs="+", dest="exclude", help="ignora estes check ids")
    scan.add_argument("--min-severity", choices=[s.value for s in Severity], default="info")
    scan.add_argument("--workers", type=int, default=8, help="regiões em paralelo (padrão: 8)")
    scan.add_argument("--json", dest="json_path", help="salva o resultado em JSON")
    scan.add_argument("--split-json", dest="split_json_dir", help="salva o resultado quebrado em múltiplos JSONs por serviço neste diretório")
    scan.add_argument("--html", dest="html_path", help="gera relatório HTML")
    scan.add_argument("--csv", dest="csv_path", help="exporta findings em CSV")
    scan.add_argument("--all", action="store_true", help="imprime todos os achados no console")
    scan.add_argument("--quiet", action="store_true", help="não imprime o relatório no console")
    scan.add_argument("--progress", action="store_true", help="mostra progresso em stderr")
    scan.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity] + ["none"],
        default="none",
        help="sai com código 2 se houver achado igual ou acima desta severidade",
    )
    scan.add_argument("-v", "--verbose", action="store_true")

    lst = sub.add_parser("list-checks", help="lista os checks registrados")
    lst.add_argument("--pillars", nargs="+")
    lst.add_argument("--services", nargs="+")
    lst.add_argument("--permissions", action="store_true", help="mostra as permissões IAM exigidas")
    return p


def cmd_list(args) -> int:
    checks = select(pillars=args.pillars, services=args.services)
    perms = set()
    for c in sorted(checks, key=lambda c: (c.pillar.value, c.id)):
        print(f"{c.id:<36} {c.pillar.value:<18} {c.scope:<8} {c.title}")
        perms.update(c.permissions)
    print(f"\n{len(checks)} checks registrados.")
    if args.permissions:
        print("\nPermissões IAM necessárias:")
        for p in sorted(perms):
            print(f"  {p}")
    return 0


def cmd_scan(args) -> int:
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    checks = select(
        pillars=args.pillars, services=args.services, include=args.include, exclude=args.exclude
    )
    if not checks:
        print("Nenhum check corresponde aos filtros informados.", file=sys.stderr)
        return 1

    factory = SessionFactory(
        profile=args.profile, role_arn=args.role_arn, external_id=args.external_id
    )

    def progress(check_id: str, region: str, done: int, total: int) -> None:
        pct = done * 100 // max(total, 1)
        print(f"\r[{pct:>3}%] {done}/{total}  {region:<16} {check_id:<34}", end="", file=sys.stderr)

    scanner = Scanner(
        factory=factory,
        checks_to_run=checks,
        regions=args.regions,
        max_workers=args.workers,
        progress=progress if args.progress else None,
    )

    try:
        result = scanner.run()
    except NoCredentialsError:
        print("Credenciais AWS não encontradas. Configure um profile ou use --role-arn.", file=sys.stderr)
        return 1
    except (ClientError, BotoCoreError) as exc:
        print(f"Falha ao iniciar o scan: {exc}", file=sys.stderr)
        return 1

    if args.progress:
        print("", file=sys.stderr)

    floor = Severity(args.min_severity)
    result.findings = [f for f in result.findings if f.severity.weight >= floor.weight]

    if not args.quiet:
        print(render_console(result, show_all=args.all))

    if args.json_path:
        write_json(result, args.json_path)
        print(f"JSON salvo em {args.json_path}", file=sys.stderr)
    if args.split_json_dir:
        write_split_json(result, args.split_json_dir)
        print(f"JSONs separados por serviço salvos na pasta: {args.split_json_dir}/", file=sys.stderr)
    if args.html_path:
        write_html(result, args.html_path)
        print(f"Relatório HTML salvo em {args.html_path}", file=sys.stderr)
    if args.csv_path:
        write_csv(result, args.csv_path)
        print(f"CSV salvo em {args.csv_path}", file=sys.stderr)

    if args.fail_on != "none":
        threshold = Severity(args.fail_on).weight
        if any(f.severity.weight >= threshold for f in result.findings):
            return 2
    return 0


def main(argv: List[str] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "list-checks":
        return cmd_list(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
