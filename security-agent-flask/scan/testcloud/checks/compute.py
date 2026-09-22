"""Checks de Lambda, ECR, EKS e Elastic Load Balancing. Escopo regional."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from ..context import ScanContext, tags_to_dict
from ..models import Pillar, Severity
from ..registry import check

# Runtimes sem suporte de patch pela AWS. Ajuste conforme o calendário oficial.
DEPRECATED_RUNTIMES = {
    "python2.7", "python3.6", "python3.7", "python3.8", "python3.9",
    "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x", "nodejs18.x",
    "ruby2.5", "ruby2.7", "ruby3.2",
    "java8", "dotnetcore2.1", "dotnetcore3.1", "dotnet6", "go1.x",
}

SECRET_HINT = re.compile(
    r"(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|conn(ection)?[_-]?string)",
    re.IGNORECASE,
)
SAFE_VALUE = re.compile(r"^(arn:aws[a-z\-]*:|/aws/reference/secretsmanager|ssm://|\{\{resolve:)", re.IGNORECASE)

WEAK_TLS_POLICIES = ("ELBSecurityPolicy-2016-08", "ELBSecurityPolicy-TLS-1-0", "ELBSecurityPolicy-TLS-1-1")


def functions(ctx: ScanContext) -> List[Dict[str, Any]]:
    return ctx.cached(
        "lambda:functions", lambda: ctx.paginate("lambda", "list_functions", "Functions")
    )


def load_balancers(ctx: ScanContext) -> List[Dict[str, Any]]:
    return ctx.cached(
        "elbv2:lbs", lambda: ctx.paginate("elbv2", "describe_load_balancers", "LoadBalancers")
    )


@check(
    "LAMBDA.DEPRECATED_RUNTIME",
    "Lambda em runtime sem suporte",
    Pillar.SECURITY,
    "lambda",
    well_architected="SEC06-BP03",
    permissions=["lambda:ListFunctions"],
)
def deprecated_runtime(ctx: ScanContext):
    for fn in functions(ctx):
        runtime = fn.get("Runtime")
        if not runtime or runtime not in DEPRECATED_RUNTIMES:
            continue
        yield ctx.finding(
            title=f"Função '{fn['FunctionName']}' usa runtime {runtime}",
            severity=Severity.MEDIUM,
            pillar=Pillar.SECURITY,
            resource_id=fn["FunctionName"],
            resource_arn=fn["FunctionArn"],
            description=(
                "Runtimes fora de suporte deixam de receber patches do sistema operacional e da "
                "linguagem, e eventualmente perdem a permissão de atualizar o código."
            ),
            remediation="Migre para a versão suportada mais recente e valide em staging antes do cutover.",
            evidence={"runtime": runtime, "last_modified": fn.get("LastModified")},
        )


@check(
    "LAMBDA.PLAINTEXT_SECRET",
    "Possível segredo em variável de ambiente",
    Pillar.SECURITY,
    "lambda",
    well_architected="SEC02-BP03",
    permissions=["lambda:ListFunctions"],
)
def plaintext_secret(ctx: ScanContext):
    for fn in functions(ctx):
        env = (fn.get("Environment") or {}).get("Variables") or {}
        suspects = [
            k for k, v in env.items()
            if SECRET_HINT.search(k) and v and not SAFE_VALUE.match(str(v))
        ]
        if not suspects:
            continue
        yield ctx.finding(
            title=f"Função '{fn['FunctionName']}' com {len(suspects)} variável(is) suspeita(s) de segredo",
            severity=Severity.MEDIUM,
            pillar=Pillar.SECURITY,
            resource_id=fn["FunctionName"],
            resource_arn=fn["FunctionArn"],
            description=(
                "Variáveis de ambiente aparecem em GetFunctionConfiguration, no console e em "
                f"exports de IaC. Chaves sinalizadas: {', '.join(sorted(suspects)[:8])}. "
                "O valor não foi lido nem armazenado por este scan."
            ),
            remediation=(
                "Mova para Secrets Manager ou SSM Parameter Store (SecureString) e resolva em runtime, "
                "com cache via extensão de parâmetros."
            ),
            evidence={"suspect_keys": sorted(suspects)},
        )


@check(
    "LAMBDA.NO_DLQ",
    "Lambda assíncrona sem destino de falha",
    Pillar.RELIABILITY,
    "lambda",
    well_architected="REL05-BP02",
    permissions=["lambda:ListFunctions", "lambda:GetFunctionEventInvokeConfig"],
)
def lambda_dlq(ctx: ScanContext):
    for fn in functions(ctx):
        if fn.get("DeadLetterConfig", {}).get("TargetArn"):
            continue
        cfg = ctx.call(
            "lambda",
            "get_function_event_invoke_config",
            ignore=["ResourceNotFoundException"],
            FunctionName=fn["FunctionName"],
        )
        if cfg and cfg.get("DestinationConfig", {}).get("OnFailure", {}).get("Destination"):
            continue
        yield ctx.finding(
            title=f"Função '{fn['FunctionName']}' sem DLQ nem destino OnFailure",
            severity=Severity.LOW,
            pillar=Pillar.RELIABILITY,
            resource_id=fn["FunctionName"],
            resource_arn=fn["FunctionArn"],
            description=(
                "Invocações assíncronas que esgotam as retentativas são descartadas silenciosamente — "
                "o evento se perde sem rastro além da métrica de erro."
            ),
            remediation="Configure OnFailure destination (SQS/SNS/EventBridge) para reprocessamento.",
        )


@check(
    "ECR.SCAN_ON_PUSH_DISABLED",
    "Repositório ECR sem scan de imagem",
    Pillar.SECURITY,
    "ecr",
    well_architected="SEC06-BP01",
    permissions=["ecr:DescribeRepositories"],
)
def ecr_scan(ctx: ScanContext):
    repos = ctx.cached(
        "ecr:repos", lambda: ctx.paginate("ecr", "describe_repositories", "repositories")
    )
    for repo in repos:
        if repo.get("imageScanningConfiguration", {}).get("scanOnPush"):
            continue
        yield ctx.finding(
            title=f"Repositório ECR '{repo['repositoryName']}' sem scan on push",
            severity=Severity.MEDIUM,
            pillar=Pillar.SECURITY,
            resource_id=repo["repositoryName"],
            resource_arn=repo["repositoryArn"],
            description="Imagens são promovidas sem verificação de CVEs conhecidas nas camadas do SO.",
            remediation="Ative Enhanced scanning (Inspector) no nível do registry e falhe o pipeline em severidade alta.",
        )


@check(
    "ECR.MUTABLE_TAGS",
    "Tags de imagem mutáveis",
    Pillar.SECURITY,
    "ecr",
    well_architected="SEC06-BP01",
    permissions=["ecr:DescribeRepositories"],
)
def ecr_mutable(ctx: ScanContext):
    repos = ctx.cached(
        "ecr:repos", lambda: ctx.paginate("ecr", "describe_repositories", "repositories")
    )
    for repo in repos:
        if repo.get("imageTagMutability") == "IMMUTABLE":
            continue
        yield ctx.finding(
            title=f"Repositório ECR '{repo['repositoryName']}' permite sobrescrever tags",
            severity=Severity.LOW,
            pillar=Pillar.SECURITY,
            resource_id=repo["repositoryName"],
            resource_arn=repo["repositoryArn"],
            description=(
                "Com tags mutáveis, o artefato que rodou no ambiente não é reproduzível e um push "
                "pode substituir a imagem já auditada."
            ),
            remediation="Mude para IMMUTABLE e faça deploy por digest (sha256) no manifesto.",
        )


@check(
    "EKS.PUBLIC_ENDPOINT",
    "Endpoint do EKS aberto",
    Pillar.SECURITY,
    "eks",
    well_architected="SEC05-BP01",
    permissions=["eks:ListClusters", "eks:DescribeCluster"],
)
def eks_endpoint(ctx: ScanContext):
    names = ctx.cached("eks:clusters", lambda: ctx.paginate("eks", "list_clusters", "clusters"))
    for name in names:
        resp = ctx.call("eks", "describe_cluster", name=name)
        if not resp:
            continue
        cluster = resp["cluster"]
        vpc = cluster.get("resourcesVpcConfig", {})
        if not vpc.get("endpointPublicAccess"):
            continue
        cidrs = vpc.get("publicAccessCidrs", [])
        wide = "0.0.0.0/0" in cidrs
        yield ctx.finding(
            title=f"Cluster EKS '{name}' com API server público{' e sem restrição de CIDR' if wide else ''}",
            severity=Severity.HIGH if wide else Severity.LOW,
            pillar=Pillar.SECURITY,
            resource_id=name,
            resource_arn=cluster["arn"],
            description=(
                "O endpoint do control plane responde na internet. A autenticação continua exigindo "
                "IAM, mas a superfície de ataque e o risco de credential stuffing aumentam."
            ),
            remediation=(
                "Restrinja publicAccessCidrs à faixa corporativa ou desligue o acesso público e "
                "use acesso privado via VPN / SSM port forwarding."
            ),
            evidence={"public_access_cidrs": cidrs, "version": cluster.get("version")},
            exposure=["internet_facing"] if wide else [],
        )


@check(
    "EKS.CONTROL_PLANE_LOGS",
    "Logs do control plane do EKS desligados",
    Pillar.SECURITY,
    "eks",
    well_architected="SEC04-BP01",
    permissions=["eks:DescribeCluster"],
)
def eks_logs(ctx: ScanContext):
    names = ctx.cached("eks:clusters", lambda: ctx.paginate("eks", "list_clusters", "clusters"))
    for name in names:
        resp = ctx.call("eks", "describe_cluster", name=name)
        if not resp:
            continue
        cluster = resp["cluster"]
        enabled = set()
        for group in cluster.get("logging", {}).get("clusterLogging", []):
            if group.get("enabled"):
                enabled.update(group.get("types", []))
        missing = {"api", "audit", "authenticator"} - enabled
        if not missing:
            continue
        yield ctx.finding(
            title=f"Cluster EKS '{name}' sem logs de {', '.join(sorted(missing))}",
            severity=Severity.MEDIUM,
            pillar=Pillar.SECURITY,
            resource_id=name,
            resource_arn=cluster["arn"],
            description="Sem audit log do Kubernetes não há como reconstruir ações dentro do cluster.",
            remediation=(
                "Habilite api, audit e authenticator. Defina retenção no log group — o custo "
                "do audit em clusters grandes é relevante."
            ),
            evidence={"enabled": sorted(enabled)},
        )


@check(
    "ELB.INSECURE_LISTENER",
    "Listener HTTP ou TLS fraco",
    Pillar.SECURITY,
    "elbv2",
    well_architected="SEC09-BP02",
    permissions=["elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeListeners"],
)
def elb_listener(ctx: ScanContext):
    for lb in load_balancers(ctx):
        if lb.get("Type") != "application":
            continue
        listeners = ctx.paginate(
            "elbv2", "describe_listeners", "Listeners", LoadBalancerArn=lb["LoadBalancerArn"]
        )
        internet = lb.get("Scheme") == "internet-facing"
        for ls in listeners:
            if ls.get("Protocol") == "HTTP":
                actions = ls.get("DefaultActions", [])
                redirects = any(
                    a.get("Type") == "redirect" and a.get("RedirectConfig", {}).get("Protocol") == "HTTPS"
                    for a in actions
                )
                if redirects:
                    continue
                yield ctx.finding(
                    title=f"ALB '{lb['LoadBalancerName']}' atende HTTP na porta {ls.get('Port')} sem redirect",
                    severity=Severity.HIGH if internet else Severity.MEDIUM,
                    pillar=Pillar.SECURITY,
                    resource_id=lb["LoadBalancerName"],
                    resource_arn=lb["LoadBalancerArn"],
                    description="Tráfego trafega em texto claro, incluindo cookies de sessão e headers de autorização.",
                    remediation="Troque a default action por redirect 301 para HTTPS e force HSTS na aplicação.",
                    evidence={"port": ls.get("Port"), "scheme": lb.get("Scheme")},
                    exposure=["internet_facing"] if internet else [],
                )
            elif ls.get("SslPolicy") in WEAK_TLS_POLICIES:
                yield ctx.finding(
                    title=f"ALB '{lb['LoadBalancerName']}' usa política TLS obsoleta",
                    severity=Severity.MEDIUM,
                    pillar=Pillar.SECURITY,
                    resource_id=lb["LoadBalancerName"],
                    resource_arn=lb["LoadBalancerArn"],
                    description=f"A policy {ls.get('SslPolicy')} ainda aceita TLS 1.0/1.1.",
                    remediation="Migre para ELBSecurityPolicy-TLS13-1-2-2021-06 após validar clientes legados.",
                    evidence={"ssl_policy": ls.get("SslPolicy"), "port": ls.get("Port")},
                    exposure=["internet_facing"] if internet else [],
                )


@check(
    "ELB.SINGLE_AZ",
    "Load balancer em uma única AZ",
    Pillar.RELIABILITY,
    "elbv2",
    well_architected="REL10-BP01",
    permissions=["elasticloadbalancing:DescribeLoadBalancers"],
)
def elb_single_az(ctx: ScanContext):
    for lb in load_balancers(ctx):
        azs = lb.get("AvailabilityZones", [])
        if len(azs) > 1:
            continue
        yield ctx.finding(
            title=f"Load balancer '{lb['LoadBalancerName']}' está em apenas 1 AZ",
            severity=Severity.HIGH,
            pillar=Pillar.RELIABILITY,
            resource_id=lb["LoadBalancerName"],
            resource_arn=lb["LoadBalancerArn"],
            description="A indisponibilidade de uma zona derruba todo o ponto de entrada do serviço.",
            remediation="Adicione subnets em pelo menos duas AZs e mantenha cross-zone load balancing ativo.",
            evidence={"zones": [z.get("ZoneName") for z in azs]},
        )


@check(
    "ELB.ACCESS_LOGS_DISABLED",
    "Load balancer sem access logs",
    Pillar.SECURITY,
    "elbv2",
    well_architected="SEC04-BP01",
    permissions=["elasticloadbalancing:DescribeLoadBalancerAttributes"],
)
def elb_logs(ctx: ScanContext):
    for lb in load_balancers(ctx):
        resp = ctx.call(
            "elbv2", "describe_load_balancer_attributes", LoadBalancerArn=lb["LoadBalancerArn"]
        )
        if not resp:
            continue
        attrs = {a["Key"]: a["Value"] for a in resp.get("Attributes", [])}
        if attrs.get("access_logs.s3.enabled") == "true":
            continue
        yield ctx.finding(
            title=f"Load balancer '{lb['LoadBalancerName']}' sem access logs",
            severity=Severity.LOW,
            pillar=Pillar.SECURITY,
            resource_id=lb["LoadBalancerName"],
            resource_arn=lb["LoadBalancerArn"],
            description="Sem logs de acesso não há análise de tráfego malicioso nem forense de requisições.",
            remediation="Ative entrega para S3 com lifecycle e consulte via Athena.",
        )


@check(
    "ELB.DROP_INVALID_HEADERS",
    "ALB aceita headers HTTP inválidos",
    Pillar.SECURITY,
    "elbv2",
    well_architected="SEC09-BP02",
    permissions=["elasticloadbalancing:DescribeLoadBalancerAttributes"],
)
def elb_drop_invalid_headers(ctx: ScanContext):
    """FSBP ELB.4 — ALB deve descartar headers HTTP inválidos (routing.http.drop_invalid_header_fields.enabled)."""
    for lb in load_balancers(ctx):
        if lb.get("Type") != "application":
            continue
        resp = ctx.call(
            "elbv2", "describe_load_balancer_attributes", LoadBalancerArn=lb["LoadBalancerArn"]
        )
        if not resp:
            continue
        attrs = {a["Key"]: a["Value"] for a in resp.get("Attributes", [])}
        if attrs.get("routing.http.drop_invalid_header_fields.enabled") == "true":
            continue
        internet = lb.get("Scheme") == "internet-facing"
        yield ctx.finding(
            title=f"ALB '{lb['LoadBalancerName']}' não descarta headers HTTP inválidos",
            severity=Severity.MEDIUM if internet else Severity.LOW,
            pillar=Pillar.SECURITY,
            resource_id=lb["LoadBalancerName"],
            resource_arn=lb["LoadBalancerArn"],
            description=(
                "Com o descarte desligado, o ALB repassa headers malformados ao backend. "
                "Isso pode ser usado para contornar WAFs e proxies que inspecionam o header "
                "original (header smuggling / desync)."
            ),
            remediation=(
                "Ative o atributo routing.http.drop_invalid_header_fields.enabled no ALB "
                "(console: Attributes > Drop invalid header fields)."
            ),
            evidence={"scheme": lb.get("Scheme")},
            exposure=["internet_facing"] if internet else [],
        )


@check(
    "ELB.NO_DELETION_PROTECTION",
    "Load balancer sem proteção contra exclusão",
    Pillar.RELIABILITY,
    "elbv2",
    well_architected="REL09-BP03",
    permissions=["elasticloadbalancing:DescribeLoadBalancerAttributes"],
)
def elb_deletion_protection(ctx: ScanContext):
    """FSBP ELB.6 — deletion protection deve estar habilitado no ALB."""
    for lb in load_balancers(ctx):
        if lb.get("Type") != "application":
            continue
        resp = ctx.call(
            "elbv2", "describe_load_balancer_attributes", LoadBalancerArn=lb["LoadBalancerArn"]
        )
        if not resp:
            continue
        attrs = {a["Key"]: a["Value"] for a in resp.get("Attributes", [])}
        if attrs.get("deletion_protection.enabled") == "true":
            continue
        yield ctx.finding(
            title=f"ALB '{lb['LoadBalancerName']}' sem deletion protection",
            severity=Severity.LOW,
            pillar=Pillar.RELIABILITY,
            resource_id=lb["LoadBalancerName"],
            resource_arn=lb["LoadBalancerArn"],
            description=(
                "Um delete acidental (console, IaC, automação) remove o ponto de entrada do "
                "serviço sem barreira adicional."
            ),
            remediation="Ative deletion_protection.enabled no ALB e proteja o recurso no IaC (prevent_destroy).",
        )
