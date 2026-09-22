"""Checks de bancos gerenciados: RDS, Aurora e DynamoDB. Escopo regional."""

from __future__ import annotations

from typing import Any, Dict, List

from ..context import ScanContext, env_exposure, tags_to_dict
from ..models import Pillar, Severity
from ..registry import check

MIN_BACKUP_DAYS = 7


def db_instances(ctx: ScanContext) -> List[Dict[str, Any]]:
    return ctx.cached(
        "rds:instances", lambda: ctx.paginate("rds", "describe_db_instances", "DBInstances")
    )


def db_clusters(ctx: ScanContext) -> List[Dict[str, Any]]:
    return ctx.cached(
        "rds:clusters", lambda: ctx.paginate("rds", "describe_db_clusters", "DBClusters")
    )


def _tags(db: Dict[str, Any]) -> Dict[str, str]:
    return tags_to_dict(db.get("TagList"))


@check(
    "RDS.PUBLICLY_ACCESSIBLE",
    "Instância RDS com IP público",
    Pillar.SECURITY,
    "rds",
    well_architected="SEC05-BP01",
    permissions=["rds:DescribeDBInstances"],
)
def rds_public(ctx: ScanContext):
    for db in db_instances(ctx):
        if not db.get("PubliclyAccessible"):
            continue
        tags = _tags(db)
        yield ctx.finding(
            title=f"RDS '{db['DBInstanceIdentifier']}' está marcado como publicamente acessível",
            severity=Severity.CRITICAL,
            pillar=Pillar.SECURITY,
            resource_id=db["DBInstanceIdentifier"],
            resource_arn=db["DBInstanceArn"],
            description=(
                "A instância recebe endereço resolvível pela internet. A exposição efetiva ainda "
                "depende do security group, mas é uma regra permissiva a um erro de distância."
            ),
            remediation=(
                "Modifique a instância para PubliclyAccessible=false, mova para subnets privadas "
                "e publique acesso apenas via bastion SSM ou VPN."
            ),
            evidence={
                "engine": db.get("Engine"),
                "endpoint": db.get("Endpoint", {}).get("Address"),
                "security_groups": [g["VpcSecurityGroupId"] for g in db.get("VpcSecurityGroups", [])],
            },
            exposure=["internet_facing", "data_store"] + env_exposure(tags),
        )


@check(
    "RDS.STORAGE_NOT_ENCRYPTED",
    "RDS sem criptografia em repouso",
    Pillar.SECURITY,
    "rds",
    well_architected="SEC08-BP02",
    permissions=["rds:DescribeDBInstances"],
)
def rds_encryption(ctx: ScanContext):
    for db in db_instances(ctx):
        if db.get("StorageEncrypted"):
            continue
        yield ctx.finding(
            title=f"RDS '{db['DBInstanceIdentifier']}' sem criptografia em repouso",
            severity=Severity.HIGH,
            pillar=Pillar.SECURITY,
            resource_id=db["DBInstanceIdentifier"],
            resource_arn=db["DBInstanceArn"],
            description=(
                "Storage, snapshots automáticos e read replicas ficam sem criptografia. "
                "Não é possível habilitar in-place."
            ),
            remediation=(
                "Snapshot > copy com KMS key > restore para nova instância > cutover com janela "
                "planejada. Avalie DMS para reduzir downtime."
            ),
            evidence={"engine": db.get("Engine"), "class": db.get("DBInstanceClass")},
            exposure=["data_store"] + env_exposure(_tags(db)),
        )


@check(
    "RDS.BACKUP_RETENTION",
    "Retenção de backup insuficiente",
    Pillar.RELIABILITY,
    "rds",
    well_architected="REL09-BP01",
    permissions=["rds:DescribeDBInstances"],
)
def rds_backups(ctx: ScanContext):
    for db in db_instances(ctx):
        retention = db.get("BackupRetentionPeriod", 0)
        if retention >= MIN_BACKUP_DAYS:
            continue
        yield ctx.finding(
            title=f"RDS '{db['DBInstanceIdentifier']}' com retenção de {retention} dia(s)",
            severity=Severity.HIGH if retention == 0 else Severity.MEDIUM,
            pillar=Pillar.RELIABILITY,
            resource_id=db["DBInstanceIdentifier"],
            resource_arn=db["DBInstanceArn"],
            description=(
                "Retenção 0 desliga backups automáticos e point-in-time recovery."
                if retention == 0
                else f"Janela de PITR de apenas {retention} dia(s): corrupção silenciosa detectada depois disso é irrecuperável."
            ),
            remediation=f"Defina BackupRetentionPeriod ≥ {MIN_BACKUP_DAYS} e centralize retenção longa no AWS Backup.",
            evidence={"retention_days": retention, "window": db.get("PreferredBackupWindow")},
            exposure=["data_store"] + env_exposure(_tags(db)),
        )


@check(
    "RDS.NO_MULTI_AZ",
    "RDS sem Multi-AZ",
    Pillar.RELIABILITY,
    "rds",
    well_architected="REL10-BP01",
    permissions=["rds:DescribeDBInstances"],
)
def rds_multi_az(ctx: ScanContext):
    cluster_members = {
        m["DBInstanceIdentifier"]
        for c in db_clusters(ctx)
        for m in c.get("DBClusterMembers", [])
    }
    for db in db_instances(ctx):
        if db.get("MultiAZ") or db["DBInstanceIdentifier"] in cluster_members:
            continue
        tags = _tags(db)
        exposure = env_exposure(tags)
        yield ctx.finding(
            title=f"RDS '{db['DBInstanceIdentifier']}' roda em AZ única",
            severity=Severity.MEDIUM if "non_production_tag" in exposure else Severity.HIGH,
            pillar=Pillar.RELIABILITY,
            resource_id=db["DBInstanceIdentifier"],
            resource_arn=db["DBInstanceArn"],
            description=(
                "Falha da AZ ou manutenção do host derruba o banco. O failover manual a partir "
                "de snapshot leva dezenas de minutos."
            ),
            remediation=(
                "Habilite Multi-AZ (conversão online, com pico de latência de escrita). "
                "Para Aurora, adicione um reader em outra AZ."
            ),
            evidence={"az": db.get("AvailabilityZone"), "class": db.get("DBInstanceClass")},
            exposure=["data_store"] + exposure,
        )


@check(
    "RDS.NO_DELETION_PROTECTION",
    "RDS sem proteção contra exclusão",
    Pillar.RELIABILITY,
    "rds",
    well_architected="REL09-BP03",
    permissions=["rds:DescribeDBInstances"],
)
def rds_deletion_protection(ctx: ScanContext):
    for db in db_instances(ctx):
        if db.get("DeletionProtection"):
            continue
        yield ctx.finding(
            title=f"RDS '{db['DBInstanceIdentifier']}' sem deletion protection",
            severity=Severity.LOW,
            pillar=Pillar.RELIABILITY,
            resource_id=db["DBInstanceIdentifier"],
            resource_arn=db["DBInstanceArn"],
            description="Um terraform destroy ou clique errado remove o banco sem barreira adicional.",
            remediation="Ative DeletionProtection e, no Terraform, use prevent_destroy no lifecycle.",
            exposure=env_exposure(_tags(db)),
        )


@check(
    "RDS.AUTO_MINOR_UPGRADE_OFF",
    "RDS sem upgrade automático de minor version",
    Pillar.SECURITY,
    "rds",
    well_architected="SEC06-BP03",
    permissions=["rds:DescribeDBInstances"],
)
def rds_minor_upgrade(ctx: ScanContext):
    for db in db_instances(ctx):
        if db.get("AutoMinorVersionUpgrade"):
            continue
        yield ctx.finding(
            title=f"RDS '{db['DBInstanceIdentifier']}' não aplica minor versions automaticamente",
            severity=Severity.LOW,
            pillar=Pillar.SECURITY,
            resource_id=db["DBInstanceIdentifier"],
            resource_arn=db["DBInstanceArn"],
            description=f"Engine {db.get('Engine')} {db.get('EngineVersion')} fica sem patches de segurança até intervenção manual.",
            remediation="Ative AutoMinorVersionUpgrade com janela de manutenção fora do horário de pico.",
            evidence={"engine_version": db.get("EngineVersion")},
        )


@check(
    "RDS.SNAPSHOT_NOT_ENCRYPTED",
    "Snapshot RDS sem criptografia",
    Pillar.SECURITY,
    "rds",
    well_architected="SEC08-BP02",
    permissions=["rds:DescribeDBSnapshots", "rds:DescribeDBClusterSnapshots"],
)
def rds_snapshot_encryption(ctx: ScanContext):
    """FSBP RDS.4 — snapshots de instância e de cluster devem ser criptografados."""
    for snap in ctx.paginate("rds", "describe_db_snapshots", "DBSnapshots", SnapshotType="manual"):
        if snap.get("Encrypted"):
            continue
        yield ctx.finding(
            title=f"Snapshot RDS '{snap['DBSnapshotIdentifier']}' sem criptografia",
            severity=Severity.HIGH,
            pillar=Pillar.SECURITY,
            resource_id=snap["DBSnapshotIdentifier"],
            resource_arn=snap["DBSnapshotArn"],
            description=(
                "Snapshots manuais herdam a criptografia da instância de origem. Um snapshot "
                "sem criptografia expõe os dados em repouso a quem tiver acesso ao bucket/backup."
            ),
            remediation=(
                "Copie o snapshot com uma CMK (rds-copy-db-snapshot --source-region) e delete o "
                "original. Para novos bancos, ative StorageEncrypted na criação."
            ),
            evidence={"engine": snap.get("Engine"), "instance": snap.get("DBInstanceIdentifier")},
            exposure=["data_store"],
        )
    for snap in ctx.paginate("rds", "describe_db_cluster_snapshots", "DBClusterSnapshots", SnapshotType="manual"):
        if snap.get("StorageEncrypted"):
            continue
        yield ctx.finding(
            title=f"Snapshot de cluster '{snap['DBClusterSnapshotIdentifier']}' sem criptografia",
            severity=Severity.HIGH,
            pillar=Pillar.SECURITY,
            resource_id=snap["DBClusterSnapshotIdentifier"],
            resource_arn=snap["DBClusterSnapshotArn"],
            description="Snapshots manuais de Aurora sem criptografia expõem os dados em repouso.",
            remediation=(
                "Copie o snapshot com uma CMK e delete o original. Para novos clusters, ative "
                "StorageEncrypted na criação."
            ),
            evidence={"engine": snap.get("Engine"), "cluster": snap.get("DBClusterIdentifier")},
            exposure=["data_store"],
        )


@check(
    "RDS.NO_IAM_AUTH",
    "RDS sem autenticação IAM",
    Pillar.SECURITY,
    "rds",
    well_architected="SEC02-BP03",
    permissions=["rds:DescribeDBInstances", "rds:DescribeDBClusters"],
)
def rds_iam_auth(ctx: ScanContext):
    """FSBP RDS.10 (instâncias) e RDS.12 (clusters) — IAM auth deve estar habilitado."""
    for db in db_instances(ctx):
        if db.get("IAMDatabaseAuthenticationEnabled"):
            continue
        yield ctx.finding(
            title=f"RDS '{db['DBInstanceIdentifier']}' sem autenticação IAM",
            severity=Severity.LOW,
            pillar=Pillar.SECURITY,
            resource_id=db["DBInstanceIdentifier"],
            resource_arn=db["DBInstanceArn"],
            description=(
                "Sem IAM auth, o acesso ao banco depende de senhas de longa duração armazenadas "
                "em configs e secrets. Com IAM auth, o cliente troca credenciais AWS por um "
                "token de banco de 15 minutos."
            ),
            remediation=(
                "Ative IAMDatabaseAuthenticationEnabled e use o driver com token gerado via "
                "rds.generate-db-auth-token (ou o proxy RDS Data API)."
            ),
            evidence={"engine": db.get("Engine")},
        )
    for cluster in db_clusters(ctx):
        if cluster.get("IAMDatabaseAuthenticationEnabled"):
            continue
        yield ctx.finding(
            title=f"Cluster RDS '{cluster['DBClusterIdentifier']}' sem autenticação IAM",
            severity=Severity.LOW,
            pillar=Pillar.SECURITY,
            resource_id=cluster["DBClusterIdentifier"],
            resource_arn=cluster["DBClusterArn"],
            description=(
                "Sem IAM auth, o acesso ao cluster depende de senhas de longa duração. "
                "Com IAM auth, o cliente troca credenciais AWS por um token de banco de 15 minutos."
            ),
            remediation=(
                "Ative IAMDatabaseAuthenticationEnabled no cluster e use o driver com token "
                "gerado via rds.generate-db-auth-token."
            ),
            evidence={"engine": cluster.get("Engine")},
        )


@check(
    "RDS.NO_COPY_TAGS_TO_SNAPSHOT",
    "RDS não copia tags para snapshots",
    Pillar.SECURITY,
    "rds",
    well_architected="SEC03-BP05",
    permissions=["rds:DescribeDBInstances", "rds:DescribeDBClusters"],
)
def rds_copy_tags(ctx: ScanContext):
    """FSBP RDS.16 (clusters) e RDS.17 (instâncias) — tags devem ser copiadas para snapshots."""
    for db in db_instances(ctx):
        if db.get("CopyTagsToSnapshot"):
            continue
        yield ctx.finding(
            title=f"RDS '{db['DBInstanceIdentifier']}' não copia tags para snapshots",
            severity=Severity.LOW,
            pillar=Pillar.SECURITY,
            resource_id=db["DBInstanceIdentifier"],
            resource_arn=db["DBInstanceArn"],
            description=(
                "Sem CopyTagsToSnapshot, os snapshots nascem sem as tags de owner/custo/ambiente "
                "da instância — dificultando governança, chargeback e localização de backups."
            ),
            remediation="Ative CopyTagsToSnapshot na instância (modify-db-instance).",
        )
    for cluster in db_clusters(ctx):
        if cluster.get("CopyTagsToSnapshot"):
            continue
        yield ctx.finding(
            title=f"Cluster RDS '{cluster['DBClusterIdentifier']}' não copia tags para snapshots",
            severity=Severity.LOW,
            pillar=Pillar.SECURITY,
            resource_id=cluster["DBClusterIdentifier"],
            resource_arn=cluster["DBClusterArn"],
            description=(
                "Sem CopyTagsToSnapshot, os snapshots do cluster nascem sem as tags de "
                "owner/custo/ambiente — dificultando governança e chargeback."
            ),
            remediation="Ative CopyTagsToSnapshot no cluster (modify-db-cluster).",
        )


@check(
    "DYNAMODB.PITR_DISABLED",
    "Tabela DynamoDB sem PITR",
    Pillar.RELIABILITY,
    "dynamodb",
    well_architected="REL09-BP01",
    permissions=["dynamodb:ListTables", "dynamodb:DescribeContinuousBackups"],
)
def ddb_pitr(ctx: ScanContext):
    tables = ctx.cached(
        "ddb:tables", lambda: ctx.paginate("dynamodb", "list_tables", "TableNames")
    )
    for name in tables:
        resp = ctx.call("dynamodb", "describe_continuous_backups", TableName=name)
        if not resp:
            continue
        status = (
            resp["ContinuousBackupsDescription"]
            .get("PointInTimeRecoveryDescription", {})
            .get("PointInTimeRecoveryStatus")
        )
        if status == "ENABLED":
            continue
        yield ctx.finding(
            title=f"Tabela DynamoDB '{name}' sem point-in-time recovery",
            severity=Severity.MEDIUM,
            pillar=Pillar.RELIABILITY,
            resource_id=name,
            resource_arn=ctx.arn("dynamodb", f"table/{name}"),
            description="Sem PITR não há restauração para um instante anterior após escrita ou delete indevido.",
            remediation="Ative PITR (35 dias de janela). O custo é proporcional ao tamanho da tabela.",
            exposure=["data_store"],
        )


@check(
    "DYNAMODB.NO_AUTOSCALING",
    "Tabela DynamoDB sem auto scaling",
    Pillar.RELIABILITY,
    "dynamodb",
    well_architected="REL13-BP02",
    permissions=["dynamodb:ListTables", "dynamodb:DescribeTable"],
)
def ddb_autoscaling(ctx: ScanContext):
    """FSBP DynamoDB.1 — tabelas devem escalar capacidade com a demanda (soft enforcement)."""
    tables = ctx.cached(
        "ddb:tables", lambda: ctx.paginate("dynamodb", "list_tables", "TableNames")
    )
    for name in tables:
        resp = ctx.call("dynamodb", "describe_table", TableName=name)
        if not resp:
            continue
        table = resp["Table"]
        if table.get("BillingModeSummary", {}).get("BillingMode") == "PAY_PER_REQUEST":
            continue  # on-demand escala sozinho; sem necessidade de auto scaling
        provisioned = table.get("ProvisionedThroughput", {})
        if provisioned.get("ReadCapacityUnits") and provisioned.get("WriteCapacityUnits"):
            continue  # provisioned com capacidade definida — auto scaling é configurado via Application Auto Scaling
        yield ctx.finding(
            title=f"Tabela DynamoDB '{name}' provisionada sem capacidade definida",
            severity=Severity.LOW,
            pillar=Pillar.RELIABILITY,
            resource_id=name,
            resource_arn=ctx.arn("dynamodb", f"table/{name}"),
            description=(
                "A tabela usa billing provisioned, mas sem capacidade mínima/máxima definida "
                "não há como o Application Auto Scaling ajustar a capacidade com a demanda."
            ),
            remediation=(
                "Defina ReadCapacityUnits/WriteCapacityUnits e configure auto scaling via "
                "Application Auto Scaling (ou migre para on-demand se o tráfego for imprevisível)."
            ),
            evidence={"billing_mode": table.get("BillingModeSummary", {}).get("BillingMode")},
            exposure=["data_store"],
        )
