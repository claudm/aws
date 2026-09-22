"""Testes com botocore Stubber: validam a lógica dos checks contra o formato
real de resposta das APIs, sem tocar em nenhuma conta AWS.

    python3 -m pytest tests/ -q
"""

from __future__ import annotations

import datetime as dt

import boto3
import pytest
from botocore.stub import ANY, Stubber

from scanstacktestcloud.checks import (
    cloudfront,
    compute,
    cost,
    databases,
    ec2,
    iam,
    sns,
    sqs,
)
from scanstacktestcloud.context import ScanContext, SessionFactory
from scanstacktestcloud.models import Severity
from scanstacktestcloud.registry import all_checks, select


def make_ctx(region="us-east-1"):
    ctx = ScanContext.__new__(ScanContext)
    ctx.factory = None
    ctx.account_id = "123456789012"
    ctx.region = region
    ctx.partition = "aws"
    ctx.account_alias = "test"
    ctx.all_regions = [region]
    ctx.session = boto3.Session(
        aws_access_key_id="test", aws_secret_access_key="test", region_name=region
    )
    ctx._clients = {}
    ctx._cache = {}
    ctx.resources_seen = 0
    ctx.current_check = None
    return ctx


def attach(ctx, service, client):
    ctx._clients[f"{service}:{ctx.region}"] = client
    return client


def stub(ctx, service):
    client = ctx.session.client(service, region_name=ctx.region)
    attach(ctx, service, client)
    return client, Stubber(client)


# ----------------------------------------------------------------- registry
def test_check_ids_are_unique():
    ids = [c.id for c in all_checks()]
    assert len(ids) == len(set(ids))


def test_every_check_declares_permissions():
    missing = [c.id for c in all_checks() if not c.permissions]
    assert not missing, f"checks sem permissões declaradas: {missing}"


def test_scan_role_covers_all_check_permissions():
    """Toda permissão declarada nos checks precisa existir na role de deploy.

    A role usa as managed policies SecurityAudit + ViewOnlyAccess, que cobrem a
    maioria das permissões de leitura. O bloco PostureScanExtras cobre o resto.
    Este teste garante que nenhuma permissão de check fique sem cobertura.
    """
    import yaml
    from pathlib import Path

    class _CfnLoader(yaml.SafeLoader):
        pass

    def _multi(loader, tag_suffix, node):
        return tag_suffix

    _CfnLoader.add_multi_constructor("!", _multi)

    role_path = Path(__file__).parent.parent / "deploy" / "scan-role.yaml"
    doc = yaml.load(role_path.read_text(encoding="utf-8"), Loader=_CfnLoader)
    policies = doc["Resources"]["ScanRole"]["Properties"]["Policies"]
    allowed = set()
    for pol in policies:
        for st in pol["PolicyDocument"]["Statement"]:
            if st.get("Effect") == "Allow":
                allowed.update(st["Action"])

    # Permissões cobertas pelas managed policies SecurityAudit + ViewOnlyAccess.
    # Se um check novo precisar de algo fora daqui, adicione ao PostureScanExtras.
    managed_covered = {
        "budgets:DescribeBudgets",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "config:DescribeConfigurationRecorderStatus",
        "dynamodb:DescribeContinuousBackups",
        "ec2:DescribeAddresses",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeInstances",
        "ec2:DescribeNatGateways",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshotAttribute",
        "ec2:DescribeSnapshots",
        "ec2:DescribeVolumes",
        "ec2:DescribeVpcs",
        "ecr:DescribeRepositories",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "guardduty:ListDetectors",
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:GetPolicyVersion",
        "iam:ListPolicies",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "kms:ListKeys",
        "lambda:GetFunctionEventInvokeConfig",
        "lambda:ListFunctions",
        "s3:GetBucketAcl",
        "s3:GetBucketLogging",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:GetEncryptionConfiguration",
        "s3:GetLifecycleConfiguration",
        "secretsmanager:ListSecrets",
    }

    missing = {}
    for c in all_checks():
        for perm in c.permissions:
            if perm not in allowed and perm not in managed_covered:
                missing.setdefault(c.id, []).append(perm)
    assert not missing, f"permissões sem cobertura na role: {missing}"


def test_select_filters_by_pillar():
    assert all(c.pillar.value == "cost_optimization" for c in select(pillars=["cost_optimization"]))


# ------------------------------------------------------------------ ec2/sg
def test_sg_open_ssh_is_critical_when_attached():
    ctx = make_ctx()
    client, stubber = stub(ctx, "ec2")
    stubber.add_response(
        "describe_security_groups",
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-01",
                    "GroupName": "web",
                    "VpcId": "vpc-01",
                    "OwnerId": "123456789012",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                            "Ipv6Ranges": [],
                            "UserIdGroupPairs": [],
                        }
                    ],
                    "IpPermissionsEgress": [],
                }
            ]
        },
        {},
    )
    stubber.add_response("describe_instances", {"Reservations": []}, {})
    stubber.add_response(
        "describe_network_interfaces",
        {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-1", "Groups": [{"GroupId": "sg-01"}]}]},
        {},
    )
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "EC2.SG_OPEN_SENSITIVE_PORT")
        findings = list(ec2.sg_open_ports(ctx))

    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.CRITICAL  # SG em uso => risco real
    assert "SSH" in f.title
    assert f.risk_score == 100.0


def test_sg_open_port_unattached_is_downgraded():
    ctx = make_ctx()
    client, stubber = stub(ctx, "ec2")
    stubber.add_response(
        "describe_security_groups",
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-02",
                    "GroupName": "legacy",
                    "VpcId": "vpc-01",
                    "OwnerId": "123456789012",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 3389,
                            "ToPort": 3389,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                    "IpPermissionsEgress": [],
                }
            ]
        },
        {},
    )
    stubber.add_response("describe_instances", {"Reservations": []}, {})
    stubber.add_response("describe_network_interfaces", {"NetworkInterfaces": []}, {})
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "EC2.SG_OPEN_SENSITIVE_PORT")
        findings = list(ec2.sg_open_ports(ctx))

    assert findings[0].severity is Severity.HIGH


def test_sg_internal_cidr_is_not_flagged():
    ctx = make_ctx()
    client, stubber = stub(ctx, "ec2")
    stubber.add_response(
        "describe_security_groups",
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-03",
                    "GroupName": "db",
                    "VpcId": "vpc-01",
                    "OwnerId": "123456789012",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 5432,
                            "ToPort": 5432,
                            "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
                        }
                    ],
                    "IpPermissionsEgress": [],
                }
            ]
        },
        {},
    )
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "EC2.SG_OPEN_SENSITIVE_PORT")
        assert list(ec2.sg_open_ports(ctx)) == []


def test_imdsv1_with_instance_profile_is_high():
    ctx = make_ctx()
    client, stubber = stub(ctx, "ec2")
    stubber.add_response(
        "describe_instances",
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-0abc",
                            "InstanceType": "m5.large",
                            "State": {"Name": "running"},
                            "MetadataOptions": {"HttpTokens": "optional", "HttpEndpoint": "enabled"},
                            "IamInstanceProfile": {"Arn": "arn:aws:iam::123456789012:instance-profile/app"},
                            "Tags": [{"Key": "Environment", "Value": "production"}],
                        }
                    ]
                }
            ]
        },
        {},
    )
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "EC2.IMDSV2_NOT_REQUIRED")
        findings = list(ec2.imdsv2(ctx))

    assert findings[0].severity is Severity.HIGH
    assert "privileged_identity" in findings[0].exposure
    assert "production_tag" in findings[0].exposure


# --------------------------------------------------------------------- rds
def test_rds_public_instance_is_critical():
    ctx = make_ctx()
    client, stubber = stub(ctx, "rds")
    stubber.add_response(
        "describe_db_instances",
        {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "core-db",
                    "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:core-db",
                    "Engine": "postgres",
                    "PubliclyAccessible": True,
                    "StorageEncrypted": True,
                    "BackupRetentionPeriod": 7,
                    "MultiAZ": True,
                    "Endpoint": {"Address": "core-db.abc.us-east-1.rds.amazonaws.com", "Port": 5432},
                    "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-01", "Status": "active"}],
                    "TagList": [{"Key": "Environment", "Value": "production"}],
                }
            ]
        },
        {},
    )
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "RDS.PUBLICLY_ACCESSIBLE")
        findings = list(databases.rds_public(ctx))

    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].resource_arn.endswith("db:core-db")


def test_rds_backup_retention_zero_is_high():
    ctx = make_ctx()
    client, stubber = stub(ctx, "rds")
    stubber.add_response(
        "describe_db_instances",
        {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "scratch",
                    "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:scratch",
                    "BackupRetentionPeriod": 0,
                    "TagList": [],
                }
            ]
        },
        {},
    )
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "RDS.BACKUP_RETENTION")
        findings = list(databases.rds_backups(ctx))

    assert findings[0].severity is Severity.HIGH


# -------------------------------------------------------------------- cost
def test_unattached_volume_estimates_monthly_cost():
    ctx = make_ctx()
    client, stubber = stub(ctx, "ec2")
    stubber.add_response(
        "describe_volumes",
        {
            "Volumes": [
                {
                    "VolumeId": "vol-01",
                    "Size": 500,
                    "VolumeType": "gp3",
                    "State": "available",
                    "Encrypted": True,
                    "CreateTime": dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc),
                    "Attachments": [],
                    "Tags": [],
                    "AvailabilityZone": "us-east-1a",
                }
            ]
        },
        {},
    )
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "COST.EBS_UNATTACHED")
        findings = list(cost.unattached_volumes(ctx))

    assert findings[0].monthly_waste_usd == pytest.approx(40.0)  # 500 GiB * US$0,08
    assert findings[0].severity is Severity.MEDIUM


def test_attached_volume_is_ignored_by_cost_check():
    ctx = make_ctx()
    client, stubber = stub(ctx, "ec2")
    stubber.add_response(
        "describe_volumes",
        {
            "Volumes": [
                {
                    "VolumeId": "vol-02",
                    "Size": 100,
                    "VolumeType": "gp3",
                    "State": "in-use",
                    "Encrypted": True,
                    "Attachments": [{"InstanceId": "i-1", "State": "attached"}],
                    "AvailabilityZone": "us-east-1a",
                }
            ]
        },
        {},
    )
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "COST.EBS_UNATTACHED")
        assert list(cost.unattached_volumes(ctx)) == []


# ------------------------------------------------------------------ lambda
def test_lambda_secret_heuristic_ignores_arn_references():
    ctx = make_ctx()
    client, stubber = stub(ctx, "lambda")
    stubber.add_response(
        "list_functions",
        {
            "Functions": [
                {
                    "FunctionName": "billing",
                    "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:billing",
                    "Runtime": "python3.12",
                    "Environment": {
                        "Variables": {
                            "DB_PASSWORD": "hunter2",
                            "API_KEY_ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:k",
                            "LOG_LEVEL": "info",
                        }
                    },
                }
            ]
        },
        {},
    )
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "LAMBDA.PLAINTEXT_SECRET")
        findings = list(compute.plaintext_secret(ctx))

    assert findings[0].evidence["suspect_keys"] == ["DB_PASSWORD"]
    # O valor do segredo nunca é copiado para o finding.
    assert "hunter2" not in str(findings[0].to_dict())


# --------------------------------------------------------------------- iam
def test_wildcard_policy_detection():
    assert iam._policy_is_wildcard_admin(
        {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    )
    assert not iam._policy_is_wildcard_admin(
        {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
    )
    # Wildcard com condição (ex.: restrição por região/MFA) não é admin irrestrito.
    assert not iam._policy_is_wildcard_admin(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:RequestedRegion": "sa-east-1"}},
                }
            ]
        }
    )


def test_root_mfa_missing_is_critical():
    ctx = make_ctx()
    client, stubber = stub(ctx, "iam")
    stubber.add_response(
        "get_account_summary",
        {"SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 0}},
        {},
    )
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "IAM.ROOT_MFA_DISABLED")
        findings = list(iam.root_mfa(ctx))

    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].region == "global"


# ------------------------------------------------------------- elb (FSBP)
def test_elb_drop_invalid_headers_disabled_is_flagged():
    ctx = make_ctx()
    client, stubber = stub(ctx, "elbv2")
    lb_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web-alb/abc"
    stubber.add_response(
        "describe_load_balancers",
        {
            "LoadBalancers": [
                {
                    "LoadBalancerName": "web-alb",
                    "LoadBalancerArn": lb_arn,
                    "Type": "application",
                    "Scheme": "internet-facing",
                    "AvailabilityZones": [{"ZoneName": "us-east-1a"}, {"ZoneName": "us-east-1b"}],
                }
            ]
        },
        {},
    )
    stubber.add_response(
        "describe_load_balancer_attributes",
        {"Attributes": [{"Key": "routing.http.drop_invalid_header_fields.enabled", "Value": "false"}]},
        {"LoadBalancerArn": lb_arn},
    )
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "ELB.DROP_INVALID_HEADERS")
        findings = list(compute.elb_drop_invalid_headers(ctx))

    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert "internet_facing" in findings[0].exposure


def test_elb_drop_invalid_headers_enabled_is_ok():
    ctx = make_ctx()
    client, stubber = stub(ctx, "elbv2")
    lb_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web-alb/abc"
    stubber.add_response(
        "describe_load_balancers",
        {
            "LoadBalancers": [
                {
                    "LoadBalancerName": "web-alb",
                    "LoadBalancerArn": lb_arn,
                    "Type": "application",
                    "Scheme": "internal",
                    "AvailabilityZones": [{"ZoneName": "us-east-1a"}, {"ZoneName": "us-east-1b"}],
                }
            ]
        },
        {},
    )
    stubber.add_response(
        "describe_load_balancer_attributes",
        {"Attributes": [{"Key": "routing.http.drop_invalid_header_fields.enabled", "Value": "true"}]},
        {"LoadBalancerArn": lb_arn},
    )
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "ELB.DROP_INVALID_HEADERS")
        assert list(compute.elb_drop_invalid_headers(ctx)) == []


def test_elb_deletion_protection_disabled_is_flagged():
    ctx = make_ctx()
    client, stubber = stub(ctx, "elbv2")
    lb_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web-alb/abc"
    stubber.add_response(
        "describe_load_balancers",
        {
            "LoadBalancers": [
                {
                    "LoadBalancerName": "web-alb",
                    "LoadBalancerArn": lb_arn,
                    "Type": "application",
                    "Scheme": "internet-facing",
                    "AvailabilityZones": [{"ZoneName": "us-east-1a"}, {"ZoneName": "us-east-1b"}],
                }
            ]
        },
        {},
    )
    stubber.add_response(
        "describe_load_balancer_attributes",
        {"Attributes": [{"Key": "deletion_protection.enabled", "Value": "false"}]},
        {"LoadBalancerArn": lb_arn},
    )
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "ELB.NO_DELETION_PROTECTION")
        findings = list(compute.elb_deletion_protection(ctx))

    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW


# ------------------------------------------------------------- rds (FSBP)
def test_rds_snapshot_unencrypted_is_high():
    ctx = make_ctx()
    client, stubber = stub(ctx, "rds")
    stubber.add_response(
        "describe_db_snapshots",
        {
            "DBSnapshots": [
                {
                    "DBSnapshotIdentifier": "manual-snap-1",
                    "DBSnapshotArn": "arn:aws:rds:us-east-1:123456789012:snapshot:manual-snap-1",
                    "Engine": "postgres",
                    "DBInstanceIdentifier": "core-db",
                    "Encrypted": False,
                }
            ]
        },
        {"SnapshotType": "manual"},
    )
    stubber.add_response("describe_db_cluster_snapshots", {"DBClusterSnapshots": []}, {"SnapshotType": "manual"})
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "RDS.SNAPSHOT_NOT_ENCRYPTED")
        findings = list(databases.rds_snapshot_encryption(ctx))

    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "data_store" in findings[0].exposure


def test_rds_iam_auth_disabled_is_flagged():
    ctx = make_ctx()
    client, stubber = stub(ctx, "rds")
    stubber.add_response(
        "describe_db_instances",
        {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "core-db",
                    "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:core-db",
                    "Engine": "postgres",
                    "IAMDatabaseAuthenticationEnabled": False,
                }
            ]
        },
        {},
    )
    stubber.add_response("describe_db_clusters", {"DBClusters": []}, {})
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "RDS.NO_IAM_AUTH")
        findings = list(databases.rds_iam_auth(ctx))

    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW


def test_rds_copy_tags_disabled_is_flagged():
    ctx = make_ctx()
    client, stubber = stub(ctx, "rds")
    stubber.add_response(
        "describe_db_instances",
        {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "core-db",
                    "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:core-db",
                    "CopyTagsToSnapshot": False,
                }
            ]
        },
        {},
    )
    stubber.add_response("describe_db_clusters", {"DBClusters": []}, {})
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "RDS.NO_COPY_TAGS_TO_SNAPSHOT")
        findings = list(databases.rds_copy_tags(ctx))

    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW


# ---------------------------------------------------------- dynamodb (FSBP)
def test_ddb_provisioned_without_capacity_is_flagged():
    ctx = make_ctx()
    client, stubber = stub(ctx, "dynamodb")
    stubber.add_response(
        "list_tables", {"TableNames": ["orders"]}, {}
    )
    stubber.add_response(
        "describe_table",
        {
            "Table": {
                "TableName": "orders",
                "BillingModeSummary": {"BillingMode": "PROVISIONED"},
                "ProvisionedThroughput": {},
            }
        },
        {"TableName": "orders"},
    )
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "DYNAMODB.NO_AUTOSCALING")
        findings = list(databases.ddb_autoscaling(ctx))

    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW


def test_ddb_on_demand_is_not_flagged():
    ctx = make_ctx()
    client, stubber = stub(ctx, "dynamodb")
    stubber.add_response(
        "list_tables", {"TableNames": ["orders"]}, {}
    )
    stubber.add_response(
        "describe_table",
        {
            "Table": {
                "TableName": "orders",
                "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
                "ProvisionedThroughput": {},
            }
        },
        {"TableName": "orders"},
    )
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "DYNAMODB.NO_AUTOSCALING")
        assert list(databases.ddb_autoscaling(ctx)) == []


# ------------------------------------------------------------------- sns
def test_sns_topic_without_kms_is_flagged():
    ctx = make_ctx()
    client, stubber = stub(ctx, "sns")
    topic_arn = "arn:aws:sns:us-east-1:123456789012:alerts"
    stubber.add_response(
        "list_topics",
        {"Topics": [{"TopicArn": topic_arn}]},
        {},
    )
    stubber.add_response(
        "get_topic_attributes",
        {"Attributes": {"DisplayName": "alerts", "TopicArn": topic_arn}},
        {"TopicArn": topic_arn},
    )
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "SNS.NOT_ENCRYPTED")
        findings = list(sns.sns_encryption(ctx))

    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].resource_id == "alerts"


def test_sns_topic_with_kms_is_ok():
    ctx = make_ctx()
    client, stubber = stub(ctx, "sns")
    topic_arn = "arn:aws:sns:us-east-1:123456789012:alerts"
    stubber.add_response(
        "list_topics",
        {"Topics": [{"TopicArn": topic_arn}]},
        {},
    )
    stubber.add_response(
        "get_topic_attributes",
        {
            "Attributes": {
                "KmsMasterKeyId": "arn:aws:kms:us-east-1:123456789012:key/abc",
                "TopicArn": topic_arn,
            }
        },
        {"TopicArn": topic_arn},
    )
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "SNS.NOT_ENCRYPTED")
        assert list(sns.sns_encryption(ctx)) == []


# ------------------------------------------------------------------- sqs
def test_sqs_queue_without_kms_is_flagged():
    ctx = make_ctx()
    client, stubber = stub(ctx, "sqs")
    queue_url = "https://sqs.us-east-1.amazonaws.com/123456789012/jobs"
    stubber.add_response(
        "list_queues",
        {"QueueUrls": [queue_url]},
        {},
    )
    stubber.add_response(
        "get_queue_attributes",
        {"Attributes": {"VisibilityTimeout": "30", "QueueArn": "arn:aws:sqs:us-east-1:123456789012:jobs"}},
        {"QueueUrl": queue_url, "AttributeNames": ["All"]},
    )
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "SQS.NOT_ENCRYPTED")
        findings = list(sqs.sqs_encryption(ctx))

    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].resource_id == "jobs"


def test_sqs_queue_with_kms_is_ok():
    ctx = make_ctx()
    client, stubber = stub(ctx, "sqs")
    queue_url = "https://sqs.us-east-1.amazonaws.com/123456789012/jobs"
    stubber.add_response(
        "list_queues",
        {"QueueUrls": [queue_url]},
        {},
    )
    stubber.add_response(
        "get_queue_attributes",
        {
            "Attributes": {
                "KmsMasterKeyId": "arn:aws:kms:us-east-1:123456789012:key/abc",
                "QueueArn": "arn:aws:sqs:us-east-1:123456789012:jobs",
            }
        },
        {"QueueUrl": queue_url, "AttributeNames": ["All"]},
    )
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "SQS.NOT_ENCRYPTED")
        assert list(sqs.sqs_encryption(ctx)) == []


# ------------------------------------------------------------- cloudfront
def _cf_dist_item(web_acl_id="", root_object="index.html", logging_enabled=True):
    """Item válido de DistributionList (shape do botocore)."""
    return {
        "Id": "E1234567890",
        "ARN": "arn:aws:cloudfront::123456789012:distribution/E1234567890",
        "Status": "Deployed",
        "LastModifiedTime": dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc),
        "DomainName": "d123.cloudfront.net",
        "Aliases": {"Quantity": 0, "Items": []},
        "Origins": {"Quantity": 1, "Items": [{"Id": "origin-1", "DomainName": "origin.example.com"}]},
        "OriginGroups": {"Quantity": 0},
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin-1",
            "ViewerProtocolPolicy": "redirect-to-https",
            "AllowedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"], "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]}},
            "SmoothStreaming": False,
            "Compress": True,
            "LambdaFunctionAssociations": {"Quantity": 0},
            "FunctionAssociations": {"Quantity": 0},
            "FieldLevelEncryptionId": "",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",
            "OriginRequestPolicyId": "88a5eaf4-2fd4-4709-b370-b4c650ea3fcf",
        },
        "CacheBehaviors": {"Quantity": 0},
        "CustomErrorResponses": {"Quantity": 0},
        "Comment": "",
        "PriceClass": "PriceClass_All",
        "Enabled": True,
        "ViewerCertificate": {"CloudFrontDefaultCertificate": True, "MinimumProtocolVersion": "TLSv1.2_2021", "CertificateSource": "cloudfront"},
        "Restrictions": {"GeoRestriction": {"RestrictionType": "none", "Quantity": 0}},
        "WebACLId": web_acl_id,
        "HttpVersion": "HTTP2",
        "IsIPV6Enabled": True,
        "Staging": False,
    }


def _cf_full_config(root_object="index.html", logging_enabled=True):
    """DistributionConfig completo (shape do get_distribution)."""
    return {
        "CallerReference": "ref-1",
        "Aliases": {"Quantity": 0, "Items": []},
        "DefaultRootObject": root_object,
        "Origins": {"Quantity": 1, "Items": [{"Id": "origin-1", "DomainName": "origin.example.com"}]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin-1",
            "ViewerProtocolPolicy": "redirect-to-https",
            "AllowedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"], "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]}},
            "SmoothStreaming": False,
            "Compress": True,
            "LambdaFunctionAssociations": {"Quantity": 0},
            "FunctionAssociations": {"Quantity": 0},
            "FieldLevelEncryptionId": "",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",
            "OriginRequestPolicyId": "88a5eaf4-2fd4-4709-b370-b4c650ea3fcf",
        },
        "CacheBehaviors": {"Quantity": 0},
        "CustomErrorResponses": {"Quantity": 0},
        "Comment": "",
        "Logging": {"Enabled": logging_enabled, "IncludeCookies": False, "Bucket": "logs-bucket.s3.amazonaws.com" if logging_enabled else ""},
        "PriceClass": "PriceClass_All",
        "Enabled": True,
        "ViewerCertificate": {"CloudFrontDefaultCertificate": True, "MinimumProtocolVersion": "TLSv1.2_2021", "CertificateSource": "cloudfront"},
        "Restrictions": {"GeoRestriction": {"RestrictionType": "none", "Quantity": 0}},
        "HttpVersion": "HTTP2",
        "IsIPV6Enabled": True,
    }


def test_cf_distribution_without_waf_is_flagged():
    ctx = make_ctx()
    client, stubber = stub(ctx, "cloudfront")
    stubber.add_response(
        "list_distributions",
        {"DistributionList": {"Marker": "", "MaxItems": 100, "IsTruncated": False, "Quantity": 1, "Items": [_cf_dist_item()]}},
        {"MaxItems": "100"},
    )
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "CLOUDFRONT.NO_WAF")
        findings = list(cloudfront.cf_waf(ctx))

    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].region == "global"
    assert "internet_facing" in findings[0].exposure


def test_cf_distribution_with_waf_is_ok():
    ctx = make_ctx()
    client, stubber = stub(ctx, "cloudfront")
    stubber.add_response(
        "list_distributions",
        {
            "DistributionList": {
                "Marker": "",
                "MaxItems": 100,
                "IsTruncated": False,
                "Quantity": 1,
                "Items": [_cf_dist_item(web_acl_id="arn:aws:wafv2:us-east-1:123456789012:regional/webacl/main/abc")],
            }
        },
        {"MaxItems": "100"},
    )
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "CLOUDFRONT.NO_WAF")
        assert list(cloudfront.cf_waf(ctx)) == []


def test_cf_distribution_without_root_object_is_flagged():
    ctx = make_ctx()
    client, stubber = stub(ctx, "cloudfront")
    stubber.add_response(
        "list_distributions",
        {"DistributionList": {"Marker": "", "MaxItems": 100, "IsTruncated": False, "Quantity": 1, "Items": [_cf_dist_item()]}},
        {"MaxItems": "100"},
    )
    stubber.add_response(
        "get_distribution",
        {
            "Distribution": {
                "Id": "E1234567890",
                "ARN": "arn:aws:cloudfront::123456789012:distribution/E1234567890",
                "Status": "Deployed",
                "LastModifiedTime": dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc),
                "InProgressInvalidationBatches": 0,
                "DomainName": "d123.cloudfront.net",
                "ActiveTrustedSigners": {"Enabled": False, "Quantity": 0},
                "ActiveTrustedKeyGroups": {"Enabled": False, "Quantity": 0},
                "DistributionConfig": _cf_full_config(root_object=""),
            }
        },
        {"Id": "E1234567890"},
    )
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "CLOUDFRONT.NO_ROOT_OBJECT")
        findings = list(cloudfront.cf_root_object(ctx))

    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW


def test_cf_distribution_without_logging_is_flagged():
    ctx = make_ctx()
    client, stubber = stub(ctx, "cloudfront")
    stubber.add_response(
        "list_distributions",
        {"DistributionList": {"Marker": "", "MaxItems": 100, "IsTruncated": False, "Quantity": 1, "Items": [_cf_dist_item()]}},
        {"MaxItems": "100"},
    )
    stubber.add_response(
        "get_distribution",
        {
            "Distribution": {
                "Id": "E1234567890",
                "ARN": "arn:aws:cloudfront::123456789012:distribution/E1234567890",
                "Status": "Deployed",
                "LastModifiedTime": dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc),
                "InProgressInvalidationBatches": 0,
                "DomainName": "d123.cloudfront.net",
                "ActiveTrustedSigners": {"Enabled": False, "Quantity": 0},
                "ActiveTrustedKeyGroups": {"Enabled": False, "Quantity": 0},
                "DistributionConfig": _cf_full_config(logging_enabled=False),
            }
        },
        {"Id": "E1234567890"},
    )
    with stubber:
        ctx.current_check = next(c for c in all_checks() if c.id == "CLOUDFRONT.NO_LOGGING")
        findings = list(cloudfront.cf_logging(ctx))

    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
