# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "pentest" {
  name              = "/securityagent/${var.name}-pentest"
  retention_in_days = var.log_retention_days
}

# O Security Agent restringe a sessao da role do web app a este namespace para
# ler os logs de task.
resource "aws_cloudwatch_log_group" "pentest_session" {
  name              = "/aws/securityagent/${var.name}-pentest"
  retention_in_days = var.log_retention_days
}

# ---------------------------------------------------------------------------
# Application — bootstrap de conta, uma por conta. Os Agent Spaces vivem sob ela.
# ---------------------------------------------------------------------------

resource "awscc_securityagent_application" "this" {
  role_arn = aws_iam_role.app.arn
  tags     = local.tags

  depends_on = [time_sleep.iam_propagation]
}

# ---------------------------------------------------------------------------
# Target domains
# ---------------------------------------------------------------------------

resource "awscc_securityagent_target_domain" "this" {
  for_each = toset(var.target_domains)

  target_domain_name  = each.value
  verification_method = "DNS_TXT"
  tags                = local.tags
}

data "aws_route53_zone" "this" {
  count = var.route53_zone_name == "" ? 0 : 1

  name         = var.route53_zone_name
  private_zone = false
}

# O token do desafio e atributo computed, entao o TXT sai no mesmo apply.
resource "aws_route53_record" "verification" {
  for_each = var.route53_zone_name == "" ? {} : awscc_securityagent_target_domain.this

  zone_id = data.aws_route53_zone.this[0].zone_id
  name    = each.value.verification_details.dns_txt.dns_record_name
  type    = each.value.verification_details.dns_txt.dns_record_type
  ttl     = 60
  records = [each.value.verification_details.dns_txt.token]
}

# Nao existe recurso para VerifyTargetDomain e o servico nao consulta o DNS
# sozinho — e preciso chamar a operacao depois de publicar o TXT.
resource "terraform_data" "verify_domain" {
  for_each = var.route53_zone_name == "" ? {} : awscc_securityagent_target_domain.this

  triggers_replace = [each.value.target_domain_id]

  provisioner "local-exec" {
    interpreter = ["/bin/sh", "-c"]

    command = <<-EOT
      sleep 10
      for i in 1 2 3 4 5 6; do
        status=$(aws securityagent verify-target-domain \
          --region ${var.region} \
          --target-domain-id "${each.value.target_domain_id}" \
          --query status --output text 2>&1)
        [ "$status" = "VERIFIED" ] && exit 0
        echo "tentativa $i: ${each.value.target_domain_name} status=$status"
        sleep 20
      done
      echo "dominio nao chegou a VERIFIED"
      exit 1
    EOT
  }

  depends_on = [aws_route53_record.verification]
}

# ---------------------------------------------------------------------------
# Agent Space
# ---------------------------------------------------------------------------

resource "awscc_securityagent_agent_space" "this" {
  name        = var.agent_space_name
  description = var.agent_space_description
  kms_key_id  = var.kms_key_id == "" ? null : var.kms_key_id
  tags        = local.tags

  target_domain_ids = [for d in awscc_securityagent_target_domain.this : d.target_domain_id]

  # A service role precisa estar registrada aqui antes de o pentest referencia-la,
  # senao vem "not found in agent instance IAM roles".
  aws_resources = {
    iam_roles = [aws_iam_role.pentest.arn]

    log_groups = [
      aws_cloudwatch_log_group.pentest.arn,
      aws_cloudwatch_log_group.pentest_session.arn,
    ]

    s3_buckets  = [data.aws_s3_bucket.artifacts.arn]
    secret_arns = [for s in aws_secretsmanager_secret.actor : s.arn]
    vpcs        = local.vpcs
  }

  depends_on = [awscc_securityagent_application.this]
}

# ---------------------------------------------------------------------------
# Artefatos de contexto (upload direto, sem passar pelo S3 do app)
# ---------------------------------------------------------------------------

resource "awscc_securityagent_artifact" "this" {
  for_each = local.artifacts

  agent_space_id   = awscc_securityagent_agent_space.this.agent_space_id
  file_name        = each.key
  artifact_type    = each.value.artifact_type
  artifact_content = filebase64(each.value.path)
}

# ---------------------------------------------------------------------------
# Pentest
# ---------------------------------------------------------------------------

resource "awscc_securityagent_pentest" "this" {
  count = var.create_pentest ? 1 : 0

  agent_space_id = awscc_securityagent_agent_space.this.agent_space_id
  title          = var.pentest_title
  service_role   = aws_iam_role.pentest.arn

  code_remediation_strategy = var.code_remediation_strategy
  clean_up_strategy         = var.clean_up_strategy
  exclude_risk_types        = length(var.exclude_risk_types) == 0 ? null : var.exclude_risk_types

  assets = merge(
    { endpoints = [for uri in var.pentest_endpoints : { uri = uri }] },

    length(var.actors) == 0 ? {} : {
      actors = [for a in var.actors : {
        identifier  = a.identifier
        description = a.description
        uris        = a.uris

        authentication = {
          provider_type = "SECRETS_MANAGER"
          value         = aws_secretsmanager_secret.actor[a.identifier].arn
        }
      }]
    },

    length([for a in var.artifacts : a if a.as_document]) == 0 ? {} : {
      documents = [
        for k, a in local.artifacts : { artifact_id = awscc_securityagent_artifact.this[k].artifact_id }
        if a.as_document
      ]
    },
  )

  log_config = {
    log_group  = aws_cloudwatch_log_group.pentest.name
    log_stream = var.name
  }

  vpc_config = var.vpc_config == null ? null : {
    vpc_arn             = local.vpcs[0].vpc_arn
    subnet_arns         = local.vpcs[0].subnet_arns
    security_group_arns = local.vpcs[0].security_group_arns
  }

  depends_on = [
    terraform_data.verify_domain,
    aws_secretsmanager_secret_version.actor,
  ]
}

# StartPentestJob nao tem recurso em lugar nenhum — e operacao, nao estado.
resource "terraform_data" "start_pentest_job" {
  count = var.create_pentest && var.start_pentest_job ? 1 : 0

  triggers_replace = [awscc_securityagent_pentest.this[0].pentest_id]

  provisioner "local-exec" {
    interpreter = ["/bin/sh", "-c"]

    command = <<-EOT
      aws securityagent start-pentest-job \
        --region ${var.region} \
        --agent-space-id ${awscc_securityagent_agent_space.this.agent_space_id} \
        --pentest-id ${awscc_securityagent_pentest.this[0].pentest_id}
    EOT
  }
}
