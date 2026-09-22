# ---------------------------------------------------------------------------
# Role da Application (o web app do proprio Security Agent)
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "service_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["securityagent.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "app" {
  name               = "${var.name}-app"
  assume_role_policy = data.aws_iam_policy_document.service_trust.json
}

resource "aws_iam_role_policy_attachment" "app_webapp" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSSecurityAgentWebAppPolicy"
}

# ---------------------------------------------------------------------------
# Service role do pentest (a que o app grava em target.service_role_arn)
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "pentest_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["securityagent.amazonaws.com"]
    }

    dynamic "condition" {
      for_each = var.pentest_external_id == "" ? [] : [1]

      content {
        test     = "StringEquals"
        variable = "sts:ExternalId"
        values   = [var.pentest_external_id]
      }
    }
  }
}

resource "aws_iam_role" "pentest" {
  name               = var.pentest_role_name
  assume_role_policy = data.aws_iam_policy_document.pentest_trust.json
}

resource "aws_iam_role_policy_attachment" "pentest_audit" {
  role       = aws_iam_role.pentest.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# O servico cria um log group proprio por execucao sob /aws/securityagent/<space>/pt-*,
# entao o CreateLogGroup e no caminho, nao so nos grupos declarados abaixo.
data "aws_iam_policy_document" "pentest_logs" {
  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]

    resources = [
      "arn:aws:logs:${var.region}:${local.account_id}:log-group:/securityagent/*",
      "arn:aws:logs:${var.region}:${local.account_id}:log-group:/securityagent/*:*",
      "arn:aws:logs:${var.region}:${local.account_id}:log-group:/aws/securityagent/*",
      "arn:aws:logs:${var.region}:${local.account_id}:log-group:/aws/securityagent/*:*",
    ]
  }

  dynamic "statement" {
    for_each = length(var.actors) == 0 ? [] : [1]

    content {
      effect    = "Allow"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = [for s in aws_secretsmanager_secret.actor : s.arn]
    }
  }
}

resource "aws_iam_role_policy" "pentest_logs" {
  name   = "pentest-logs"
  role   = aws_iam_role.pentest.id
  policy = data.aws_iam_policy_document.pentest_logs.json
}

# ---------------------------------------------------------------------------
# Role de execucao do app Flask (equivalente de iam-policy.json)
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "console_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = [var.console_trusted_service]
    }
  }
}

data "aws_iam_policy_document" "console" {
  statement {
    sid    = "SecurityAgentAgentSpaces"
    effect = "Allow"

    actions = [
      "securityagent:ListAgentSpaces",
      "securityagent:BatchGetAgentSpaces",
      "securityagent:CreateAgentSpace",
      "securityagent:UpdateAgentSpace",
      "securityagent:ListTagsForResource",
      "securityagent:TagResource",
      "securityagent:UntagResource",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "SecurityAgentArtifacts"
    effect = "Allow"

    actions = [
      "securityagent:AddArtifact",
      "securityagent:ListArtifacts",
      "securityagent:GetArtifact",
      "securityagent:BatchGetArtifactMetadata",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "SecurityAgentTargetDomains"
    effect = "Allow"

    actions = [
      "securityagent:ListTargetDomains",
      "securityagent:BatchGetTargetDomains",
      "securityagent:CreateTargetDomain",
      "securityagent:VerifyTargetDomain",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "SecurityAgentPentests"
    effect = "Allow"

    actions = [
      "securityagent:ListPentests",
      "securityagent:BatchGetPentests",
      "securityagent:CreatePentest",
      "securityagent:UpdatePentest",
      "securityagent:StartPentestJob",
      "securityagent:ListPentestJobsForPentest",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "NetworkAndRolesReadOnly"
    effect = "Allow"

    actions = [
      "ec2:DescribeVpcs",
      "ec2:DescribeSubnets",
      "ec2:DescribeSecurityGroups",
      "iam:ListRoles",
      "sts:GetCallerIdentity",
    ]

    resources = ["*"]
  }

  statement {
    sid       = "PassServiceRoleToPentest"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.pentest.arn]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["securityagent.amazonaws.com"]
    }
  }

  statement {
    sid       = "CrossAccountAssumeRole"
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = ["arn:aws:iam::*:role/${var.pentest_role_name}"]
  }

  statement {
    sid    = "SecretsAppPrefix"
    effect = "Allow"

    actions = [
      "secretsmanager:CreateSecret",
      "secretsmanager:PutSecretValue",
      "secretsmanager:TagResource",
    ]

    resources = ["arn:aws:secretsmanager:${var.region}:${local.account_id}:secret:${var.secrets_prefix}/*"]
  }

  statement {
    sid       = "ArtifactsPutObject"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${data.aws_s3_bucket.artifacts.arn}/${var.artifacts_prefix}/*"]
  }

  statement {
    sid       = "ArtifactsListBucket"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [data.aws_s3_bucket.artifacts.arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["${var.artifacts_prefix}/*"]
    }
  }
}

resource "aws_iam_role" "console" {
  name               = "${var.name}-console"
  assume_role_policy = data.aws_iam_policy_document.console_trust.json
}

resource "aws_iam_role_policy" "console" {
  name   = "console"
  role   = aws_iam_role.console.id
  policy = data.aws_iam_policy_document.console.json
}

# As roles precisam propagar antes de o Cloud Control referencia-las.
resource "time_sleep" "iam_propagation" {
  create_duration = "15s"

  depends_on = [
    aws_iam_role_policy_attachment.app_webapp,
    aws_iam_role_policy_attachment.pentest_audit,
    aws_iam_role_policy.pentest_logs,
  ]
}
