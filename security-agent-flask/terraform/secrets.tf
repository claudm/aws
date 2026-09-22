# Credenciais dos atores. O app grava o mesmo payload
# ({username, password, totp_secret}) sob SECRETS_PREFIX; aqui o nome nao inclui
# o pentest_id porque ele so existe depois do apply — e o pentest referencia
# estes ARNs.

resource "aws_secretsmanager_secret" "actor" {
  for_each = local.actors

  name = "${var.secrets_prefix}/${var.agent_space_name}/${replace(replace(each.key, "/", "_"), " ", "-")}"

  tags = merge(var.tags, {
    app   = "security-agent"
    actor = each.key
    space = var.agent_space_name
  })
}

resource "aws_secretsmanager_secret_version" "actor" {
  for_each = local.actors

  secret_id = aws_secretsmanager_secret.actor[each.key].id

  secret_string = sensitive(jsonencode({
    username    = each.value.username
    password    = each.value.password
    totp_secret = each.value.totp_secret
  }))
}
