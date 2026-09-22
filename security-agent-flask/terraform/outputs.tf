output "agent_space_id" {
  description = "Use na tela: e o space_id que o app lista."
  value       = awscc_securityagent_agent_space.this.agent_space_id
}

output "application_domain" {
  description = "Dominio do web app do Security Agent."
  value       = awscc_securityagent_application.this.domain
}

output "pentest_id" {
  value = var.create_pentest ? awscc_securityagent_pentest.this[0].pentest_id : null
}

output "pentest_service_role_arn" {
  description = "Vai em target.service_role_arn na criacao de pentest pelo app."
  value       = aws_iam_role.pentest.arn
}

output "console_role_arn" {
  description = "Role de execucao do app Flask."
  value       = aws_iam_role.console.arn
}

output "target_domains" {
  value = {
    for k, d in awscc_securityagent_target_domain.this : k => {
      id     = d.target_domain_id
      status = d.verification_status
      dns_txt = {
        name  = d.verification_details.dns_txt.dns_record_name
        type  = d.verification_details.dns_txt.dns_record_type
        token = d.verification_details.dns_txt.token
      }
    }
  }
}

output "artifact_ids" {
  value = { for k, a in awscc_securityagent_artifact.this : k => a.artifact_id }
}

output "actor_secret_arns" {
  value = { for k, s in aws_secretsmanager_secret.actor : k => s.arn }
}
