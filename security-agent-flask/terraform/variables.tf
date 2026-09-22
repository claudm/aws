variable "region" {
  description = "Regiao (AWS_REGION do .env)."
  type        = string
  default     = "sa-east-1"
}

variable "name" {
  description = "Prefixo dos recursos IAM/CloudWatch criados aqui."
  type        = string
  default     = "security-agent"
}

# ---- Agent Space ----

variable "agent_space_name" {
  description = "Nome do Agent Space."
  type        = string
}

variable "agent_space_description" {
  description = "Descricao do Agent Space."
  type        = string
  default     = ""
}

variable "kms_key_id" {
  description = "KMS key do Agent Space. Vazio = chave gerenciada pela AWS. So vale na criacao."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags do Agent Space (mapa; convertido para a lista key/value do awscc)."
  type        = map(string)
  default     = {}
}

variable "vpc_config" {
  description = "VPC alcancada pelo ambiente de teste. Null = sem VPC."
  type = object({
    vpc_id             = string
    subnet_ids         = list(string)
    security_group_ids = list(string)
  })
  default = null
}

# ---- Target domains ----

variable "target_domains" {
  description = "Dominios registrados no Space (verificacao DNS_TXT)."
  type        = list(string)
  default     = []
}

variable "route53_zone_name" {
  description = <<-EOT
    Hosted zone publica que hospeda os target_domains. Se preenchida, o TXT de
    verificacao e publicado e o verify-target-domain e disparado no mesmo apply.
    Vazia = publique o TXT por fora e rode o verify na mao (ver README).
  EOT
  type        = string
  default     = ""
}

# ---- Pentest ----

variable "create_pentest" {
  description = "Cria o recurso de pentest."
  type        = bool
  default     = true
}

variable "pentest_title" {
  description = "Titulo do pentest."
  type        = string
  default     = "pentest"
}

variable "pentest_endpoints" {
  description = "Endpoints alvo. Precisam estar sob um target domain VERIFIED."
  type        = list(string)
  default     = []
}

variable "exclude_risk_types" {
  description = "Risk types excluidos da execucao (ver RiskType na API 2025-09-06)."
  type        = list(string)
  default     = []
}

variable "code_remediation_strategy" {
  description = "AUTOMATIC ou DISABLED."
  type        = string
  default     = "DISABLED"
}

variable "clean_up_strategy" {
  description = "BEST_EFFORT_DELETE ou RETAIN_ALL."
  type        = string
  default     = "BEST_EFFORT_DELETE"
}

variable "start_pentest_job" {
  description = "Dispara StartPentestJob apos o apply (nao existe recurso; usa a CLI)."
  type        = bool
  default     = false
}

# ---- Actors (credenciais) ----

variable "actors" {
  description = <<-EOT
    Atores autenticados do pentest. Cada um vira um secret no Secrets Manager
    sob secrets_prefix e entra em assets.actors com providerType SECRETS_MANAGER.
    O payload do secret e o mesmo que o app grava: username/password/totp_secret.
    A variavel nao pode ser sensitive: o identifier e chave de for_each. As
    senhas sao envolvidas em sensitive() onde entram no secret.
  EOT
  type = list(object({
    identifier  = string
    description = optional(string, "")
    uris        = optional(list(string), [])
    username    = string
    password    = string
    totp_secret = optional(string, "")
  }))
  default = []
}

variable "secrets_prefix" {
  description = "Prefixo dos secrets (SECRETS_PREFIX do .env)."
  type        = string
  default     = "security-agent/pentests"
}

# ---- Artefatos ----

variable "artifacts" {
  description = <<-EOT
    Artefatos de contexto enviados ao Space (diagramas, OpenAPI, etc).
    artifact_type: TXT, PNG, JPEG, MD, PDF, DOCX, DOC, JSON ou YAML.
  EOT
  type = list(object({
    path          = string
    file_name     = optional(string, "")
    artifact_type = string
    as_document   = optional(bool, false) # tambem anexa em assets.documents
  }))
  default = []
}

variable "artifacts_bucket" {
  description = "Bucket de artefatos que o app usa via presigned (S3_ARTIFACTS_BUCKET)."
  type        = string
  default     = "uploads-uva-dev"
}

variable "artifacts_prefix" {
  description = "Prefixo no bucket (S3_ARTIFACTS_PREFIX)."
  type        = string
  default     = "security-agent-artifacts"
}

# ---- IAM ----

variable "pentest_role_name" {
  description = "Nome da service role do pentest (CROSS_ACCOUNT_ROLE_NAME do app)."
  type        = string
  default     = "role-security-agent-pentest"
}

variable "pentest_external_id" {
  description = <<-EOT
    ExternalId que o servico cunha por Agent Space e so mostra no console (nao
    vem por API nem CloudFormation). Vazio = trust sem a condition, so pelo
    principal securityagent.amazonaws.com. Preencha e reaplique depois de ler
    o valor no console.
  EOT
  type        = string
  default     = ""
}

variable "console_trusted_service" {
  description = "Servico que assume a role de execucao do app Flask (ex.: ec2.amazonaws.com)."
  type        = string
  default     = "ec2.amazonaws.com"
}

variable "log_retention_days" {
  description = "Retencao dos log groups de pentest."
  type        = number
  default     = 14
}
