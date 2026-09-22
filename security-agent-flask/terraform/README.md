# Terraform (awscc) — o lado declarativo deste app

Provisiona com o provider `hashicorp/awscc` o que o app Flask cria em runtime:
Application, Agent Space, target domains, artefatos, credenciais dos atores e a
configuracao do pentest — mais as roles IAM (`iam-policy.json`/`trust-policy.json`
viraram `iam.tf`).

## Uso

```bash
cp terraform.tfvars.example terraform.tfvars   # ajuste
terraform init
terraform apply
```

O `agent_space_id` do output e o mesmo `space_id` que a tela lista.

## Cobertura

| Rota / operacao do app | Aqui |
|---|---|
| `POST /api/context/spaces/create`, `PATCH .../<id>` | `awscc_securityagent_agent_space` |
| Tags do Space | atributo `tags` — o Cloud Control resolve o ARN, entao `AGENT_SPACE_ARN_TEMPLATE` nao e necessario |
| `GET/POST /api/targets/endpoints` (target domains) | `awscc_securityagent_target_domain` |
| **Verify** do endpoint | `terraform_data.verify_domain` (local-exec — ver abaixo) |
| `POST /api/pentests` | `awscc_securityagent_pentest` |
| Credenciais do bloco Authentication | `aws_secretsmanager_secret` + `assets.actors[].authentication` (`SECRETS_MANAGER`) |
| `POST /api/resources/upload-url` (artefatos) | `awscc_securityagent_artifact` (base64 direto, sem S3) |
| VPC / subnet / SG do Space | `aws_resources.vpcs` e `pentest.vpc_config` |
| **Iniciar** pentest (`StartPentestJob`) | `terraform_data.start_pentest_job` (local-exec) |
| Listar VPCs/subnets/SGs/roles para escolher | fora de escopo — e a tela |

## Os dois pontos que nao sao declarativos

Nao existe recurso CloudFormation (logo, nem `awscc`) para nenhuma das duas:

- **`VerifyTargetDomain`** — o servico nao consulta o DNS sozinho; depois de
  publicar o TXT e preciso chamar a operacao. Com `route53_zone_name`
  preenchida, o TXT e publicado (o token e atributo computed, entao sai no
  mesmo apply) e o verify e disparado em loop ate `VERIFIED`. Sem a zona,
  publique o TXT pelos outputs `target_domains[*].dns_txt` e rode:
  `aws securityagent verify-target-domain --target-domain-id <id>`.
- **`StartPentestJob`** — operacao, nao estado. `start_pentest_job = true`
  dispara uma vez por `pentest_id`.

Ambas usam `local-exec` com `/bin/sh`; no Windows, rode via Git Bash ou WSL.

## Gotchas

- **ExternalId da service role.** O servico cunha um por Agent Space e so mostra
  no console — nao vem por API nem por atributo do CloudFormation. O trust aqui
  sai sem a condition (`pentest_external_id = ""`), escopado so pelo principal
  `securityagent.amazonaws.com`. Em producao: aplique, leia o ExternalId no
  console, preencha a variavel e reaplique.
- **`kms_key_id` so vale na criacao** do Agent Space (mesma restricao que o app
  documenta). Mudar depois forca replace.
- **A service role precisa estar em `aws_resources.iam_roles`** antes de o
  pentest referencia-la, senao vem `not found in agent instance IAM roles`.
- **Nome do secret.** O app usa `<prefix>/<space_id>/<pentest_id>/<actor>`; aqui
  o `pentest_id` nao existe antes do apply (o pentest referencia o ARN do
  secret), entao o nome e `<prefix>/<space_name>/<actor>`.
- **`awscc_securityagent_pentest` pode dar timeout** via Cloud Control (o sample
  da AWS avisa o mesmo). Se acontecer, crie pela CLI e importe.
- O bucket de artefatos e lido com `data`, nao criado — e o bucket compartilhado
  do `.env`. Se o upload pelo browser (presigned POST) for usado, o CORS do
  bucket continua sendo responsabilidade de quem o gerencia.

## Fora daqui

`awscc_securityagent_security_requirement_pack` existe e nao foi usado — nao ha
nada equivalente no app.
