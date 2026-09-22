# Posture scan de conta AWS com boto3

Reimplementação do conceito do testcloud: um scanner **somente leitura** que varre
uma conta AWS e devolve achados priorizados em três pilares do Well-Architected —
Segurança, Confiabilidade e Otimização de Custo — com ARN do recurso e instrução de
correção em português.

67 checks, execução paralela por região, saída em console, JSON, CSV e HTML.

```
pip install -r requirements.txt
python -m testcloud.cli scan --profile meu-perfil --html relatorio.html
```

## Garantias de segurança do próprio scanner

* Nenhuma chamada de escrita. Só `Describe*`, `Get*`, `List*`.
* Credenciais nunca são gravadas em disco: o `SessionFactory` mantém a sessão
  temporária do `AssumeRole` apenas em memória.
* Conteúdo de dados não é lido. O check de segredo em Lambda, por exemplo, olha o
  *nome* da variável de ambiente e nunca copia o valor para o finding — há teste
  cobrindo isso (`test_lambda_secret_heuristic_ignores_arn_references`).
* A role sugerida em `deploy/scan-role.yaml` tem um `Deny` explícito para
  `s3:GetObject`, `dynamodb:GetItem`, `secretsmanager:GetSecretValue` e `kms:Decrypt`.

## Uso

```bash
# scan completo, todas as regiões habilitadas
python -m testcloud.cli scan --profile prod --html relatorio.html --json scan.json

# cross-account, como o produto original faz
python -m testcloud.cli scan \
  --role-arn arn:aws:iam::123456789012:role/PostureScanReadOnly \
  --external-id $EXTERNAL_ID --progress

# só custo, só sa-east-1
python -m testcloud.cli scan --pillars cost_optimization --regions sa-east-1

# no CI: falha o pipeline se aparecer algo alto ou crítico
python -m testcloud.cli scan --min-severity high --fail-on high --quiet --json scan.json

# catálogo de checks e as permissões que eles exigem
python -m testcloud.cli list-checks --permissions
```

Códigos de saída: `0` sem bloqueio, `1` erro de execução, `2` achado igual ou acima
do `--fail-on`.

## Arquitetura

```
testcloud/
  models.py      Pillar, Severity, Finding, ScanResult, cálculo de risco
  registry.py    decorator @check + seleção por pilar/serviço/id
  context.py     SessionFactory, clients cacheados, paginação, helper de finding
  engine.py      descoberta de regiões, pool de threads, captura de erro por check
  pricing.py     Price List API com fallback estático
  report.py      console, JSON, CSV, HTML autocontido
  cli.py         argparse
  checks/        iam, s3, ec2, databases, detective, compute, cost
deploy/
  scan-role.yaml CloudFormation da role read-only com ExternalId
tests/
  test_checks.py botocore Stubber, sem tocar em conta real
```

Adicionar um check é uma função e um decorator:

```python
@check("EFS.NOT_ENCRYPTED", "EFS sem criptografia", Pillar.SECURITY, "efs",
       permissions=["elasticfilesystem:DescribeFileSystems"])
def efs_encryption(ctx):
    for fs in ctx.paginate("efs", "describe_file_systems", "FileSystems"):
        if fs.get("Encrypted"):
            continue
        yield ctx.finding(
            title=f"EFS {fs['FileSystemId']} sem criptografia",
            severity=Severity.HIGH, pillar=Pillar.SECURITY,
            resource_id=fs["FileSystemId"], resource_arn=fs["FileSystemArn"],
            description="...", remediation="...",
        )
```

O registry é populado pelo import em `checks/__init__.py`; o engine descobre o
resto sozinho.

### Paralelismo

Uma `ScanContext` por região, regiões em paralelo (`--workers`, padrão 8), checks
sequenciais dentro da região. Isso dá duas coisas de graça: cache compartilhado
(`describe_instances` roda uma vez e serve seis checks) e uma pressão de API
previsível por região, o que importa porque `describe_*` compartilha bucket de
throttling. Cada `ScanContext` cria a própria `boto3.Session` — `Session` não é
thread-safe na criação de clients.

### Ranking por risco, não por severidade nominal

O problema de scanner de postura é o relatório com 400 achados "HIGH" que ninguém
lê. Aqui cada finding carrega fatores de exposição (`internet_facing`,
`privileged_identity`, `data_store`, `production_tag`, `empty_resource`) e o
`risk_score` ajusta a severidade **dentro da banda dela**: um HIGH muito exposto
chega a 95, nunca ultrapassa um CRITICAL. Na prática:

| Achado | Severidade | Risco |
|---|---|---|
| SG com 22/tcp aberto, anexado a ENI ativa | CRITICAL | 100 |
| Mesmo SG, sem nenhum recurso anexado | HIGH | 70 |
| IMDSv1 em instância com instance profile e tag `Environment=production` | HIGH | 95,5 |
| NAT gateway ocioso | MEDIUM | 28 |

A mesma ideia vale para custo: findings de custo carregam `monthly_waste_usd`, e a
ordenação usa risco e depois economia estimada.

## Catálogo de checks

**Segurança (46)** — root sem MFA, access keys do root, MFA de usuário, rotação e
ociosidade de chaves, política de senha, policy `*:*`, usuário inativo; bucket
público, Block Public Access (conta e bucket), SSE-KMS, política TLS-only, access
logging; security group com porta administrativa aberta, SG default permissivo,
IMDSv1, EBS sem criptografia, criptografia padrão de EBS, snapshot público ou
compartilhado, VPC sem flow logs; RDS público, RDS sem criptografia, minor version
automática, snapshot RDS sem criptografia, RDS sem IAM auth, RDS sem copy de tags
para snapshot; CloudTrail multi-região e hardening do trail, GuardDuty, AWS Config,
Access Analyzer, rotação de CMK, rotação de secret; runtime de Lambda fora de
suporte, segredo em variável de ambiente, ECR sem scan e com tag mutável, endpoint
público do EKS, logs do control plane, listener HTTP e política TLS fraca, ALB sem
access logs, ALB sem drop de headers inválidos; tópico SNS sem KMS, fila SQS sem
KMS; distribuição CloudFront sem root object, sem logging e sem WAF.

**Confiabilidade (10)** — S3 sem versionamento, RDS com retenção de backup baixa,
RDS em AZ única, RDS sem deletion protection, DynamoDB sem PITR, DynamoDB sem auto
scaling, Lambda assíncrona sem DLQ, load balancer em uma AZ, ALB sem deletion
protection.

**Custo (10)** — volume EBS órfão, frota gp2 migrável para gp3, Elastic IP ocioso,
instância parada segurando EBS, instância subutilizada (CloudWatch, 14 dias),
snapshots antigos, load balancer sem target saudável, NAT gateway sem tráfego,
lifecycle de multipart incompleto, conta sem budget.

As estimativas de custo usam a Price List API quando `pricing:GetProducts` está
disponível e caem para uma tabela de us-east-1 quando não está. São números de
lista, para priorizar — não para conferir fatura.

### Alinhamento com o Security Hub (FSBP)

Os checks abaixo mapeiam controles do Foundational Security Best Practices
(FSBP), os mesmos que o pacote CDK `@enfo/aws-cdkompliance` gerencia via
Constructs compliant:

| Controle FSBP | Check no scanner |
|---|---|
| S3.1 / S3.2 / S3.3 / S3.8 | `S3.ACCOUNT_PUBLIC_ACCESS_BLOCK`, `S3.BUCKET_PUBLIC`, `S3.BUCKET_PUBLIC_ACCESS_BLOCK` |
| S3.4 | `S3.DEFAULT_ENCRYPTION` |
| S3.5 | `S3.TLS_ONLY_POLICY` |
| ELB.4 | `ELB.DROP_INVALID_HEADERS` |
| ELB.5 | `ELB.ACCESS_LOGS_DISABLED` |
| ELB.6 | `ELB.NO_DELETION_PROTECTION` |
| CloudFront.1 | `CLOUDFRONT.NO_ROOT_OBJECT` |
| CloudFront.5 | `CLOUDFRONT.NO_LOGGING` |
| CloudFront.6 | `CLOUDFRONT.NO_WAF` |
| DynamoDB.1 | `DYNAMODB.NO_AUTOSCALING` |
| DynamoDB.2 | `DYNAMODB.PITR_DISABLED` |
| EC2.8 | `EC2.IMDSV2_NOT_REQUIRED` |
| Lambda.2 | `LAMBDA.DEPRECATED_RUNTIME` |
| RDS.2 | `RDS.PUBLICLY_ACCESSIBLE` |
| RDS.3 | `RDS.STORAGE_NOT_ENCRYPTED` |
| RDS.4 | `RDS.SNAPSHOT_NOT_ENCRYPTED` |
| RDS.5 | `RDS.NO_MULTI_AZ` |
| RDS.7 / RDS.8 | `RDS.NO_DELETION_PROTECTION` |
| RDS.10 / RDS.12 | `RDS.NO_IAM_AUTH` |
| RDS.13 | `RDS.AUTO_MINOR_UPGRADE_OFF` |
| RDS.16 / RDS.17 | `RDS.NO_COPY_TAGS_TO_SNAPSHOT` |
| SNS.1 | `SNS.NOT_ENCRYPTED` |
| SQS.1 | `SQS.NOT_ENCRYPTED` |

## Testes

```bash
python -m pytest tests/ -q
```

30 testes com `botocore.stub.Stubber`. Eles cobrem a parte que costuma quebrar em
scanner: a lógica de classificação (SG anexado vs. órfão, retenção 0 vs. 3 dias,
wildcard com e sem `Condition`) contra o formato real de resposta de cada API.

## Limitações conhecidas

* Escopo de conta única. Para Organizations, itere as contas membro com
  `--role-arn` apontando para a `OrganizationAccountAccessRole` equivalente.
* `EC2.SNAPSHOT_PUBLIC` faz uma chamada por snapshot; em contas com milhares de
  snapshots, filtre com `--skip EC2.SNAPSHOT_PUBLIC` ou rode fora do horário de pico.
* O check de subutilização enxerga só CPU. Memória exige o agente do CloudWatch,
  então trate o resultado como candidato a análise, não como decisão.
* Regiões sem workload ainda são varridas por padrão (é justamente onde abuso de
  credencial costuma aparecer). Use `--regions` para restringir.
