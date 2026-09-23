# Posture scan de conta AWS com boto3

Reimplementação do conceito do testcloud: um scanner **somente leitura** que varre
uma conta AWS e devolve achados priorizados em três pilares do Well-Architected —
Segurança, Confiabilidade e Otimização de Custo — com ARN do recurso e instrução de
correção em português.

115 checks, execução paralela por região, saída em console, JSON, CSV e HTML. A
lógica de cada check fica em JSON (`testcloud/catalog/rules/`); o Python só lista
os recursos.

```
pip install .                      # instala o comando `testcloud`
testcloud scan --profile meu-perfil --html relatorio.html
```

Sem instalar: `pip install -r requirements.txt` e `python -m testcloud.cli ...`.

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
  registry.py    @resource_provider + carga das regras JSON + seleção por pilar/serviço/id
  context.py     SessionFactory, clients cacheados, paginação, avaliador das regras
  engine.py      descoberta de regiões, pool de threads, captura de erro por check
  pricing.py     Price List API + tabela estática de EBS/snapshot/NAT/EIP/LB
  report.py      console, JSON, CSV, HTML autocontido
  cli.py         argparse
  checks/        um módulo por serviço, só com @resource_provider
  catalog/rules/ um JSON por serviço: textos, severidade, permissões e a regra (`evaluate`)
deploy/
  scan-role.yaml CloudFormation da role read-only com ExternalId
tests/
  test_checks.py botocore Stubber, sem tocar em conta real
```

### Adicionar um check

Um check tem duas partes. O **provider** (Python) só enumera os recursos; toda a
lógica — que API chamar, o que testar, severidade, textos, custo — fica na **regra**
(JSON). Os módulos de `checks/` e os JSONs de `catalog/rules/` são carregados
sozinhos; não há lista para editar.

```python
# testcloud/checks/efs.py
@resource_provider("efs", "file_system")
def iter_file_systems(ctx):
    for fs in ctx.paginate("efs", "describe_file_systems", "FileSystems"):
        yield {
            "resource_id": fs["FileSystemId"],
            "region": ctx.region,
            "arn": ctx.arn("elasticfilesystem", f"file-system/{fs['FileSystemId']}"),
            "params": {"FileSystemId": fs["FileSystemId"]},   # vão para as chamadas da regra
            "vars": [fs["FileSystemId"]],                     # primeiros {var} dos textos
        }
```

```json
// testcloud/catalog/rules/efs.json
"EFS.NOT_ENCRYPTED": {
  "title": "EFS '{var}' sem criptografia em repouso",
  "severity": "high",
  "pillar": "security",
  "description": "...", "remediation": "...",
  "well_architected": "SEC08-BP02",
  "permissions": ["elasticfilesystem:DescribeFileSystems"],
  "exposure": ["data_store"],
  "evaluate": {
    "resource": "efs.file_system",
    "service": "efs",
    "operation": "describe_file_systems",
    "extract": "FileSystems.0.Encrypted",
    "operator": "falsy",
    "skip_if_none": true
  }
}
```

O arquivo JSON é o prefixo do ID em minúsculas (`EFS.*` → `efs.json`); IDs `COST.*`
ficam em `cost.json`, salvo os mapeados em `catalog.py`. O serviço do check é o
prefixo do `resource`. `pillar` aceita `security`, `reliability` e `cost` (ou
`cost_optimization`); `scope: "global"` roda uma vez só, em us-east-1.

#### Referência do `evaluate`

**Condição folha** — chama `operation` do `service` (resposta em cache por região)
e aplica `operator` ao valor em `extract` (caminho com ponto; números indexam
listas: `DBInstances.0.StorageEncrypted`).

| Operador | Passa quando |
|---|---|
| `truthy` / `falsy` | valor verdadeiro / falso ou ausente |
| `equals` / `not_equals` | `== value` / `!= value` |
| `in` / `not_in` | valor está / não está na lista `value` |
| `contains` | a lista (ou string única) contém `value` |
| `lt` `lte` `gt` `gte` | comparação numérica com `value` |
| `len_lt` / `len_gt` | tamanho da lista comparado a `value` |
| `regex` / `not_regex` | `value` casa / não casa (case-insensitive) |
| `age_days_gt` / `age_days_lte` | data com mais de / até `value` dias |
| `days_until_between` | data vence em `[min, max]` dias |
| `missing_keys` | alguma das `keys` falta ou é falsa |
| `env_is` | tags de ambiente resultam em `value` (`production_tag`, `non_production_tag`) |
| `range_hits` | faixa `from`–`to` do objeto cobre chaves do mapa `value` (portas) |
| `jsonpath` | `expression` com `expected`: `empty`, `not_empty`, `not_contains`, `missing_any` |
| `any_item` / `none_item` | algum / nenhum item da lista satisfaz a árvore `where` |
| `aggregate` | `fn` (`avg`, `max`, `min`, `sum`, `count`) dos valores comparado (`compare`) a `value`, ou a `value_from` × `factor`; exige `min_count` pontos |

**Nó** — `{"operator": "and" | "or", "conditions": [...]}`, aninhável.

Dentro de `where`, folhas **sem** `operation` avaliam o item corrente; folhas **com**
`operation` chamam a API usando `{item.Campo}` nos params. `any_item`/`none_item`/
`aggregate` com `id` guardam `count`, `values` (campo `collect`), `sum` (campo `sum`),
`labels` e `value`, que outras folhas leem com `{"capture": "id", ...}`.

**Params** — sem `params`, a folha usa os params do provider (e os `params` do
bloco). Uma folha aninhada com `params` próprios usa só eles. Placeholders:
`{account_id}`, `{region}`, `{now}`, `{now-14d}`, `{Param}` e `{Param.0}` (params do
provider) e `{item.Campo}`. Outras chaves: `region`, `ignore_errors` (código tratado
como "sem configuração" → `None`), `skip_if_none` (resposta `None` reprova a folha),
`json_parse` (campos string que são JSON/URL-encoded, como policies).

**Métricas** — folhas `get_metric_data` com `"batch": true` são buscadas em lote para
todos os recursos do provider (até 500 queries por chamada) e caem para a chamada
individual se o lote falhar.

**Chaves do bloco** (além da condição):

| Chave | Uso |
|---|---|
| `vars` | valores para os `{var}` dos textos, depois dos `vars` do provider: `{"extract": ...}`, `{"capture": ...}`, `{"value": "{region}"}`, com `transform` (`days_since`, `days_until`, `count`, `join`, `sum`, `round`, `mb`, `family_map`) e `default` |
| `overrides` | `[{"when": condição, "severity", "title", "description", "remediation", "exposure", "vars"}]` — o que casar sobrescreve |
| `waste` | `{"fn": função de pricing.py, "args": [...], "ctx": bool, "factor": n}` → `monthly_waste_usd`; retorno `None` vira `waste_estimated: false` |
| `env_tags` | `{"operation", "extract"}` das tags → soma `production_tag`/`non_production_tag` à exposure |
| `evidence` | `{"nome": spec}` gravado na evidência do finding |
| `join` | separador dos `label` das folhas que passaram (vira o último `{var}`) |
| `title` `description` `remediation` `severity` `exposure` | sobrescrevem o catálogo para o bloco |

`evaluate` também pode ser uma **lista de blocos**, um por tipo de recurso (ex.:
instâncias e clusters RDS no mesmo check). Os `{var}` são posicionais: cada texto
consome a lista de variáveis a partir do início.

### Paralelismo

Uma `ScanContext` por região, regiões em paralelo (`--workers`, padrão 8), checks
sequenciais dentro da região. Isso dá duas coisas de graça: cache compartilhado
(cada chamada das regras roda uma vez por região e serve todos os checks que a
usam; métricas do CloudWatch vêm em lote) e uma pressão de API
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

**Segurança (82)** — root sem MFA, access keys do root, MFA de usuário, rotação e
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
KMS; distribuição CloudFront sem root object, sem logging e sem WAF; e controles
de Amplify, API Gateway, AppSync, Athena, Backup, Bedrock, CodeBuild, Cognito,
DocumentDB, ECS, EFS, ElastiCache, Elastic Beanstalk, EMR, EventBridge, Global
Accelerator, Glue, Kinesis, Macie, Amazon MQ, MSK, OpenSearch, Organizations,
Redshift, Route 53, SageMaker, SES, Systems Manager, Step Functions e WAF.

**Confiabilidade (12)** — S3 sem versionamento, RDS com retenção de backup baixa,
RDS em AZ única, RDS sem deletion protection, DynamoDB sem PITR, DynamoDB sem auto
scaling, Lambda assíncrona sem DLQ, load balancer em uma AZ, ALB sem deletion
protection, Auto Scaling em uma AZ, stack CloudFormation sem proteção de deleção,
certificado ACM vencendo.

**Custo (21)** — com economia estimada por finding:

* *Disco:* volume EBS órfão, frota gp2 migrável para gp3, io1/io2 com IOPS
  provisionado ocioso (→ gp3), gp3 com IOPS/throughput extra sem uso, volume anexado
  sem I/O, snapshots antigos, snapshots órfãos (volume apagado, fora de AMI).
* *Compute:* instância subutilizada (CPU, 14 dias), instância parada segurando EBS,
  tipo de geração anterior (com o equivalente atual e a diferença de preço).
* *Banco:* RDS sem conexões, RDS com storage io1/io2 ocioso (→ gp3), RDS em classe
  de geração anterior, DynamoDB com capacidade provisionada abaixo de 30% de uso.
* *Outros:* Lambda com memória alta para execuções curtas (usa o pico de memória do
  Lambda Insights), Elastic IP ocioso, load balancer sem target saudável, NAT gateway
  sem tráfego, lifecycle de multipart incompleto, log group sem retenção, conta sem
  budget.

As estimativas usam a Price List API (`pricing:GetProducts`) para EC2 e RDS —
incluindo edição e licença de Oracle e SQL Server — e uma tabela de us-east-1 para
EBS, snapshots, NAT, Elastic IP, load balancer, DynamoDB e Lambda. Quando não há
preço (sem permissão, ou tipo inexistente na região) o finding sai com
`evidence.waste_estimated = false` e a descrição diz por quê, em vez de mostrar
economia zero. São números de lista, para priorizar — não para conferir fatura.

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

35 testes com `botocore.stub.Stubber`, rodando as regras JSON pelo registry. Eles
cobrem a parte que costuma quebrar em scanner: a lógica de classificação (SG
anexado vs. órfão, retenção 0 vs. 3 dias, wildcard com e sem `Condition`, io1
ocioso vs. usado) contra o formato real de resposta de cada API. Um teste confere
que toda permissão declarada pelos checks está coberta pela `scan-role.yaml`.

## Limitações conhecidas

* Escopo de conta única. Para Organizations, itere as contas membro com
  `--role-arn` apontando para a `OrganizationAccountAccessRole` equivalente.
* As regras fazem uma chamada de detalhe por recurso (`describe_*`/`get_*`), com
  cache por região. Em contas com milhares de snapshots, SGs ou usuários IAM o scan
  fica mais lento; restrinja com `--services`, `--skip` ou `--regions`.
* O check de subutilização enxerga só CPU. Memória exige o agente do CloudWatch,
  então trate o resultado como candidato a análise, não como decisão.
* A economia de Lambda assume a mesma duração com menos memória — razoável para as
  funções curtas que o check sinaliza, mas confirme com o Power Tuning.
* Regiões sem workload ainda são varridas por padrão (é justamente onde abuso de
  credencial costuma aparecer). Use `--regions` para restringir.
