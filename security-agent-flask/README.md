# Security Agent · Pentests — Flask (back + front)

Porte da aplicação para **Flask**: mesma API (validada com Pydantic) e o
**frontend da tela servido pelo próprio Flask** (Jinja + JS). Como
front e back ficam na mesma origem, o `Failed to fetch` da versão original não
acontece.

## Rodar (dev, sem AWS)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # SA_BACKEND=memory já é o padrão
python run.py                 # http://localhost:8000
```

Abra `http://localhost:8000`, clique em **Carregar Spaces**, selecione
`uva-with-role3` e a tela popula os pentests e endpoints de exemplo — tudo sem
credencial AWS.

### Mocks

Com `SA_BACKEND=memory` (padrão) nenhuma chamada sai para a AWS e **nada é
persistido fora do processo**: uma classe só serve todo o JSON a partir de
`app/mock_data.json`.

| Classe | Arquivo | Cobre |
|---|---|---|
| `MockState` | `app/mock.py` | Tudo: Spaces, Pentests, VPCs, subnets, SGs, roles, artefatos S3 e Secrets Manager |

É um estado só, compartilhado pelo `get_store()` e pela camada `aws.py`, com um
gate único (`mock.is_mock()`). O JSON é lido uma vez por processo e **nunca é
reescrito**: criação, atualização e remoção (criar Space, criar/editar/excluir
Pentest, verificar endpoint, upload) valem só em memória e somem no restart.
O upload usa uma URL da própria app (`PUT /api/resources/mock-upload`) no lugar
do presigned S3, e as credenciais recebem um ARN fake — a senha não sai do request.

Os seis Spaces de exemplo vêm completos (descrição, tags, `awsResources`,
endpoints) e os sete pentests cobrem os quatro status — `PENDING` (com o botão
**Iniciar**), `RUNNING`, `COMPLETED` e `FAILED` — além de credenciais com e sem
2FA e artefatos anexados. `UVA-Code-Review` fica sem pentest de propósito, para
exercitar o estado vazio da tabela.

Para editar ou acrescentar dados de exemplo, mexa só em `app/mock_data.json`.

## Produção

```bash
# .env
SA_BACKEND=securityagent
EXPECTED_ACCOUNT_ID=000000000000
AWS_REGION=sa-east-1

gunicorn "app:create_app()" -b 0.0.0.0:8000 -w 4
```

Spaces e Pentests ficam no próprio serviço AWS Security Agent — não há mais
persistência local (o backend DynamoDB foi removido). Credenciais da AWS vêm
do ambiente (instance role / SSO); use `ASSUME_ROLE_ARN` para cross-account.

## Estrutura

```
app/
  __init__.py        app factory + error handler
  config.py          settings (pydantic-settings)
  errors.py          ApiError -> JSON
  schemas.py         modelos Pydantic (validação e serialização)
  validation.py      parse_body / dump helpers
  aws.py             boto3: EC2, IAM, STS, Secrets Manager, S3
  store.py           acesso a Spaces/Pentests (aponta para o estado em memória)
  mock_data.json     fixtures dos mocks (rede, IAM, Spaces, Pentests, artefatos)
  mock.py            MockState: loader do JSON + todo o estado fake em memória
  routes/            rotas de API (JSON) sob /api — um módulo por entidade
    __init__.py      blueprint da API + /api/health
    context.py       Spaces (GET/POST/PATCH/DELETE)
    network.py       VPCs, subnets, security groups
    targets.py       endpoints (target domains) e roles
    pentests.py      Pentests (GET/POST/PATCH/DELETE + start)
    resources.py     upload-url, listagem e mock-upload
  views/             rotas que renderizam template
    __init__.py      blueprint das páginas
    index.py         GET / -> templates/index.html
  templates/index.html
  static/css/styles.css
  static/js/app.js
run.py
```

## Rotas × tela

| Elemento | Rota |
|---|---|
| Carregar Spaces | `POST /api/context/spaces` |
| Criar / Editar Space (nome, rede, role, alvos, tags) | `POST /api/context/spaces/create` · `PATCH /api/context/spaces/<space_id>` |
| Atualizar (pentests) | `GET /api/pentests/space/<space_id>` |
| Listar VPCs / subnets / SGs | `GET /api/network/...` |
| Listar endpoints / Verify | `GET` / `POST /api/targets/endpoints...` |
| Listar roles | `GET /api/targets/roles` |
| Criar Pentest / Editar | `POST /api/pentests` · `PATCH /api/pentests/<id>` |
| Recursos (upload / listar) | `POST /api/resources/upload-url` · `GET /api/resources` |
| Excluir Space / Pentest (só no modo mock) | `DELETE /api/context/spaces/<space_id>` · `DELETE /api/pentests/<id>` |

## Segurança (mantida do porte anterior)

- Credencial nunca entra no registro do pentest: em prod vira secret no Secrets
  Manager (guarda só o ARN); em dev a senha é descartada.
- Alvo restrito à allowlist de domínios verificados do Space (403 fora do escopo).
- Upload direto do browser pro S3 via presigned POST — arquivo não passa pelo backend.
- Rode o serviço com IAM de menor privilégio (Describe de EC2, ListRoles,
  Secrets no prefixo do app, S3 no prefixo de artefatos).

## Integração real (boto3 securityagent + ec2)

Por padrão o app roda em `SA_BACKEND=memory` (dados de exemplo, sem AWS). Para
usar o serviço real **AWS Security Agent**:

```
SA_BACKEND=securityagent
AWS_REGION=sa-east-1
EXPECTED_ACCOUNT_ID=000000000000
```

Com isso:

- **Spaces** vêm de `securityagent:list_agent_spaces` / `batch_get_agent_spaces`;
  o botão **+ Criar Space** chama `create_agent_space` e o **Editar** de cada
  linha chama `update_agent_space`. `kmsKeyId` só existe na criação.
- **Tags** não passam pelo `update_agent_space`: são lidas com
  `list_tags_for_resource` e gravadas com `tag_resource` / `untag_resource`
  (só o diff — grava o que mudou, remove o que saiu da lista). Ver a ressalva
  do ARN abaixo.
- **Pentests** vêm de `list_pentests` + `batch_get_pentests`; o status da lista
  é best-effort via `list_pentest_jobs_for_pentest`. Criar chama `create_pentest`.
- **Endpoints** = target domains (`list_target_domains` / `batch_get_target_domains`);
  **Verify** chama `verify_target_domain`.
- **VPC/subnet/SG** continuam via `ec2:Describe*`; **roles** via `iam:ListRoles`.

Precisa de boto3 recente (o serviço `securityagent`, API 2025-09-06, não existe
em boto3 antigo). IAM mínimo adicional: `securityagent:ListAgentSpaces`,
`BatchGetAgentSpaces`, `CreateAgentSpace`, `UpdateAgentSpace`, `TagResource`,
`UntagResource`, `ListTagsForResource`, `ListPentests`, `BatchGetPentests`,
`CreatePentest`, `ListPentestJobsForPentest`, `ListTargetDomains`,
`BatchGetTargetDomains`, `VerifyTargetDomain`.

### ARN do Agent Space (tags)

`TagResource`, `UntagResource` e `ListTagsForResource` exigem `resourceArn`, mas
**nenhuma** operação de agent space devolve o ARN e o modelo do botocore não
documenta o formato (conferido no `service-2.json`: zero padrões
`arn:...securityagent...`). O app monta o ARN por convenção:

```
arn:aws:securityagent:{region}:{account_id}:agent-space/{space_id}
```

Se a sua conta usar outro formato, ajuste `AGENT_SPACE_ARN_TEMPLATE` no `.env`
em vez de mexer no código. A **leitura** de tags é best-effort: com ARN errado
a tela mostra o Space sem tags e registra um warning no log, sem quebrar. A
**gravação** propaga o erro real da AWS (502) — é o sinal de que o formato do
ARN precisa ser corrigido.

Observação: no `create_pentest`, as credenciais do bloco Authentication
(actors/authentication) não são enviadas automaticamente — o esquema de
authentication depende do provider; ligue conforme sua política.
