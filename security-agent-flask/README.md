# Security Agent · Pentests — Flask (back + front)

Porte da aplicação para **Flask**: mesma API (agora em blueprints, validada com
Pydantic) e o **frontend da tela servido pelo próprio Flask** (Jinja + JS). Como
front e back ficam na mesma origem, o `Failed to fetch` da versão original não
acontece.

## Rodar (dev, sem AWS)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # STORE_BACKEND=memory já é o padrão
python run.py                 # http://localhost:8000
```

Abra `http://localhost:8000`, clique em **Carregar Spaces**, selecione
`uva-with-role3` e a tela popula os pentests e endpoints de exemplo — tudo sem
credencial AWS.

### Mocks

Com `SA_BACKEND=memory` (padrão) nenhuma chamada sai para a AWS e **nada é
gravado no DynamoDB**: duas classes servem todo o JSON a partir de
`app/mock_data.json`.

| Classe | Arquivo | Cobre |
|---|---|---|
| `MockStore` | `app/mock_store.py` | Spaces e Pentests (mesma interface de `store.Store`) |
| `MockAwsClient` | `app/mock_aws.py` | VPCs, subnets, SGs, roles, artefatos S3, Secrets Manager |

O JSON é lido uma vez por processo; escritas (criar Space, criar/editar Pentest,
verificar endpoint, upload) ficam em memória e somem no restart. O upload usa
uma URL da própria app (`PUT /api/resources/mock-upload`) no lugar do presigned
S3, e as credenciais recebem um ARN fake — a senha não sai do request.

Para editar ou acrescentar dados de exemplo, mexa só em `app/mock_data.json`.

## Produção

```bash
# .env
STORE_BACKEND=dynamodb
EXPECTED_ACCOUNT_ID=000000000000
AWS_REGION=sa-east-1

gunicorn "app:create_app()" -b 0.0.0.0:8000 -w 4
```

Tabelas DynamoDB: `security-agent-spaces` (PK `space_id`) e
`security-agent-pentests` (PK `id`). Credenciais da AWS vêm do ambiente
(instance role / SSO); use `ASSUME_ROLE_ARN` para cross-account.

## Estrutura

```
app/
  __init__.py        app factory + error handler + /api/health
  config.py          settings (pydantic-settings)
  errors.py          ApiError -> JSON
  schemas.py         modelos Pydantic (validação e serialização)
  validation.py      parse_body / dump helpers
  aws.py             boto3: EC2, IAM, STS, Secrets Manager, S3
  store.py           persistência (memory | dynamodb)
  mock_data.json     fixtures dos mocks (rede, IAM, Spaces, Pentests, artefatos)
  mock_data.py       loader do JSON (resolve {account_id}/{region}/{bucket})
  mock_store.py      MockStore: Spaces/Pentests em memória, sem DynamoDB
  mock_aws.py        MockAwsClient: EC2/IAM/S3/Secrets em memória, sem AWS
  blueprints/        context, network, targets, pentests, resources, ui
  templates/index.html
  static/css/styles.css
  static/js/app.js
run.py
```

## Rotas × tela

| Elemento | Rota |
|---|---|
| Carregar Spaces | `POST /api/context/spaces` |
| Criar / Editar Space | `POST /api/context/spaces/create` · `PATCH /api/context/spaces/<space_id>` |
| Atualizar (pentests) | `GET /api/pentests/space/<space_id>` |
| Listar VPCs / subnets / SGs | `GET /api/network/...` |
| Listar endpoints / Verify | `GET` / `POST /api/targets/endpoints...` |
| Listar roles | `GET /api/targets/roles` |
| Criar Pentest / Editar | `POST /api/pentests` · `PATCH /api/pentests/<id>` |
| Recursos (upload / listar) | `POST /api/resources/upload-url` · `GET /api/resources` |

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
  linha chama `update_agent_space` (a operação não aceita `kmsKeyId` nem `tags`,
  que só existem na criação).
- **Pentests** vêm de `list_pentests` + `batch_get_pentests`; o status da lista
  é best-effort via `list_pentest_jobs_for_pentest`. Criar chama `create_pentest`.
- **Endpoints** = target domains (`list_target_domains` / `batch_get_target_domains`);
  **Verify** chama `verify_target_domain`.
- **VPC/subnet/SG** continuam via `ec2:Describe*`; **roles** via `iam:ListRoles`.

Precisa de boto3 recente (o serviço `securityagent`, API 2025-09-06, não existe
em boto3 antigo). IAM mínimo adicional: `securityagent:ListAgentSpaces`,
`BatchGetAgentSpaces`, `CreateAgentSpace`, `UpdateAgentSpace`, `ListPentests`, `BatchGetPentests`,
`CreatePentest`, `ListPentestJobsForPentest`, `ListTargetDomains`,
`BatchGetTargetDomains`, `VerifyTargetDomain`.

Observação: no `create_pentest`, as credenciais do bloco Authentication
(actors/authentication) não são enviadas automaticamente — o esquema de
authentication depende do provider; ligue conforme sua política.
