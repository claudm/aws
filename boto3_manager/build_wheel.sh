#!/usr/bin/env bash
#
# Gera o pacote aws_security_agent_suite-1.0.0-py3-none-any.whl a partir do
# pyproject.toml deste diretório.
#
#   ./build_wheel.sh                 # limpa artefatos antigos e constrói
#   ./build_wheel.sh --no-clean      # mantém build/ e dist/ existentes
#   ./build_wheel.sh --outdir /tmp/x # grava a wheel em outro diretório
#
set -euo pipefail

# Roda sempre a partir do diretório do script, não do diretório atual.
cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

PROJETO="aws_security_agent_suite"
VERSAO="1.0.0"
WHEEL="${PROJETO}-${VERSAO}-py3-none-any.whl"
OUTDIR="dist"
LIMPAR=1

while [ $# -gt 0 ]; do
    case "$1" in
        --no-clean) LIMPAR=0; shift ;;
        --outdir)   OUTDIR="${2:?--outdir exige um caminho}"; shift 2 ;;
        -h|--help)  sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)          echo "erro: opção desconhecida '$1' (use --help)" >&2; exit 2 ;;
    esac
done

# ---------------------------------------------------------------- interpretador
PYTHON=""
for candidato in python3 python py; do
    command -v "$candidato" >/dev/null 2>&1 || continue
    # Estar no PATH não basta: no Windows, 'python3' costuma ser o atalho da
    # Microsoft Store, que existe mas não executa nada. Só serve quem roda de
    # verdade e é 3.8+, o mínimo declarado no pyproject.
    if "$candidato" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
        PYTHON="$candidato"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "erro: nenhum Python 3.8+ utilizável no PATH (tentados: python3, python, py)" >&2
    exit 1
fi

echo "==> Python: $($PYTHON --version 2>&1) ($(command -v "$PYTHON"))"

if [ ! -f pyproject.toml ]; then
    echo "erro: pyproject.toml não encontrado em $(pwd)" >&2
    exit 1
fi

# ------------------------------------------------------------- frontend de build
if ! $PYTHON -m build --version >/dev/null 2>&1; then
    echo "==> Módulo 'build' ausente; instalando"
    $PYTHON -m pip install --quiet --upgrade build
fi

# ------------------------------------------------------------------------ limpeza
if [ "$LIMPAR" -eq 1 ]; then
    echo "==> Removendo artefatos de builds anteriores"
    # build/ e dist/ são saída de build; o .egg-info é regerado a cada execução.
    rm -rf build "$OUTDIR" ./*.egg-info
fi

# O MANIFEST.in inclui os pacotes com 'recursive-include ... *', o que arrasta
# junto o bytecode de __pycache__/ para dentro da wheel. Apagar antes do build
# é o que mantém o pacote só com fonte.
echo "==> Limpando bytecode (__pycache__)"
find . -type d -name '__pycache__' -not -path './.git/*' -prune -exec rm -rf {} + 2>/dev/null || true

# -------------------------------------------------------------------------- build
echo "==> Construindo a wheel em '$OUTDIR/'"
if ! $PYTHON -m build --wheel --outdir "$OUTDIR" 2>&1 | sed 's/^/    /'; then
    echo "==> Build isolado falhou; tentando novamente com --no-isolation" >&2
    $PYTHON -m build --wheel --no-isolation --outdir "$OUTDIR" 2>&1 | sed 's/^/    /'
fi

# ---------------------------------------------------------------------- validação
CAMINHO="$OUTDIR/$WHEEL"
if [ ! -f "$CAMINHO" ]; then
    echo "erro: build terminou mas '$CAMINHO' não existe. Gerado em '$OUTDIR/':" >&2
    ls -1 "$OUTDIR" >&2 || true
    exit 1
fi

# Confere que os módulos da arquitetura hexagonal entraram no pacote: um
# pyproject com 'include' errado gera uma wheel válida e vazia sem avisar.
echo "==> Verificando conteúdo do pacote"
CONTEUDO="$($PYTHON -m zipfile -l "$CAMINHO")"
FALTANDO=""
for esperado in main.py domain/entities.py ports/outbound.py service/pentest_service.py \
                adapters/outbound/boto3_adapter.py adapters/inbound/cli_adapter.py; do
    if ! printf '%s' "$CONTEUDO" | grep -q "$esperado"; then
        FALTANDO="$FALTANDO $esperado"
    fi
done

if [ -n "$FALTANDO" ]; then
    echo "erro: a wheel não contém:$FALTANDO" >&2
    exit 1
fi

PYC="$($PYTHON - "$CAMINHO" <<'PY'
import sys, zipfile
nomes = zipfile.ZipFile(sys.argv[1]).namelist()
print(sum(1 for n in nomes if n.endswith('.pyc')))
PY
)"
if [ "$PYC" -ne 0 ]; then
    echo "erro: a wheel contém $PYC arquivo(s) .pyc; deveria levar apenas fonte" >&2
    exit 1
fi

# jobs_config.yaml está no MANIFEST.in, mas MANIFEST.in só governa o sdist: como
# o arquivo fica na raiz (ao lado do módulo 'main'), e não dentro de um pacote,
# package-data não o alcança e ele fica de fora da wheel. Quem instalar o pacote
# precisa usar --source terraform ou apontar um jobs_config.yaml próprio.
if ! printf '%s' "$CONTEUDO" | grep -q 'jobs_config.yaml'; then
    echo "aviso: jobs_config.yaml não vai na wheel; '--source yaml' e '--source hybrid'"
    echo "       exigem o arquivo no diretório de instalação do pacote."
fi

if $PYTHON -m twine --version >/dev/null 2>&1; then
    echo "==> twine check"
    $PYTHON -m twine check "$CAMINHO" | sed 's/^/    /'
fi

TAMANHO="$(du -h "$CAMINHO" | cut -f1)"
ARQUIVOS="$($PYTHON - "$CAMINHO" <<'PY'
import sys, zipfile
nomes = zipfile.ZipFile(sys.argv[1]).namelist()
print(sum(1 for n in nomes if n.endswith('.py')))
PY
)"

echo
echo "OK: $CAMINHO ($TAMANHO, $ARQUIVOS módulos .py)"
echo "    instalar: $PYTHON -m pip install --force-reinstall '$CAMINHO'"
echo "    executar: aws-security-agent --help"
