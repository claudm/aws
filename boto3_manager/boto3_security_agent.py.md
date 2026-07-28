#!/usr/bin/env python3
"""
Execução e acompanhamento de Pen-Test automatizado utilizando boto3 e AWS Security Agent.
"""

import time
import json
import boto3
from botocore.exceptions import ClientError

# ==========================================
# CONFIGURAÇÕES DO TESTE
# ==========================================
AGENT_SPACE_ID = "pentest-demo-space"
TARGET_URL = "http://vulnerable-app.pentest.svc"
ENDPOINT_URL = "http://localhost:4566"  # Utilize None se estiver acessando a API real da AWS no cluster
REGION_NAME = "us-east-1"
POLLING_INTERVAL_SEC = 5
MAX_RETRIES = 60  # Timeout máximo de ~5 minutos


def main():
    print(f"[*] Inicializando cliente boto3 para AWS Security Agent...")

    # Inicializa o cliente boto3.
    # Nota: Caso esteja usando um ambiente simulado (ex: kumo / LocalStack), passamos o endpoint_url customizado.
    client = boto3.client(
        "security-agent",
        region_name=REGION_NAME,
        endpoint_url=ENDPOINT_URL
    )

    # 1. CRIAR O PENTEST (CreatePentest)
    print(f"[*] Registrando alvo {TARGET_URL} no espaço {AGENT_SPACE_ID}...")
    try:
        response_create = client.create_pentest(
            agentSpaceId=AGENT_SPACE_ID,
            title="Automated Pen-Test via Boto3",
            assets={
                "endpoints": [
                    {"uri": TARGET_URL}
                ]
            }
        )
        pentest_id = response_create["pentestId"]
        print(f"[+] Pen-Test criado com sucesso! Pentest ID: {pentest_id}")
    except ClientError as e:
        print(f"[-] Erro ao criar pen-test: {e}")
        return 1

    # 2. INICIAR O JOB DO PENTEST (StartPentestJob)
    print(f"[*] Disparando Job de scan do Pen-Test...")
    try:
        response_start = client.start_pentest_job(
            agentSpaceId=AGENT_SPACE_ID,
            pentestId=pentest_id
        )
        job_id = response_start["pentestJobId"]
        status = response_start.get("status", "IN_PROGRESS")
        print(f"[+] Job iniciado! Job ID: {job_id} | Status inicial: {status}")
    except ClientError as e:
        print(f"[-] Erro ao iniciar job de pen-test: {e}")
        return 1

    # 3. ACOMPANHAMENTO DO TESTE EM TEMPO REAL (Polling)
    print("[*] Aguardando a conclusão das análises de segurança e exploração...")
    terminais = ("COMPLETED", "FAILED", "STOPPED")

    for tentativa in range(1, MAX_RETRIES + 1):
        try:
            status_response = client.batch_get_pentests(
                agentSpaceId=AGENT_SPACE_ID,
                pentestIds=[pentest_id]
            )

            pentests_info = status_response.get("pentests", [])
            if pentests_info:
                status = pentests_info[0].get("status", status)

            print(f"    [+ {tentativa * POLLING_INTERVAL_SEC}s] Status do Job: {status}")

            if status in terminais:
                print(f"[+] Job finalizado com status terminal: {status}")
                break

            time.sleep(POLLING_INTERVAL_SEC)
        except ClientError as e:
            print(f"[!] Erro de comunicação ao verificar status: {e}. Tentando novamente...")
            time.sleep(POLLING_INTERVAL_SEC)
    else:
        print("[-] Tempo limite atingido aguardando o término do job.")

    # 4. COLETAR AS VULNERABILIDADES ENCONTRADAS (ListFindings / BatchGetFindings)
    print(f"\n[*] Consultando descobertas do teste de invasão no Job {job_id}...")
    try:
        list_response = client.list_findings(
            agentSpaceId=AGENT_SPACE_ID,
            pentestJobId=job_id
        )
        resumos = list_response.get("findingsSummaries", [])
        ids_findings = [f["findingId"] for f in resumos]

        print(f"[+] Foram identificadas {len(ids_findings)} potenciais vulnerabilidades.")

        findings = []
        if ids_findings:
            batch_response = client.batch_get_findings(
                agentSpaceId=AGENT_SPACE_ID,
                findingIds=ids_findings
            )
            findings = batch_response.get("findings", [])

        gerar_relatorio(pentest_id, job_id, status, findings)

    except ClientError as e:
        print(f"[-] Erro ao coletar resultados do pen-test: {e}")
        return 1

    return 0


def gerar_relatorio(pentest_id, job_id, status, findings):
    """Exibe no console um relatório formatado das vulnerabilidades encontradas."""
    ordem_severidade = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4, "UNKNOWN": 5}
    findings_ordenados = sorted(findings, key=lambda f: ordem_severidade.get(f.get("riskLevel", "UNKNOWN"), 9))

    print("\n" + "=" * 70)
    print("RELATÓRIO FINAL DO AWS SECURITY AGENT PEN-TEST")
    print("=" * 70)
    print(f"Target      : {TARGET_URL}")
    print(f"Pentest ID  : {pentest_id}")
    print(f"Job ID      : {job_id}")
    print(f"Status      : {status}")
    print(f"Total Ocor. : {len(findings)}")
    print("-" * 70)

    if not findings_ordenados:
        print("Nenhuma vulnerabilidade confirmada. Verifique se o Target é roteável pelo Agente.")
        return

    for idx, f in enumerate(findings_ordenados, start=1):
        nome = f.get("name", "(Sem Nome)")
        severidade = f.get("riskLevel", "UNKNOWN")
        score = f.get("riskScore", "?")
        tipo = f.get("riskType", "Desconhecido")
        confiança = f.get("confidence", "?")
        desc = f.get("description", "Sem descrição.")

        print(f"\n[{idx}] {nome} ({severidade} - Score: {score})")
        print(f"    Tipo        : {tipo}")
        print(f"    Confiança   : {confiança}")
        print(f"    Descrição   : {desc}")

        if f.get("attackScript"):
            print("    Reprodução (Payload/Script):")
            for line in f.get("attackScript", "").splitlines():
                print(f"       > {line}")
        print("-" * 70)


if __name__ == "__main__":
    import sys
    sys.exit(main())
