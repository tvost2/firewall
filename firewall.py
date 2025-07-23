# 🔐 Firewall adaptativo aprimorado
import psutil
import time
import platform
import os
import socket
import threading
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

try:
    from scapy.all import sniff, ICMP, IP
except ImportError:
    print("⚠️ scapy não instalado. Execute: pip install scapy")
    exit(1)

# === CONFIG ===
LIMITE_CONEXOES_POR_IP = 5
LIMITE_PINGS = 5
LOG_INTERVALO = 60  # segundos

PORTAS_TODAS = list(range(1, 65536))
PORTAS_ROTEADOR = [21, 23, 80, 443, 7547, 8080, 8443, 2323, 9000]

BLOQUEADOS = set()
PING_CONTADOR = defaultdict(int)
WHITELIST = set(["127.0.0.1"])  # pode adicionar IPs confiáveis aqui

LOGS = []
LOG_LOCK = threading.Lock()

PASTA_LOG = r"C:\Users\tvost\Documents\denuncia algar"
os.makedirs(PASTA_LOG, exist_ok=True)
LOG_ARQUIVO = os.path.join(PASTA_LOG, "firewall_adaptativo.log")

# === FUNÇÕES DE LOG E BLOQUEIO ===

def log_evento(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    linha = f"{timestamp} - {msg}"
    with LOG_LOCK:
        LOGS.append(linha)
    print(linha)

def salvar_logs_periodicamente():
    while True:
        time.sleep(LOG_INTERVALO)
        with LOG_LOCK:
            if LOGS:
                with open(LOG_ARQUIVO, "a", encoding="utf-8") as f:
                    for linha in LOGS:
                        f.write(linha + "\n")
                LOGS.clear()

def bloquear_ip(ip):
    if ip in BLOQUEADOS or ip in WHITELIST:
        return
    sistema = platform.system()
    log_evento(f"🚫 Bloqueando IP: {ip}")
    if sistema == "Windows":
        os.system(f'netsh advfirewall firewall add rule name="Firewall - {ip}" dir=in action=block remoteip={ip}')
    elif sistema == "Linux":
        os.system(f'sudo iptables -A INPUT -s {ip} -j DROP')
    BLOQUEADOS.add(ip)

# === MONITORAMENTO DE CONEXÕES ===

def analisar_conexoes():
    conexoes = psutil.net_connections(kind='inet')
    contagem_ips = defaultdict(int)
    for c in conexoes:
        if c.raddr:
            ip = c.raddr.ip
            if ip in WHITELIST or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
                continue
            contagem_ips[ip] += 1

    for ip, total in contagem_ips.items():
        if ip not in BLOQUEADOS and total >= LIMITE_CONEXOES_POR_IP:
            log_evento(f"⚠️ IP {ip} excedeu {total} conexões simultâneas")
            bloquear_ip(ip)

# === MONITORAMENTO DE PING ===

def monitorar_pings(packet):
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:
        ip_origem = packet[IP].src
        if ip_origem in BLOQUEADOS or ip_origem in WHITELIST:
            return
        PING_CONTADOR[ip_origem] += 1
        log_evento(f"[PING] {ip_origem} enviou {PING_CONTADOR[ip_origem]} pings")
        if PING_CONTADOR[ip_origem] >= LIMITE_PINGS:
            bloquear_ip(ip_origem)

def iniciar_sniffer():
    log_evento("🕵️‍♂️ Sniffer ICMP iniciado...")
    sniff(filter="icmp", prn=monitorar_pings, store=0)

# === ESCANEAMENTO DE PORTAS ===

def get_gateway():
    for nic, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                parts = addr.address.split(".")
                return ".".join(parts[:3] + ["1"])
    return None

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            s.connect((ip, port))
            log_evento(f"[ROTEADOR] Porta {port} ABERTA em {ip}")
    except:
        pass

def escanear_roteador():
    gateway = get_gateway()
    if not gateway:
        log_evento("❌ Gateway não identificado.")
        return

    log_evento(f"📡 Escaneando {gateway}...")
    with ThreadPoolExecutor(max_workers=200) as executor:
        executor.map(lambda p: scan_port(gateway, p), PORTAS_ROTEADOR)
    log_evento("✅ Scan do roteador finalizado.")

# === LOOP PRINCIPAL ===

def firewall_loop():
    log_evento("🛡️ Firewall adaptativo iniciado.")
    escanear_roteador()

    threading.Thread(target=iniciar_sniffer, daemon=True).start()
    threading.Thread(target=salvar_logs_periodicamente, daemon=True).start()

    try:
        while True:
            analisar_conexoes()
            time.sleep(5)
    except KeyboardInterrupt:
        log_evento("🛑 Encerrado pelo usuário.")

# === EXECUÇÃO ===

if __name__ == "__main__":
    firewall_loop()
