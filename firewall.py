import psutil
import time
import platform
import os
import socket
import threading
from collections import defaultdict

# === CONFIGURAÇÕES ===
LIMITE_CONEXOES_POR_IP = 20
PORTAS_SUSPEITAS = {135, 139, 445, 3389, 4444, 8080, 6667, 12345, 31337}
PORTAS_ROTEADOR = [21, 23, 80, 443, 7547, 8080, 8443, 2323, 9000]
BLOQUEADOS = set()

# === FIREWALL ADAPTATIVO ===
def bloquear_ip(ip):
    if ip in BLOQUEADOS:
        return
    sistema = platform.system()
    print(f"🚫 Bloqueando IP suspeito: {ip}")
    if sistema == "Windows":
        os.system(f'netsh advfirewall firewall add rule name="Firewall Adaptativo - {ip}" dir=in action=block remoteip={ip}')
    elif sistema == "Linux":
        os.system(f'sudo iptables -A INPUT -s {ip} -j DROP')
    else:
        print("⚠️ Sistema não suportado.")
    BLOQUEADOS.add(ip)

def analisar_conexoes():
    conexoes = psutil.net_connections(kind='inet')
    contagem_ips = defaultdict(int)
    portas_estranhas = defaultdict(set)

    for c in conexoes:
        if c.raddr:
            ip_remoto = c.raddr.ip
            porta_local = c.laddr.port
            contagem_ips[ip_remoto] += 1
            if porta_local in PORTAS_SUSPEITAS:
                portas_estranhas[ip_remoto].add(porta_local)

    for ip, conexoes in contagem_ips.items():
        if conexoes >= LIMITE_CONEXOES_POR_IP:
            print(f"⚠️ IP {ip} excedeu limite de conexões: {conexoes}")
            bloquear_ip(ip)
        elif portas_estranhas[ip]:
            print(f"⚠️ IP {ip} acessou portas suspeitas: {portas_estranhas[ip]}")
            bloquear_ip(ip)

# === SCANNER DE ROTEADOR LOCAL ===
def get_gateway():
    for nic, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                ip = addr.address
                parts = ip.split(".")
                gateway = ".".join(parts[:3] + ["1"])
                return gateway
    return None

def scan_port(ip, port):
    try:
        s = socket.socket()
        s.settimeout(0.3)
        s.connect((ip, port))
        print(f"[ROTEADOR] Porta {port} ABERTA em {ip}")
        s.close()
    except:
        pass

def escanear_roteador():
    print("\n📡 Escaneando portas do roteador local...")
    gateway = get_gateway()
    if not gateway:
        print("❌ Não foi possível determinar o gateway da rede.")
        return

    threads = []
    for port in PORTAS_ROTEADOR:
        t = threading.Thread(target=scan_port, args=(gateway, port))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()
    print("✅ Scanner do roteador finalizado.\n")

# === LOOP DE PROTEÇÃO ===
def firewall_loop():
    print("🛡️ Firewall adaptativo iniciado. Monitorando conexões...")
    escanear_roteador()  # Executa o scanner logo no início

    try:
        while True:
            analisar_conexoes()
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n🛑 Encerrado pelo usuário.")

firewall_loop()
