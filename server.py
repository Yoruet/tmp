#!/usr/bin/env python3
import socket, threading, subprocess, logging, csv, os, statistics
from datetime import datetime
from scapy.all import rdpcap, TCP, IP

# ——— Configuration ———
HOST      = ''
PORT      = 8443
THRESHOLD = 100
PCAP_DIR  = 'pcaps'
STAT_FILE = 'stats.csv'
LOG_FILE  = 'tcp_service.log'
FULL_PCAP = '/tmp/full.pcap'   # tcpdump 全量抓包

# ——— Logging ———
logger = logging.getLogger(); logger.setLevel(logging.INFO)
fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S")
ch = logging.StreamHandler(); ch.setFormatter(fmt); logger.addHandler(ch)
fh = logging.FileHandler(LOG_FILE); fh.setFormatter(fmt); logger.addHandler(fh)

client_data = {}   # ip -> {'count':int,'active':bool}
data_lock   = threading.Lock()
csv_lock    = threading.Lock()

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def init_csv():
    if not os.path.exists(STAT_FILE):
        with open(STAT_FILE,'w',newline='') as f:
            w=csv.writer(f)
            w.writerow([
                'IP',
                'TS_RTT_min_ms','TS_RTT_avg_ms','TS_RTT_std_ms',
                'MSS_bytes','PMTU_bytes',
                'MTR_min_ms','MTR_avg_ms','MTR_std_ms'
            ])

def start_tcpdump():
    cmd = [
        'tcpdump','-i','any','-s','0','-U','-C','100','-W','1',
        'tcp port', str(PORT),
        '-w', FULL_PCAP
    ]
    p = subprocess.Popen(cmd,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    logger.info(f"tcpdump started → {FULL_PCAP}")
    return p

def filter_and_write(ip, out_pcap):
    subprocess.run([
        'tcpdump','-r', FULL_PCAP, '-w', out_pcap,
        'host', ip, 'and', 'port', str(PORT)
    ], check=True)

def analyze_ts_handshake(pcap_file, client_ip):
    """
    用 TCP Timestamp 选项计算三次握手 RTT：
      - 抓 SYN-ACK（flags&0x12）包里的 TSval 和 pkt.time 存到 ts_map
      - 抓回显 ACK（flags&0x10）包里的 TSecr，从 ts_map 找到原 TSval 的发送时间
    """
    try:
        pkts = rdpcap(pcap_file)
    except Exception as e:
        logger.error(f"read {pcap_file} failed: {e}")
        return None, None, None

    ts_map = {}   # TSval -> send_time
    rtts   = []

    for p in pkts:
        if IP in p and TCP in p and p[TCP].flags & 0x12 == 0x12:
            # 这是一条 SYN-ACK from server -> client
            if p[IP].dst == client_ip and p[TCP].sport == PORT:
                # 拿到 TSval
                for opt in p[TCP].options:
                    if opt[0] == 'Timestamp':
                        tsval = opt[1][0]
                        ts_map[tsval] = p.time
                        break

        elif IP in p and TCP in p and p[TCP].flags & 0x10:
            # 普通 ACK from client -> server
            if p[IP].src == client_ip and p[TCP].dport == PORT:
                for opt in p[TCP].options:
                    if opt[0] == 'Timestamp':
                        tsecr = opt[1][1]  # 回显的 TSval
                        if tsecr in ts_map:
                            delta = (p.time - ts_map[tsecr]) * 1000.0
                            if delta >= 0:
                                rtts.append(delta)
                            del ts_map[tsecr]
                        break

    if not rtts:
        return None, None, None
    mn  = round(min(rtts), 3)
    avg = round(statistics.mean(rtts), 3)
    std = round(statistics.stdev(rtts), 3) if len(rtts)>1 else 0.0
    return mn, avg, std

def analyze_mss(pcap_file, client_ip):
    try:
        pkts = rdpcap(pcap_file)
    except Exception as e:
        logger.error(f"read {pcap_file} failed: {e}")
        return None, None

    for p in pkts:
        if IP in p and TCP in p \
        and p[TCP].flags == 0x02 \
        and p[IP].src == client_ip and p[TCP].dport == PORT:
            for opt in p[TCP].options:
                if opt[0] == 'MSS':
                    mss = int(opt[1])
                    return mss, mss + 40
            break
    return None, None

def analyze_mtr(ip, count=5):
    try:
        out = subprocess.check_output(
            ['mtr','-n','-r','-c',str(count),ip],
            stderr=subprocess.DEVNULL, text=True, timeout=30
        )
    except Exception as e:
        logger.error(f"mtr failed for {ip}: {e}")
        return None, None, None
    lines = [l for l in out.splitlines() if ip in l]
    if not lines:
        return None, None, None
    parts = lines[-1].split()
    try:
        avg = float(parts[4]); mn = float(parts[5]); std = float(parts[8])
    except:
        return None, None, None
    return mn, avg, std

def process_ip(ip):
    dirp = os.path.join(PCAP_DIR, ip.replace(':','_'))
    ensure_dir(dirp)
    ts = datetime.now().strftime("%Y%m%d%H%M%S")
    out_pcap = os.path.join(dirp, f"{ip}_{ts}.pcap")

    filter_and_write(ip, out_pcap)
    logger.info(f"Filtered pcap for {ip} → {out_pcap}")

    mn_rtt, avg_rtt, std_rtt = analyze_ts_handshake(out_pcap, ip)
    logger.info(f"{ip} TCP-TS RTT: min={mn_rtt}, avg={avg_rtt}, std={std_rtt} ms")

    mss, pmtu = analyze_mss(out_pcap, ip)
    logger.info(f"{ip} MSS={mss}, PMTU={pmtu}")

    mn2, avg2, std2 = analyze_mtr(ip)
    logger.info(f"{ip} mtr RTT: min={mn2}, avg={avg2}, std={std2} ms")

    with csv_lock:
        with open(STAT_FILE,'a',newline='') as f:
            w = csv.writer(f)
            w.writerow([
                ip,
                mn_rtt, avg_rtt, std_rtt,
                mss, pmtu,
                mn2, avg2, std2
            ])
    logger.info(f"Wrote stats for {ip}")

def handle_client(conn, addr):
    ip = addr[0]; conn.close()
    with data_lock:
        rec = client_data.setdefault(ip, {'count':0,'active':True})
        rec['count']+=1
        cnt = rec['count']
        logger.info(f"{ip} connection count: {cnt}")
        if cnt==THRESHOLD and rec['active']:
            rec['active']=False
            threading.Thread(target=process_ip,
                             args=(ip,), daemon=True).start()

def main():
    ensure_dir(PCAP_DIR)
    init_csv()
    p = start_tcpdump()

    srv=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    srv.bind((HOST,PORT)); srv.listen()
    logger.info(f"Server listening on {PORT}")

    try:
        while True:
            c,a = srv.accept()
            threading.Thread(target=handle_client,
                             args=(c,a), daemon=True).start()
    except KeyboardInterrupt:
        logger.info("Shutting down")
    finally:
        p.terminate()
        srv.close()
        logger.info("Exited cleanly")

if __name__=='__main__':
    main()
