import asyncio
import json
import time
import os
from datetime import datetime
from collections import defaultdict

from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list, rdpcap
import websockets

# ── Config ────────────────────────────────────────────
INTERFACE = "en0"       # your WiFi interface
WS_HOST   = "localhost"
WS_PORT   = 8765

# ── Connected clients ─────────────────────────────────
clients = set()

# ── Threat detection state ────────────────────────────
syn_tracker  = defaultdict(int)   # src_ip → SYN count
port_tracker = defaultdict(set)   # src_ip → set of ports
icmp_tracker = defaultdict(int)   # src_ip → ICMP count
last_reset   = time.time()

# ── Classify a packet into a threat event ─────────────
def classify_packet(pkt):
    global last_reset

    # Reset counters every 10 seconds
    now = time.time()
    if now - last_reset > 10:
        syn_tracker.clear()
        port_tracker.clear()
        icmp_tracker.clear()
        last_reset = now

    if not pkt.haslayer(IP):
        return None

    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = None
    sev = None
    msg = None

    # TCP analysis
    if pkt.haslayer(TCP):
        proto = "TCP"
        flags = pkt[TCP].flags
        dport = pkt[TCP].dport

        # SYN flood detection
        if "S" in str(flags) and "A" not in str(flags):
            syn_tracker[src] += 1
            if syn_tracker[src] > 80:
                sev = "CRIT"
                msg = f"SYN flood detected — {syn_tracker[src]} SYNs from {src}"

        # Port scan detection
        port_tracker[src].add(dport)
        if len(port_tracker[src]) > 20:
            sev = "HIGH"
            msg = f"Port scan detected — {len(port_tracker[src])} ports swept from {src}"

        # Suspicious ports
        if dport in [22, 23, 3389, 445, 1433, 3306] and sev is None:
            sev = "MED"
            msg = f"Probe on sensitive port {dport} from {src}"

    # UDP analysis
    elif pkt.haslayer(UDP):
        proto = "UDP"
        dport = pkt[UDP].dport
        if dport == 53:
            sev = "LOW"
            msg = f"DNS query from {src}"
        else:
            sev = "LOW"
            msg = f"UDP traffic to port {dport} from {src}"

    # ICMP analysis
    elif pkt.haslayer(ICMP):
        proto = "ICMP"
        icmp_tracker[src] += 1
        if icmp_tracker[src] > 30:
            sev = "HIGH"
            msg = f"ICMP flood — {icmp_tracker[src]} packets from {src}"
        else:
            sev = "LOW"
            msg = f"ICMP ping from {src}"

    if sev is None or msg is None:
        return None

    return {
        "time": datetime.now().strftime("%H:%M:%S"),
        "sev":  sev,
        "src":  src,
        "dst":  dst,
        "msg":  msg,
        "proto": proto,
    }

# ── Broadcast to all connected WebSocket clients ───────
async def broadcast(event):
    if clients:
        data = json.dumps(event)
        await asyncio.gather(*[c.send(data) for c in clients])

# ── WebSocket connection handler ───────────────────────
async def ws_handler(websocket):
    clients.add(websocket)
    print(f"[+] Client connected ({len(clients)} total)")
    try:
        await websocket.wait_closed()
    finally:
        clients.discard(websocket)
        print(f"[-] Client disconnected ({len(clients)} total)")

# ── Packet callback (runs in a thread) ────────────────
loop = None

def packet_callback(pkt):
    event = classify_packet(pkt)
    if event:
        print(f"[{event['sev']}] {event['msg']}")
        asyncio.run_coroutine_threadsafe(broadcast(event), loop)

# ── Pcap replay ───────────────────────────────────────
def replay_pcap(filepath):
    """Replay a .pcap file through the same classifier as live traffic."""
    print(f"[*] Replaying pcap: {filepath}")
    packets = rdpcap(filepath)
    for pkt in packets:
        event = classify_packet(pkt)
        if event:
            print(f"[{event['sev']}] {event['msg']}")
            asyncio.run_coroutine_threadsafe(broadcast(event), loop)
            time.sleep(0.05)
    print(f"[*] Pcap replay complete — switching to live sniffing")

# ── Main ──────────────────────────────────────────────
async def main():
    global loop
    loop = asyncio.get_running_loop()

    print(f"[*] Starting WebSocket server on ws://{WS_HOST}:{WS_PORT}")
    print(f"[*] Sniffing on interface: {INTERFACE}")
    print(f"[*] Available interfaces: {get_if_list()}")

    async with websockets.serve(ws_handler, WS_HOST, WS_PORT):
        if os.path.exists("capture.pcap"):
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: replay_pcap("capture.pcap")
            )
        await asyncio.get_event_loop().run_in_executor(
            None, lambda: sniff(iface=INTERFACE, prn=packet_callback, store=False)
        )

if __name__ == "__main__":
    asyncio.run(main())