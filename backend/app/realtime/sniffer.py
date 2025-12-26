from scapy.all import sniff
from app.realtime.flow_table import update_flow, expire_flows
from app.realtime.extractor import extract_features
from app.decision import detect
import threading
import time
import signal
import sys

stop_event = threading.Event()

def packet_handler(pkt):
    if stop_event.is_set():
        return
    update_flow(pkt)

def flow_monitor_loop():
    while not stop_event.is_set():
        expired = expire_flows()
        for key, flow in expired:
            features = extract_features(flow)
            result = detect(features)

            print("\n=== FLOW DETECTED ===")
            print("Flow:", key)
            print("Features:", features)
            print("IDS Result:", result)

        time.sleep(1)

def handle_shutdown(sig, frame):
    print("\n[*] Shutting down IDS sensor cleanly...")
    stop_event.set()
    sys.exit(0)

def start_sniffing():
    print("[*] Starting Scapy sniffing with flow monitor...")

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    monitor_thread = threading.Thread(target=flow_monitor_loop)
    monitor_thread.start()

    sniff(prn=packet_handler, store=False)
