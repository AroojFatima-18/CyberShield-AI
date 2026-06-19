"""
CyberShield AI – Search Algorithms v2
Real-world styled cyber investigation graph with actual IP addresses,
email accounts, device IDs, servers, and crypto wallets.

This simulates a real cybercrime investigation network where:
- Nodes = actual digital entities found during investigation
- Edges = traced communication/transaction links between entities
- BFS   = find shortest connection chain between suspect and victim
- DFS   = explore full depth of criminal network
- A*    = find optimal high-threat investigation path
"""
import heapq
import networkx as nx
import random

random.seed(42)

# ── Real-world styled investigation entities ──────────────────────────────────
INVESTIGATION_NODES = [
    # Suspected attackers
    {"id": "SUSP-IP-001",           "type": "ip_address",   "label": "Suspect IP Address",           "risk": 91, "level": "critical"},
    {"id": "SUSP-IP-002",           "type": "ip_address",   "label": "TOR Exit Node",                "risk": 88, "level": "critical"},
    {"id": "SUSP-IP-003",           "type": "ip_address",   "label": "VPN Relay Server",             "risk": 85, "level": "critical"},

    # Fake/compromised accounts
    {"id": "SUSP-EMAIL-001",        "type": "email",        "label": "Phishing Email Account",       "risk": 94, "level": "critical"},
    {"id": "SUSP-EMAIL-002",        "type": "email",        "label": "Spoofed Service Account",      "risk": 89, "level": "critical"},
    {"id": "COMP-ACCT-001",         "type": "user_account", "label": "Compromised User Account",     "risk": 76, "level": "high"},
    {"id": "FAKE-ACCT-001",         "type": "user_account", "label": "Fake Social Media Account",    "risk": 72, "level": "high"},

    # Devices
    {"id": "SUSP-DEVICE-AND-001",   "type": "device",       "label": "Suspect Android Device",       "risk": 83, "level": "critical"},
    {"id": "SUSP-DEVICE-WIN-001",   "type": "device",       "label": "Infected Windows PC",          "risk": 78, "level": "high"},
    {"id": "VICTIM-DEVICE-MOB-001", "type": "device",       "label": "Victim Mobile Device",         "risk": 35, "level": "medium"},

    # Servers and infrastructure
    {"id": "PHISH-SERVER-001",      "type": "server",       "label": "Phishing Website Server",      "risk": 97, "level": "critical"},
    {"id": "PROXY-SERVER-001",      "type": "server",       "label": "Anonymizing Proxy Server",     "risk": 82, "level": "critical"},
    {"id": "C2-SERVER-001",         "type": "server",       "label": "Malware Command & Control",    "risk": 99, "level": "critical"},

    # Crypto wallets
    {"id": "WALLET-BTC-001",        "type": "wallet",       "label": "Bitcoin Ransom Wallet",        "risk": 93, "level": "critical"},
    {"id": "WALLET-ETH-001",        "type": "wallet",       "label": "Ethereum Fraud Wallet",        "risk": 87, "level": "critical"},

    # Victims
    {"id": "VICTIM-EMAIL-001",      "type": "email",        "label": "Victim Email Account",         "risk": 15, "level": "low"},
    {"id": "VICTIM-DEVICE-001",     "type": "device",       "label": "Victim Endpoint Device",       "risk": 20, "level": "low"},
    {"id": "VICTIM-IP-001",         "type": "ip_address",   "label": "Victim IP Address",            "risk": 18, "level": "low"},
]

# ── Communication edges ──────────────────────────────────────────────────────
# (source_id, target_id, weight, comm_type)
# Weight = suspicion score (1-10). Higher = more suspicious.
INVESTIGATION_EDGES = [
    # Attacker chain: Suspect IP → TOR → VPN → Phishing Server
    ("SUSP-IP-001",          "SUSP-IP-002",           9.2, "tor_routing"),
    ("SUSP-IP-002",          "SUSP-IP-003",           8.8, "vpn_tunnel"),
    ("SUSP-IP-003",          "PHISH-SERVER-001",  9.5, "server_deploy"),
    ("SUSP-IP-003",          "PROXY-SERVER-001",   8.1, "proxy_connect"),

    # Phishing campaign
    ("PHISH-SERVER-001", "SUSP-EMAIL-001", 9.0, "phishing_email"),
    ("SUSP-EMAIL-001", "VICTIM-EMAIL-001", 8.5, "email_sent"),
    ("SUSP-EMAIL-002", "VICTIM-EMAIL-001", 8.7, "phishing_email"),

    # Device connections
    ("SUSP-IP-001",          "SUSP-DEVICE-AND-001",  9.8, "device_origin"),
    ("SUSP-DEVICE-AND-001", "SUSP-DEVICE-WIN-001",   7.2, "local_network"),
    ("SUSP-DEVICE-WIN-001",  "C2-SERVER-001",    9.6, "malware_beacon"),
    ("C2-SERVER-001",   "VICTIM-DEVICE-MOB-001",       8.9, "exploit_delivery"),
    ("C2-SERVER-001",   "VICTIM-DEVICE-001",    9.1, "ransomware_deploy"),

    # Financial trail
    ("COMP-ACCT-001",       "WALLET-BTC-001",    9.3, "crypto_transfer"),
    ("FAKE-ACCT-001",     "WALLET-ETH-001",  8.6, "fraud_payment"),
    ("WALLET-BTC-001",   "SUSP-IP-003",           7.8, "money_laundering"),

    # Victim connections
    ("VICTIM-EMAIL-001","VICTIM-DEVICE-MOB-001",       3.1, "legitimate_use"),
    ("VICTIM-DEVICE-MOB-001",      "VICTIM-IP-001",            2.8, "legitimate_use"),
    ("VICTIM-IP-001",           "VICTIM-DEVICE-001",    3.5, "home_network"),

    # Proxy chain
    ("PROXY-SERVER-001",  "COMP-ACCT-001",        8.4, "account_access"),
    ("PROXY-SERVER-001",  "FAKE-ACCT-001",      7.9, "account_access"),
    ("COMP-ACCT-001",       "VICTIM-DEVICE-001",    8.2, "credential_theft"),
]

def build_investigation_graph(num_nodes=18, seed=42) -> nx.DiGraph:
    """Build the real-world styled cyber investigation graph."""
    G = nx.DiGraph()

    for node in INVESTIGATION_NODES:
        G.add_node(
            node["id"],
            node_type  = node["type"],
            label      = node["label"],
            risk_score = node["risk"],
            risk_level = node["level"],
        )

    for src, tgt, weight, comm_type in INVESTIGATION_EDGES:
        if src in G and tgt in G:
            G.add_edge(src, tgt, weight=weight, comm_type=comm_type)

    return G

# ── BFS ───────────────────────────────────────────────────────────────────────
def bfs_path(G, source, target):
    """
    BFS: finds shortest hop-count path.
    Use: Minimum relay chain between suspect and victim.
    """
    visited = set()
    queue   = [(source, [source])]
    explored_order = []

    while queue:
        node, path = queue.pop(0)
        if node in visited:
            continue
        visited.add(node)
        explored_order.append(node)
        if node == target:
            return {"found": True, "path": path,
                    "nodes_explored": len(explored_order),
                    "explored_order": explored_order,
                    "algorithm": "BFS",
                    "description": "Shortest hop-count path (fewest relay nodes)"}
        for neighbor in G.successors(node):
            if neighbor not in visited:
                queue.append((neighbor, path + [neighbor]))

    return {"found": False, "path": [], "nodes_explored": len(explored_order),
            "explored_order": explored_order, "algorithm": "BFS",
            "description": "No path found via BFS"}

# ── DFS ───────────────────────────────────────────────────────────────────────
def dfs_path(G, source, target, visited=None, path=None):
    """
    DFS: explores full depth of criminal network recursively.
    Use: Uncover deeply nested attack chains.
    """
    if visited is None:
        visited = set()
        path    = [source]
    visited.add(source)

    if source == target:
        return {"found": True, "path": path,
                "nodes_explored": len(visited),
                "explored_order": list(visited),
                "algorithm": "DFS",
                "description": "Deep recursive traversal of full attack chain"}

    for neighbor in G.successors(source):
        if neighbor not in visited:
            result = dfs_path(G, neighbor, target, visited, path + [neighbor])
            if result["found"]:
                return result

    return {"found": False, "path": [], "nodes_explored": len(visited),
            "explored_order": list(visited), "algorithm": "DFS",
            "description": "No path found via DFS"}

# ── A* ────────────────────────────────────────────────────────────────────────
def _heuristic(G, node, target):
    """
    Heuristic: difference in risk scores.
    Guides A* toward highest-threat nodes first.
    Admissible — never overestimates true cost.
    """
    target_risk = G.nodes[target].get("risk_score", 50)
    node_risk   = G.nodes[node].get("risk_score", 50)
    return abs(target_risk - node_risk) / 100.0

def astar_path(G, source, target):
    """
    A*: cost-optimal path using edge weights + risk heuristic.
    Use: GPS-style routing through highest-threat investigation path.
    """
    open_set = [(0, source, [source])]
    g_cost   = {source: 0.0}
    explored_order = []

    while open_set:
        f, current, path = heapq.heappop(open_set)
        if current in explored_order:
            continue
        explored_order.append(current)

        if current == target:
            return {"found": True, "path": path,
                    "total_cost": round(g_cost[current], 3),
                    "nodes_explored": len(explored_order),
                    "explored_order": explored_order,
                    "algorithm": "A*",
                    "description": "Optimal-cost path via threat-score heuristic"}

        for neighbor in G.successors(current):
            edge_weight = G[current][neighbor].get("weight", 1.0)
            new_g = g_cost[current] + edge_weight
            if new_g < g_cost.get(neighbor, float("inf")):
                g_cost[neighbor] = new_g
                h = _heuristic(G, neighbor, target)
                heapq.heappush(open_set, (new_g + h, neighbor, path + [neighbor]))

    return {"found": False, "path": [], "total_cost": 0,
            "nodes_explored": len(explored_order),
            "explored_order": explored_order, "algorithm": "A*",
            "description": "No path found via A*"}

def run_all_algorithms(G, source, target):
    return {
        "BFS": bfs_path(G, source, target),
        "DFS": dfs_path(G, source, target),
        "A*":  astar_path(G, source, target),
    }
