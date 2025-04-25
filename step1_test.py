# --- START OF FILE hsbp_step1_test.py ---

import time
import logging
import os
import sys
import traceback
import re
from pathlib import Path # Keep for host-side operations if any

# Add H-SBP directory to Python path if needed
hsbp_dir = "/mnt/workarea/H-SBP" # Adjust if your path is different
if hsbp_dir not in sys.path:
    sys.path.append(hsbp_dir)

from core.api.grpc import client
from core.api.grpc.wrappers import NodeType, Position, LinkOptions
from core.emane.models.rfpipe import EmaneRfPipeModel

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Configuration ---
HSBP_SCRIPT_DIR = "/mnt/workarea/H-SBP" # Path to scripts *inside* CORE nodes
CONFIG_FILE_PATH = os.path.join(HSBP_SCRIPT_DIR, "config/hsbp_config.json")
PYTHON_EXEC = "/opt/core/venv/bin/python3"

# *** Define the ABSOLUTE log path as seen INSIDE the node ***
# *** THIS PATH MUST BE WRITABLE FROM INSIDE THE NODE ***
NODE_LOG_DIR_ABS = "/mnt/workarea/H-SBP/logs"
# **********************************************************

NODE_IDS = { # Mapping friendly name to config ID
    "SL": "sl-0", "CH1": "ch-1", "CH2": "ch-2", "M101": "m-101", "M201": "m-201"
}
NODE_TARGET_IPS = { # Based on typical gRPC start node IDs
     1: "172.16.0.2", 2: "172.16.0.3", 3: "172.16.0.4", 4: "172.16.0.5", 5: "172.16.0.6"
}
IP4_MASK = 16
# --- End Configuration ---

# --- get_node_ip_via_cmd function (keep as before) ---
def get_node_ip_via_cmd(core: client.CoreGrpcClient, session_id: int, node_id: int, iface_name: str = "eth0"):
    # ... (previous version using node_command 'ip addr') ...
    command = f"ip -4 addr show {iface_name}"
    logging.debug(f"Executing command on node {node_id}: {command}")
    try:
        return_code, output = core.node_command(session_id, node_id, command, wait=True, shell=False)
        logging.debug(f"Node {node_id} 'ip addr show {iface_name}' output:\n{output}")
        if return_code == 0 and output:
            match = re.search(rf"inet\s+(\d+\.\d+\.\d+\.\d+)/\d+", output)
            if match:
                ip_address = match.group(1)
                logging.info(f"  SUCCESS: Parsed IP {ip_address} for node {node_id} iface {iface_name}")
                return ip_address
            else:
                logging.warning(f"Could not parse IPv4 address from 'ip addr' output for node {node_id}, iface {iface_name}.")
                return None
        else:
            logging.warning(f"Command '{command}' failed on node {node_id} or returned no output. Return code: {return_code}")
            return None
    except Exception as e:
        logging.error(f"Error executing or parsing 'ip addr' command on node {node_id}: {e}")
        # traceback.print_exc() # Uncomment for detailed debugging if needed
        return None
# ----------------------------------------------------

def main():
    # Create host log directory if it doesn't exist (optional, good practice)
    host_log_path = Path(NODE_LOG_DIR_ABS)
    try:
         host_log_path.mkdir(parents=True, exist_ok=True)
         logging.info(f"Ensured host log directory exists: {host_log_path.resolve()}")
    except Exception as e:
         logging.warning(f"Could not create host log directory '{host_log_path.resolve()}': {e}. Ensure it exists and is writable.")
         # Continue anyway, assuming it exists or node redirection handles creation

    iface_helper = client.InterfaceHelper(ip4_prefix="172.16.0.0/16")
    core = client.CoreGrpcClient()
    session = None
    nodes = {}

    try:
        core.connect()
        logging.info("Connected to CORE gRPC")

        session = core.create_session()
        logging.info(f"Created CORE session {session.id}")

        # --- Network Topology ---
        emane_position = Position(x=300, y=300)
        emane_node = session.add_node(
            100, _type=NodeType.EMANE, position=emane_position, emane=EmaneRfPipeModel.name
            )
        logging.info(f"Added EMANE node {emane_node.id} with model {EmaneRfPipeModel.name}")

        positions = { # name_key: position
            "SL": Position(x=300, y=100), "CH1": Position(x=150, y=250),
            "CH2": Position(x=450, y=250), "M101": Position(x=150, y=350),
            "M201": Position(x=450, y=350),
        }

        # Create Nodes and Links
        node_id_counter = 1
        for name_key, pos in positions.items():
             node = session.add_node(
                 node_id_counter, model="PC", name=name_key, position=pos
             )
             nodes[name_key] = node
             logging.info(f"Added {name_key} node {node.id} ({NODE_IDS[name_key]})")

             iface = iface_helper.create_iface(node.id, 0)
             target_ip = NODE_TARGET_IPS.get(node.id)
             if not target_ip:
                 logging.error(f"FATAL: No target IP defined for Node ID {node.id}"); return

             iface.ip4 = target_ip; iface.ip4_mask = IP4_MASK
             iface.ip6 = None; iface.ip6_mask = None
             logging.info(f"  Manually configured iface {iface.name or 'eth0'} for node {node.id}: IP={iface.ip4}/{iface.ip4_mask}")

             session.add_link(node1=node, node2=emane_node, iface1=iface)
             logging.info(f"Linked {name_key} node {node.id} interface {iface.name or 'eth0'} to EMANE node {emane_node.id}")
             node_id_counter += 1

        # Start Session & Wait
        core.start_session(session)
        logging.info("Session started.")
        wait_time = 2
        logging.info(f"Waiting {wait_time} seconds for network initialization...")
        time.sleep(wait_time)

        # --- Get/Verify Node IPs ---
        node_ips = {}
        all_ips_found = True
        logging.info("Attempting to retrieve/verify Node IPs via node_command...")
        for name_key, node in nodes.items():
            ip = get_node_ip_via_cmd(core, session.id, node.id, "eth0")
            expected_ip = NODE_TARGET_IPS.get(node.id)
            if ip and ip == expected_ip:
                node_ips[name_key] = ip
            elif ip and ip != expected_ip:
                 logging.error(f"  IP MISMATCH for {name_key} ({node.id}): Expected {expected_ip}, Got {ip}")
                 all_ips_found = False
            else:
                logging.error(f"  FAILURE: Could not get/verify IP for {name_key} ({node.id}) (Expected {expected_ip})")
                all_ips_found = False
            time.sleep(0.2)

        if not all_ips_found:
            logging.error("IP verification failed. Aborting script launch.")
            input("Press Enter to stop session...")
            return

        # --- Construct and Execute Commands with DIRECT Redirection ---
        commands_to_run = []

        # Define commands with redirection TO THE SHARED HOST PATH
        sl_script = os.path.join(HSBP_SCRIPT_DIR, "swarm_leader.py")
        sl_log = os.path.join(NODE_LOG_DIR_ABS, f"{NODE_IDS['SL']}.log") # Use absolute path
        sl_cmd = f"{PYTHON_EXEC} -u {sl_script} --id {NODE_IDS['SL']} --config {CONFIG_FILE_PATH} > {sl_log} 2>&1"
        commands_to_run.append((nodes["SL"].id, sl_cmd))

        ch1_script = os.path.join(HSBP_SCRIPT_DIR, "cluster_head.py")
        ch1_log = os.path.join(NODE_LOG_DIR_ABS, f"{NODE_IDS['CH1']}.log")
        ch1_cmd = f"{PYTHON_EXEC} -u {ch1_script} --id {NODE_IDS['CH1']} --config {CONFIG_FILE_PATH} --sl-ip {node_ips['SL']} > {ch1_log} 2>&1"
        commands_to_run.append((nodes["CH1"].id, ch1_cmd))

        ch2_script = os.path.join(HSBP_SCRIPT_DIR, "cluster_head.py")
        ch2_log = os.path.join(NODE_LOG_DIR_ABS, f"{NODE_IDS['CH2']}.log")
        ch2_cmd = f"{PYTHON_EXEC} -u {ch2_script} --id {NODE_IDS['CH2']} --config {CONFIG_FILE_PATH} --sl-ip {node_ips['SL']} > {ch2_log} 2>&1"
        commands_to_run.append((nodes["CH2"].id, ch2_cmd))

        m101_script = os.path.join(HSBP_SCRIPT_DIR, "member.py")
        m101_log = os.path.join(NODE_LOG_DIR_ABS, f"{NODE_IDS['M101']}.log")
        m101_cmd = f"{PYTHON_EXEC} -u {m101_script} --id {NODE_IDS['M101']} --config {CONFIG_FILE_PATH} --ch-ip {node_ips['CH1']} > {m101_log} 2>&1"
        commands_to_run.append((nodes["M101"].id, m101_cmd))

        m201_script = os.path.join(HSBP_SCRIPT_DIR, "member.py")
        m201_log = os.path.join(NODE_LOG_DIR_ABS, f"{NODE_IDS['M201']}.log")
        m201_cmd = f"{PYTHON_EXEC} -u {m201_script} --id {NODE_IDS['M201']} --config {CONFIG_FILE_PATH} --ch-ip {node_ips['CH2']} > {m201_log} 2>&1"
        commands_to_run.append((nodes["M201"].id, m201_cmd))

        logging.info(f"\n--- Starting H-SBP Node Scripts (output redirected to {NODE_LOG_DIR_ABS}/*.log on host) ---")
        for node_id, cmd in commands_to_run:
            logging.info(f"Executing on node {node_id}: {cmd}")
            core.node_command(session.id, node_id, cmd, wait=False, shell=True) # Must use shell=True for redirection
            time.sleep(0.5)

        logging.info("\n--- All scripts launched ---")
        logging.info("Scripts running. Check logs directly in the host directory:")
        logging.info(f"  '{Path(NODE_LOG_DIR_ABS).resolve()}'")
        logging.info("You can use 'tail -f' on the host to monitor them.")
        input("Press Enter to stop the session and scripts...")

        # *** Log collection function is NO LONGER NEEDED ***
        # collect_node_logs(core, session.id, nodes, NODE_IDS) # REMOVED

    except Exception as e:
        logging.error(f"An error occurred during main execution: {e}")
        traceback.print_exc()
    finally:
        if session:
            try:
                # Optionally try to stop scripts running in background on nodes
                # This is less critical now as logs are on the host
                logging.info("Stopping session - scripts will be terminated by CORE.")
                core.stop_session(session.id)
            except Exception as e:
                logging.error(f"Error stopping session {session.id}: {e}")
        core.close()
        logging.info("Disconnected from CORE")

if __name__ == "__main__":
    main()
# --- END OF FILE hsbp_step1_test.py ---
