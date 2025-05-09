# --- START OF FILE hsbp_step1_test.py ---

import time
import logging
import os
import sys
import traceback
import re
from pathlib import Path # Added for host-side path handling

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
HSBP_SCRIPT_DIR = "/mnt/workarea/H-SBP" # Path inside CORE nodes
CONFIG_FILE_PATH = os.path.join(HSBP_SCRIPT_DIR, "config/hsbp_config.json")
PYTHON_EXEC = "/opt/core/venv/bin/python3" # Path to python in CORE venv
HOST_LOG_DIR = Path("./hsbp_logs") # Directory next to the script on the HOST

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

def collect_node_logs(core: client.CoreGrpcClient, session_id: int, nodes_dict: dict, node_ids_map: dict):
    """Collects logs from /tmp/*.log on each node and saves them to HOST_LOG_DIR."""
    logging.info(f"\n--- Collecting Logs from Nodes to {HOST_LOG_DIR} ---")
    HOST_LOG_DIR.mkdir(parents=True, exist_ok=True) # Ensure host log directory exists

    for name_key, node in nodes_dict.items():
        node_config_id = node_ids_map.get(name_key)
        if not node_config_id:
            logging.warning(f"Skipping log collection for node {name_key}: Config ID not found.")
            continue

        log_file_on_node = f"/tmp/{node_config_id}.log"
        host_log_file = HOST_LOG_DIR / f"{node_config_id}.log"
        command = f"cat {log_file_on_node}"
        logging.info(f"Attempting to collect log from node {node.id} ({name_key}): {command}")

        try:
            # Execute 'cat' on the node and wait for the output
            return_code, output = core.node_command(session_id, node.id, command, wait=True, shell=True)

            if return_code == 0:
                logging.info(f"  Successfully retrieved log from node {node.id}. Size: {len(output)} bytes.")
                try:
                    with open(host_log_file, "w") as f:
                        f.write(output)
                    logging.info(f"  Saved log to host: {host_log_file}")
                except Exception as e:
                    logging.error(f"  Error writing log file {host_log_file} on host: {e}")
            else:
                # Log file might not exist if script failed early or didn't produce output
                logging.warning(f"  Command '{command}' failed on node {node.id} (RC={return_code}). Log file might not exist or be empty.")
                # Optionally create an empty file or write an error marker on the host
                try:
                     with open(host_log_file, "w") as f:
                          f.write(f"# Log collection failed. Command '{command}' on node {node.id} returned code {return_code}.\n")
                     logging.info(f"  Created marker file on host: {host_log_file}")
                except Exception as e:
                     logging.error(f"  Error writing marker file {host_log_file} on host: {e}")


        except Exception as e:
            logging.error(f"  Error collecting log from node {node.id} using command '{command}': {e}")
        time.sleep(0.1) # Small delay between nodes

def main():
    iface_helper = client.InterfaceHelper(ip4_prefix="172.16.0.0/16")
    core = client.CoreGrpcClient()
    session = None
    nodes = {} # Define nodes dict outside try block for finally access

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
        # No need for node_interfaces dict anymore

        for name_key, pos in positions.items():
             node = session.add_node(
                 node_id_counter, model="PC", name=name_key, position=pos
             )
             nodes[name_key] = node # Store node object by friendly name
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
        wait_time = 15
        logging.info(f"Waiting {wait_time} seconds for network initialization...")
        time.sleep(wait_time)

        # --- Get/Verify Node IPs ---
        node_ips = {}
        all_ips_found = True
        logging.info("Attempting to retrieve/verify Node IPs via node_command...")
        for name_key, node in nodes.items():
            ip = get_node_ip_via_cmd(core, session.id, node.id, "eth0") # Use eth0 default
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

        # --- Construct and Execute Commands with Redirection ---
        commands_to_run = []
        log_dir_on_node = "/tmp"

        # Define commands with redirection
        sl_script = os.path.join(HSBP_SCRIPT_DIR, "swarm_leader.py")
        sl_log = os.path.join(log_dir_on_node, f"{NODE_IDS['SL']}.log")
        sl_cmd = f"{PYTHON_EXEC} -u {sl_script} --id {NODE_IDS['SL']} --config {CONFIG_FILE_PATH} > {sl_log} 2>&1"
        commands_to_run.append((nodes["SL"].id, sl_cmd))

        ch1_script = os.path.join(HSBP_SCRIPT_DIR, "cluster_head.py")
        ch1_log = os.path.join(log_dir_on_node, f"{NODE_IDS['CH1']}.log")
        ch1_cmd = f"{PYTHON_EXEC} -u {ch1_script} --id {NODE_IDS['CH1']} --config {CONFIG_FILE_PATH} --sl-ip {node_ips['SL']} > {ch1_log} 2>&1"
        commands_to_run.append((nodes["CH1"].id, ch1_cmd))

        ch2_script = os.path.join(HSBP_SCRIPT_DIR, "cluster_head.py")
        ch2_log = os.path.join(log_dir_on_node, f"{NODE_IDS['CH2']}.log")
        ch2_cmd = f"{PYTHON_EXEC} -u {ch2_script} --id {NODE_IDS['CH2']} --config {CONFIG_FILE_PATH} --sl-ip {node_ips['SL']} > {ch2_log} 2>&1"
        commands_to_run.append((nodes["CH2"].id, ch2_cmd))

        m101_script = os.path.join(HSBP_SCRIPT_DIR, "member.py")
        m101_log = os.path.join(log_dir_on_node, f"{NODE_IDS['M101']}.log")
        m101_cmd = f"{PYTHON_EXEC} -u {m101_script} --id {NODE_IDS['M101']} --config {CONFIG_FILE_PATH} --ch-ip {node_ips['CH1']} > {m101_log} 2>&1"
        commands_to_run.append((nodes["M101"].id, m101_cmd))

        m201_script = os.path.join(HSBP_SCRIPT_DIR, "member.py")
        m201_log = os.path.join(log_dir_on_node, f"{NODE_IDS['M201']}.log")
        m201_cmd = f"{PYTHON_EXEC} -u {m201_script} --id {NODE_IDS['M201']} --config {CONFIG_FILE_PATH} --ch-ip {node_ips['CH2']} > {m201_log} 2>&1"
        commands_to_run.append((nodes["M201"].id, m201_cmd))

        logging.info("\n--- Starting H-SBP Node Scripts (output redirected to /tmp/*.log on nodes) ---")
        for node_id, cmd in commands_to_run:
            logging.info(f"Executing on node {node_id}: {cmd}")
            core.node_command(session.id, node_id, cmd, wait=False, shell=True) # Must use shell=True for redirection
            time.sleep(0.5)

        logging.info("\n--- All scripts launched ---")
        logging.info(f"Scripts running. Check logs in /tmp/ on nodes via GUI or wait until script finishes.")
        logging.info(f"Logs will be collected to '{HOST_LOG_DIR.resolve()}' on this host upon completion.")
        input("Press Enter to stop the scenario, collect logs, and stop the session...")

        # *** Add Log Collection Step Here ***
        collect_node_logs(core, session.id, nodes, NODE_IDS)
        # ***********************************

    except Exception as e:
        logging.error(f"An error occurred during main execution: {e}")
        traceback.print_exc()
    finally:
        if session:
            try:
                # If scripts were still running, optionally try to stop them gracefully first
                # for node_id, _ in commands_to_run:
                #     core.node_command(session.id, node_id, "pkill -f swarm_leader.py", wait=False, shell=True)
                #     core.node_command(session.id, node_id, "pkill -f cluster_head.py", wait=False, shell=True)
                #     core.node_command(session.id, node_id, "pkill -f member.py", wait=False, shell=True)
                # time.sleep(1) # Give pkill time

                logging.info(f"Stopping session {session.id}")
                core.stop_session(session.id)
            except Exception as e:
                logging.error(f"Error stopping session {session.id}: {e}")
        core.close()
        logging.info("Disconnected from CORE")

if __name__ == "__main__":
    main()
# --- END OF FILE hsbp_step1_test.py ---
