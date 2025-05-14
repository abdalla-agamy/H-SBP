# --- START OF FILE hsbp_init_join_test.py ---
import time
import logging
import os
import sys
import traceback
import re
from pathlib import Path
import json

hsbp_dir = "/mnt/workarea/H-SBP"
if hsbp_dir not in sys.path: sys.path.append(hsbp_dir)

from core.api.grpc import client
from core.api.grpc.wrappers import NodeType, Position, LinkOptions
from core.emane.models.rfpipe import EmaneRfPipeModel

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

HSBP_SCRIPT_DIR = "/mnt/workarea/H-SBP"
CONFIG_FILE_PATH = os.path.join(HSBP_SCRIPT_DIR, "config/hsbp_config.json")
PYTHON_EXEC = "/opt/core/venv/bin/python3"
HOST_LOG_DIR = Path("/mnt/workarea/H-SBP/logs")
NODE_LOG_DIR_ABS = "/mnt/workarea/H-SBP/logs"
NUM_RUNS = 4 # Number of times to repeat the scenario for each swarm size
SWARM_SIZES = [1000, 2000, 3000, 4000, 5000] # Example total swarm sizes
NUM_CLUSTERS = 5
TARGET_CLUSTER_ID_FOR_JOIN_LEAVE = "1" # Always test join/leave on Cluster 1
num_members_to_leave = 100 # Example: leave 2 members from CH1

NODE_IDS = {
    "SL": "sl-0",
    "CH1": "ch-1",
    "CH2": "ch-2",
    "CH3": "ch-3",
    "CH4": "ch-4",
    "CH5": "ch-5",
    "M10201": "m-10201",
    "M10401": "m-10401",
    "M10601": "m-10601",
    "M10801": "m-10801",
    "M11001": "m-11001",
}

NODE_TARGET_IPS = {
     1: "172.16.0.1",
     2: "172.16.0.2",
     3: "172.16.0.3",
     4: "172.16.0.4",
     5: "172.16.0.5",
     6: "172.16.0.6",
     7: "172.16.0.7",
     8: "172.16.0.8",
     9: "172.16.0.9",
     10: "172.16.0.10",
     11: "172.16.0.11",
}
IP4_MASK = 16

def get_node_ip_via_cmd(core: client.CoreGrpcClient, session_id: int, node_id: int, iface_name: str = "eth0"):
    command = f"ip -4 addr show {iface_name}"
    logging.debug(f"Executing command on node {node_id}: {command}")
    try:
        return_code, output = core.node_command(session_id, node_id, command, wait=True, shell=False)
        logging.debug(f"Node {node_id} 'ip addr show {iface_name}' output:\n{output}")
        if return_code == 0 and output:
            match = re.search(rf"inet\s+(\d+\.\d+\.\d+\.\d+)/\d+", output)
            if match: ip_address = match.group(1); logging.info(f"  CMD CHECK: Parsed IP {ip_address} for node {node_id} iface {iface_name}"); return ip_address
            else: logging.warning(f"CMD CHECK: Could not parse IP from cmd output for node {node_id}, iface {iface_name}."); return None
        else: logging.warning(f"CMD CHECK: Command failed on node {node_id}. RC: {return_code}"); return None
    except Exception as e: logging.error(f"Error during command execution/parsing on node {node_id}: {e}"); return None

def main():
    host_log_path = Path(NODE_LOG_DIR_ABS)
    try: host_log_path.mkdir(parents=True, exist_ok=True); logging.info(f"Ensured host log directory exists: {host_log_path.resolve()}")
    except Exception as e: logging.warning(f"Could not create host log directory '{host_log_path.resolve()}': {e}.")

    iface_helper = client.InterfaceHelper(ip4_prefix="172.16.0.0/16")
    core = client.CoreGrpcClient()
    try:
        session = None
        nodes = {}
        for total_followers in SWARM_SIZES:
            logging.info(f"\n\n{'='*20} STARTING SCENARIO FOR TOTAL FOLLOWERS: {total_followers} {'='*20}")

            # 1. Generate hsbp_config.json for this swarm size
            #    (Assuming generate_config.py is callable or run as a subprocess)
            #    For simplicity, let's assume it's manually run before this script for each size,
            #    OR you integrate the call here. For now, we assume config is ready.
            #    If integrating:
            initial_m_per_cluster = (total_followers // NUM_CLUSTERS) 
            if initial_m_per_cluster < 0: initial_m_per_cluster = 0
            os.system(f"python3 /mnt/workarea/H-SBP/config/generate_config.py {total_followers} {NUM_CLUSTERS}") # Adjust path
            logging.info(f"Generated hsbp_config.json for {total_followers} followers, {initial_m_per_cluster} initial per cluster.")
            time.sleep(1) # Give file system a moment
            os.system(f"python3 /mnt/workarea/H-SBP/config/generate_secrets.py {NUM_CLUSTERS} {initial_m_per_cluster}") # Adjust path
            logging.info(f"Generated hsbp_secrets.json for {NUM_CLUSTERS} clusters, {initial_m_per_cluster} initial per cluster.")
            time.sleep(1) # Give file system a moment

            # Clear previous logs for this swarm size OR use appending (>>)
            # For simplicity with current parser, let's clear before the first run of a new size
            # (If appending, parser will average over all runs for that size)
            # If you want per-run distinct logs, filename needs _run<N> suffix
# Load the generated config to know which nodes to create
            try:
                with open(CONFIG_FILE_PATH, 'r') as f:
                    current_config_data = json.load(f)
                sl_config_id = current_config_data['structure']['sl_id']
                # We'll create SL, all CHs, and ONE joining member for the target cluster
                ch_config_ids = [cluster_info['ch_id'] for cluster_info in current_config_data['structure']['clusters'].values()]
                target_joining_member_config_id = current_config_data['structure']['clusters'][TARGET_CLUSTER_ID_FOR_JOIN_LEAVE]['joining_member']
            except Exception as e:
                logging.error(f"Error reading generated config for {total_followers} followers: {e}. Skipping this size.")
                continue

            # Create a map from config ID (e.g., "sl-0") to a friendly key for 'nodes' dict
            # and define the list of nodes to physically create in CORE
            node_config_id_to_key = {}
            nodes_to_create_in_core = []

            node_config_id_to_key[sl_config_id] = "SL"
            nodes_to_create_in_core.append("SL")

            for i, ch_cid in enumerate(ch_config_ids):
                ch_key = f"CH{i+1}"
                node_config_id_to_key[ch_cid] = ch_key
                nodes_to_create_in_core.append(ch_key)

            # Find the friendly key for the target joining member
            # This assumes NODE_IDS in this script has a mapping for it
            target_joining_member_key = None
            for key, cfg_id in NODE_IDS.items(): # NODE_IDS is your hardcoded map at top of this script
                if cfg_id == target_joining_member_config_id:
                    target_joining_member_key = key
                    break
            if not target_joining_member_key:
                logging.error(f"Could not find friendly key for joining member {target_joining_member_config_id} in NODE_IDS map. Check config.")
                continue
            node_config_id_to_key[target_joining_member_config_id] = target_joining_member_key
            nodes_to_create_in_core.append(target_joining_member_key)


            # Clear/Truncate logs for this swarm size before starting runs
            for node_key in nodes_to_create_in_core:
                log_file_to_clear = Path(NODE_LOG_DIR_ABS) / f"{NODE_IDS[node_key]}.log" # Use NODE_IDS for filename
                print(log_file_to_clear)
                if log_file_to_clear.exists():
                    logging.info(f"Clearing previous log for {NODE_IDS[node_key]}: {log_file_to_clear}")
                    open(log_file_to_clear, 'w').close()


            for run_num in range(1, NUM_RUNS + 1):
                logging.info(f"\n--- Swarm Size: {total_followers}, Run: {run_num}/{NUM_RUNS} ---")
                session = None
                nodes = {}
                try:
                    # --- Create Session and Nodes (as before) ---
                    core.connect()
                    logging.info("Connected to CORE gRPC")
                    session = core.create_session()
                    logging.info(f"Run {run_num}: Created CORE session {session.id}")
                    # ... (Add EMANE node) ...
                    # ... (Create SL, 5 CHs, and 1 Joining Member nodes, link them) ...
                    # This part uses your existing node creation logic from hsbp_init_join_leave_test.py

                    # Example snippet for creating nodes (adapt from your script)
                    emane_node = session.add_node(100, _type=NodeType.EMANE, position=Position(x=300,y=300), emane=EmaneRfPipeModel.name)
                    node_id_counter = 1
                    #nodes_to_create_in_core = ["SL", "CH1", "CH2", "CH3", "CH4", "CH5", "M1200"] # Target joining member of CH1
                    
                    # Define positions for all nodes involved in this run
                    positions_this_run = {
                        "SL": Position(x=300, y=100), "CH1": Position(x=150, y=250),
                        "CH2": Position(x=450, y=250), "CH3": Position(x=200, y=100),
                        "CH4": Position(x=400, y=100), "CH5": Position(x=300, y=400), # Example positions
                        target_joining_member_key: Position(x=150, y=350), # Joining CH1
                    }

                    for name_key in nodes_to_create_in_core:
                         pos = positions_this_run.get(name_key)
                         node_config_id = NODE_IDS[name_key] # Get the ID like "sl-0"
                         node = session.add_node(node_id_counter, model="PC", name=name_key, position=pos)
                         nodes[name_key] = node
                         logging.info(f"Run {run_num}: Added {name_key} node {node.id} ({node_config_id})")
                         iface = iface_helper.create_iface(node.id, 0)
                         target_ip = NODE_TARGET_IPS.get(node.id) # Uses CORE node ID (1,2,3...)
                         iface.ip4 = target_ip; iface.ip4_mask = IP4_MASK; iface.ip6 = None; iface.ip6_mask = None
                         session.add_link(node1=node, node2=emane_node, iface1=iface)
                         node_id_counter += 1
                    # --- End Node Creation Snippet ---


                    core.start_session(session)
                    logging.info(f"Run {run_num}: Session started.")
                    time.sleep(10) # Increased initial wait for network

                    # --- Get/Verify IPs (as before) ---
                    node_ips = {}
                    all_ips_found_run = True
                    for name_key in nodes_to_create_in_core:
                        # ... (IP verification logic) ...
                        ip = get_node_ip_via_cmd(core, session.id, nodes[name_key].id, "eth0")
                        expected_ip = NODE_TARGET_IPS.get(nodes[name_key].id)
                        if ip and ip == expected_ip: node_ips[name_key] = ip
                        else: all_ips_found_run = False; logging.error(f"Run {run_num}: IP verify failed for {name_key}")
                    if not all_ips_found_run: logging.error(f"Run {run_num}: IP verification failed. Skipping this run."); continue # Skip to next run

                    # --- Start Scripts with APPEND Redirection '>>' ---
                    log_dir_on_node = NODE_LOG_DIR_ABS
                    redirect_op = ">>" # Use append for subsequent runs

                    # SL
                    sl_log = os.path.join(log_dir_on_node, f"{NODE_IDS['SL']}.log")
                    sl_cmd = f"{PYTHON_EXEC} -u {HSBP_SCRIPT_DIR}/swarm_leader.py --id {NODE_IDS['SL']} --config {CONFIG_FILE_PATH} {redirect_op} {sl_log} 2>&1"
                    core.node_command(session.id, nodes["SL"].id, sl_cmd, wait=False, shell=True); time.sleep(4)

                    # CHs
                    for i in range(1, NUM_CLUSTERS + 1):
                        ch_name_key = f"CH{i}"
                        ch_config_id = NODE_IDS[ch_name_key]
                        ch_script = os.path.join(HSBP_SCRIPT_DIR, "cluster_head.py")
                        ch_log = os.path.join(log_dir_on_node, f"{ch_config_id}.log")
                        ch_cmd = f"{PYTHON_EXEC} -u {ch_script} --id {ch_config_id} --config {CONFIG_FILE_PATH} --sl-ip {node_ips['SL']} {redirect_op} {ch_log} 2>&1"
                        logging.info(f"Run {run_num}: Executing {ch_name_key} on node {nodes[ch_name_key].id}")
                        core.node_command(session.id, nodes[ch_name_key].id, ch_cmd, wait=False, shell=True)
                        time.sleep(1) # Stagger CH starts

                    logging.info(f"Run {run_num}: SL/CHs running. Waiting 2s for init...")
                    time.sleep(2)

                    # Start ONE Joining Member (e.g., M1200 for CH1)
                    #joining_member_name_key = "Mjoin" # Corresponds to NODE_IDS["M1200"] = "m-1200"
                    joining_member_config_id = NODE_IDS[target_joining_member_key]

                    target_ch_for_join = "CH1" # Member joins CH1

                    if target_joining_member_key in nodes and target_ch_for_join in node_ips:
                        member_script = os.path.join(HSBP_SCRIPT_DIR, "member.py")
                        member_log = os.path.join(log_dir_on_node, f"{joining_member_config_id}.log")
                        member_cmd = f"{PYTHON_EXEC} -u {member_script} --id {joining_member_config_id} --config {CONFIG_FILE_PATH} --ch-ip {node_ips[target_ch_for_join]} {redirect_op} {member_log} 2>&1"
                        logging.info(f"Run {run_num}: Executing JOINING {target_joining_member_key} for {target_ch_for_join}")
                        core.node_command(session.id, nodes[target_joining_member_key].id, member_cmd, wait=False, shell=True)
                    else:
                        logging.warning(f"Run {run_num}: Could not start joining member {target_joining_member_key}")

                    logging.info(f"Run {run_num}: Single Join event triggered. Waiting 2s...")
                    time.sleep(2) # Time for join to process

                    # --- Trigger Batch Leave ---
                    ch_to_trigger_leave = "CH1"
                    if ch_to_trigger_leave in node_ips:
                        ch_ip_for_trigger = node_ips[ch_to_trigger_leave]
                        # Assuming CH1 is cluster_id "1" for control port calculation
                        # ch_control_port = CONFIG['network']['ch_control_base_port'] + 1 -1 # From config
                        ch_control_port = 5100 + 1 -1
                        
                        trigger_script_path = os.path.join(HSBP_SCRIPT_DIR, "batch_leave_trigger_ch.py")
                        trigger_cmd = f"{PYTHON_EXEC} {trigger_script_path} {ch_ip_for_trigger} {ch_control_port} {num_members_to_leave}"
                        logging.info(f"Run {run_num}: Executing leave trigger for {ch_to_trigger_leave} via SL: {trigger_cmd}")
                        core.node_command(session.id, nodes["SL"].id, trigger_cmd, wait=True, shell=True)
                    else:
                        logging.error(f"Run {run_num}: {ch_to_trigger_leave} IP not found, cannot trigger batch leave.")

                    logging.info(f"Run {run_num}: Batch Leave triggered. Waiting 5s...")
                    time.sleep(5) # Time for leave to process

                except Exception as e_run:
                    logging.error(f"Error during Run {run_num} for swarm size {total_followers}: {e_run}")
                    traceback.print_exc()
                finally:
                    if session:
                        try:
                            logging.info(f"Run {run_num}: Stopping session {session.id}")
                            core.stop_session(session.id)
                        except Exception as e_stop:
                            logging.error(f"Run {run_num}: Error stopping session {session.id}: {e_stop}")
                    logging.info(f"--- Run {run_num}/{NUM_RUNS} for swarm size {total_followers} finished ---")
                    time.sleep(5) # Pause between runs

            logging.info(f"--- All runs for Swarm Size {total_followers} completed ---")
            # Optionally call parser here for this swarm size, or parse all at the very end
            os.system(f"python3 /mnt/workarea/H-SBP/parse_hsbp_logs.py {total_followers} > /mnt/workarea/H-SBP/logs/{total_followers}_metrics.log")

    # --- Outer Finally Block ---
    finally:
        core.close()
        logging.info("Disconnected from CORE")
        logging.info(f"All scenarios finished. Logs are in '{HOST_LOG_DIR.resolve()}'")
        #logging.info("Run 'python3 parse_hsbp_logs.py' to get metrics.")

if __name__ == "__main__":
    main()
# --- END OF MODIFIED SECTION in auto_hsbp_experiment_runner.py ---

    

