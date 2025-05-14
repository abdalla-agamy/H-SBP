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
HOST_LOG_DIR = Path("./hsbp_logs")
NODE_LOG_DIR_ABS = "/mnt/workarea/H-SBP/logs"

NODE_IDS = {
    "SL": "sl-0",
    "CH1": "ch-1",
    "CH2": "ch-2",
    "CH3": "ch-3",
    "CH4": "ch-4",
    "CH5": "ch-5",
    "M1200": "m-1200",
}

NODE_TARGET_IPS = {
     1: "172.16.0.1",
     2: "172.16.0.2",
     3: "172.16.0.3",
     4: "172.16.0.4",
     5: "172.16.0.5",
     6: "172.16.0.6",
     7: "172.16.0.7",
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
    session = None
    nodes = {}

    try:
        core.connect()
        logging.info("Connected to CORE gRPC")
        session = core.create_session()
        logging.info(f"Created CORE session {session.id}")

        emane_position = Position(x=300, y=300)
        emane_node = session.add_node(100, _type=NodeType.EMANE, position=emane_position, emane=EmaneRfPipeModel.name)
        logging.info(f"Added EMANE node {emane_node.id}...")

        positions = {
            "SL": Position(x=300, y=100),
            "CH1": Position(x=150, y=250),
            "CH2": Position(x=450, y=250),
            "CH3": Position(x=550, y=100),
            "CH4": Position(x=650, y=250),
            "CH5": Position(x=750, y=250),
            "M1200": Position(x=150, y=410),
        }

        node_id_counter = 1
        nodes_to_create = ["SL", "CH1", "CH2", "CH3", "CH4", "CH5", "M1200"]

        for name_key in nodes_to_create:
             pos = positions.get(name_key)
             if not pos: logging.warning(f"Position not defined for {name_key}, skipping node creation."); continue
             node = session.add_node(node_id_counter, model="PC", name=name_key, position=pos)
             nodes[name_key] = node
             logging.info(f"Added {name_key} node {node.id} ({NODE_IDS[name_key]})")

             iface = iface_helper.create_iface(node.id, 0)
             target_ip = NODE_TARGET_IPS.get(node.id)
             if not target_ip: logging.error(f"FATAL: No target IP defined for Node ID {node.id}"); return

             iface.ip4 = target_ip
             iface.ip4_mask = IP4_MASK
             iface.ip6 = None
             iface.ip6_mask = None
             logging.info(f"  Manually configured iface eth0 for node {node.id}: IP={iface.ip4}/{iface.ip4_mask}")

             session.add_link(node1=node, node2=emane_node, iface1=iface)
             logging.info(f"Linked {name_key} node {node.id} interface eth0 to EMANE node {emane_node.id}")
             node_id_counter += 1

        core.start_session(session)
        logging.info("Session started.")
        wait_time = 5
        logging.info(f"Waiting {wait_time} seconds for network initialization...")
        time.sleep(wait_time)

        node_ips = {}
        all_ips_found = True
        logging.info("Verifying ALL Node IPs via node_command...")
        for name_key in nodes_to_create:
            if name_key not in nodes: continue
            ip = get_node_ip_via_cmd(core, session.id, nodes[name_key].id, "eth0")
            expected_ip = NODE_TARGET_IPS.get(nodes[name_key].id)
            if ip and ip == expected_ip: node_ips[name_key] = ip
            else: all_ips_found = False; logging.error(f"IP verify failed for {name_key} ({nodes[name_key].id})")
            time.sleep(0.2)
        if not all_ips_found: logging.error("IP verification failed. Aborting."); input("Press Enter..."); return

        logging.info(f"\n--- Starting SL and CH Scripts (output redirected to {NODE_LOG_DIR_ABS}/*.log) ---")
        sl_script = os.path.join(HSBP_SCRIPT_DIR, "swarm_leader.py")
        sl_log = os.path.join(NODE_LOG_DIR_ABS, f"{NODE_IDS['SL']}.log")
        sl_cmd = f"{PYTHON_EXEC} -u {sl_script} --id {NODE_IDS['SL']} --config {CONFIG_FILE_PATH} > {sl_log} 2>&1"
        logging.info(f"Executing SL on node {nodes['SL'].id}: {sl_cmd}")
        core.node_command(session.id, nodes["SL"].id, sl_cmd, wait=False, shell=True)
        time.sleep(1)
        ch1_script = os.path.join(HSBP_SCRIPT_DIR, "cluster_head.py")
        ch1_log = os.path.join(NODE_LOG_DIR_ABS, f"{NODE_IDS['CH1']}.log")
        ch1_cmd = f"{PYTHON_EXEC} -u {ch1_script} --id {NODE_IDS['CH1']} --config {CONFIG_FILE_PATH} --sl-ip {node_ips['SL']} > {ch1_log} 2>&1"
        logging.info(f"Executing CH1 on node {nodes['CH1'].id}: {ch1_cmd}")
        core.node_command(session.id, nodes["CH1"].id, ch1_cmd, wait=False, shell=True)
        time.sleep(1)
        ch2_script = os.path.join(HSBP_SCRIPT_DIR, "cluster_head.py")
        ch2_log = os.path.join(NODE_LOG_DIR_ABS, f"{NODE_IDS['CH2']}.log")
        ch2_cmd = f"{PYTHON_EXEC} -u {ch2_script} --id {NODE_IDS['CH2']} --config {CONFIG_FILE_PATH} --sl-ip {node_ips['SL']} > {ch2_log} 2>&1"
        logging.info(f"Executing CH2 on node {nodes['CH2'].id}: {ch2_cmd}")
        core.node_command(session.id, nodes["CH2"].id, ch2_cmd, wait=False, shell=True)
        time.sleep(1)
        ch3_script = os.path.join(HSBP_SCRIPT_DIR, "cluster_head.py")
        ch3_log = os.path.join(NODE_LOG_DIR_ABS, f"{NODE_IDS['CH3']}.log")
        ch3_cmd = f"{PYTHON_EXEC} -u {ch3_script} --id {NODE_IDS['CH3']} --config {CONFIG_FILE_PATH} --sl-ip {node_ips['SL']} > {ch3_log} 2>&1"
        logging.info(f"Executing CH3 on node {nodes['CH3'].id}: {ch3_cmd}")
        core.node_command(session.id, nodes["CH3"].id, ch3_cmd, wait=False, shell=True)
        time.sleep(1)
        ch4_script = os.path.join(HSBP_SCRIPT_DIR, "cluster_head.py")
        ch4_log = os.path.join(NODE_LOG_DIR_ABS, f"{NODE_IDS['CH4']}.log")
        ch4_cmd = f"{PYTHON_EXEC} -u {ch4_script} --id {NODE_IDS['CH4']} --config {CONFIG_FILE_PATH} --sl-ip {node_ips['SL']} > {ch4_log} 2>&1"
        logging.info(f"Executing CH4 on node {nodes['CH4'].id}: {ch4_cmd}")
        core.node_command(session.id, nodes["CH4"].id, ch4_cmd, wait=False, shell=True)
        time.sleep(1)
        ch5_script = os.path.join(HSBP_SCRIPT_DIR, "cluster_head.py")
        ch5_log = os.path.join(NODE_LOG_DIR_ABS, f"{NODE_IDS['CH5']}.log")
        ch5_cmd = f"{PYTHON_EXEC} -u {ch5_script} --id {NODE_IDS['CH5']} --config {CONFIG_FILE_PATH} --sl-ip {node_ips['SL']} > {ch5_log} 2>&1"
        logging.info(f"Executing CH5 on node {nodes['CH5'].id}: {ch5_cmd}")
        core.node_command(session.id, nodes["CH5"].id, ch5_cmd, wait=False, shell=True)       

        logging.info("\n--- SL/CHs running. Waiting 15s for CH internal initialization and inter-CH key exchange ---")
        time.sleep(1)

        logging.info("\n--- Starting Single Joining Member Script(s) ---")
        try:
            with open(CONFIG_FILE_PATH, 'r') as f: config_data = json.load(f)
            cluster1_joining_id = config_data['structure']['clusters']['1'].get('joining_member')
            #cluster2_joining_id = config_data['structure']['clusters']['2'].get('joining_member')
        except Exception as e: logging.error(f"FATAL: Could not parse joining members from config: {e}"); return

        joining_member_key_map = {}
        if cluster1_joining_id: joining_member_key_map[cluster1_joining_id] = "M1200"
        #if cluster2_joining_id: joining_member_key_map[cluster2_joining_id] = "M204"

        nodes_started_join = {}
        for joining_config_id, name_key in joining_member_key_map.items():
            if name_key not in nodes: logging.warning(f"Joining node {name_key} was not created. Skipping."); continue
            if name_key not in node_ips: logging.warning(f"IP for joining node {name_key} not verified. Skipping."); continue

            member_script = os.path.join(HSBP_SCRIPT_DIR, "member.py")
            member_log = os.path.join(NODE_LOG_DIR_ABS, f"{joining_config_id}.log")
            ch_key = "CH1" if joining_config_id == cluster1_joining_id else "CH2"
            member_cmd = f"{PYTHON_EXEC} -u {member_script} --id {joining_config_id} --config {CONFIG_FILE_PATH} --ch-ip {node_ips[ch_key]} > {member_log} 2>&1"
            logging.info(f"Executing JOINING {name_key} ({joining_config_id}) on node {nodes[name_key].id}: {member_cmd}")
            core.node_command(session.id, nodes[name_key].id, member_cmd, wait=False, shell=True)
            nodes_started_join[name_key] = True
            time.sleep(1)

        if not nodes_started_join: logging.warning("No joining member scripts were started.")

        logging.info("\n--- Single Join event(s) triggered ---")
        logging.info("Observe logs for join overhead measurements.")
        time.sleep(2)

        logging.info("\n--- Triggering Batch Leave Event for CH1 ---")
        ch1_ip_for_trigger = node_ips.get("CH1")
        ch1_control_port_for_trigger = 5100 + 1 -1
        num_members_to_leave = 10

        if ch1_ip_for_trigger:
            trigger_cmd = f"{PYTHON_EXEC} /mnt/workarea/H-SBP/batch_leave_trigger_ch.py {ch1_ip_for_trigger} {ch1_control_port_for_trigger} {num_members_to_leave}"
            logging.info(f"Executing leave trigger for CH1 (node {nodes['CH1'].id}): {trigger_cmd}")
            core.node_command(session.id, nodes["SL"].id, trigger_cmd, wait=True, shell=True)
        else: logging.error("CH1 IP not found, cannot trigger batch leave.")

        logging.info("\n--- Batch Leave event triggered ---")
        logging.info("Observe logs for leave overhead measurements.")

        logging.info(f"Logs are in '{Path(NODE_LOG_DIR_ABS).resolve()}'")
        input("Press Enter to stop the session and scripts...")

    except Exception as e: logging.error(f"An error occurred: {e}"); traceback.print_exc()
    finally:
        if session:
            try: logging.info(f"Stopping session {session.id}"); core.stop_session(session.id)
            except Exception as e: logging.error(f"Error stopping session {session.id}: {e}")
        core.close()
        logging.info("Disconnected from CORE")

if __name__ == "__main__":
    main()
# --- END OF FILE hsbp_init_join_test.py ---
