# --- START OF FILE member.py ---

import base64
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA256, Hash
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import time
import sys
import json
import builtins
import math
import argparse
import select
import traceback
import os

# --- Role/Config Specific ---
MY_ID = None
MY_ROLE = None
MY_CLUSTER_ID = None
CONFIG = None
SECRETS = None
g = None
p = None
sk_i = None
T_i = None
my_ch_id = None
my_ch_tcp_address = None
cluster_bcast_address = None
ch_public_key = None
script_dir = os.path.dirname(os.path.abspath(__file__))
# --------------------------

# Override print function
def print_with_timestamp(*args, **kwargs):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    builtins.print(f"{timestamp} - [{MY_ID or 'MEMBER'}]", *args, **kwargs)

print = print_with_timestamp

# Constants
BUFFER_SIZE = 8192
TCP_BUFFER_SIZE = 4096
REASSEMBLY_TIMEOUT = 15
FRAGMENT_PREFIX = "FRAG"
# --------------------------

# SBP State
k_cluster = None
cluster_swarm_sequence = []
# --------------------------

# Reassembly Buffer
reassembly_buffer = {}
# --------------------------

# --- Cryptography Functions ---
def load_public_key(path):
    try:
        with open(path, "rb") as key_file:
            return serialization.load_pem_public_key(key_file.read())
    except Exception as e:
        print(f"Error loading public key from {path}: {e}")
        return None

def decrypt_message_aes(encrypted_message, key):
    if key is None:
        print("Error decrypting: Cluster key (k_cluster) is None!")
        return None
    try:
        key_int = int(key)
        key_bytes = key_int.to_bytes(32, 'big', signed=False)
        encrypted_data = base64.b64decode(encrypted_message)
        if len(encrypted_data) < 16:
            print("Error decrypting: Encrypted data too short")
            return None
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        unpadded_message = decrypted_padded_message.rstrip(b"\0")
        try:
            return unpadded_message.decode("utf-8")
        except UnicodeDecodeError:
            print("Warning: Could not decode decrypted message as UTF-8. Returning raw bytes.")
            return unpadded_message
    except Exception as e:
        print(f"Error during AES decryption: {e}")
        return None

def verify_message_rsa(message_bytes, signature, pub_key):
    if pub_key is None:
        print("Error verifying: Public key (ch_public_key) is None!")
        return False
    if not signature:
        print("Error verifying: Signature is empty.")
        return False
    try:
        pub_key.verify(base64.b64decode(signature), message_bytes, padding.PKCS1v15(), SHA256())
        return True
    except Exception:
        return False
# -----------------------------

# --- Reassembly/UDP Handling ---
def cleanup_reassembly_buffer():
    now = time.time()
    messages_to_delete = []
    buffer_copy = list(reassembly_buffer.items())
    for msg_id, data in buffer_copy:
        if msg_id not in reassembly_buffer:
            continue
        if now - data['timestamp'] > REASSEMBLY_TIMEOUT:
            messages_to_delete.append(msg_id)
            print(f"Timing out incomplete message {msg_id}")
    for msg_id in messages_to_delete:
        if msg_id in reassembly_buffer:
            del reassembly_buffer[msg_id]

def process_udp_packet(data_bytes):
    global reassembly_buffer
    try:
        prefix_check_len = len(FRAGMENT_PREFIX)+1
        is_fragment = False
        if len(data_bytes) >= prefix_check_len:
            try:
                start_str = data_bytes[:prefix_check_len].decode('utf-8', errors='ignore')
                is_fragment = start_str.startswith(FRAGMENT_PREFIX + "/")
            except UnicodeDecodeError:
                pass
        
        if is_fragment:
            try:
                delimiter_pos = data_bytes.find(b'|')
                if delimiter_pos == -1:
                    print("Invalid fragment: Missing delimiter")
                    return
                
                header_bytes = data_bytes[:delimiter_pos]
                payload_bytes = data_bytes[delimiter_pos+1:]
                header_str = header_bytes.decode('utf-8')
                _, message_id, frag_num_str, total_str = header_str.split('/')
                frag_num = int(frag_num_str)
                total_fragments_hint = int(total_str)
                now = time.time()
                
                if message_id not in reassembly_buffer:
                    reassembly_buffer[message_id] = {
                        'fragments': {},
                        'total_hint': total_fragments_hint,
                        'received_count': 0,
                        'timestamp': now
                    }
                elif frag_num in reassembly_buffer[message_id]['fragments']:
                    return
                
                reassembly_buffer[message_id]['fragments'][frag_num] = payload_bytes
                reassembly_buffer[message_id]['received_count'] += 1
                reassembly_buffer[message_id]['timestamp'] = now
                
                if reassembly_buffer[message_id]['received_count'] == total_fragments_hint:
                    print(f"Received all {total_fragments_hint} fragments for message {message_id}. Reassembling...")
                    fragments_dict = reassembly_buffer[message_id]['fragments']
                    
                    if len(fragments_dict) != total_fragments_hint or not all(i in fragments_dict for i in range(1, total_fragments_hint + 1)):
                        print(f"Error: Missing fragments for {message_id}. Discarding.")
                        del reassembly_buffer[message_id]
                        return
                    
                    reassembled_bytes = b"".join([fragments_dict[i] for i in range(1, total_fragments_hint + 1)])
                    original_message = reassembled_bytes.decode('utf-8').strip()
                    print(f"Reassembly successful for {message_id}. Processing.")
                    handle_cluster_message(original_message)
                    del reassembly_buffer[message_id]
            except Exception as e:
                print(f"Error parsing fragment: {e}. Header: {data_bytes[:100]}...")
        else:
            try:
                message = data_bytes.decode('utf-8').strip()
                if message:
                    handle_cluster_message(message)
            except UnicodeDecodeError:
                print("Received UDP packet that is not UTF-8 text or fragment.")
    except Exception as e:
        print(f"Error in process_udp_packet: {e}")
        traceback.print_exc()

def setup_broadcast_listener(listen_address):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bind_ip = listen_address[0] if listen_address[0] != '0.0.0.0' else ''
        sock.bind((bind_ip, listen_address[1]))
        print(f"Successfully bound UDP listener to {listen_address}")
        return sock
    except Exception as e:
        print(f"Error setting up UDP listener on {listen_address}: {e}")
        return None
# -----------------------------------------

# --- SBP Logic (Intra-Cluster - Follower Role - MODIFIED) ---
def apply_minimal_join_update(joining_member_id, T_joiner, g_I_prev_joiner):
    """Updates the cluster key based on a minimal join message (for EXISTING members)."""
    global k_cluster
    global cluster_swarm_sequence
    global p
    global MY_ID
    print(f"Applying minimal join update for member {joining_member_id} (I am {MY_ID})...")
    start_time = time.perf_counter()
    if k_cluster is None:
        print("Error: Cannot apply join update, current cluster key is None.")
        return False
    new_k_cluster = pow(T_joiner, k_cluster, p)
    k_cluster = new_k_cluster
    if joining_member_id not in cluster_swarm_sequence:
        cluster_swarm_sequence.append(joining_member_id)
    end_time = time.perf_counter()
    duration_ms = (end_time - start_time) * 1000
    print(f"Updated K_cluster after join (as existing member): {str(k_cluster)[:30]}... (took {duration_ms:.3f} ms)")
    return True

def compute_cluster_key_as_joiner(g_I_prev_for_me):
    """Calculates the cluster key for the FIRST time as the JOINING member."""
    global k_cluster
    global p
    global sk_i
    print("Computing cluster key as the JOINING member...")
    start_time = time.perf_counter()
    new_k_cluster = pow(g_I_prev_for_me, sk_i, p)
    k_cluster = new_k_cluster
    end_time = time.perf_counter()
    duration_ms = (end_time - start_time) * 1000
    print(f"Computed initial K_cluster as JOINER: {str(k_cluster)[:30]}... (took {duration_ms:.3f} ms)")
    print(f"[MEMBER] Execution time for joining key computation: {duration_ms:.3f} ms")
    return True


def compute_cluster_key_from_full_state(rcvd_swarm_sequence, rcvd_blind_keys, rcvd_g_I_prev_values):
    """Compute the cluster key based on received FULL state update (Initial or Leave)."""
    global k_cluster
    global g
    global p
    global sk_i
    global MY_ID
    print("Attempting to compute cluster key from full state...")
    start_time = time.perf_counter()
    try:
        my_pos = -1
        for i, fid in enumerate(rcvd_swarm_sequence):
            if fid == MY_ID:
                my_pos = i
                break
        if my_pos == -1:
            print(f"Error: Own ID '{MY_ID}' not found in sequence: {rcvd_swarm_sequence}")
            return None
        if my_pos == 0:
            print("Error: Member node cannot be at position 0 (CH position).")
            return None
        if MY_ID not in rcvd_g_I_prev_values:
            print(f"Error: Required g^I_prev for ID {MY_ID} not found in {list(rcvd_g_I_prev_values.keys())}")
            return None
        my_g_I_prev = rcvd_g_I_prev_values[MY_ID]
        I_mine = pow(my_g_I_prev, sk_i, p)
        current_I = I_mine
        for i in range(my_pos + 1, len(rcvd_swarm_sequence)):
            forward_node_id = rcvd_swarm_sequence[i]
            if forward_node_id not in rcvd_blind_keys:
                print(f"Error: Blind key for forward node {forward_node_id} not found.")
                return None
            T_forward = rcvd_blind_keys[forward_node_id]
            current_I = pow(T_forward, current_I, p)
        k_cluster = current_I
        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000
        print(f"Computed new cluster key K_cluster (from full state): {str(k_cluster)[:30]}... (took {duration_ms:.3f} ms)")
        print(f"[MEMBER] Execution time for key computation (full state): {duration_ms:.3f} ms")
        return k_cluster
    except Exception as e:
        print(f"Error during cluster key computation: {e}")
        traceback.print_exc()
        return None


def handle_cluster_message(message):
    """Handles messages received on the cluster broadcast channel."""
    global k_cluster
    global cluster_swarm_sequence
    global ch_public_key
    try:
        if message.startswith("RELAYED_MSG|"):
            encrypted_content = message.split('|', 1)[1]
            print("Received relayed global message.")
            decrypted_content = decrypt_message_aes(encrypted_content, k_cluster)
            if decrypted_content:
                if isinstance(decrypted_content, str):
                    content_to_print = decrypted_content[:100]
                else:
                    content_to_print = decrypted_content.hex()[:100]
                print(f"Decrypted Global Content: {content_to_print}...")
            else:
                print("Error: Failed to decrypt relayed message.")
            return

        elif message.startswith("KEY_UPDATE|"):
            print("Processing KEY_UPDATE from CH...")
            _, message_body_signed = message.split('|', 1)
            message_parts = message_body_signed.rsplit('|', 1)
            if len(message_parts) != 2:
                print(f"Error: Invalid CH KEY_UPDATE format: {message[:100]}...")
                return
            message_body = message_parts[0]
            signature = message_parts[1]
            message_body_bytes = message_body.encode('utf-8')
            if not verify_message_rsa(message_body_bytes, signature, ch_public_key):
                print("Error: Invalid signature for KEY_UPDATE from CH.")
                return

            body_parts = message_body.split('|')
            if len(body_parts) == 3 and ':' not in body_parts[0] and ':' not in body_parts[1] and ':' not in body_parts[2]:
                print("Detected minimal join update format.")
                try:
                    joining_member_id = body_parts[0]
                    T_joiner = int(body_parts[1])
                    g_I_prev_for_joiner = int(body_parts[2])

                    if joining_member_id == MY_ID:
                        compute_cluster_key_as_joiner(g_I_prev_for_joiner)
                        if MY_ID not in cluster_swarm_sequence:
                            cluster_swarm_sequence.append(MY_ID)
                    else:
                        apply_minimal_join_update(joining_member_id, T_joiner, g_I_prev_for_joiner)
                except (ValueError, IndexError) as e:
                    print(f"Error parsing minimal join update: {e}. Body: {message_body}")
                return

            elif len(body_parts) == 3:
                print("Processing full state update format.")
                rcvd_seq_str = body_parts[0]
                rcvd_blind_keys_str = body_parts[1]
                rcvd_gI_str = body_parts[2]
                rcvd_swarm_sequence = rcvd_seq_str.split(',') if rcvd_seq_str else []
                if not rcvd_swarm_sequence:
                    print("Warning: Received empty swarm sequence from CH.")
                    return
                rcvd_blind_keys = {}
                rcvd_g_I_prev_values = {}
                if rcvd_blind_keys_str:
                    try:
                        rcvd_blind_keys = {fid: int(key) for fid, key in [pair.split(':') for pair in rcvd_blind_keys_str.split(',')]}
                    except Exception as e:
                        print(f"Error parsing CH blind keys: {e}")
                        return
                if rcvd_gI_str:
                    try:
                        rcvd_g_I_prev_values = {fid: int(key) for fid, key in [pair.split(':') for pair in rcvd_gI_str.split(',')]}
                    except Exception as e:
                        print(f"Error parsing CH g^I_prev values: {e}")
                        return
                print(f"Received Cluster State: Seq={rcvd_swarm_sequence}")
                cluster_swarm_sequence = rcvd_swarm_sequence
                compute_cluster_key_from_full_state(rcvd_swarm_sequence, rcvd_blind_keys, rcvd_g_I_prev_values)
            else:
                print(f"Error: Unknown KEY_UPDATE body format ({len(body_parts)} parts): {message_body[:100]}...")
                return
        else:
            print(f"Received unknown message type from CH: {message[:50]}...")
    except Exception as e:
        print(f"Error processing cluster message: {e}")
        traceback.print_exc()
# --------------------------------------------------------------------

# --- Connection Logic ---
def connect_to_cluster_head():
    client = None
    broadcast_socket = None
    connection_attempts = 0
    max_connection_attempts = 5
    
    while connection_attempts < max_connection_attempts:
        connection_attempts += 1
        e = None  # Clear exception from previous loop
        
        try:
            if not broadcast_socket:
                broadcast_socket = setup_broadcast_listener(cluster_bcast_address)
                if not broadcast_socket:
                    print(f"Attempt {connection_attempts}: Failed UDP listen bind, retrying...")
                    time.sleep(5)
                    continue
            
            print(f"Attempt {connection_attempts}: Connecting to CH {my_ch_id} at {my_ch_tcp_address}")
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(10)
            client.connect(my_ch_tcp_address)
            client.settimeout(None)
            print("Connected to CH via TCP.")
            
            try:
                writer = client.makefile('w', encoding='utf-8')
                id_message = f"ID:{MY_ID}\n"
                print(f"Sending ID: {id_message.strip()}")
                writer.write(id_message)
                writer.flush()
                
                ti_message = f"T_I:{T_i}\n"
                print(f"Sending T_i: {ti_message.strip()}")
                writer.write(ti_message)
                writer.flush()
                print("ID and T_i sent.")
            except Exception as send_err:
                print(f"Error sending initial data to CH: {send_err}")
                if client:
                    client.close()
                time.sleep(3)
                continue
            
            print(f"Listening on UDP {cluster_bcast_address} for cluster messages...")
            read_sockets = [broadcast_socket]
            last_cleanup_time = time.time()
            
            while True:  # Main listening loop
                readable, _, exceptional = select.select(read_sockets, [], read_sockets, 1.0)
                
                if exceptional:
                    print("Exceptional socket condition. Reconnecting.")
                    break
                
                for sock in readable:
                    if sock is broadcast_socket:
                        try:
                            data_bytes, addr = broadcast_socket.recvfrom(BUFFER_SIZE)
                            if data_bytes:
                                process_udp_packet(data_bytes)
                        except Exception as recv_err:
                            print(f"Error receiving UDP packet: {recv_err}")
                
                now = time.time()
                if now - last_cleanup_time > REASSEMBLY_TIMEOUT:
                    cleanup_reassembly_buffer()
                    last_cleanup_time = now
        
        except socket.timeout:
            print(f"Attempt {connection_attempts}: Connection to CH timed out, retrying...")
        except (ConnectionRefusedError, OSError) as e:
            print(f"Attempt {connection_attempts}: Connection refused/OS error ({e}), CH not ready? Retrying...")
        except KeyboardInterrupt:
            print("Process interrupted.")
            break
        except Exception as e:
            print(f"Unexpected Error in connection loop: {type(e).__name__}: {e}")
            traceback.print_exc()
            print("Retrying connection in 10s...")
            time.sleep(10)
        finally:
            if client:
                client.close()
                client = None
            if broadcast_socket:
                broadcast_socket.close()
                broadcast_socket = None
            if connection_attempts < max_connection_attempts and not isinstance(e, KeyboardInterrupt):
                time.sleep(5)
    
    if connection_attempts >= max_connection_attempts:
        print("FATAL: Max connection attempts to CH reached. Exiting.")
    print("Connection closed.")
# ----------------------------------------------------------------

# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="H-SBP Member Node")
    parser.add_argument("--id", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--ch-ip", required=True)
    args = parser.parse_args()
    MY_ID = args.id
    my_ch_ip_arg = args.ch_ip
    print(f"Starting Member Node: {MY_ID}")
    
    try:
        print(f"Loading config: {args.config}")
        with open(args.config, 'r') as f:
            CONFIG = json.load(f)
        
        secrets_path = os.path.join(script_dir, CONFIG['paths']['secret_keys_file'])
        print(f"Loading secrets: {secrets_path}")
        with open(secrets_path, 'r') as f:
            SECRETS = json.load(f)
    except Exception as e:
        print(f"FATAL: Failed load config/secrets: {e}")
        sys.exit(1)
    
    try:
        g = CONFIG['general']['g']
        p = CONFIG['general']['p']
        sk_i = int(SECRETS[MY_ID])
        T_i = pow(g, sk_i, p)
        print(f"Loaded DH params...")
    except Exception as e:
        print(f"FATAL: Failed process DH/secret key: {e}")
        sys.exit(1)
    
    try:
        node_def = CONFIG['structure']['node_definitions'][MY_ID]
        MY_ROLE = node_def['role']
        
        if MY_ROLE != "MEMBER":
            print(f"FATAL: Role mismatch! Expected MEMBER, got {MY_ROLE}")
            sys.exit(1)
        
        MY_CLUSTER_ID = node_def['cluster_id']
    except KeyError:
        print(f"FATAL: Node definition/cluster ID not found for '{MY_ID}'.")
        sys.exit(1)
    
    try:
        cluster_info = CONFIG['structure']['clusters'][MY_CLUSTER_ID]
        my_ch_id = cluster_info['ch_id']
        net_conf = CONFIG['network']
        
        ch_tcp_port = net_conf['ch_tcp_base_port'] + int(MY_CLUSTER_ID) - 1
        my_ch_tcp_address = (my_ch_ip_arg, ch_tcp_port)
        
        cluster_bcast_port = net_conf['cluster_bcast_base_port'] + int(MY_CLUSTER_ID) - 1
        cluster_bcast_addr_str = net_conf['inter_ch_bcast_addr']
        cluster_bcast_address = (cluster_bcast_addr_str, cluster_bcast_port)
    except Exception as e:
        print(f"FATAL: Failed determine CH/Network details: {e}")
        sys.exit(1)
    
    try:
        #ch_pub_key_path = CONFIG['paths']['ch_pub_key_template'].format(MY_CLUSTER_ID)
        ch_pub_key_path = os.path.join(script_dir, CONFIG['paths']['ch_pub_key_template'].format(MY_CLUSTER_ID))
        print(f"Loading CH public key: {ch_pub_key_path}")
        ch_public_key = load_public_key(ch_pub_key_path)
        
        if not ch_public_key:
            print("FATAL: Failed load CH public key.")
            sys.exit(1)
    except Exception as e:
        print(f"FATAL: Error loading CH public key: {e}")
        sys.exit(1)
    
    print(f"Starting node {MY_ID} as {MY_ROLE} in Cluster {MY_CLUSTER_ID}")
    print(f"My CH is {my_ch_id}. Target CH Address: {my_ch_tcp_address}")
    print(f"Listening for cluster broadcasts on UDP {cluster_bcast_address}")
    connect_to_cluster_head()
# --- END OF FILE member.py ---
