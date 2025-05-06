# --- START OF FILE swarm_leader.py ---

import socket
import threading
import time
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA256, Hash
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import secrets
import sys
import json
import builtins
import math
import argparse
import traceback

# --- Role/Config Specific ---
MY_ID = None
MY_ROLE = None
CONFIG = None
SECRETS = None
g = None
p = None
sk_i = None  # SL's own secret key
T_i = None   # SL's own blind key (T_sl)
private_key = None  # SL's signing key
script_dir = os.path.dirname(os.path.abspath(__file__))

# --------------------------

# Override print function to include a timestamp
def print_with_timestamp(*args, **kwargs):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    builtins.print(f"{timestamp} - [{MY_ID or 'SL'}]", *args, **kwargs)

# Replace the built-in print function
print = print_with_timestamp

# Constants
BUFFER_SIZE = 8192
MAX_UDP_PAYLOAD_SIZE = 1400  # Safer limit
FRAGMENT_PREFIX = "FRAG"
TCP_LISTEN_ADDRESS = None
INTER_CH_BCAST_ADDRESS = None

# --------------------------

# Data Structures
connected_chs = {}  # {ch_id: {'client': socket, 'blind_key': T_ch}}
chs_lock = threading.Lock()

# DH Chain State (Inter-CH level)
inter_ch_intermediate_keys = {}  # {node_id: I_intermediate}
inter_ch_blind_keys = {}  # {node_id: T_blind} (T_sl, T_ch1, T_ch2...)
inter_ch_g_I_prev_values = {}  # {ch_id: g^I_prev_for_ch}
inter_ch_swarm_sequence = []  # Stores sequence like [sl_id, ch1_id, ch2_id]
k_main = None  # The broadcast key shared among SL and CHs

# --------------------------

def fragment_message(full_message_str, max_payload_size=MAX_UDP_PAYLOAD_SIZE):
    message_bytes = full_message_str.encode('utf-8')
    message_len = len(message_bytes)
    message_id = f"{time.time():.6f}"
    if message_len == 0:
        return []
    
    actual_total_fragments = 0
    current_pos_pass1 = 0
    temp_frag_num = 1
    while current_pos_pass1 < message_len:
        max_digits_total = 6
        temp_header = f"{FRAGMENT_PREFIX}/{message_id}/{temp_frag_num}/{'9'*max_digits_total}|"
        temp_header_bytes = temp_header.encode('utf-8')
        temp_header_len = len(temp_header_bytes)
        payload_size = max_payload_size - temp_header_len
        if payload_size <= 0:
            raise ValueError(f"max_payload_size ({max_payload_size}) too small for header pass 1")
        end_pos_pass1 = min(current_pos_pass1 + payload_size, message_len)
        actual_total_fragments += 1
        current_pos_pass1 = end_pos_pass1
        temp_frag_num += 1
    
    if actual_total_fragments > message_len + 10:
        raise RuntimeError("Frag pass 1 loop")
    if actual_total_fragments == 0:
        raise RuntimeError("0 frags for non-empty msg pass 1")
    
    fragments = []
    current_pos_pass2 = 0
    for fragment_num in range(1, actual_total_fragments + 1):
        header = f"{FRAGMENT_PREFIX}/{message_id}/{fragment_num}/{actual_total_fragments}|"
        header_bytes = header.encode('utf-8')
        header_len = len(header_bytes)
        payload_size = max_payload_size - header_len
        if payload_size < 0:
            raise ValueError(f"max_payload_size too small pass 2 frag {fragment_num}")
        end_pos_pass2 = min(current_pos_pass2 + payload_size, message_len)
        payload_chunk = message_bytes[current_pos_pass2:end_pos_pass2]
        fragment_packet = header_bytes + payload_chunk
        fragments.append(fragment_packet)
        current_pos_pass2 = end_pos_pass2
    
    if current_pos_pass2 != message_len:
        raise RuntimeError(f"Frag pass 2 incomplete {current_pos_pass2}/{message_len}")
    if len(fragments) != actual_total_fragments:
        raise RuntimeError(f"Frag pass 2 count mismatch {len(fragments)}/{actual_total_fragments}")
    return fragments

# --------------------------------------------------------

def load_private_key(path):
    try:
        with open(path, "rb") as key_file:
            return serialization.load_pem_private_key(key_file.read(), password=None)
    except Exception as e:
        print(f"Error loading private key from {path}: {e}")
        return None

def sign_message_rsa(message_bytes, priv_key):
    if not priv_key:
        print("Error signing: Private key not loaded.")
        return None
    try:
        sig = priv_key.sign(message_bytes, padding.PKCS1v15(), SHA256())
        return base64.b64encode(sig).decode('utf-8')
    except Exception as e:
        print(f"Error signing message: {e}")
        return None

def encrypt_message_aes(message_bytes, key):
    if key is None:
        print("Error encrypting: Key is None.")
        return None
    try:
        iv = secrets.token_bytes(16)
        key_int = int(key)
        key_bytes = key_int.to_bytes(32, 'big', signed=False)
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padding_len = 16 - (len(message_bytes) % 16)
        padded_message = message_bytes + (b"\0" * padding_len)
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode('utf-8')
    except Exception as e:
        print(f"Error encrypting message: {e}")
        return None

# -----------------------------------------------------------------------

def setup_broadcast_socket():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return sock
    except Exception as e:
        print(f"Error setting up broadcast socket: {e}")
        return None

def compute_main_broadcast_key(new_ch_id):
    global k_main, inter_ch_g_I_prev_values, inter_ch_intermediate_keys, inter_ch_swarm_sequence, p, g
    if not inter_ch_swarm_sequence:
        print("Error: inter_ch_swarm_sequence empty.")
        return None, None
    if new_ch_id not in inter_ch_blind_keys:
        print(f"Error: Blind key for new CH {new_ch_id} not found.")
        return None, None
    
    if len(inter_ch_swarm_sequence) == 1:
        I_prev = inter_ch_intermediate_keys[MY_ID]
    else:
        prev_id_index = inter_ch_swarm_sequence.index(new_ch_id) - 1
        if prev_id_index < 0:
            print(f"Error: Cannot find prev node for {new_ch_id} in {inter_ch_swarm_sequence}")
            return None, None
        prev_id = inter_ch_swarm_sequence[prev_id_index]
        if prev_id not in inter_ch_intermediate_keys:
            print(f"Error: Intermed key for prev node {prev_id} not found.")
            return None, None
        I_prev = inter_ch_intermediate_keys[prev_id]
    
    T_new_ch = inter_ch_blind_keys[new_ch_id]
    I_new = pow(T_new_ch, I_prev, p)
    g_I_prev = pow(g, I_prev, p)
    inter_ch_intermediate_keys[new_ch_id] = I_new
    inter_ch_g_I_prev_values[new_ch_id] = g_I_prev
    k_main = I_new
    print(f"Computed K_main: {str(k_main)[:30]}...")
    print(f"Stored g^I_prev for {new_ch_id}: {str(g_I_prev)[:30]}...")
    return k_main, g_I_prev

def broadcast_inter_ch_update(broadcast_socket, event_type, joining_ch_id=None, leaving_ch_ids=None):
    global k_main, inter_ch_swarm_sequence, inter_ch_blind_keys, inter_ch_g_I_prev_values, private_key
    message_body = ""
    start_time_calc = time.perf_counter()
    
    #with chs_lock:
    if not inter_ch_swarm_sequence:
        print("Cannot broadcast update: Inter-CH sequence empty.")
        return 0
    
    # Send Full state for now, regardless of event type
    seq_str = ','.join(map(str, inter_ch_swarm_sequence))
    blind_keys_str = ','.join([f'{fid}:{inter_ch_blind_keys[fid]}' for fid in inter_ch_swarm_sequence if fid != MY_ID and fid in inter_ch_blind_keys])
    g_I_prev_str = ','.join([f'{fid}:{inter_ch_g_I_prev_values[fid]}' for fid in inter_ch_swarm_sequence if fid != MY_ID and fid in inter_ch_g_I_prev_values])
    message_body = f"{seq_str}|{blind_keys_str}|{g_I_prev_str}"
    
    if not message_body:
        print("Error: Could not construct inter-CH update body.")
        return 0
    
    signature = sign_message_rsa(message_body.encode('utf-8'), private_key)
    if not signature:
        print("Error: Failed to sign inter-CH update.")
        return 0
    
    full_message = f"KEY_UPDATE|{message_body}|{signature}\n"
    end_time_calc = time.perf_counter()
    calc_duration_ms = (end_time_calc - start_time_calc) * 1000
    # --- FIX: Add Specific Event Timing Logs ---
    if event_type == "join":
        print(f"[SL] Execution time for CH {joining_ch_id} join event calculation: {calc_duration_ms:.3f} ms")
    elif event_type == "leave":
         # Placeholder - need to know how many left if needed
         num_left = len(leaving_ch_ids) if leaving_ch_ids else "?"
         print(f"[SL] Execution time for {num_left} CHs batch leave event calculation: {calc_duration_ms:.3f} ms")
    else: # e.g., initial setup or other event types
         print(f"Inter-CH update message calculation time ({event_type}): {calc_duration_ms:.3f} ms")
    # ----------------------------------------
    
    try:
        full_message_bytes = full_message.encode('utf-8')
        original_message_size = len(full_message_bytes)
        # --- FIX: Add Specific Event Length Logs ---
        event_desc = event_type
        if event_type == "join": event_desc = f"CH_join({joining_ch_id})"
        elif event_type == "leave": event_desc = f"CH_leave({leaving_ch_ids})"
        print(f"[SL] Key update message length for {event_desc}: {original_message_size} bytes")
        # ------------------------------------------
        if original_message_size > MAX_UDP_PAYLOAD_SIZE:
            print(f"Inter-CH msg size ({original_message_size}) exceeds limit. Fragmenting...")
            fragments = fragment_message(full_message, MAX_UDP_PAYLOAD_SIZE)
            print(f"Sending {len(fragments)} fragments for Inter-CH update ({event_type})...")
            bytes_sent_this_msg = 0
            start_time_send = time.perf_counter()
            for i, frag in enumerate(fragments):
                try:
                    sent = broadcast_socket.sendto(frag, INTER_CH_BCAST_ADDRESS)
                    bytes_sent_this_msg += sent
                    time.sleep(0.001)
                except Exception as send_err:
                    print(f"Error sending Inter-CH fragment {i+1}: {send_err}")
            end_time_send = time.perf_counter()
            send_duration_ms = (end_time_send - start_time_send) * 1000
            print(f"Finished sending Inter-CH fragments. Total bytes: {bytes_sent_this_msg}. Send duration: {send_duration_ms:.3f} ms")
            return original_message_size
        else:
            start_time_send = time.perf_counter()
            bytes_sent = broadcast_socket.sendto(full_message_bytes, INTER_CH_BCAST_ADDRESS)
            end_time_send = time.perf_counter()
            send_duration_ms = (end_time_send - start_time_send) * 1000
            print(f"Broadcasting non-fragmented Inter-CH update ({event_type}). Size: {bytes_sent}. Send duration: {send_duration_ms:.3f} ms")
            return bytes_sent
    except Exception as e:
        print(f"Error during Inter-CH update send: {e}")
        traceback.print_exc()
        return 0

def handle_ch_departure(ch_id):
    global k_main, inter_ch_swarm_sequence, inter_ch_blind_keys, inter_ch_intermediate_keys, inter_ch_g_I_prev_values, p, g
    print(f"Handling departure for CH {ch_id}")
    updated = False
    
    with chs_lock:
        if ch_id not in connected_chs:
            print(f"Warning: CH {ch_id} already departed/unknown.")
            return False
        
        if 'client' in connected_chs[ch_id]:
            try:
                connected_chs[ch_id]['client'].close()
            except Exception:
                pass
            del connected_chs[ch_id]
        
        if ch_id in inter_ch_blind_keys:
            del inter_ch_blind_keys[ch_id]
        
        if ch_id not in inter_ch_swarm_sequence:
            print(f"Warning: Departing CH {ch_id} not in sequence {inter_ch_swarm_sequence}")
            return False
        
        try:
            departure_index = inter_ch_swarm_sequence.index(ch_id)
        except ValueError:
            print(f"Warning: Could not find index for departing CH {ch_id}.")
            return False
        
        old_sequence = inter_ch_swarm_sequence[:]
        nodes_after_departure = inter_ch_swarm_sequence[departure_index:]
        inter_ch_swarm_sequence = inter_ch_swarm_sequence[:departure_index]
        
        for node_id in nodes_after_departure:
            if node_id in inter_ch_intermediate_keys:
                del inter_ch_intermediate_keys[node_id]
            if node_id in inter_ch_g_I_prev_values:
                del inter_ch_g_I_prev_values[node_id]
        
        print(f"Sequence after removing {ch_id} and subsequent: {inter_ch_swarm_sequence}")
        
        if departure_index == 0:
            print("Error: SL departure not handled.")
            return False
        elif departure_index == 1:
            I_prev = inter_ch_intermediate_keys[MY_ID]
        else:
            I_prev = inter_ch_intermediate_keys[inter_ch_swarm_sequence[departure_index - 1]]
        
        nodes_to_re_add = [node for node in old_sequence if node != ch_id and node not in inter_ch_swarm_sequence]
        print(f"Nodes to re-add: {nodes_to_re_add}")
        
        for node_id in nodes_to_re_add:
            if node_id not in inter_ch_blind_keys:
                print(f"Error: Cannot recompute chain, blind key for {node_id} missing.")
                return False
            T_node = inter_ch_blind_keys[node_id]
            I_new = pow(T_node, I_prev, p)
            g_I_prev_recomputed = pow(g, I_prev, p)
            inter_ch_intermediate_keys[node_id] = I_new
            inter_ch_g_I_prev_values[node_id] = g_I_prev_recomputed
            inter_ch_swarm_sequence.append(node_id)
            I_prev = I_new
            updated = True
        
        if len(inter_ch_swarm_sequence) <= 1:
            k_main = sk_i
        else:
            k_main = inter_ch_intermediate_keys[inter_ch_swarm_sequence[-1]]
        
        print(f"Recomputed sequence: {inter_ch_swarm_sequence}")
        print(f"Recomputed K_main: {str(k_main)[:30]}...")
        return updated

def handle_ch_connection(broadcast_socket, client, addr):
    global k_main, inter_ch_swarm_sequence, inter_ch_blind_keys, inter_ch_intermediate_keys, inter_ch_g_I_prev_values
    ch_id = None
    departure_handled = False
    
    try:
        reader = client.makefile('r', encoding='utf-8')
        writer = client.makefile('w', encoding='utf-8')
        id_line = reader.readline().strip()
        
        if not id_line.startswith("ID:"):
            print(f"Invalid initial message from {addr}: {id_line}. Closing.")
            client.close()
            return
        
        ch_id = id_line.split(":", 1)[1]
        tch_line = reader.readline().strip()
        
        if not tch_line.startswith("T_CH:"):
            print(f"Invalid second message from {ch_id}@{addr}: {tch_line}. Closing.")
            client.close()
            return
        
        T_ch = int(tch_line.split(":", 1)[1])
        
        if ch_id not in CONFIG['structure']['node_definitions'] or CONFIG['structure']['node_definitions'][ch_id]['role'] != 'CH':
            print(f"Error: Received connection from unknown or non-CH ID '{ch_id}'. Closing.")
            client.close()
            return
        
        print(f"CH {ch_id} connected from {addr} with T_ch: {T_ch}")
        
        with chs_lock:
            connected_chs[ch_id] = {'client': client, 'blind_key': T_ch, 'address': addr, 'reader': reader, 'writer': writer}
            inter_ch_blind_keys[ch_id] = T_ch
            
            if ch_id not in inter_ch_swarm_sequence:
                inter_ch_swarm_sequence.append(ch_id)
            else:
                print(f"Warning: CH {ch_id} reconnected.")
            
            compute_main_broadcast_key(ch_id)
            broadcast_inter_ch_update(broadcast_socket, "join", joining_ch_id=ch_id)
            
        while True:  # Keep connection alive, check status
            try:
                client.settimeout(5.0)
                data = client.recv(1, socket.MSG_PEEK)
                client.settimeout(None)
                if not data:
                    print(f"CH {ch_id} TCP connection closed (detected by recv).")
                    break
                time.sleep(4)
            except socket.timeout:
                continue
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                print(f"CH {ch_id} TCP connection error: {e}")
                break
            except Exception as e:
                print(f"Unexpected error reading from CH {ch_id}: {e}")
                break
    except Exception as e:
        print(f"Error handling CH {ch_id or addr}: {type(e).__name__}: {e}")
        traceback.print_exc()
    finally:
        if client:
            client.close()
        if ch_id:
            if handle_ch_departure(ch_id):
                departure_handled = True
            if departure_handled:
                if broadcast_socket:
                    broadcast_inter_ch_update(broadcast_socket, "leave", leaving_ch_ids=[ch_id])
                else:
                    print(f"Error: Cannot broadcast leave update for {ch_id}, socket unavailable.")

def start_swarm_leader():
    global TCP_LISTEN_ADDRESS, INTER_CH_BCAST_ADDRESS, k_main, inter_ch_swarm_sequence, inter_ch_intermediate_keys, T_i
    print("Initializing Swarm Leader...")
    net_conf = CONFIG['network']
    TCP_LISTEN_ADDRESS = (net_conf['sl_tcp_address'], net_conf['sl_tcp_port'])
    INTER_CH_BCAST_ADDRESS = (net_conf['inter_ch_bcast_addr'], net_conf['inter_ch_bcast_port'])
    
    with chs_lock:
        inter_ch_swarm_sequence = [MY_ID]
        inter_ch_intermediate_keys = {MY_ID: sk_i}
        inter_ch_blind_keys = {MY_ID: T_i}
        k_main = sk_i  # Initial key
        print(f"Initial SL state: Sequence={inter_ch_swarm_sequence}, K_main={str(k_main)[:30]}...")
    
    server = None
    broadcast_socket = None
    
    try:
        broadcast_socket = setup_broadcast_socket()
        if not broadcast_socket:
            raise ConnectionError("Failed broadcast socket")
        
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(TCP_LISTEN_ADDRESS)
        server.listen(len(CONFIG['structure']['clusters']) + 2)
        
        print(f"TCP Server listening on {TCP_LISTEN_ADDRESS} for CHs")
        print(f"Broadcasting Inter-CH updates on {INTER_CH_BCAST_ADDRESS}")
        
        while True:
            client, addr = server.accept()
            print(f"Accepted potential CH connection from {addr}")
            threading.Thread(target=handle_ch_connection, args=(broadcast_socket, client, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("Process interrupted.")
    except Exception as e:
        print(f"Error in start_swarm_leader: {e}")
        traceback.print_exc()
    finally:
        print("Shutting down.")
        if broadcast_socket:
            broadcast_socket.close()
        if server:
            server.close()
            time.sleep(0.5)

# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="H-SBP Swarm Leader")
    parser.add_argument("--id", required=True)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    MY_ID = args.id
    print(f"Starting SL Node: {MY_ID}")
    
    try:
        print(f"Loading config: {args.config}")
        with open(args.config, 'r') as f:
            CONFIG = json.load(f)
        
        secrets_path = os.path.join(script_dir, CONFIG['paths']['secret_keys_file'])
        print(f"Loading secrets: {secrets_path}")
        with open(secrets_path, 'r') as f:
            SECRETS = json.load(f)
    except Exception as e:
        print(f"FATAL: Load config/secrets failed: {e}")
        sys.exit(1)
    
    try:
        g = CONFIG['general']['g']
        p = CONFIG['general']['p']
        sk_i = int(SECRETS[MY_ID])
        T_i = pow(g, sk_i, p)
        print(f"Loaded DH params...")
    except Exception as e:
        print(f"FATAL: Process DH/secret key failed: {e}")
        sys.exit(1)
    
    try:
        MY_ROLE = CONFIG['structure']['node_definitions'][MY_ID]['role']
        if MY_ROLE != "SL":
            print(f"FATAL: Role mismatch! Expected SL, got {MY_ROLE}")
            sys.exit(1)
    except KeyError:
        print(f"FATAL: Node definition for '{MY_ID}' not found.")
        sys.exit(1)
    
    try:
        sl_priv_key_path = os.path.join(script_dir, CONFIG['paths']['sl_priv_key'])
        print(f"Loading SL private key: {sl_priv_key_path}")
        private_key = load_private_key(sl_priv_key_path)
        if not private_key:
            print(f"FATAL: Failed load SL private key.")
            sys.exit(1)
    except Exception as e:
        print(f"FATAL: Error loading SL private key: {e}")
        sys.exit(1)
    
    print(f"Starting node {MY_ID} as {MY_ROLE}")
    start_swarm_leader()

# --- END OF FILE swarm_leader.py ---
