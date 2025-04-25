# --- START OF FILE cluster_head.py ---
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
import select
import traceback

# --- Role/Config Specific ---
MY_ID = None
MY_ROLE = None
MY_CLUSTER_ID = None
CONFIG = None
SECRETS = None
g = None
p = None
sk_i = None # CH's own secret key
T_i = None  # CH's own blind key (T_ch)
# SL interaction
sl_ip_arg = None # Added: Store SL IP passed from command line
sl_tcp_address = None
inter_ch_bcast_address = None
sl_public_key = None
# Member interaction
my_member_ids = []
my_tcp_listen_address = None
my_cluster_bcast_address = None
my_private_key = None # CH's key for signing cluster messages
# --------------------------

# Override print function
def print_with_timestamp(*args, **kwargs):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    builtins.print(f"{timestamp} - [{MY_ID or 'CH'}]", *args, **kwargs)
print = print_with_timestamp

# Constants
BUFFER_SIZE = 8192
TCP_BUFFER_SIZE = 4096
REASSEMBLY_TIMEOUT = 15
FRAGMENT_PREFIX = "FRAG"
MAX_UDP_PAYLOAD_SIZE = 1400
# --------------------------

# SBP State
# Inter-CH (as Follower)
k_main = None
inter_ch_swarm_sequence = []
# Intra-Cluster (as Leader)
k_cluster = None
cluster_swarm_sequence = [] # Includes self (CH) as position 0
cluster_intermediate_keys = {} # {member_id: I_intermediate}
cluster_blind_keys = {} # {member_id: T_member}
cluster_g_I_prev_values = {} # {member_id: g^I_prev_for_member}
# --------------------------

# Network State
connected_members = {} # {member_id: {'client': socket, 'blind_key': T_member, 'addr': addr}}
members_lock = threading.Lock()
sl_socket = None # TCP socket connection TO SL
listener_socket = None # TCP socket listening FOR members
inter_ch_udp_socket = None # UDP socket listening for SL broadcasts
cluster_udp_socket = None # UDP socket broadcasting TO members
stop_event = threading.Event() # To signal threads to stop

# Reassembly Buffer (for messages from SL)
reassembly_buffer = {}
# --------------------------

# --- Cryptography Functions (Load Keys, Sign, Verify, Encrypt, Decrypt) ---
# (Similar to member.py and swarm_leader.py, need load_public_key, load_private_key,
#  sign_message_rsa, verify_message_rsa, encrypt_message_aes, decrypt_message_aes)

def load_public_key(path):
    try:
        with open(path, "rb") as key_file: return serialization.load_pem_public_key(key_file.read())
    except Exception as e: print(f"Error loading public key from {path}: {e}"); return None

def load_private_key(path):
    try:
        with open(path, "rb") as key_file: return serialization.load_pem_private_key(key_file.read(), password=None)
    except Exception as e: print(f"Error loading private key from {path}: {e}"); return None

def sign_message_rsa(message_bytes, priv_key):
    if not priv_key: print("Error signing: Private key not loaded."); return None
    try:
        sig = priv_key.sign(message_bytes, padding.PKCS1v15(), SHA256())
        return base64.b64encode(sig).decode('utf-8')
    except Exception as e: print(f"Error signing message: {e}"); return None

def verify_message_rsa(message_bytes, signature, pub_key):
    if not pub_key: print("Error verifying: Public key not loaded."); return False
    if not signature: print("Error verifying: Signature is empty."); return False
    try:
        pub_key.verify(base64.b64decode(signature), message_bytes, padding.PKCS1v15(), SHA256())
        return True
    except Exception: return False # Less verbose

def encrypt_message_aes(message_bytes, key):
    # Encrypts using K_cluster for sending to members
    if key is None: print("Error encrypting for cluster: Key is None."); return None
    try:
        iv = secrets.token_bytes(16)
        key_int = int(key); key_bytes = key_int.to_bytes(32, 'big', signed=False)
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padding_len = 16 - (len(message_bytes) % 16); padded_message = message_bytes + (b"\0" * padding_len)
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode('utf-8')
    except Exception as e: print(f"Error encrypting cluster message: {e}"); return None

def decrypt_message_aes(encrypted_message, key):
    # Decrypts using K_main received from SL
    if key is None: print("Error decrypting global msg: K_main is None!"); return None
    try:
        key_int = int(key); key_bytes = key_int.to_bytes(32, 'big', signed=False)
        encrypted_data = base64.b64decode(encrypted_message)
        iv = encrypted_data[:16]; ciphertext = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        unpadded_message = decrypted_padded_message.rstrip(b"\0")
        try: return unpadded_message.decode("utf-8") # Try decode
        except UnicodeDecodeError: return unpadded_message # Return bytes if needed
    except Exception as e: print(f"Error decrypting global message: {e}"); return None
# ----------------------------------------------------------------------

# --- Fragmentation/Reassembly Functions ---
# (Need fragment_message for broadcasting to cluster, and reassembly logic for receiving from SL)
def fragment_message(full_message_str, max_payload_size=MAX_UDP_PAYLOAD_SIZE):
     # ... (Copy the two-pass fragment_message function from swarm_leader.py) ...
    message_bytes = full_message_str.encode('utf-8'); message_len = len(message_bytes)
    message_id = f"{time.time():.6f}"
    if message_len == 0: return []
    actual_total_fragments = 0; current_pos_pass1 = 0; temp_frag_num = 1
    while current_pos_pass1 < message_len:
        max_digits_total = 6; temp_header = f"{FRAGMENT_PREFIX}/{message_id}/{temp_frag_num}/{'9'*max_digits_total}|"
        temp_header_bytes = temp_header.encode('utf-8'); temp_header_len = len(temp_header_bytes)
        payload_size = max_payload_size - temp_header_len
        if payload_size <= 0: raise ValueError(f"max_payload_size ({max_payload_size}) too small for header pass 1")
        end_pos_pass1 = min(current_pos_pass1 + payload_size, message_len)
        actual_total_fragments += 1; current_pos_pass1 = end_pos_pass1; temp_frag_num += 1
        if actual_total_fragments > message_len + 10: raise RuntimeError("Frag pass 1 loop")
    if actual_total_fragments == 0: raise RuntimeError("0 frags for non-empty msg pass 1")
    fragments = []; current_pos_pass2 = 0
    for fragment_num in range(1, actual_total_fragments + 1):
        header = f"{FRAGMENT_PREFIX}/{message_id}/{fragment_num}/{actual_total_fragments}|"
        header_bytes = header.encode('utf-8'); header_len = len(header_bytes)
        payload_size = max_payload_size - header_len
        if payload_size < 0: raise ValueError(f"max_payload_size too small pass 2 frag {fragment_num}")
        end_pos_pass2 = min(current_pos_pass2 + payload_size, message_len)
        payload_chunk = message_bytes[current_pos_pass2:end_pos_pass2]
        fragment_packet = header_bytes + payload_chunk; fragments.append(fragment_packet)
        current_pos_pass2 = end_pos_pass2
    if current_pos_pass2 != message_len: raise RuntimeError(f"Frag pass 2 incomplete {current_pos_pass2}/{message_len}")
    if len(fragments) != actual_total_fragments: raise RuntimeError(f"Frag pass 2 count mismatch {len(fragments)}/{actual_total_fragments}")
    return fragments

def cleanup_reassembly_buffer():
     # ... (Copy cleanup_reassembly_buffer from member.py) ...
    now = time.time(); messages_to_delete = []
    buffer_copy = list(reassembly_buffer.items())
    for msg_id, data in buffer_copy:
        if msg_id not in reassembly_buffer: continue
        if now - data['timestamp'] > REASSEMBLY_TIMEOUT:
            messages_to_delete.append(msg_id); print(f"Timing out incomplete SL message {msg_id}")
    for msg_id in messages_to_delete:
        if msg_id in reassembly_buffer: del reassembly_buffer[msg_id]

def process_inter_ch_udp_packet(data_bytes):
    # Processes UDP packets *from SL*, handles reassembly, calls handle_inter_ch_message
    global reassembly_buffer
    # ... (Logic is identical to process_udp_packet in member.py, but calls handle_inter_ch_message at the end) ...
    try:
        prefix_check_len = len(FRAGMENT_PREFIX)+1; is_fragment = False
        if len(data_bytes) >= prefix_check_len:
             try: start_str = data_bytes[:prefix_check_len].decode('utf-8', errors='ignore'); is_fragment = start_str.startswith(FRAGMENT_PREFIX + "/")
             except UnicodeDecodeError: pass
        if is_fragment:
            try:
                delimiter_pos = data_bytes.find(b'|');
                if delimiter_pos == -1: print("Invalid SL fragment: Missing delimiter"); return
                header_bytes = data_bytes[:delimiter_pos]; payload_bytes = data_bytes[delimiter_pos+1:]
                header_str = header_bytes.decode('utf-8')
                _, message_id, frag_num_str, total_str = header_str.split('/')
                frag_num = int(frag_num_str); total_fragments_hint = int(total_str)
                now = time.time()
                if message_id not in reassembly_buffer: reassembly_buffer[message_id] = {'fragments': {}, 'total_hint': total_fragments_hint, 'received_count': 0, 'timestamp': now}
                elif frag_num in reassembly_buffer[message_id]['fragments']: return # Ignore duplicate
                reassembly_buffer[message_id]['fragments'][frag_num] = payload_bytes
                reassembly_buffer[message_id]['received_count'] += 1; reassembly_buffer[message_id]['timestamp'] = now
                if reassembly_buffer[message_id]['received_count'] == total_fragments_hint:
                    print(f"Received all {total_fragments_hint} fragments from SL for message {message_id}. Reassembling...")
                    fragments_dict = reassembly_buffer[message_id]['fragments']
                    if len(fragments_dict) != total_fragments_hint or not all(i in fragments_dict for i in range(1, total_fragments_hint + 1)):
                        print(f"Error: Missing fragments from SL for {message_id}. Discarding."); del reassembly_buffer[message_id]; return
                    reassembled_bytes = b"".join([fragments_dict[i] for i in range(1, total_fragments_hint + 1)])
                    original_message = reassembled_bytes.decode('utf-8').strip()
                    print(f"SL Reassembly successful for {message_id}. Processing.")
                    handle_inter_ch_message(original_message) # Call SL message handler
                    del reassembly_buffer[message_id]
            except Exception as e: print(f"Error parsing SL fragment: {e}. Header: {data_bytes[:100]}...")
        else: # Non-fragmented from SL
            try: 
                message = data_bytes.decode('utf-8').strip();
                if message: handle_inter_ch_message(message) # Call SL message handler
            except UnicodeDecodeError: print("Received UDP from SL that is not UTF-8 text or fragment.")
    except Exception as e: print(f"Error in process_inter_ch_udp_packet: {e}"); traceback.print_exc()

# ------------------------------------------

# --- SBP Logic ---

# -- As Follower (Inter-CH) --
def compute_main_key(rcvd_swarm_sequence, rcvd_blind_keys, rcvd_g_I_prev_values):
    """Compute K_main based on update received from SL."""
    global k_main, g, p, sk_i, MY_ID
    print("Attempting to compute K_main...")
    # ... (Logic is identical to compute_cluster_key in member.py, but operates on inter_ch state) ...
    start_time = time.perf_counter()
    try:
        my_pos = -1
        for i, fid in enumerate(rcvd_swarm_sequence):
             if fid == MY_ID: my_pos = i; break
        if my_pos == -1: print(f"Error: Own ID '{MY_ID}' not found in inter-CH sequence: {rcvd_swarm_sequence}"); return None
        if my_pos == 0: print("Error: CH node cannot be at position 0 (SL position)."); return None
        if MY_ID not in rcvd_g_I_prev_values: print(f"Error: Required g^I_prev for ID {MY_ID} not found in SL data {list(rcvd_g_I_prev_values.keys())}"); return None
        my_g_I_prev = rcvd_g_I_prev_values[MY_ID]
        I_mine = pow(my_g_I_prev, sk_i, p)
        current_I = I_mine
        for i in range(my_pos + 1, len(rcvd_swarm_sequence)):
            forward_node_id = rcvd_swarm_sequence[i]
            if forward_node_id not in rcvd_blind_keys: print(f"Error: Blind key for forward node {forward_node_id} (from SL) not found."); return None
            T_forward = rcvd_blind_keys[forward_node_id]
            current_I = pow(T_forward, current_I, p)
        k_main = current_I
        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000
        print(f"Computed new main key K_main: {str(k_main)[:30]}... (took {duration_ms:.3f} ms)")
        return k_main
    except Exception as e: print(f"Error during main key computation: {e}"); traceback.print_exc(); return None


def handle_inter_ch_message(message):
    """Handle messages received on the inter-CH broadcast channel (from SL)."""
    global k_main, inter_ch_swarm_sequence, sl_public_key
    # ... (Logic is similar to handle_cluster_message in member.py, but uses sl_public_key and calls compute_main_key) ...
    try:
        if message.startswith("KEY_UPDATE|"):
            print("Processing KEY_UPDATE from SL...")
            _, message_body_signed = message.split('|', 1)
            message_parts = message_body_signed.rsplit('|', 1)
            if len(message_parts) != 2: print(f"Error: Invalid SL KEY_UPDATE format: {message[:100]}..."); return
            message_body = message_parts[0]; signature = message_parts[1]
            message_body_bytes = message_body.encode('utf-8')
            if not verify_message_rsa(message_body_bytes, signature, sl_public_key): print("Error: Invalid signature for KEY_UPDATE from SL."); return
            # print("SL signature verified for KEY_UPDATE.")
            body_parts = message_body.split('|')
            if len(body_parts) != 3: print(f"Error: Invalid SL KEY_UPDATE body format: {message_body[:100]}..."); return
            rcvd_seq_str, rcvd_blind_keys_str, rcvd_gI_str = body_parts
            rcvd_swarm_sequence = rcvd_seq_str.split(',') if rcvd_seq_str else []
            if not rcvd_swarm_sequence: print("Warning: Received empty inter-CH sequence from SL."); return
            rcvd_blind_keys = {}; rcvd_g_I_prev_values = {}
            if rcvd_blind_keys_str:
                try: rcvd_blind_keys = {fid: int(key) for fid, key in [pair.split(':') for pair in rcvd_blind_keys_str.split(',')]}
                except Exception as e: print(f"Error parsing SL blind keys: {e}, Data: {rcvd_blind_keys_str}"); return
            if rcvd_gI_str:
                 try: rcvd_g_I_prev_values = {fid: int(key) for fid, key in [pair.split(':') for pair in rcvd_gI_str.split(',')]}
                 except Exception as e: print(f"Error parsing SL g^I_prev values: {e}, Data: {rcvd_gI_str}"); return
            print(f"Received Inter-CH State: Seq={rcvd_swarm_sequence}")
            inter_ch_swarm_sequence = rcvd_swarm_sequence
            compute_main_key(rcvd_swarm_sequence, rcvd_blind_keys, rcvd_g_I_prev_values)

        elif message.startswith("GLOBAL_MSG|"):
            # Handle global message relay
            print("Received GLOBAL_MSG from SL.")
            encrypted_content = message.split('|', 1)[1]
            decrypted_content_bytes_or_str = decrypt_message_aes(encrypted_content, k_main)
            if decrypted_content_bytes_or_str:
                 # Determine if it's bytes or string before encrypting for cluster
                 if isinstance(decrypted_content_bytes_or_str, str):
                      content_bytes = decrypted_content_bytes_or_str.encode('utf-8')
                 else:
                      content_bytes = decrypted_content_bytes_or_str # Assume already bytes

                 # Re-encrypt with K_cluster and broadcast to members
                 cluster_encrypted_content = encrypt_message_aes(content_bytes, k_cluster)
                 if cluster_encrypted_content and cluster_udp_socket:
                      relay_message = f"RELAYED_MSG|{cluster_encrypted_content}"
                      try:
                          cluster_udp_socket.sendto(relay_message.encode('utf-8'), my_cluster_bcast_address)
                          print(f"Relayed global message to cluster {MY_CLUSTER_ID}")
                      except Exception as e:
                          print(f"Error relaying global message to cluster: {e}")
                 elif not cluster_encrypted_content:
                       print("Error: Failed to re-encrypt global message for cluster.")
                 elif not cluster_udp_socket:
                        print("Error: Cluster broadcast socket not available for relay.")
            else:
                 print("Error: Failed to decrypt GLOBAL_MSG from SL.")
        else:
            print(f"Received unknown message type from SL: {message[:50]}...")

    except Exception as e: print(f"Error processing inter-CH message: {e}"); traceback.print_exc()


# -- As Leader (Intra-Cluster) --
def compute_cluster_broadcast_key(new_member_id):
    """Compute updated K_cluster when a new Member joins this cluster."""
    global k_cluster, cluster_g_I_prev_values, cluster_intermediate_keys, cluster_swarm_sequence, p, g, T_i
    # ... (Logic is identical to compute_main_broadcast_key in SL, but operates on cluster state) ...
    if not cluster_swarm_sequence: print("Error: cluster_swarm_sequence empty."); return None, None
    if new_member_id not in cluster_blind_keys: print(f"Error: Blind key for {new_member_id} not found."); return None, None
    if len(cluster_swarm_sequence) == 1: I_prev = cluster_intermediate_keys[MY_ID] # CH's sk_i
    else:
         prev_id_index = cluster_swarm_sequence.index(new_member_id) - 1
         if prev_id_index < 0: print(f"Error: Cannot find prev node for {new_member_id} in {cluster_swarm_sequence}"); return None, None
         prev_id = cluster_swarm_sequence[prev_id_index]
         if prev_id not in cluster_intermediate_keys: print(f"Error: Intermed key for prev node {prev_id} not found."); return None, None
         I_prev = cluster_intermediate_keys[prev_id]
    T_new_member = cluster_blind_keys[new_member_id]
    I_new = pow(T_new_member, I_prev, p)
    g_I_prev = pow(g, I_prev, p)
    cluster_intermediate_keys[new_member_id] = I_new
    cluster_g_I_prev_values[new_member_id] = g_I_prev
    k_cluster = I_new
    print(f"Computed K_cluster: {str(k_cluster)[:30]}...")
    print(f"Stored g^I_prev for {new_member_id}: {str(g_I_prev)[:30]}...")
    return k_cluster, g_I_prev


def broadcast_cluster_update(event_type, joining_member_id=None, leaving_member_ids=None):
    """Broadcasts the Intra-Cluster key update, fragmenting if necessary."""
    global k_cluster, cluster_swarm_sequence, cluster_blind_keys, cluster_g_I_prev_values, my_private_key, cluster_udp_socket, my_cluster_bcast_address
    # ... (Logic is identical to broadcast_inter_ch_update in SL, but uses cluster state, CH key, cluster socket/address) ...
    if not cluster_udp_socket: print("Error: Cluster UDP socket not initialized."); return 0

    message_body = ""
    start_time_calc = time.perf_counter()
    with members_lock:
        if not cluster_swarm_sequence: print("Cannot broadcast cluster update: Sequence empty."); return 0
        seq_str = ','.join(map(str, cluster_swarm_sequence))
        blind_keys_str = ','.join([f'{fid}:{cluster_blind_keys[fid]}' for fid in cluster_swarm_sequence if fid != MY_ID and fid in cluster_blind_keys])
        g_I_prev_str = ','.join([f'{fid}:{cluster_g_I_prev_values[fid]}' for fid in cluster_swarm_sequence if fid != MY_ID and fid in cluster_g_I_prev_values])
        message_body = f"{seq_str}|{blind_keys_str}|{g_I_prev_str}"
        if not message_body: print("Error: Could not construct cluster update body."); return 0
        signature = sign_message_rsa(message_body.encode('utf-8'), my_private_key)
        if not signature: print("Error: Failed to sign cluster update."); return 0
        full_message = f"KEY_UPDATE|{message_body}|{signature}\n"
    end_time_calc = time.perf_counter(); calc_duration_ms = (end_time_calc - start_time_calc) * 1000
    print(f"Cluster update message calculation time: {calc_duration_ms:.3f} ms")

    try:
        full_message_bytes = full_message.encode('utf-8'); original_message_size = len(full_message_bytes)
        if original_message_size > MAX_UDP_PAYLOAD_SIZE:
            print(f"Cluster message size ({original_message_size}) exceeds limit. Fragmenting...")
            fragments = fragment_message(full_message, MAX_UDP_PAYLOAD_SIZE)
            print(f"Sending {len(fragments)} fragments for Cluster update ({event_type})...")
            bytes_sent_this_msg = 0; start_time_send = time.perf_counter()
            for i, frag in enumerate(fragments):
                try: sent = cluster_udp_socket.sendto(frag, my_cluster_bcast_address); bytes_sent_this_msg += sent; time.sleep(0.001)
                except Exception as send_err: print(f"Error sending Cluster fragment {i+1}: {send_err}")
            end_time_send = time.perf_counter(); send_duration_ms = (end_time_send - start_time_send) * 1000
            print(f"Finished sending Cluster fragments. Total bytes: {bytes_sent_this_msg}. Send duration: {send_duration_ms:.3f} ms")
            return original_message_size
        else:
            start_time_send = time.perf_counter()
            bytes_sent = cluster_udp_socket.sendto(full_message_bytes, my_cluster_bcast_address)
            end_time_send = time.perf_counter(); send_duration_ms = (end_time_send - start_time_send) * 1000
            print(f"Broadcasting non-fragmented Cluster update ({event_type}). Size: {bytes_sent}. Send duration: {send_duration_ms:.3f} ms")
            return bytes_sent
    except Exception as e: print(f"Error during Cluster update send: {e}"); traceback.print_exc(); return 0


def handle_member_departure(member_id):
    """Handles the departure of a cluster member."""
    global k_cluster, cluster_swarm_sequence, cluster_blind_keys, cluster_intermediate_keys, cluster_g_I_prev_values, p, g
    # ... (Logic is identical to handle_ch_departure in SL, but operates on cluster state) ...
    print(f"Handling departure for Member {member_id}")
    with members_lock:
        if member_id not in connected_members: print(f"Warning: Member {member_id} already departed/unknown."); return False
        if 'client' in connected_members[member_id]:
            try: connected_members[member_id]['client'].close()
            except Exception: pass
        del connected_members[member_id]
        if member_id in cluster_blind_keys: del cluster_blind_keys[member_id]
        if member_id in cluster_intermediate_keys: del cluster_intermediate_keys[member_id]
        if member_id in cluster_g_I_prev_values: del cluster_g_I_prev_values[member_id]
        if member_id not in cluster_swarm_sequence: print(f"Warning: Departing Member {member_id} not in seq {cluster_swarm_sequence}"); return False
        try: departure_index = cluster_swarm_sequence.index(member_id)
        except ValueError: print(f"Warning: Could not find index for departing Member {member_id}."); return False
        old_sequence = cluster_swarm_sequence[:]
        nodes_after_departure = cluster_swarm_sequence[departure_index:]
        cluster_swarm_sequence = cluster_swarm_sequence[:departure_index]
        for node_id in nodes_after_departure:
            if node_id in cluster_intermediate_keys: del cluster_intermediate_keys[node_id]
            if node_id in cluster_g_I_prev_values: del cluster_g_I_prev_values[node_id]
        print(f"Cluster Sequence after removing {member_id} and subsequent: {cluster_swarm_sequence}")
        if departure_index == 0: print("Error: CH departure cannot be handled here."); return False # CH is position 0
        I_prev = cluster_intermediate_keys[cluster_swarm_sequence[departure_index - 1]]
        nodes_to_re_add = [node for node in old_sequence if node != member_id and node not in cluster_swarm_sequence]
        print(f"Nodes to re-add to cluster seq: {nodes_to_re_add}")
        for node_id in nodes_to_re_add:
             if node_id not in cluster_blind_keys: print(f"Error: Cannot recompute cluster chain, blind key for {node_id} missing."); return False
             T_node = cluster_blind_keys[node_id]; I_new = pow(T_node, I_prev, p); g_I_prev_recomputed = pow(g, I_prev, p)
             cluster_intermediate_keys[node_id] = I_new; cluster_g_I_prev_values[node_id] = g_I_prev_recomputed
             cluster_swarm_sequence.append(node_id); I_prev = I_new
        if len(cluster_swarm_sequence) <= 1: k_cluster = cluster_intermediate_keys[MY_ID] # Reset to CH's I_0 = sk_i
        else: last_node_id = cluster_swarm_sequence[-1]; k_cluster = cluster_intermediate_keys[last_node_id]
        print(f"Recomputed Cluster sequence: {cluster_swarm_sequence}")
        print(f"Recomputed K_cluster: {str(k_cluster)[:30]}...")
        return True


def handle_member_connection(client, addr):
    """Handle connection from a single cluster member."""
    global k_cluster, cluster_swarm_sequence, cluster_blind_keys, cluster_intermediate_keys, cluster_g_I_prev_values
    member_id = None
    # ... (Logic similar to handle_ch_connection in SL, but uses member state and cluster broadcast) ...
    try:
        reader = client.makefile('r', encoding='utf-8'); writer = client.makefile('w', encoding='utf-8')
        id_line = reader.readline().strip()
        if not id_line.startswith("ID:"): print(f"Invalid initial msg from {addr}: {id_line}. Closing."); client.close(); return
        member_id = id_line.split(":", 1)[1]
        ti_line = reader.readline().strip()
        if not ti_line.startswith("T_I:"): print(f"Invalid second msg from {member_id}@{addr}: {ti_line}. Closing."); client.close(); return
        T_member = int(ti_line.split(":", 1)[1])
        # Verify Member ID is part of this cluster
        if member_id not in my_member_ids: print(f"Error: Received connection from unknown/wrong cluster Member ID '{member_id}'. Closing."); client.close(); return
        print(f"Member {member_id} connected from {addr} with T_i: {T_member}")
        with members_lock:
            connected_members[member_id] = {'client': client, 'blind_key': T_member, 'address': addr, 'reader': reader, 'writer': writer}
            cluster_blind_keys[member_id] = T_member
            if member_id not in cluster_swarm_sequence: cluster_swarm_sequence.append(member_id)
            else: print(f"Warning: Member {member_id} reconnected.")
            compute_cluster_broadcast_key(member_id) # Compute new K_cluster
        broadcast_cluster_update("join", joining_member_id=member_id) # Broadcast update TO CLUSTER
        while not stop_event.is_set(): # Check stop event
            try:
                client.settimeout(2.0); data = client.recv(1, socket.MSG_PEEK); client.settimeout(None)
                if not data: print(f"Member {member_id} TCP connection closed."); break
                time.sleep(1.5) # Check less frequently
            except socket.timeout: continue
            except (ConnectionResetError, BrokenPipeError, OSError) as e: print(f"Member {member_id} TCP connection error: {e}"); break
            except Exception as e: print(f"Unexpected error reading from Member {member_id}: {e}"); break
    except (ConnectionResetError, BrokenPipeError, OSError, ValueError) as e: print(f"Member {member_id or addr} disconnected/invalid data: {e}")
    except Exception as e: print(f"Error handling Member {member_id or addr}: {e}"); traceback.print_exc()
    finally:
        if client: client.close()
        if member_id:
            if handle_member_departure(member_id): # Handle departure logic
                 broadcast_cluster_update("leave", leaving_member_ids=[member_id]) # Broadcast cluster update


# --- Network Setup and Main Loop ---

def setup_cluster_udp_socket():
    """Sets up UDP socket for broadcasting TO cluster members."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return sock
    except Exception as e: print(f"Error setting up cluster broadcast socket: {e}"); return None

def setup_inter_ch_udp_listener(listen_address):
    """Sets up UDP socket for listening TO SL."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bind_ip = listen_address[0] if listen_address[0] != '0.0.0.0' else ''
        sock.bind((bind_ip, listen_address[1]))
        print(f"Successfully bound Inter-CH UDP listener to {listen_address}")
        return sock
    except Exception as e: print(f"Error setting up Inter-CH UDP listener on {listen_address}: {e}"); return None


def connect_to_swarm_leader():
    """Connects to the Swarm Leader via TCP."""
    global sl_socket
    retries = 0
    max_retries = 5
    while retries < max_retries and not stop_event.is_set():
        retries += 1
        try:
            print(f"Attempt {retries}: Connecting to SL at {sl_tcp_address}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(sl_tcp_address)
            sock.settimeout(None)
            sl_socket = sock # Store the connected socket globally
            print("Connected to SL via TCP.")
            # Send ID and T_ch
            writer = sl_socket.makefile('w', encoding='utf-8')
            writer.write(f"ID:{MY_ID}\n")
            writer.write(f"T_CH:{T_i}\n")
            writer.flush()
            print("Sent ID and T_ch to SL.")
            return True # Success
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            print(f"Connection attempt {retries} to SL failed: {e}")
            if sl_socket: sl_socket.close(); sl_socket = None
            if retries < max_retries: time.sleep(5) # Wait before retrying
        except Exception as e:
            print(f"Unexpected error connecting to SL: {e}")
            if sl_socket: sl_socket.close(); sl_socket = None
            traceback.print_exc()
            if retries < max_retries: time.sleep(10)
    print("FATAL: Could not connect to Swarm Leader after multiple attempts.")
    stop_event.set() # Signal other threads to stop
    return False

def listen_for_members():
    """Thread target: Listens for incoming TCP connections from members."""
    global listener_socket
    try:
        listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener_socket.bind(my_tcp_listen_address)
        listener_socket.listen(len(my_member_ids) + 2) # Listen for all potential members + buffer
        print(f"TCP Server listening on {my_tcp_listen_address} for Members")

        while not stop_event.is_set():
             try:
                  # Use select with timeout to allow checking stop_event
                  listener_socket.settimeout(1.0)
                  client, addr = listener_socket.accept()
                  listener_socket.settimeout(None)
                  print(f"Accepted potential Member connection from {addr}")
                  # Handle the member in a separate thread
                  threading.Thread(target=handle_member_connection, args=(client, addr), daemon=True).start()
             except socket.timeout:
                  continue # Timeout just allows checking stop_event
             except Exception as e:
                  if not stop_event.is_set(): # Avoid error messages during shutdown
                       print(f"Error accepting member connection: {e}")
                  time.sleep(0.5) # Avoid busy loop on errors

    except Exception as e:
        print(f"FATAL: Member listener thread failed: {e}")
        traceback.print_exc()
    finally:
        if listener_socket: listener_socket.close()
        print("Member listener thread stopped.")
        stop_event.set() # Ensure other threads know we stopped


def listen_for_sl_udp():
    """Thread target: Listens for UDP broadcasts from the SL."""
    global inter_ch_udp_socket
    if not inter_ch_udp_socket:
        print("Error: Inter-CH UDP listener socket not initialized.")
        return
    print(f"Starting Inter-CH UDP listener on {inter_ch_bcast_address}")
    last_cleanup_time = time.time()
    while not stop_event.is_set():
        try:
            # Use select with timeout to allow checking stop_event
            readable, _, _ = select.select([inter_ch_udp_socket], [], [], 1.0)
            if readable:
                 data_bytes, addr = inter_ch_udp_socket.recvfrom(BUFFER_SIZE)
                 if data_bytes:
                     # Verify it came from SL's expected IP? Optional.
                     process_inter_ch_udp_packet(data_bytes)

            # Periodic cleanup
            now = time.time()
            if now - last_cleanup_time > REASSEMBLY_TIMEOUT:
                 cleanup_reassembly_buffer()
                 last_cleanup_time = now

        except Exception as e:
            if not stop_event.is_set():
                 print(f"Error in SL UDP listener loop: {e}")
            # Avoid busy loop on errors
            time.sleep(0.5)
    print("Inter-CH UDP listener thread stopped.")

def start_cluster_head():
    """Initializes and starts all CH functionalities."""
    global cluster_swarm_sequence, cluster_intermediate_keys, cluster_blind_keys, k_cluster
    global cluster_udp_socket, inter_ch_udp_socket
    # Make sure sl_socket and listener_socket are accessible and initialized if used in finally
    global sl_socket, listener_socket
    
    sl_socket = None # Initialize here to ensure it exists in this scope
    listener_socket = None # Initialize here
    
    print("Initializing Cluster Head...")

    try: # Wrap the whole setup and main loop
        # Setup networking sockets
        cluster_udp_socket = setup_cluster_udp_socket()
        inter_ch_udp_socket = setup_inter_ch_udp_listener(inter_ch_bcast_address)
        if not cluster_udp_socket or not inter_ch_udp_socket:
            print("FATAL: Failed to initialize UDP sockets.")
            stop_event.set() # Signal potential threads to stop
            return

        # Connect to SL (blocking) - This assigns to global sl_socket
        if not connect_to_swarm_leader():
            stop_event.set()
            return # Stop if connection failed

        # Start TCP listener thread for members - This assigns to global listener_socket inside thread
        member_listener_thread = threading.Thread(target=listen_for_members, daemon=True)
        member_listener_thread.start()

        # Start UDP listener thread for SL messages
        sl_listener_thread = threading.Thread(target=listen_for_sl_udp, daemon=True)
        sl_listener_thread.start()

        print("CH Initialization complete. Running...")

        # Keep main thread alive
        while not stop_event.is_set():
            # ... (check SL connection, sleep, etc.) ...
            if sl_socket:
                # ... (socket checking logic) ...
                pass # Placeholder for check logic
            else:
                 # Attempt reconnect if socket is None
                 print("SL socket is down, attempting reconnect...")
                 if not connect_to_swarm_leader():
                     print("Reconnection to SL failed. Shutting down.")
                     stop_event.set()
            time.sleep(5)

    except KeyboardInterrupt:
         print("Keyboard interrupt received. Shutting down CH...")
    except Exception as main_err:
         print(f"Error in CH main loop/setup: {main_err}")
         traceback.print_exc()
    finally:
        stop_event.set() # Signal all threads to stop
        print("Waiting for threads to stop...")
        # Safely close sockets if they were assigned
        if listener_socket:
             try: listener_socket.close()
             except Exception: pass
        if sl_socket:
             try: sl_socket.close()
             except Exception: pass
        if inter_ch_udp_socket:
             try: inter_ch_udp_socket.close()
             except Exception: pass
        if cluster_udp_socket:
             try: cluster_udp_socket.close()
             except Exception: pass

        # Wait for threads (check if they were assigned and started first)
        if 'member_listener_thread' in locals() and member_listener_thread.is_alive():
             member_listener_thread.join(timeout=2)
        if 'sl_listener_thread' in locals() and sl_listener_thread.is_alive():
             sl_listener_thread.join(timeout=2)
        print("CH Shutdown complete.")
        
# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="H-SBP Cluster Head")
    parser.add_argument("--id", required=True, help="ID of this Cluster Head node")
    parser.add_argument("--config", required=True, help="Path to the H-SBP configuration JSON file")
    parser.add_argument("--sl-ip", required=True, help="IP address of the Swarm Leader") # Added argument
    args = parser.parse_args()

    MY_ID = args.id
    sl_ip_arg = args.sl_ip # Store the passed IP
    print(f"Starting Cluster Head Node: {MY_ID}")
    # Load configuration
    try:
        print(f"Loading config file: {args.config}")
        with open(args.config, 'r') as f: CONFIG = json.load(f)
        
        script_dir = os.path.dirname(os.path.abspath(__file__))
        secrets_path = os.path.join(script_dir, CONFIG['paths']['secret_keys_file'])
        print(f"Loading secrets file: {secrets_path}")
        
        with open(secrets_path, 'r') as f:
            SECRETS = json.load(f)
        #print(f"Loading secrets file: {CONFIG['paths']['secret_keys_file']}")
        #with open(CONFIG['paths']['secret_keys_file'], 'r') as f: SECRETS = json.load(f)
    except Exception as e: print(f"FATAL: Failed to load config/secrets: {e}"); sys.exit(1)

    # Load parameters
    try:
        g = CONFIG['general']['g']; p = CONFIG['general']['p']
        sk_i = int(SECRETS[MY_ID]); T_i = pow(g, sk_i, p)
        print(f"Loaded DH params. g={g}, p={str(p)[:20]}..., sk_i={str(sk_i)[:20]}..., T_i={str(T_i)[:20]}...")
    except Exception as e: print(f"FATAL: Failed to load DH params/secret key: {e}"); sys.exit(1)

    # Determine Role, Cluster, Members
    try:
        node_def = CONFIG['structure']['node_definitions'][MY_ID]
        MY_ROLE = node_def['role']
        if MY_ROLE != "CH": print(f"FATAL: Role mismatch! Expected CH, got {MY_ROLE}"); sys.exit(1)
        MY_CLUSTER_ID = node_def['cluster_id']
        my_member_ids = CONFIG['structure']['clusters'][MY_CLUSTER_ID]['members']
    except Exception as e: print(f"FATAL: Config error finding role/cluster/members: {e}"); sys.exit(1)

    # Network Config
    try:
        net_conf = CONFIG['network']

        # *** USE THE COMMAND LINE ARGUMENT FOR SL IP ***
        sl_tcp_address = (sl_ip_arg, net_conf['sl_tcp_port'])
        # ***********************************************

        # Inter-CH broadcast listen address (usually 0.0.0.0 + port, or specific IP + port)
        # Config defines the IP/Port - this seems okay if config is correct
        inter_ch_bcast_address = (net_conf['inter_ch_bcast_addr'], net_conf['inter_ch_bcast_port'])

        # Member TCP listen address (listen on all interfaces)
        my_tcp_listen_port = net_conf['ch_tcp_base_port'] + int(MY_CLUSTER_ID) - 1
        my_tcp_listen_address = (net_conf['sl_tcp_address'], my_tcp_listen_port) # Uses 0.0.0.0 from config - Correct

        # Cluster broadcast address (send TO this address)
        my_cluster_bcast_port = net_conf['cluster_bcast_base_port'] + int(MY_CLUSTER_ID) - 1
        # *** USE CONFIGURED BROADCAST IP CONSISTENTLY ***
        my_cluster_bcast_addr_str = net_conf['inter_ch_bcast_addr']
        # ************************************************
        my_cluster_bcast_address = (my_cluster_bcast_addr_str, my_cluster_bcast_port)

    except Exception as e:
        print(f"FATAL: Config error finding network details: {e}")
        sys.exit(1)

    # Load Keys
    try:
        sl_public_key_path = os.path.join(script_dir, CONFIG['paths']['sl_pub_key'])
        print(f"Loading SL public key: {sl_public_key}")
                
        #print(f"Loading SL public key: {CONFIG['paths']['sl_pub_key']}")
        sl_public_key = load_public_key(sl_public_key_path)
        my_priv_key_path = CONFIG['paths']['ch_priv_key_template'].format(MY_CLUSTER_ID)
        
        my_priv_key_path_full = os.path.join(script_dir, my_priv_key_path)
        print(f"Loading own private key: {my_priv_key_path_full}")
        my_private_key = load_private_key(my_priv_key_path_full)
        if not sl_public_key or not my_private_key:
            print("FATAL: Failed to load required cryptographic keys."); sys.exit(1)
    except Exception as e: print(f"FATAL: Error loading keys: {e}"); sys.exit(1)

    print(f"Starting node {MY_ID} as {MY_ROLE} for Cluster {MY_CLUSTER_ID}")
    print(f"SL Target: {sl_tcp_address}. Inter-CH UDP Listen: {inter_ch_bcast_address}") # Should show correct SL IP
    print(f"Member TCP Listen: {my_tcp_listen_address}. Cluster UDP Broadcast: {my_cluster_bcast_address}")
    print(f"Managing Members: {my_member_ids}")

    start_cluster_head()
# --- END OF FILE cluster_head.py ---
