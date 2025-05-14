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
sk_i = None
T_i = None
sl_tcp_address = None
inter_ch_bcast_address = None
sl_public_key = None
my_initial_member_ids = []  # New: Members to init with
my_joining_member_id = None  # New: The single member expected to join later
my_member_ids = []  # List of ALL members this CH manages (from config)
my_tcp_listen_address = None
my_cluster_bcast_address = None
my_private_key = None
my_control_listen_address = None # New for batch leave trigger
script_dir = os.path.dirname(os.path.abspath(__file__))
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
CH_CONTROL_BASE_PORT = 5100 # Base port for CH control commands
# --------------------------

# SBP State
k_main = None
inter_ch_swarm_sequence = []
k_cluster = None
cluster_swarm_sequence = []
cluster_intermediate_keys = {}
cluster_blind_keys = {}
cluster_g_I_prev_values = {}
# --------------------------

# Network State
connected_members = {}
members_lock = threading.Lock()
sl_socket = None
listener_socket = None
inter_ch_udp_socket = None
cluster_udp_socket = None
stop_event = threading.Event()
# --------------------------

# Reassembly Buffer (for messages from SL)
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

def verify_message_rsa(message_bytes, signature, pub_key):
    if not pub_key:
        print("Error verifying: Public key not loaded.")
        return False
    if not signature:
        print("Error verifying: Signature is empty.")
        return False
    try:
        pub_key.verify(base64.b64decode(signature), message_bytes, padding.PKCS1v15(), SHA256())
        return True
    except Exception:
        return False  # Less verbose

def encrypt_message_aes(message_bytes, key):  # For cluster
    if key is None:
        print("Error encrypting for cluster: Key is None.")
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
        print(f"Error encrypting cluster message: {e}")
        return None

def decrypt_message_aes(encrypted_message, key):  # For SL messages
    if key is None:
        print("Error decrypting global msg: K_main is None!")
        return None
    try:
        key_int = int(key)
        key_bytes = key_int.to_bytes(32, 'big', signed=False)
        encrypted_data = base64.b64decode(encrypted_message)
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        unpadded_message = decrypted_padded_message.rstrip(b"\0")
        try:
            return unpadded_message.decode("utf-8")
        except UnicodeDecodeError:
            return unpadded_message
    except Exception as e:
        print(f"Error decrypting global message: {e}")
        return None
# ----------------------------------------------------------------------

# --- Fragmentation/Reassembly Functions ---
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
            raise ValueError(f"max_payload_size ({max_payload_size}) too small pass 1")
        end_pos_pass1 = min(current_pos_pass1 + payload_size, message_len)
        actual_total_fragments += 1
        current_pos_pass1 = end_pos_pass1
        temp_frag_num += 1
        if actual_total_fragments > message_len + 10:
            raise RuntimeError("Frag pass 1 loop")
    
    if actual_total_fragments == 0:
        raise RuntimeError("0 frags pass 1")
    
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

def cleanup_reassembly_buffer():  # For SL messages
    now = time.time()
    messages_to_delete = []
    buffer_copy = list(reassembly_buffer.items())
    for msg_id, data in buffer_copy:
        if msg_id not in reassembly_buffer:
            continue
        if now - data['timestamp'] > REASSEMBLY_TIMEOUT:
            messages_to_delete.append(msg_id)
            print(f"Timing out incomplete SL message {msg_id}")
    for msg_id in messages_to_delete:
        if msg_id in reassembly_buffer:
            del reassembly_buffer[msg_id]

def process_inter_ch_udp_packet(data_bytes):  # Processes UDP from SL
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
                    print("Invalid SL fragment: Missing delimiter")
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
                    print(f"Received all {total_fragments_hint} fragments from SL for message {message_id}. Reassembling...")
                    fragments_dict = reassembly_buffer[message_id]['fragments']
                    if len(fragments_dict) != total_fragments_hint or not all(i in fragments_dict for i in range(1, total_fragments_hint + 1)):
                        print(f"Error: Missing fragments from SL for {message_id}. Discarding.")
                        del reassembly_buffer[message_id]
                        return
                    
                    reassembled_bytes = b"".join([fragments_dict[i] for i in range(1, total_fragments_hint + 1)])
                    original_message = reassembled_bytes.decode('utf-8').strip()
                    print(f"SL Reassembly successful for {message_id}. Processing.")
                    handle_inter_ch_message(original_message)
                    del reassembly_buffer[message_id]
            except Exception as e:
                print(f"Error parsing SL fragment: {e}. Header: {data_bytes[:100]}...")
        else:  # Non-fragmented from SL
            try:
                message = data_bytes.decode('utf-8').strip()
                if message:
                    handle_inter_ch_message(message)
            except UnicodeDecodeError:
                print("Received UDP from SL that is not UTF-8 text or fragment.")
    except Exception as e:
        print(f"Error in process_inter_ch_udp_packet: {e}")
        traceback.print_exc()
# ------------------------------------------

# --- SBP Logic ---

# -- As Follower (Inter-CH) --
def compute_main_key(rcvd_swarm_sequence, rcvd_blind_keys, rcvd_g_I_prev_values):
    global k_main, g, p, sk_i, MY_ID
    print("Attempting to compute K_main...")
    start_time = time.perf_counter()
    try:
        my_pos = -1
        for i, fid in enumerate(rcvd_swarm_sequence):
            if fid == MY_ID:
                my_pos = i
                break
        
        if my_pos == -1:
            print(f"Error: Own ID '{MY_ID}' not found in inter-CH sequence: {rcvd_swarm_sequence}")
            return None
        
        if my_pos == 0:
            print("Error: CH node cannot be at position 0 (SL position).")
            return None
        
        if MY_ID not in rcvd_g_I_prev_values:
            print(f"Error: Required g^I_prev for ID {MY_ID} not found in SL data {list(rcvd_g_I_prev_values.keys())}")
            return None
        
        my_g_I_prev = rcvd_g_I_prev_values[MY_ID]
        I_mine = pow(my_g_I_prev, sk_i, p)
        current_I = I_mine
        
        for i in range(my_pos + 1, len(rcvd_swarm_sequence)):
            forward_node_id = rcvd_swarm_sequence[i]
            if forward_node_id not in rcvd_blind_keys:
                print(f"Error: Blind key for forward node {forward_node_id} (from SL) not found.")
                return None
            T_forward = rcvd_blind_keys[forward_node_id]
            current_I = pow(T_forward, current_I, p)
        
        k_main = current_I
        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000
        print(f"Computed new main key K_main: {str(k_main)[:30]}... (took {duration_ms:.3f} ms)")
        print(f"[CH] As-follower, Execution time for joining SL key computation : {duration_ms:.3f} ms")
        return k_main
    except Exception as e:
        print(f"Error during main key computation: {e}")
        traceback.print_exc()
        return None

def handle_inter_ch_message(message):  # Handles messages FROM SL
    global k_main, inter_ch_swarm_sequence, sl_public_key
    try:
        if message.startswith("KEY_UPDATE|"):
            print("Processing KEY_UPDATE from SL...")
            _, message_body_signed = message.split('|', 1)
            message_parts = message_body_signed.rsplit('|', 1)
            if len(message_parts) != 2:
                print(f"Error: Invalid SL KEY_UPDATE format: {message[:100]}...")
                return
            
            message_body = message_parts[0]
            signature = message_parts[1]
            message_body_bytes = message_body.encode('utf-8')
            
            if not verify_message_rsa(message_body_bytes, signature, sl_public_key):
                print("Error: Invalid signature for KEY_UPDATE from SL.")
                return
            
            body_parts = message_body.split('|')
            if len(body_parts) != 3:
                print(f"Error: Invalid SL KEY_UPDATE body format: {message_body[:100]}...")
                return
            
            rcvd_seq_str, rcvd_blind_keys_str, rcvd_gI_str = body_parts
            rcvd_swarm_sequence = rcvd_seq_str.split(',') if rcvd_seq_str else []
            
            if not rcvd_swarm_sequence:
                print("Warning: Received empty inter-CH sequence from SL.")
                return
            
            rcvd_blind_keys = {}
            rcvd_g_I_prev_values = {}
            
            if rcvd_blind_keys_str:
                try:
                    rcvd_blind_keys = {fid: int(key) for fid, key in [pair.split(':') for pair in rcvd_blind_keys_str.split(',')]}
                except Exception as e:
                    print(f"Error parsing SL blind keys: {e}")
                    return
            
            if rcvd_gI_str:
                try:
                    rcvd_g_I_prev_values = {fid: int(key) for fid, key in [pair.split(':') for pair in rcvd_gI_str.split(',')]}
                except Exception as e:
                    print(f"Error parsing SL g^I_prev values: {e}")
                    return
            
            print(f"Received Inter-CH State: Seq={rcvd_swarm_sequence}")
            inter_ch_swarm_sequence = rcvd_swarm_sequence
            compute_main_key(rcvd_swarm_sequence, rcvd_blind_keys, rcvd_g_I_prev_values)

        elif message.startswith("GLOBAL_MSG|"):
            print("Received GLOBAL_MSG from SL.")
            encrypted_content = message.split('|', 1)[1]
            decrypted_content_bytes_or_str = decrypt_message_aes(encrypted_content, k_main)
            
            if decrypted_content_bytes_or_str:
                content_bytes = decrypted_content_bytes_or_str.encode('utf-8') if isinstance(decrypted_content_bytes_or_str, str) else decrypted_content_bytes_or_str
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
    except Exception as e:
        print(f"Error processing inter-CH message: {e}")
        traceback.print_exc()

# -- As Leader (Intra-Cluster) --
def initialize_cluster_sbp_with_initial_members():
    """Calculates the initial SBP chain using ONLY the 'initial_members'."""
    global k_cluster, cluster_intermediate_keys, cluster_blind_keys, cluster_g_I_prev_values, cluster_swarm_sequence, p, g, T_i, my_private_key, sk_i
    print(f"Initializing SBP for Cluster {MY_CLUSTER_ID} with initial members: {my_initial_member_ids}")
    start_time = time.perf_counter()

    with members_lock:  # Protect access to shared state during init
        cluster_swarm_sequence = [MY_ID] + my_initial_member_ids  # Sequence = CH + M0 members
        print(f"Initial Cluster Sequence: {cluster_swarm_sequence}")

        cluster_intermediate_keys = {MY_ID: sk_i}  # I_0 = sk_i
        cluster_blind_keys = {MY_ID: T_i}       # T_0 = T_ch
        cluster_g_I_prev_values = {}            # No g^I for index 0

        # Pre-load blind keys for initial members
        for member_id in my_initial_member_ids:
            try:
                member_sk = int(SECRETS[member_id])
                T_member = pow(g, member_sk, p)
                cluster_blind_keys[member_id] = T_member
            except KeyError:
                print(f"FATAL: Secret key for initial member '{member_id}' not found!")
                stop_event.set()
                return False
            except Exception as e:
                print(f"FATAL: Error processing secret key for '{member_id}': {e}")
                stop_event.set()
                return False

        # Calculate chain for initial members
        I_prev = sk_i
        for member_id in cluster_swarm_sequence[1:]:
            T_member = cluster_blind_keys[member_id]
            I_new = pow(T_member, I_prev, p)
            g_I_prev = pow(g, I_prev, p)
            cluster_intermediate_keys[member_id] = I_new
            cluster_g_I_prev_values[member_id] = g_I_prev
            I_prev = I_new

        k_cluster = I_prev  # Final key after initial members
        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000
        print(f"Initial K_cluster computed (M0 members): {str(k_cluster)[:30]}... (took {duration_ms:.3f} ms)")
        print(f"Initial g^I_prev values: {{ {', '.join([f'{k}: {str(v)[:15]}...' for k,v in cluster_g_I_prev_values.items()])} }}")

    # Broadcast the initial state (outside the lock)
    #if cluster_udp_socket:
    #    broadcast_cluster_update("initial_setup")
    #else:
    #    print("Error: Cannot broadcast initial cluster setup, UDP socket not ready.")
    return True

def compute_single_join_update(joining_member_id, T_joining_member):
    """Computes the update for a single joining member (M0+1)."""
    global k_cluster, cluster_intermediate_keys, cluster_blind_keys, cluster_g_I_prev_values, cluster_swarm_sequence, p, g
    print(f"Computing single join update for {joining_member_id}")
    start_time = time.perf_counter()
    
    if not cluster_swarm_sequence or not cluster_intermediate_keys:
        print("Error: Cannot compute join, initial cluster state not set.")
        return None, None, None
    
    last_node_id = cluster_swarm_sequence[-1]
    if last_node_id not in cluster_intermediate_keys:
        print(f"Error: Intermediate key for last node {last_node_id} not found.")
        return None, None, None
    
    I_prev = cluster_intermediate_keys[last_node_id]  # Old k_cluster
    I_new = pow(T_joining_member, I_prev, p)  # New k_cluster
    g_I_prev_for_joiner = pow(g, I_prev, p)
    
    #print("Before lock")
    #with members_lock:  # Protect state update
    k_cluster = I_new
    cluster_swarm_sequence.append(joining_member_id)
    cluster_blind_keys[joining_member_id] = T_joining_member
    cluster_intermediate_keys[joining_member_id] = I_new
    cluster_g_I_prev_values[joining_member_id] = g_I_prev_for_joiner
    
    #print("After lick")
    
    end_time = time.perf_counter()
    duration_ms = (end_time - start_time) * 1000
    print(f"Updated K_cluster after join: {str(k_cluster)[:30]}... (took {duration_ms:.3f} ms)")
    print(f"Calculated g^I_prev for joiner {joining_member_id}: {str(g_I_prev_for_joiner)[:30]}...")
    # Log CH's calculation time for the join event
    print(f"[CH] Execution time for single join event ({joining_member_id}): {duration_ms:.3f} ms")
    return joining_member_id, T_joining_member, g_I_prev_for_joiner



# --- MODIFIED: Batch Leave Logic ---
def perform_batch_leave(num_to_leave: int):
    """
    Handles the logic for K members leaving the cluster.
    Leaving members are the last K members from the current sequence,
    EXCLUDING the CH and EXCLUDING the very last member of the sequence.
    """
    global k_cluster, cluster_swarm_sequence, cluster_blind_keys, cluster_intermediate_keys, cluster_g_I_prev_values, p, g, sk_i
    print(f"Batch leave requested for {num_to_leave} members based on specific selection.")
    start_time = time.perf_counter()
    leaving_member_ids_actual = []

    with members_lock:
        if not cluster_swarm_sequence or len(cluster_swarm_sequence) <= 1: # Must have CH
            print("Cannot perform batch leave: Cluster sequence too short or CH missing.")
            return

        # Current members in sequence, excluding the CH (at index 0)
        current_actual_members = cluster_swarm_sequence[1:]
        print(f"Current actual members in sequence: {current_actual_members}")

        if not current_actual_members:
            print("No members in cluster to leave.")
            return
        if num_to_leave <= 0:
            print("Number to leave is 0 or less, no action taken.")
            return

        # Identify the pool of candidates for leaving:
        # Exclude CH (already done by taking current_actual_members)
        # Exclude the very last member of the current_actual_members list
        if len(current_actual_members) <= 1: # Not enough members to exclude last and pick K
            print("Not enough members to apply the specific leaving rule (need at least CH + 2 members + K).")
            # Fallback: if K=1 and only 1 member exists (after CH), that one leaves? Or error?
            # For now, let's just proceed if any candidates remain after exclusion.
            candidates_for_leaving = []
        else:
            last_member_to_stay = current_actual_members[-1]
            candidates_for_leaving = current_actual_members[:-1] # All members except the very last one
            print(f"Candidates for leaving (excluding CH and last member {last_member_to_stay}): {candidates_for_leaving}")

        if not candidates_for_leaving:
            print("No candidates for leaving after applying exclusion rules.")
            return

        if num_to_leave > len(candidates_for_leaving):
            print(f"Warning: Request to leave {num_to_leave}, but only {len(candidates_for_leaving)} candidates available. Removing all candidates.")
            leaving_member_ids_actual = list(candidates_for_leaving) # Take a copy
        else:
            # Select the last K members from the candidates_for_leaving list
            leaving_member_ids_actual = candidates_for_leaving[-num_to_leave:]

        print(f"Selected members to leave: {leaving_member_ids_actual}")

        if not leaving_member_ids_actual:
            print("No members selected to leave after applying K.")
            # Log time even if no action, to show trigger was processed
            end_time_no_action = time.perf_counter()
            duration_no_action_ms = (end_time_no_action - start_time) * 1000
            print(f"[CH] Batch leave trigger processed, no members left. Duration: {duration_no_action_ms:.3f} ms")
            return

        # Remove from SBP state (blind keys, intermediate keys, g_I_prev, sequence)
        # And close their TCP connections
        for member_id in leaving_member_ids_actual:
            if member_id in cluster_blind_keys: del cluster_blind_keys[member_id]
            if member_id in cluster_intermediate_keys: del cluster_intermediate_keys[member_id]
            if member_id in cluster_g_I_prev_values: del cluster_g_I_prev_values[member_id]
            if member_id in cluster_swarm_sequence: cluster_swarm_sequence.remove(member_id)
            if member_id in connected_members:
                try:
                    connected_members[member_id]['client'].close()
                except Exception:
                    pass
                del connected_members[member_id]

        print(f"Cluster sequence after removal: {cluster_swarm_sequence}")

        # Recompute the chain fully based on the remaining members
        # (Similar to initialize_cluster_sbp_with_initial_members but with current state)
        temp_intermediate_keys = {MY_ID: sk_i} # Start with CH
        temp_g_I_prev_values = {}       # No g^I_prev for CH itself

        I_prev = sk_i
        # Iterate through the *new* cluster_swarm_sequence (which excludes the leavers)
        for member_id in cluster_swarm_sequence[1:]: # Skip CH itself
            if member_id not in cluster_blind_keys:
                print(f"CRITICAL ERROR: Blind key for remaining member {member_id} missing during leave recompute!")
                # This should ideally not happen if state is consistent
                return # Abort if critical data missing
            T_member = cluster_blind_keys[member_id]
            I_new = pow(T_member, I_prev, p)
            g_I_prev = pow(g, I_prev, p)
            temp_intermediate_keys[member_id] = I_new
            temp_g_I_prev_values[member_id] = g_I_prev
            I_prev = I_new

        # Update the CH's global state variables for the cluster
        cluster_intermediate_keys = temp_intermediate_keys
        cluster_g_I_prev_values = temp_g_I_prev_values
        k_cluster = I_prev # New cluster key is the last I_prev in the new chain

    end_time = time.perf_counter()
    duration_ms = (end_time - start_time) * 1000
    print(f"Recomputed K_cluster after batch leave: {str(k_cluster)[:30]}... (took {duration_ms:.3f} ms)")
    # Automation Hook for CH calculation time
    print(f"[CH] Execution time for {len(leaving_member_ids_actual)} members batch leave event: {duration_ms:.3f} ms")

    # Broadcast the new full state to remaining members
    broadcast_cluster_update("batch_leave", leaving_member_ids=leaving_member_ids_actual)
# --- END MODIFIED Batch Leave ---

def broadcast_cluster_update(event_type, joining_member_id=None, T_joiner=None, g_I_prev_joiner=None, leaving_member_ids=None):
    """Broadcasts Intra-Cluster key update. Handles minimal join format."""
    global k_cluster, cluster_swarm_sequence, cluster_blind_keys, cluster_g_I_prev_values, my_private_key, cluster_udp_socket, my_cluster_bcast_address
    if not cluster_udp_socket:
        print("Error: Cluster UDP socket not initialized.")
        return 0
    
    message_body = ""
    start_time_calc = time.perf_counter()
    
    if event_type == "single_join" and joining_member_id and T_joiner is not None and g_I_prev_joiner is not None:
        message_body = f"{joining_member_id}|{T_joiner}|{g_I_prev_joiner}"
        print(f"Constructing minimal join message body: ID={joining_member_id}, T={str(T_joiner)[:15]}..., gI={str(g_I_prev_joiner)[:15]}...")
    else:  # Initial Setup or Leave Event - Send Full State
        with members_lock:  # Lock if accessing shared state that might change
            if not cluster_swarm_sequence:
                print("Cannot broadcast cluster update: Sequence empty.")
                return 0
            
            seq_str = ','.join(map(str, cluster_swarm_sequence))
            blind_keys_str = ','.join([f'{fid}:{cluster_blind_keys[fid]}' for fid in cluster_swarm_sequence if fid != MY_ID and fid in cluster_blind_keys])
            g_I_prev_str = ','.join([f'{fid}:{cluster_g_I_prev_values[fid]}' for fid in cluster_swarm_sequence if fid != MY_ID and fid in cluster_g_I_prev_values])
            message_body = f"{seq_str}|{blind_keys_str}|{g_I_prev_str}"
            print(f"Constructing full state message body for event: {event_type}")
    
    if not message_body:
        print("Error: Could not construct cluster update body.")
        return 0
    
    signature = sign_message_rsa(message_body.encode('utf-8'), my_private_key)
    if not signature:
        print("Error: Failed to sign cluster update.")
        return 0
    
    full_message = f"KEY_UPDATE|{message_body}|{signature}\n"
    end_time_calc = time.perf_counter()
    calc_duration_ms = (end_time_calc - start_time_calc) * 1000
    print(f"Cluster update message calculation time: {calc_duration_ms:.3f} ms")
    
    try:  # Fragmentation & Sending
        full_message_bytes = full_message.encode('utf-8')
        original_message_size = len(full_message_bytes)
        
        # Log message length clearly identifying the event type
        event_desc = event_type
        if event_type == "single_join": event_desc = f"single_join({joining_member_id})"
        elif event_type == "initial_setup": event_desc = "initial_setup"
        # Add leave event desc later if needed
        print(f"[CH] Key update message length for {event_desc}: {original_message_size} bytes")
        # -----------------------------
        
        if original_message_size > MAX_UDP_PAYLOAD_SIZE:
            print(f"Cluster message size ({original_message_size}) exceeds limit. Fragmenting...")
            fragments = fragment_message(full_message, MAX_UDP_PAYLOAD_SIZE)
            print(f"Sending {len(fragments)} fragments for Cluster update ({event_type})...")
            bytes_sent_this_msg = 0
            start_time_send = time.perf_counter()
            
            for i, frag in enumerate(fragments):
                try:
                    sent = cluster_udp_socket.sendto(frag, my_cluster_bcast_address)
                    bytes_sent_this_msg += sent
                    time.sleep(0.001)
                except Exception as send_err:
                    print(f"Error sending Cluster fragment {i+1}: {send_err}")
            
            end_time_send = time.perf_counter()
            send_duration_ms = (end_time_send - start_time_send) * 1000
            print(f"Finished sending Cluster fragments. Total bytes: {bytes_sent_this_msg}. Send duration: {send_duration_ms:.3f} ms")
        else:
            start_time_send = time.perf_counter()
            bytes_sent = cluster_udp_socket.sendto(full_message_bytes, my_cluster_bcast_address)
            end_time_send = time.perf_counter()
            send_duration_ms = (end_time_send - start_time_send) * 1000
            print(f"Broadcasting non-fragmented Cluster update ({event_type}). Size: {bytes_sent}. Send duration: {send_duration_ms:.3f} ms")
        
        return original_message_size
    except Exception as e:
        print(f"Error during Cluster update send: {e}")
        traceback.print_exc()
        return 0

def handle_member_departure(member_id):  # Needs full SBP leave logic later
    print(f"WARNING: Member departure handling for {member_id} needs full SBP logic.")
    updated = False
    with members_lock:
        if member_id in connected_members:
            if 'client' in connected_members[member_id]:
                try:
                    connected_members[member_id]['client'].close()
                except Exception:
                    pass
            del connected_members[member_id]
            updated = True
    return updated

def handle_member_connection(client, addr):  # Handles connections FROM Members
    global k_cluster
    member_id = None
    departure_handled = False
    
    try:
        reader = client.makefile('r', encoding='utf-8')
        writer = client.makefile('w', encoding='utf-8')
        id_line = reader.readline().strip()
        
        if not id_line.startswith("ID:"):
            print(f"Invalid initial msg from {addr}: {id_line}. Closing.")
            client.close()
            return
        
        member_id = id_line.split(":", 1)[1]
        ti_line = reader.readline().strip()
        
        if not ti_line.startswith("T_I:"):
            print(f"Invalid second msg from {member_id}@{addr}: {ti_line}. Closing.")
            client.close()
            return
        
        T_member = int(ti_line.split(":", 1)[1])

        # Check if it's the designated joining member
        if member_id == my_joining_member_id:
            print(f"Designated joining member {member_id} connected from {addr} with T_i: {T_member}")
            join_id, T_join, g_I_prev_join = None, None, None
            
            with members_lock:
                connected_members[member_id] = {
                    'client': client,
                    'blind_key': T_member,
                    'address': addr,
                    'reader': reader,
                    'writer': writer
                }
                join_id, T_join, g_I_prev_join = compute_single_join_update(member_id, T_member)
            
            if join_id:
                broadcast_cluster_update("single_join", joining_member_id=join_id, T_joiner=T_join, g_I_prev_joiner=g_I_prev_join)
            else:
                print(f"Error: Failed to compute single join update for {member_id}")

        elif member_id in my_initial_member_ids:
            print(f"Initial member {member_id} established TCP connection from {addr}.")
            with members_lock:
                connected_members[member_id] = {
                    'client': client,
                    'blind_key': T_member,
                    'address': addr,
                    'reader': reader,
                    'writer': writer
                }  # Store connection
        else:
            print(f"Error: Unexpected connection from member '{member_id}'. Closing.")
            client.close()
            return

        while not stop_event.is_set():  # Keep listening on connection
            try:
                client.settimeout(2.0)
                data = client.recv(1, socket.MSG_PEEK)
                client.settimeout(None)
            except socket.timeout:
                continue
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                print(f"Member {member_id} TCP error: {e}")
                break
            except Exception as e:
                print(f"Unexpected error reading from Member {member_id}: {e}")
                break
            
            if not data:
                print(f"Member {member_id} TCP connection closed.")
                break
            time.sleep(1.5)
    except Exception as e:
        print(f"Error handling Member {member_id or addr}: {e}")
        traceback.print_exc()
    finally:
        if client:
            client.close()
        if member_id:
            # Only handle connection cleanup here. SBP state update is via batch_leave.
            handle_member_departure(member_id) # This just cleans up the connection map

# --- Network Setup and Main Loop ---

# --- NEW: Control Command Listener Thread ---
def listen_for_control_commands():
    global my_control_listen_address
    control_socket = None
    try:
        control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        control_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        control_socket.bind(my_control_listen_address)
        control_socket.listen(1)
        print(f"Control command listener started on {my_control_listen_address}")

        while not stop_event.is_set():
            try:
                client, addr = control_socket.accept()
                print(f"Control connection from {addr}")
                data = client.recv(TCP_BUFFER_SIZE).decode('utf-8').strip()
                print(f"Received control command: {data}")
                if data.startswith("BATCH_LEAVE"):
                    try:
                        parts = data.split()
                        if len(parts) == 2:
                            k = int(parts[1])
                            perform_batch_leave(k) # Trigger batch leave
                        else:
                            print("Invalid BATCH_LEAVE command format.")
                    except ValueError:
                        print("Invalid K value in BATCH_LEAVE command.")
                else:
                    print(f"Unknown control command: {data}")
                client.close()
            except Exception as e:
                if stop_event.is_set(): break
                print(f"Error in control command listener: {e}")
                time.sleep(1) # Avoid busy loop on error
    except Exception as e:
        print(f"FATAL: Control command listener failed to start: {e}")
        stop_event.set() # Signal other threads to stop
    finally:
        if control_socket:
            control_socket.close()
        print("Control command listener stopped.")
# --- END NEW Control ---

def setup_cluster_udp_socket():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return sock
    except Exception as e:
        print(f"Error setting up cluster broadcast socket: {e}")
        return None

def setup_inter_ch_udp_listener(listen_address):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bind_ip = listen_address[0] if listen_address[0] != '0.0.0.0' else ''
        sock.bind((bind_ip, listen_address[1]))
        print(f"Successfully bound Inter-CH UDP listener to {listen_address}")
        return sock
    except Exception as e:
        print(f"Error setting up Inter-CH UDP listener on {listen_address}: {e}")
        return None

def connect_to_swarm_leader():
    global sl_socket
    retries = 0
    max_retries = 5
    
    while retries < max_retries and not stop_event.is_set():
        retries += 1
        try:
            print(f"Attempt {retries}: Connecting to SL at {sl_tcp_address}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', 0))
            sock.settimeout(5)
            sock.connect(sl_tcp_address)
            sock.settimeout(None)
            sl_socket = sock
            print(f"Connected to SL via TCP from {sock.getsockname()}")
            writer = sl_socket.makefile('w', encoding='utf-8')
            writer.write(f"ID:{MY_ID}\n")
            writer.write(f"T_CH:{T_i}\n")
            writer.flush()
            print("Sent ID and T_ch to SL.")
            return True
        except Exception as e:
            print(f"Connection attempt {retries} to SL failed: {e}")
            if sl_socket:
                sl_socket.close()
                sl_socket = None
            if retries < max_retries:
                time.sleep(5)
    
    print("FATAL: Could not connect to Swarm Leader.")
    stop_event.set()
    return False

def listen_for_members():
    global listener_socket
    try:
        listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener_socket.bind(my_tcp_listen_address)
        listener_socket.listen(len(my_member_ids) + 2)
        print(f"TCP Server listening on {my_tcp_listen_address} for Members")
        
        while not stop_event.is_set():
            try:
                listener_socket.settimeout(1.0)
                client, addr = listener_socket.accept()
                listener_socket.settimeout(None)
                print(f"Accepted potential Member connection from {addr}")
                threading.Thread(target=handle_member_connection, args=(client, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if not stop_event.is_set():
                    print(f"Error accepting member connection: {e}")
                    time.sleep(0.5)
    except Exception as e:
        print(f"FATAL: Member listener thread failed: {e}")
        traceback.print_exc()
    finally:
        if listener_socket:
            listener_socket.close()
            print("Member listener thread stopped.")
        stop_event.set()

def listen_for_sl_udp():
    global inter_ch_udp_socket
    last_cleanup_time = time.time()
    
    if not inter_ch_udp_socket:
        print("Error: Inter-CH UDP listener socket not initialized.")
        return
    
    print(f"Starting Inter-CH UDP listener on {inter_ch_bcast_address}")
    
    while not stop_event.is_set():
        try:
            readable, _, _ = select.select([inter_ch_udp_socket], [], [], 1.0)
            if readable:
                data_bytes, addr = inter_ch_udp_socket.recvfrom(BUFFER_SIZE)
                if data_bytes:
                    process_inter_ch_udp_packet(data_bytes)
            
            now = time.time()
            if now - last_cleanup_time > REASSEMBLY_TIMEOUT:
                cleanup_reassembly_buffer()
                last_cleanup_time = now
        except Exception as e:
            if not stop_event.is_set():
                print(f"Error in SL UDP listener loop: {e}")
                time.sleep(0.5)
    
    print("Inter-CH UDP listener thread stopped.")

def start_cluster_head():
    global cluster_udp_socket, inter_ch_udp_socket, sl_socket, listener_socket
    sl_socket = None
    listener_socket = None
    print("Initializing Cluster Head...")
    
    # *** Setup UDP Sockets FIRST ***
    cluster_udp_socket = setup_cluster_udp_socket()
    inter_ch_udp_socket = setup_inter_ch_udp_listener(inter_ch_bcast_address)
    if not cluster_udp_socket or not inter_ch_udp_socket:
        print("FATAL: Failed init UDP sockets.")
        stop_event.set(); return
    # ******************************
    # *** ADD: Start the Control Command Listener Thread ***
    control_listener_thread = threading.Thread(target=listen_for_control_commands, daemon=True)
    control_listener_thread.start()
    # ***************************************************
    
    if not initialize_cluster_sbp_with_initial_members():
        print("FATAL: Failed init cluster SBP.")
        return
    
    member_listener_thread = None
    sl_listener_thread = None
    
    try:
        # Connect to SL
        if not connect_to_swarm_leader():
            stop_event.set()
            return
        
        member_listener_thread = threading.Thread(target=listen_for_members, daemon=True)
        member_listener_thread.start()
        
        sl_listener_thread = threading.Thread(target=listen_for_sl_udp, daemon=True)
        sl_listener_thread.start()
        
        print("CH Initialization complete. Waiting for designated joining member...")
        
        while not stop_event.is_set():  # Main loop
            if sl_socket:  # Check SL connection health
                try:
                    sl_socket.settimeout(1.0)
                    sl_socket.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
                    sl_socket.settimeout(None)
                except socket.timeout:
                    pass
                except BlockingIOError:
                    pass
                except (ConnectionResetError, BrokenPipeError, OSError) as e:
                    print(f"SL TCP connection lost: {e}. Attempting reconnect...")
                    sl_socket.close()
                    sl_socket = None
                    if not connect_to_swarm_leader():
                        print("Reconnection to SL failed. Shutting down.")
                        stop_event.set()
                except Exception as e:
                    print(f"Error checking SL socket: {e}")
                    time.sleep(5)
            else:
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
    finally:  # Cleanup
        stop_event.set()
        print("Waiting for threads to stop...")
        
        if listener_socket:
            try:
                listener_socket.close()
            except Exception:
                pass
        
        if sl_socket:
            try:
                sl_socket.close()
            except Exception:
                pass
        
        if inter_ch_udp_socket:
            try:
                inter_ch_udp_socket.close()
            except Exception:
                pass
        
        if cluster_udp_socket:
            try:
                cluster_udp_socket.close()
            except Exception:
                pass
        
        if member_listener_thread and member_listener_thread.is_alive():
            member_listener_thread.join(timeout=2)
        
        if sl_listener_thread and sl_listener_thread.is_alive():
            sl_listener_thread.join(timeout=2)
        
        print("CH Shutdown complete.")

# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="H-SBP Cluster Head")
    parser.add_argument("--id", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--sl-ip", required=True)
    args = parser.parse_args()
    MY_ID = args.id
    sl_ip_arg = args.sl_ip
    print(f"Starting Cluster Head Node: {MY_ID}")
    
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
        print(f"FATAL: Failed load DH/secret key: {e}")
        sys.exit(1)
    
    try:  # Load role, cluster id, member lists
        node_def = CONFIG['structure']['node_definitions'][MY_ID]
        MY_ROLE = node_def['role']
        
        if MY_ROLE != "CH":
            print(f"FATAL: Role mismatch! Expected CH, got {MY_ROLE}")
            sys.exit(1)
        
        MY_CLUSTER_ID = node_def['cluster_id']
        # *** Load initial and joining member IDs from config ***
        my_initial_member_ids = CONFIG['structure']['clusters'][MY_CLUSTER_ID]['initial_members']
        my_joining_member_id = CONFIG['structure']['clusters'][MY_CLUSTER_ID].get('joining_member')  # Use .get
        my_member_ids = CONFIG['structure']['clusters'][MY_CLUSTER_ID]['all_members_for_config']
        # *******************************************************
    except Exception as e:
        print(f"FATAL: Config error finding role/cluster/members: {e}")
        sys.exit(1)
    
    try:  # Network config
        net_conf = CONFIG['network']
        sl_tcp_address = (sl_ip_arg, net_conf['sl_tcp_port'])
        inter_ch_bcast_address = (net_conf['inter_ch_bcast_addr'], net_conf['inter_ch_bcast_port'])
        my_tcp_listen_port = net_conf['ch_tcp_base_port'] + int(MY_CLUSTER_ID) - 1
        my_tcp_listen_address = (net_conf['sl_tcp_address'], my_tcp_listen_port)  # Use configured listen IP
        my_cluster_bcast_port = net_conf['cluster_bcast_base_port'] + int(MY_CLUSTER_ID) - 1
        my_cluster_bcast_address = (net_conf['inter_ch_bcast_addr'], my_cluster_bcast_port)
        # Define control address
        ch_control_port = CH_CONTROL_BASE_PORT + int(MY_CLUSTER_ID) -1
        my_control_listen_address = (net_conf['sl_tcp_address'], ch_control_port) # Listen on same IP as member listener
    except Exception as e:
        print(f"FATAL: Config error finding network details: {e}")
        sys.exit(1)
    
    try:  # Keys
        sl_public_key_path = os.path.join(script_dir, CONFIG['paths']['sl_pub_key'])
        print(f"Loading SL public key: {sl_public_key_path}")
        sl_public_key = load_public_key(sl_public_key_path)
        my_priv_key_path = os.path.join(script_dir, CONFIG['paths']['ch_priv_key_template'].format(MY_CLUSTER_ID))
        #my_priv_key_path = CONFIG['paths']['ch_priv_key_template'].format(MY_CLUSTER_ID)
        print(f"Loading own private key: {my_priv_key_path}")
        my_private_key = load_private_key(my_priv_key_path)
        
        if not sl_public_key or not my_private_key:
            print("FATAL: Failed load required keys.")
            sys.exit(1)
    except Exception as e:
        print(f"FATAL: Error loading keys: {e}")
        sys.exit(1)

    print(f"Starting node {MY_ID} as {MY_ROLE} for Cluster {MY_CLUSTER_ID}")
    print(f"Initial Members (M0): {my_initial_member_ids}. Joining Member: {my_joining_member_id or 'None'}")
    print(f"SL Target: {sl_tcp_address}. Inter-CH UDP Listen: {inter_ch_bcast_address}")
    print(f"Member TCP Listen: {my_tcp_listen_address}. Cluster UDP Broadcast: {my_cluster_bcast_address}")
    print(f"CH Control Port will be: {my_control_listen_address}") # Log for verification
    print(f"Managing Members (Full List): {my_member_ids}")

    start_cluster_head()
# --- END OF FILE cluster_head.py ---
