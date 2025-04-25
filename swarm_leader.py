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
sk_i = None # SL's own secret key
T_i = None  # SL's own blind key (T_sl)
private_key = None # SL's signing key
# --------------------------

# Override print function to include a timestamp
def print_with_timestamp(*args, **kwargs):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    builtins.print(f"{timestamp} - [{MY_ID or 'SL'}]", *args, **kwargs)

# Replace the built-in print function
print = print_with_timestamp

# Constants (some will be loaded from config)
BUFFER_SIZE = 8192
MAX_UDP_PAYLOAD_SIZE = 1400 # Safer limit
FRAGMENT_PREFIX = "FRAG"
# Addresses/Ports will be loaded from config
TCP_LISTEN_ADDRESS = None
INTER_CH_BCAST_ADDRESS = None
# --------------------------

# Data Structures (for CHs)
connected_chs = {} # {ch_id: {'client': socket, 'blind_key': T_ch}}
chs_lock = threading.Lock()

# DH Chain State (Inter-CH level)
inter_ch_intermediate_keys = {} # {node_id: I_intermediate}
inter_ch_blind_keys = {} # {node_id: T_blind} (T_sl, T_ch1, T_ch2...)
inter_ch_g_I_prev_values = {} # {ch_id: g^I_prev_for_ch}
inter_ch_swarm_sequence = [] # Stores sequence like [sl_id, ch1_id, ch2_id]
k_main = None # The broadcast key shared among SL and CHs
# --------------------------

# --- Fragmentation Function (Two-Pass) ---
def fragment_message(full_message_str, max_payload_size=MAX_UDP_PAYLOAD_SIZE):
    """Splits a large message into fragments using a two-pass approach."""
    message_bytes = full_message_str.encode('utf-8')
    message_len = len(message_bytes)
    message_id = f"{time.time():.6f}" # Unique ID for this message

    if message_len == 0:
        return [] # No fragments for empty message

    # --- Pass 1: Determine the exact number of fragments ---
    actual_total_fragments = 0
    current_pos_pass1 = 0
    temp_frag_num = 1
    while current_pos_pass1 < message_len:
        # Construct a *sample* header just to get its length
        max_digits_total = 6 # Assume max 999999 fragments
        temp_header = f"{FRAGMENT_PREFIX}/{message_id}/{temp_frag_num}/{'9'*max_digits_total}|"
        temp_header_bytes = temp_header.encode('utf-8')
        temp_header_len = len(temp_header_bytes)

        payload_size = max_payload_size - temp_header_len
        if payload_size <= 0:
            raise ValueError(f"max_payload_size ({max_payload_size}) too small even for estimated header during pass 1")

        end_pos_pass1 = min(current_pos_pass1 + payload_size, message_len)
        actual_total_fragments += 1
        current_pos_pass1 = end_pos_pass1
        temp_frag_num += 1
        if actual_total_fragments > message_len + 10: # Safety break
             raise RuntimeError("Fragmentation pass 1 seems stuck in a loop.")

    if actual_total_fragments == 0:
         raise RuntimeError("Calculated 0 fragments for non-empty message in pass 1")

    # --- Pass 2: Generate fragments with the correct total count ---
    fragments = []
    current_pos_pass2 = 0
    for fragment_num in range(1, actual_total_fragments + 1):
        header = f"{FRAGMENT_PREFIX}/{message_id}/{fragment_num}/{actual_total_fragments}|"
        header_bytes = header.encode('utf-8')
        header_len = len(header_bytes)
        payload_size = max_payload_size - header_len
        if payload_size < 0:
             raise ValueError(f"max_payload_size ({max_payload_size}) too small for actual header in pass 2 (frag {fragment_num})")

        end_pos_pass2 = min(current_pos_pass2 + payload_size, message_len)
        payload_chunk = message_bytes[current_pos_pass2:end_pos_pass2]
        fragment_packet = header_bytes + payload_chunk
        fragments.append(fragment_packet)
        current_pos_pass2 = end_pos_pass2

    if current_pos_pass2 != message_len:
         raise RuntimeError(f"Fragmentation pass 2 did not consume the entire message. Ended at {current_pos_pass2}, expected {message_len}")
    if len(fragments) != actual_total_fragments:
         raise RuntimeError(f"Fragmentation pass 2 produced {len(fragments)} fragments, expected {actual_total_fragments}")

    return fragments
# --------------------------------------------------------

# --- Cryptography Functions ---
def load_private_key(path):
    """Loads a PEM-encoded private key."""
    try:
        with open(path, "rb") as key_file:
            return serialization.load_pem_private_key(
                key_file.read(), password=None
            )
    except Exception as e:
        print(f"Error loading private key from {path}: {e}")
        return None # Return None on failure


def sign_message_rsa(message_bytes, priv_key):
    """Signs byte data using the provided private key."""
    if not priv_key:
        print("Error signing: Private key not loaded.")
        return None
    try:
        signature = priv_key.sign(
            message_bytes,
            padding.PKCS1v15(),
            SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')
    except Exception as e:
        print(f"Error signing message: {e}")
        return None

def encrypt_message_aes(message_bytes, key):
    """Encrypts byte data using AES-256-CBC."""
    if key is None:
        print("Error encrypting: Key is None.")
        return None
    try:
        iv = secrets.token_bytes(16)
        key_int = int(key)
        key_bytes = key_int.to_bytes(32, 'big')
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        encryptor = cipher.encryptor()
        # Pad message to AES block size (16 bytes) using null bytes
        padding_len = 16 - (len(message_bytes) % 16)
        padded_message = message_bytes + (b"\0" * padding_len)
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode('utf-8')
    except ValueError as e:
        print(f"Error encrypting: Invalid key format? {e}")
        return None
    except Exception as e:
        print(f"Error encrypting message: {e}")
        return None
# -----------------------------------------------------------------------

def setup_broadcast_socket():
    """Sets up a UDP socket for broadcasting."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # Consider setting SO_REUSEADDR for quicker restarts during testing
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return sock
    except Exception as e:
        print(f"Error setting up broadcast socket: {e}")
        return None

# --- SBP Logic (Inter-CH Level) ---

def compute_main_broadcast_key(new_ch_id):
    """Compute updated K_main when a new CH joins the top level."""
    global k_main, inter_ch_g_I_prev_values, inter_ch_intermediate_keys, inter_ch_swarm_sequence, p, g

    if not inter_ch_swarm_sequence:
        print("Error: inter_ch_swarm_sequence is empty during key computation.")
        return None, None

    if new_ch_id not in inter_ch_blind_keys:
        print(f"Error: Blind key for new CH {new_ch_id} not found.")
        return None, None

    # Get the previous node's intermediate key (I_prev)
    if len(inter_ch_swarm_sequence) == 1: # Only SL exists before new CH
         I_prev = inter_ch_intermediate_keys[MY_ID] # SL's own sk_i is I_0
    else:
         # Get the ID of the node just before the newly added CH in the sequence
         prev_id_index = inter_ch_swarm_sequence.index(new_ch_id) - 1
         if prev_id_index < 0:
              print(f"Error: Cannot find previous node for {new_ch_id} in {inter_ch_swarm_sequence}")
              return None, None
         prev_id = inter_ch_swarm_sequence[prev_id_index]
         if prev_id not in inter_ch_intermediate_keys:
              print(f"Error: Intermediate key for previous node {prev_id} not found.")
              return None, None
         I_prev = inter_ch_intermediate_keys[prev_id]

    # Calculate new intermediate key: I_new = (T_new_ch) ^ I_prev mod p
    T_new_ch = inter_ch_blind_keys[new_ch_id]
    I_new = pow(T_new_ch, I_prev, p)

    # Calculate g^(I_prev) required by the new CH for its *own* calculations
    g_I_prev = pow(g, I_prev, p)

    # Store results
    inter_ch_intermediate_keys[new_ch_id] = I_new
    inter_ch_g_I_prev_values[new_ch_id] = g_I_prev # Store g^I_{k-1} keyed by ch_k's ID
    k_main = I_new # New main key is the latest intermediate key in the chain

    print(f"Computed K_main: {str(k_main)[:30]}...") # Print snippet
    print(f"Stored g^I_prev for {new_ch_id}: {str(g_I_prev)[:30]}...")
    return k_main, g_I_prev

def broadcast_inter_ch_update(broadcast_socket, event_type, joining_ch_id=None, leaving_ch_ids=None):
    """Broadcasts the Inter-CH key update, fragmenting if necessary."""
    global k_main, inter_ch_swarm_sequence, inter_ch_blind_keys, inter_ch_g_I_prev_values, private_key

    # TODO: Implement specific message formats from SBP paper (Fig 5 & 6)
    # For now, send full state on join/leave for simplicity

    message_body = ""
    start_time_calc = time.perf_counter() # Start measuring calculation time

    with chs_lock:
        if not inter_ch_swarm_sequence:
            print("Cannot broadcast update: Inter-CH sequence is empty.")
            return 0

        # Construct message body (Full state format)
        seq_str = ','.join(map(str, inter_ch_swarm_sequence))
        # Include only keys for nodes *currently* in the sequence
        blind_keys_str = ','.join([f'{fid}:{inter_ch_blind_keys[fid]}'
                                   for fid in inter_ch_swarm_sequence if fid != MY_ID and fid in inter_ch_blind_keys])
        g_I_prev_str = ','.join([f'{fid}:{inter_ch_g_I_prev_values[fid]}'
                                 for fid in inter_ch_swarm_sequence if fid != MY_ID and fid in inter_ch_g_I_prev_values])

        message_body = f"{seq_str}|{blind_keys_str}|{g_I_prev_str}"

        if not message_body:
             print("Error: Could not construct inter-CH update message body.")
             return 0

        # Sign the message body
        signature = sign_message_rsa(message_body.encode('utf-8'), private_key)
        if not signature:
            print("Error: Failed to sign inter-CH update message.")
            return 0

        full_message = f"KEY_UPDATE|{message_body}|{signature}\n"

    end_time_calc = time.perf_counter()
    calc_duration_ms = (end_time_calc - start_time_calc) * 1000
    print(f"Inter-CH update message calculation time: {calc_duration_ms:.3f} ms")


    # --- Fragmentation & Sending ---
    try:
        full_message_bytes = full_message.encode('utf-8')
        original_message_size = len(full_message_bytes)

        if original_message_size > MAX_UDP_PAYLOAD_SIZE:
            print(f"Inter-CH message size ({original_message_size} bytes) exceeds limit. Fragmenting...")
            fragments = fragment_message(full_message, MAX_UDP_PAYLOAD_SIZE)
            print(f"Sending {len(fragments)} fragments for Inter-CH update ({event_type})...")
            bytes_sent_this_msg = 0
            start_time_send = time.perf_counter()
            for i, frag in enumerate(fragments):
                try:
                    sent = broadcast_socket.sendto(frag, INTER_CH_BCAST_ADDRESS)
                    bytes_sent_this_msg += sent
                    time.sleep(0.001) # Small delay between fragments
                except Exception as send_err:
                    print(f"Error sending Inter-CH fragment {i+1}: {send_err}")
            end_time_send = time.perf_counter()
            send_duration_ms = (end_time_send - start_time_send) * 1000
            print(f"Finished sending Inter-CH fragments. Total bytes: {bytes_sent_this_msg}. Send duration: {send_duration_ms:.3f} ms")
            return original_message_size # Return original size
        else:
            start_time_send = time.perf_counter()
            bytes_sent = broadcast_socket.sendto(full_message_bytes, INTER_CH_BCAST_ADDRESS)
            end_time_send = time.perf_counter()
            send_duration_ms = (end_time_send - start_time_send) * 1000
            print(f"Broadcasting non-fragmented Inter-CH update ({event_type}). Size: {bytes_sent}. Send duration: {send_duration_ms:.3f} ms")
            return bytes_sent

    except Exception as e:
        print(f"Error during Inter-CH update fragmentation/sending: {type(e).__name__}: {e}")
        traceback.print_exc()
        return 0

def handle_ch_departure(ch_id):
    """Handles the departure of a CH."""
    global k_main, inter_ch_swarm_sequence, inter_ch_blind_keys, inter_ch_intermediate_keys, inter_ch_g_I_prev_values, p, g

    print(f"Handling departure for CH {ch_id}")
    with chs_lock:
        if ch_id not in connected_chs:
            print(f"Warning: CH {ch_id} already departed or unknown.")
            return False

        # Close socket and remove from connected list
        if 'client' in connected_chs[ch_id]:
            try:
                connected_chs[ch_id]['client'].close()
            except Exception: pass # Ignore errors on closing socket
        del connected_chs[ch_id]

        # Remove from SBP state
        if ch_id in inter_ch_blind_keys: del inter_ch_blind_keys[ch_id]
        if ch_id in inter_ch_intermediate_keys: del inter_ch_intermediate_keys[ch_id]
        if ch_id in inter_ch_g_I_prev_values: del inter_ch_g_I_prev_values[ch_id]

        if ch_id not in inter_ch_swarm_sequence:
            print(f"Warning: Departing CH {ch_id} not found in sequence {inter_ch_swarm_sequence}")
            return False # Indicates state inconsistency

        # Find departure point
        try:
            departure_index = inter_ch_swarm_sequence.index(ch_id)
        except ValueError:
            print(f"Warning: Could not find index for departing CH {ch_id} in sequence.")
            return False

        # Remove the departing CH and all subsequent nodes from the sequence temporarily
        old_sequence = inter_ch_swarm_sequence[:]
        nodes_after_departure = inter_ch_swarm_sequence[departure_index:]
        inter_ch_swarm_sequence = inter_ch_swarm_sequence[:departure_index]

        # Remove intermediate keys and g^I values for nodes after departure (including the departed one)
        for node_id in nodes_after_departure:
            if node_id in inter_ch_intermediate_keys: del inter_ch_intermediate_keys[node_id]
            if node_id in inter_ch_g_I_prev_values: del inter_ch_g_I_prev_values[node_id]

        print(f"Sequence after removing {ch_id} and subsequent: {inter_ch_swarm_sequence}")

        # Recompute the chain from the node *before* the departure point
        if departure_index == 0: # SL departed? Not handled here. Assume SL persists.
             print("Error: SL departure not handled.")
             return False
        elif departure_index == 1: # First CH departed
             I_prev = inter_ch_intermediate_keys[MY_ID] # Start from SL's sk_i
        else:
             node_before_departure = inter_ch_swarm_sequence[departure_index - 1]
             I_prev = inter_ch_intermediate_keys[node_before_departure]


        # Add back the remaining nodes and recompute keys
        nodes_to_re_add = [node for node in old_sequence if node != ch_id and node not in inter_ch_swarm_sequence]
        print(f"Nodes to re-add: {nodes_to_re_add}")

        for node_id in nodes_to_re_add:
             if node_id not in inter_ch_blind_keys:
                 print(f"Error: Cannot recompute chain, blind key for {node_id} missing.")
                 # Inconsistent state, maybe stop?
                 return False # Abort recomputation

             T_node = inter_ch_blind_keys[node_id]
             I_new = pow(T_node, I_prev, p)
             g_I_prev_recomputed = pow(g, I_prev, p)

             inter_ch_intermediate_keys[node_id] = I_new
             inter_ch_g_I_prev_values[node_id] = g_I_prev_recomputed
             inter_ch_swarm_sequence.append(node_id) # Add back to sequence
             I_prev = I_new # Update for next iteration

        # Update the main broadcast key
        if not inter_ch_swarm_sequence: # Should not happen if SL exists
             k_main = sk_i # Reset to initial?
        elif len(inter_ch_swarm_sequence) == 1: # Only SL left
             k_main = sk_i
        else:
             last_node_id = inter_ch_swarm_sequence[-1]
             k_main = inter_ch_intermediate_keys[last_node_id]

        print(f"Recomputed sequence: {inter_ch_swarm_sequence}")
        print(f"Recomputed K_main: {str(k_main)[:30]}...")
        return True # Indicate successful state update


def handle_ch_connection(broadcast_socket, client, addr):
    """Handle connection from a single Cluster Head."""
    global k_main, inter_ch_swarm_sequence, inter_ch_blind_keys, inter_ch_intermediate_keys, inter_ch_g_I_prev_values
    ch_id = None # Placeholder for the ID of the connected CH

    try:
        # Protocol: Expect CH to send "ID:<ch_id>\n" then "T_CH:<T_ch>\n"
        # This makes identification robust. Use readline for simplicity.
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

        # Verify CH ID is known (from config)
        if ch_id not in CONFIG['structure']['node_definitions'] or CONFIG['structure']['node_definitions'][ch_id]['role'] != 'CH':
             print(f"Error: Received connection from unknown or non-CH ID '{ch_id}'. Closing.")
             client.close()
             return

        print(f"CH {ch_id} connected from {addr} with T_ch: {T_ch}")

        with chs_lock:
            # Store CH info
            connected_chs[ch_id] = {'client': client, 'blind_key': T_ch, 'address': addr, 'reader': reader, 'writer': writer}
            inter_ch_blind_keys[ch_id] = T_ch
            if ch_id not in inter_ch_swarm_sequence: # Avoid duplicates if reconnecting
                 inter_ch_swarm_sequence.append(ch_id)
            else:
                 print(f"Warning: CH {ch_id} reconnected.")

            # Compute new main broadcast key and g_I_prev for this CH
            compute_main_broadcast_key(ch_id)

        # Broadcast update to ALL connected CHs
        broadcast_inter_ch_update(broadcast_socket, "join", joining_ch_id=ch_id)

        # Keep listening for heartbeat or departure notification
        while True:
            # Simple check for closed connection by trying to read
            try:
                # Set a timeout for the read attempt
                client.settimeout(5.0) # Check every 5 seconds
                data = client.recv(1, socket.MSG_PEEK) # Peek without consuming
                if not data:
                    print(f"CH {ch_id} TCP connection closed (detected by recv).")
                    break
                client.settimeout(None) # Reset timeout
                time.sleep(4) # Reduce busy-wait
            except socket.timeout:
                # No data received, connection likely still alive
                continue
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                 print(f"CH {ch_id} TCP connection error: {e}")
                 break
            except Exception as e:
                 print(f"Unexpected error reading from CH {ch_id}: {e}")
                 break


    except (ConnectionResetError, BrokenPipeError, OSError, ValueError) as e:
        print(f"CH {ch_id or addr} disconnected or sent invalid data: {e}")
    except Exception as e:
        print(f"Error handling CH {ch_id or addr}: {type(e).__name__}: {e}")
        traceback.print_exc()
    finally:
        if client: client.close() # Ensure socket is closed
        if ch_id:
            # Handle departure logic and broadcast update
            if handle_ch_departure(ch_id):
                 # Only broadcast if state was successfully updated
                 broadcast_inter_ch_update(broadcast_socket, "leave", leaving_ch_ids=[ch_id])


def start_swarm_leader():
    """Start the SL server."""
    global TCP_LISTEN_ADDRESS, INTER_CH_BCAST_ADDRESS, k_main
    global inter_ch_swarm_sequence, inter_ch_intermediate_keys, T_i

    print("Initializing Swarm Leader...")
    # Load network config
    net_conf = CONFIG['network']
    TCP_LISTEN_ADDRESS = (net_conf['sl_tcp_address'], net_conf['sl_tcp_port'])
    INTER_CH_BCAST_ADDRESS = (net_conf['inter_ch_bcast_addr'], net_conf['inter_ch_bcast_port'])

    # Initialize the Inter-CH SBP chain with the SL itself
    with chs_lock: # Protect initialization
        inter_ch_swarm_sequence = [MY_ID]
        inter_ch_intermediate_keys = {MY_ID: sk_i} # I_0 = sk_i
        inter_ch_blind_keys = {MY_ID: T_i}
        k_main = sk_i # Initial key is I_0 = sk_i (used if no CHs exist?)

    print(f"Initial SL state: Sequence={inter_ch_swarm_sequence}, K_main={str(k_main)[:30]}...")

    server = None
    broadcast_socket = None
    try:
        broadcast_socket = setup_broadcast_socket()
        if not broadcast_socket: raise ConnectionError("Failed to create broadcast socket")

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(TCP_LISTEN_ADDRESS)
        server.listen(len(CONFIG['structure']['clusters']) + 2) # Listen for all potential CHs + buffer
        print(f"TCP Server listening on {TCP_LISTEN_ADDRESS} for CHs")
        print(f"Broadcasting Inter-CH updates on {INTER_CH_BCAST_ADDRESS}")

        # TODO: Add thread for periodic global message sending if needed

        while True:
            client, addr = server.accept()
            print(f"Accepted potential CH connection from {addr}")
            # Handle the CH in a separate thread
            threading.Thread(target=handle_ch_connection, args=(broadcast_socket, client, addr), daemon=True).start()

    except KeyboardInterrupt:
        print("Process interrupted by user.")
    except Exception as e:
        print(f"Error in start_swarm_leader: {type(e).__name__}: {e}")
        traceback.print_exc()
    finally:
        print("Shutting down.")
        if broadcast_socket: broadcast_socket.close()
        if server: server.close()
        # Wait briefly for threads to potentially notice shutdown?
        time.sleep(0.5)

# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="H-SBP Swarm Leader")
    parser.add_argument("--id", required=True, help="ID of this Swarm Leader node")
    parser.add_argument("--config", required=True, help="Path to the H-SBP configuration JSON file")
    args = parser.parse_args()

    MY_ID = args.id
    print(f"Starting SL Node: {MY_ID}") # Print ID early

    # Load configuration
    try:
        print(f"Loading config file: {args.config}")
        with open(args.config, 'r') as f:
            CONFIG = json.load(f)

        
        script_dir = os.path.dirname(os.path.abspath(__file__))
        secrets_path = os.path.join(script_dir, CONFIG['paths']['secret_keys_file'])
        print(f"Loading secrets file: {secrets_path}")
        
        with open(secrets_path, 'r') as f:
            SECRETS = json.load(f)
            
        #print(f"Loading secrets file: {CONFIG['paths']['secret_keys_file']}")
        #with open(CONFIG['paths']['secret_keys_file'], 'r') as f:
        #    SECRETS = json.load(f)
    except Exception as e:
        print(f"FATAL: Failed to load configuration or secrets: {e}")
        sys.exit(1)

    # Load parameters
    try:
        g = CONFIG['general']['g']
        p = CONFIG['general']['p']
        sk_i_str = SECRETS[MY_ID]
        sk_i = int(sk_i_str)
        T_i = pow(g, sk_i, p)
        print(f"Loaded DH params. g={g}, p={str(p)[:20]}..., sk_i={str(sk_i)[:20]}..., T_i={str(T_i)[:20]}...")
    except KeyError:
         print(f"FATAL: Could not find secret key for own ID '{MY_ID}' in secrets file.")
         sys.exit(1)
    except Exception as e:
        print(f"FATAL: Failed to process DH parameters or own secret key: {e}")
        sys.exit(1)

    # Verify Role
    try:
        MY_ROLE = CONFIG['structure']['node_definitions'][MY_ID]['role']
        if MY_ROLE != "SL":
            print(f"FATAL: Role mismatch! Expected SL, got {MY_ROLE} for ID {MY_ID}")
            sys.exit(1)
    except KeyError:
         print(f"FATAL: Node definition for ID '{MY_ID}' not found in config.")
         sys.exit(1)

    # Load SL signing key
    try:
        #sl_priv_key_path = CONFIG['paths']['sl_priv_key']
        
        script_dir = os.path.dirname(os.path.abspath(__file__))
        sl_priv_key_path = os.path.join(script_dir, CONFIG['paths']['sl_priv_key'])
        
        print(f"Loading SL private key: {sl_priv_key_path}")
        private_key = load_private_key(sl_priv_key_path)
        if not private_key:
             print(f"FATAL: Failed to load SL private key.")
             sys.exit(1)
    except Exception as e:
        print(f"FATAL: Error loading SL private key path from config: {e}")
        sys.exit(1)

    print(f"Starting node {MY_ID} as {MY_ROLE}")
    start_swarm_leader()
# --- END OF FILE swarm_leader.py ---
