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
import os
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
sk_i = None # Member's secret key
T_i = None  # Member's blind key
my_ch_id = None
my_ch_ip_arg = None # Added: Store CH IP passed from command line
my_ch_tcp_address = None # (host, port) to connect TO CH
cluster_bcast_address = None # (host, port) to listen ON for cluster msgs
ch_public_key = None # Key to verify CH's messages
# --------------------------

# Override print function to include a timestamp
def print_with_timestamp(*args, **kwargs):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    builtins.print(f"{timestamp} - [{MY_ID or 'MEMBER'}]", *args, **kwargs)

# Replace the built-in print function
print = print_with_timestamp

# Constants (some loaded from config)
BUFFER_SIZE = 8192 # For UDP recv
TCP_BUFFER_SIZE = 4096 # For initial TCP comms
REASSEMBLY_TIMEOUT = 15 # Seconds to keep incomplete fragments
FRAGMENT_PREFIX = "FRAG"
MAX_UDP_PAYLOAD_SIZE = 1400 # Used by CH fragmentation, needed for context? Not strictly needed here.
# --------------------------

# SBP State (Intra-Cluster Level)
k_cluster = None # The broadcast key for this member's cluster
cluster_swarm_sequence = [] # Last known sequence from CH
# --------------------------

# Reassembly Buffer
reassembly_buffer = {} # { message_id: {'fragments': {frag_num: payload_bytes}, 'total_hint': total, 'received_count': count, 'timestamp': timestamp} }
# --------------------------

# --- Cryptography Functions ---
def load_public_key(path):
    """Loads a PEM-encoded public key."""
    try:
        with open(path, "rb") as key_file:
            return serialization.load_pem_public_key(key_file.read())
    except Exception as e:
        print(f"Error loading public key from {path}: {e}")
        return None # Return None on failure

def decrypt_message_aes(encrypted_message, key):
    """Decrypts base64 encoded AES-256-CBC message."""
    if key is None:
        print("Error decrypting: Cluster key (k_cluster) is None!")
        return None
    try:
        key_int = int(key) # Ensure it's an int
        # AES-256 requires a 32-byte key
        if key_int.bit_length() > 256:
             print(f"Warning: Key bit length {key_int.bit_length()} > 256. Using lower 256 bits.")
             key_bytes = (key_int & ((1 << 256) - 1)).to_bytes(32, 'big')
        else:
             key_bytes = key_int.to_bytes(32, 'big', signed=False)

        encrypted_data = base64.b64decode(encrypted_message)
        if len(encrypted_data) < 16:
             print("Error decrypting: Encrypted data too short (missing IV?)")
             return None
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        if len(ciphertext) % 16 != 0:
             print("Warning: Ciphertext length is not a multiple of block size (16).")
             # Proceed anyway, finalize() might handle it or raise error

        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_padded_message = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding (assuming null bytes were used) and decode
        try:
            # Strip null bytes from the right
            unpadded_message = decrypted_padded_message.rstrip(b"\0")
            # Attempt decoding as UTF-8
            return unpadded_message.decode("utf-8")
        except UnicodeDecodeError:
            print("Warning: Could not decode decrypted message as UTF-8. Returning raw bytes.")
            return decrypted_padded_message.rstrip(b"\0") # Return bytes if not text
        except Exception as pad_err:
            print(f"Error removing padding/decoding: {pad_err}")
            return None

    except ValueError as e:
         print(f"Error decrypting: Invalid base64 data or key format? {e}")
         return None
    except Exception as e:
        print(f"Error during AES decryption: {e}")
        return None

def verify_message_rsa(message_bytes, signature, pub_key):
    """Verifies an RSA signature."""
    if pub_key is None:
        print("Error verifying: Public key (ch_public_key) is None!")
        return False
    if not signature:
         print("Error verifying: Signature is empty.")
         return False
    try:
        pub_key.verify(
            base64.b64decode(signature),
            message_bytes,
            padding.PKCS1v15(),
            SHA256()
        )
        return True
    except Exception:
        # print(f"Signature verification failed: {e}") # Verbose errors
        return False
# -----------------------------

# --- Reassembly/UDP Handling ---
def cleanup_reassembly_buffer():
    """Removes old, incomplete fragments."""
    now = time.time()
    messages_to_delete = []
    buffer_copy = list(reassembly_buffer.items()) # Avoid RuntimeError if dict changes
    for msg_id, data in buffer_copy:
        if msg_id not in reassembly_buffer: continue # Already deleted?
        if now - data['timestamp'] > REASSEMBLY_TIMEOUT:
            messages_to_delete.append(msg_id)
            print(f"Timing out incomplete message {msg_id}")
    for msg_id in messages_to_delete:
        if msg_id in reassembly_buffer:
            del reassembly_buffer[msg_id]

def process_udp_packet(data_bytes):
    """Handles incoming UDP data, checking for fragments."""
    global reassembly_buffer

    try:
        # Decode only enough to check the prefix, handle potential errors
        prefix_check_len = len(FRAGMENT_PREFIX)+1
        if len(data_bytes) < prefix_check_len: # Too short to be a fragment header
             is_fragment = False
        else:
             try:
                 start_str = data_bytes[:prefix_check_len].decode('utf-8', errors='ignore')
                 is_fragment = start_str.startswith(FRAGMENT_PREFIX + "/")
             except UnicodeDecodeError:
                 is_fragment = False # Cannot be our text-based fragment header

        if is_fragment:
            # --- Handle Fragment ---
            try:
                delimiter_pos = data_bytes.find(b'|')
                if delimiter_pos == -1:
                    print("Invalid fragment: Missing delimiter")
                    return

                header_bytes = data_bytes[:delimiter_pos]
                payload_bytes = data_bytes[delimiter_pos+1:]
                header_str = header_bytes.decode('utf-8') # Assume header is UTF-8

                _, message_id, frag_num_str, total_str = header_str.split('/')
                frag_num = int(frag_num_str)
                total_fragments_hint = int(total_str)

                # print(f"Received fragment {frag_num}/{total_fragments_hint} for msg {message_id}") # Verbose

                now = time.time()
                if message_id not in reassembly_buffer:
                    reassembly_buffer[message_id] = {
                        'fragments': {}, 'total_hint': total_fragments_hint,
                        'received_count': 0, 'timestamp': now
                    }
                elif frag_num in reassembly_buffer[message_id]['fragments']:
                    return # Ignore duplicate

                reassembly_buffer[message_id]['fragments'][frag_num] = payload_bytes
                reassembly_buffer[message_id]['received_count'] += 1
                reassembly_buffer[message_id]['timestamp'] = now

                # Check for completion
                if reassembly_buffer[message_id]['received_count'] == total_fragments_hint:
                    print(f"Received all {total_fragments_hint} fragments for message {message_id}. Reassembling...")
                    fragments_dict = reassembly_buffer[message_id]['fragments']

                    if len(fragments_dict) != total_fragments_hint or not all(i in fragments_dict for i in range(1, total_fragments_hint + 1)):
                        print(f"Error: Missing fragments for {message_id} despite count match. Discarding.")
                        del reassembly_buffer[message_id]
                        return

                    reassembled_bytes_list = [fragments_dict[i] for i in range(1, total_fragments_hint + 1)]
                    reassembled_bytes = b"".join(reassembled_bytes_list)
                    original_message = reassembled_bytes.decode('utf-8').strip() # Assume original was UTF-8 text
                    print(f"Reassembly successful for {message_id}. Processing.")
                    handle_cluster_message(original_message) # Process the complete message

                    del reassembly_buffer[message_id] # Clean up

            except (ValueError, IndexError, UnicodeDecodeError) as e:
                print(f"Error parsing fragment: {e}. Header bytes: {data_bytes[:100]}...")
            except Exception as e:
                 print(f"Unexpected error handling fragment: {type(e).__name__}: {e}")

        else:
            # --- Handle Non-Fragmented Message ---
            try:
                message = data_bytes.decode('utf-8').strip()
                if message:
                     # print(f"Received non-fragmented message (UDP): {message[:100]}...") # Verbose
                     handle_cluster_message(message)
            except UnicodeDecodeError:
                 print("Received UDP packet that is not UTF-8 text or a valid fragment.")

    except Exception as e:
        print(f"Error in process_udp_packet: {type(e).__name__}: {e}")
        traceback.print_exc()

def setup_broadcast_listener(listen_address):
    """Sets up a UDP socket for listening to broadcasts."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind to the specific interface address if needed, or 0.0.0.0 for all
        bind_ip = listen_address[0] if listen_address[0] != '0.0.0.0' else '' # Use '' for INADDR_ANY behavior with bind
        sock.bind((bind_ip, listen_address[1]))
        print(f"Successfully bound UDP listener to {listen_address}")
        return sock
    except Exception as e:
        print(f"Error setting up UDP listener on {listen_address}: {e}")
        return None
# -----------------------------------------

# --- SBP Logic (Intra-Cluster - Follower Role) ---

def compute_cluster_key(rcvd_swarm_sequence, rcvd_blind_keys, rcvd_g_I_prev_values):
    """Compute the cluster key based on received update and own sk_i."""
    global k_cluster, g, p, sk_i, MY_ID
    print("Attempting to compute cluster key...")
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

        # Need g^I_prev corresponding to the node *before* me in the sequence.
        # The CH should send g^I values keyed by the ID of the node *they apply to*.
        # i.e., rcvd_g_I_prev_values = { node_id_k: g^I_{k-1} } for k >= 1
        if MY_ID not in rcvd_g_I_prev_values:
             print(f"Error: Required g^I_prev for ID {MY_ID} not found in received data {list(rcvd_g_I_prev_values.keys())}")
             return None
        my_g_I_prev = rcvd_g_I_prev_values[MY_ID]

        # Compute my intermediate key: I_mine = (my_g_I_prev) ^ sk_i mod p
        I_mine = pow(my_g_I_prev, sk_i, p)

        # Compute forward keys until the end of the sequence
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
        print(f"Computed new cluster key K_cluster: {str(k_cluster)[:30]}... (took {duration_ms:.3f} ms)")

        # --- This is where the Follower timing metric comes from ---
        # Print in the format expected by the automation script
        print(f"[Leader] Execution time for the follower: {duration_ms:.3f} ms")
        # ---------------------------------------------------------

        return k_cluster

    except Exception as e:
        print(f"Error during cluster key computation: {e}")
        traceback.print_exc()
        return None


def handle_cluster_message(message):
    """Handle messages received on the cluster broadcast channel."""
    global k_cluster, cluster_swarm_sequence, ch_public_key
    try:
        # Check for non-fragmented, non-key-update messages first
        if not message.startswith("KEY_UPDATE|"):
            msg_parts = message.split('|', 1)
            msg_type = msg_parts[0]

            if msg_type == "RELAYED_MSG" and len(msg_parts) > 1:
                encrypted_content = msg_parts[1]
                print("Received relayed global message.")
                decrypted_content_bytes_or_str = decrypt_message_aes(encrypted_content, k_cluster)
                if decrypted_content_bytes_or_str:
                     if isinstance(decrypted_content_bytes_or_str, str):
                           print(f"Decrypted Global Content: {decrypted_content_bytes_or_str[:100]}...")
                     else: # Print hex if it was bytes
                           print(f"Decrypted Global Content (bytes): {decrypted_content_bytes_or_str.hex()[:100]}...")
                else:
                     print("Error: Failed to decrypt relayed message.")
            else:
                print(f"Received unknown non-key-update message type: {msg_type}")
            return

        # --- Process KEY_UPDATE ---
        print("Processing KEY_UPDATE from CH...")
        message_type, message_body_signed = message.split('|', 1)
        message_parts = message_body_signed.rsplit('|', 1) # Split only the last pipe for signature
        if len(message_parts) != 2:
             print(f"Error: Invalid KEY_UPDATE format (missing signature?): {message[:100]}...")
             return

        message_body = message_parts[0]
        signature = message_parts[1]
        message_body_bytes = message_body.encode('utf-8')

        # Verify the signature using CH public key
        if not verify_message_rsa(message_body_bytes, signature, ch_public_key):
            print("Error: Invalid signature for KEY_UPDATE from CH.")
            return
        # print("CH signature verified for KEY_UPDATE.") # Less verbose

        # Parse the message body (Expect Full state format initially)
        # Format: "seq1,seq2,...|T_1:val,T_2:val,...|gI_1:val,gI_2:val,..."
        body_parts = message_body.split('|')
        if len(body_parts) != 3:
             print(f"Error: Invalid KEY_UPDATE body format (expected 3 parts): {message_body[:100]}...")
             # TODO: Handle minimal join update format later
             return

        rcvd_seq_str, rcvd_blind_keys_str, rcvd_gI_str = body_parts

        # Parse sequence
        rcvd_swarm_sequence = rcvd_seq_str.split(',') if rcvd_seq_str else []
        if not rcvd_swarm_sequence:
             print("Warning: Received empty swarm sequence in KEY_UPDATE.")
             # What should happen? Clear local state? Ignore?
             return

        # Parse blind keys (T_i values) - only need keys for nodes after me
        rcvd_blind_keys = {}
        if rcvd_blind_keys_str:
            try:
                rcvd_blind_keys = {fid: int(key) for fid, key in [pair.split(':') for pair in rcvd_blind_keys_str.split(',')]}
            except Exception as e:
                print(f"Error parsing received blind keys: {e}, Data: {rcvd_blind_keys_str}")
                return

        # Parse g^I_prev values - only need the one for my ID
        rcvd_g_I_prev_values = {}
        if rcvd_gI_str:
             try:
                 rcvd_g_I_prev_values = {fid: int(key) for fid, key in [pair.split(':') for pair in rcvd_gI_str.split(',')]}
             except Exception as e:
                 print(f"Error parsing received g^I_prev values: {e}, Data: {rcvd_gI_str}")
                 return

        # print(f"Received Cluster State: Seq={rcvd_swarm_sequence}") # Less verbose

        # Store the latest sequence
        cluster_swarm_sequence = rcvd_swarm_sequence

        # Compute the new cluster key
        compute_cluster_key(rcvd_swarm_sequence, rcvd_blind_keys, rcvd_g_I_prev_values)

    except Exception as e:
        print(f"Error processing cluster message: {e}")
        traceback.print_exc()

# --- Connection Logic ---
def connect_to_cluster_head():
    """Establishes connection with the assigned Cluster Head."""
    client = None
    broadcast_socket = None
    connection_attempts = 0
    max_connection_attempts = 5 # Try 5 times before giving up

    while connection_attempts < max_connection_attempts:
        connection_attempts += 1
        try:
            # Setup broadcast listener for cluster messages first
            if not broadcast_socket:
                 broadcast_socket = setup_broadcast_listener(cluster_bcast_address)
                 if not broadcast_socket:
                      print(f"Attempt {connection_attempts}: Failed to bind UDP listener, retrying in 5s...")
                      time.sleep(5)
                      continue # Retry outer loop

            # Attempt TCP connection
            print(f"Attempt {connection_attempts}: Connecting to CH {my_ch_id} at {my_ch_tcp_address}")
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(10) # Connection timeout
            client.connect(my_ch_tcp_address)
            client.settimeout(None) # Reset timeout after connection
            print("Connected to CH via TCP.")

            # Send ID and Blind Key (T_i) using makefile for clear separation
            try:
                 writer = client.makefile('w', encoding='utf-8')
                 reader = client.makefile('r', encoding='utf-8') # Needed? Maybe not here.

                 id_message = f"ID:{MY_ID}\n"
                 print(f"Sending ID: {id_message.strip()}")
                 writer.write(id_message)
                 writer.flush() # Ensure it's sent

                 ti_message = f"T_I:{T_i}\n"
                 print(f"Sending T_i: {ti_message.strip()}")
                 writer.write(ti_message)
                 writer.flush()
                 print("ID and T_i sent.")
            except Exception as send_err:
                 print(f"Error sending initial data to CH: {send_err}")
                 if client: client.close()
                 time.sleep(3)
                 continue # Retry connection

            print(f"Listening on UDP {cluster_bcast_address} for cluster messages...")

            # --- Main listening loop ---
            read_sockets = [broadcast_socket]
            last_cleanup_time = time.time()

            while True:
                readable, _, exceptional = select.select(read_sockets, [], read_sockets, 1.0)

                if exceptional:
                    print("Exceptional condition on socket. Reconnecting.")
                    break # Break inner loop to reconnect

                for sock in readable:
                    if sock is broadcast_socket:
                        try:
                            data_bytes, addr = broadcast_socket.recvfrom(BUFFER_SIZE)
                            if data_bytes:
                                process_udp_packet(data_bytes)
                        except Exception as recv_err:
                             print(f"Error receiving UDP packet: {recv_err}")
                             # Decide if this is fatal or recoverable

                # Check TCP connection health periodically (optional, less reliable)
                # Can try sending a small keep-alive or rely on errors during potential future writes.
                # For now, rely on the main loop exit via exception or KeyboardInterrupt.

                # Periodic cleanup
                now = time.time()
                if now - last_cleanup_time > REASSEMBLY_TIMEOUT:
                    cleanup_reassembly_buffer()
                    last_cleanup_time = now
            # --- End of main listening loop ---

        except socket.timeout:
            print(f"Attempt {connection_attempts}: Connection to CH timed out, retrying...")
            if client: client.close(); client=None
            if broadcast_socket: broadcast_socket.close(); broadcast_socket=None # Need to rebind listener too
            time.sleep(5)
        except (ConnectionRefusedError, OSError) as e: # Catch specific errors
            print(f"Attempt {connection_attempts}: Connection refused or OS error ({e}), CH might not be ready. Retrying in 5s...")
            if client: client.close(); client=None
            if broadcast_socket: broadcast_socket.close(); broadcast_socket=None
            time.sleep(5)
        except KeyboardInterrupt:
            print("Process interrupted by user.")
            break # Exit outer loop
        except Exception as e:
            print(f"Unexpected Error in connection loop: {type(e).__name__}: {e}")
            traceback.print_exc()
            if client: client.close(); client=None
            if broadcast_socket: broadcast_socket.close(); broadcast_socket=None
            print("Retrying connection in 10s...")
            time.sleep(10) # Longer backoff for unexpected errors

    # End of while loop (max attempts reached or interrupted)
    if connection_attempts >= max_connection_attempts:
        print("FATAL: Max connection attempts to CH reached. Exiting.")

    # Cleanup
    #finally:
    if broadcast_socket: 
        broadcast_socket.close()
    if client: 
        client.close()
    print("Connection closed.")


# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="H-SBP Member Node")
    parser.add_argument("--id", required=True, help="ID of this Member node")
    parser.add_argument("--config", required=True, help="Path to the H-SBP configuration JSON file")
    parser.add_argument("--ch-ip", required=True, help="IP address of the Cluster Head for this member") # Added argument
    args = parser.parse_args()

    MY_ID = args.id
    my_ch_ip_arg = args.ch_ip # Store the passed IP
    print(f"Starting Member Node: {MY_ID}")
    
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
    except Exception as e: 
        print(f"FATAL: Failed to load config/secrets: {e}")
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

    # Determine Role and Cluster
    try:
        node_def = CONFIG['structure']['node_definitions'][MY_ID]
        MY_ROLE = node_def['role']
        if MY_ROLE != "MEMBER":
            print(f"FATAL: Role mismatch! Expected MEMBER, got {MY_ROLE} for ID {MY_ID}")
            sys.exit(1)
        MY_CLUSTER_ID = node_def['cluster_id']
    except KeyError:
        print(f"FATAL: Could not find node definition or cluster ID for '{MY_ID}' in config.")
        sys.exit(1)

    # Find my CH and network details
    try:
        cluster_info = CONFIG['structure']['clusters'][MY_CLUSTER_ID]
        my_ch_id = cluster_info['ch_id']
        net_conf = CONFIG['network']
        ch_tcp_port = net_conf['ch_tcp_base_port'] + int(MY_CLUSTER_ID) - 1

        # *** USE THE COMMAND LINE ARGUMENT FOR CH IP ***
        my_ch_tcp_address = (my_ch_ip_arg, ch_tcp_port)
        # ***********************************************

        cluster_bcast_port = net_conf['cluster_bcast_base_port'] + int(MY_CLUSTER_ID) - 1

        # *** USE CONFIGURED BROADCAST IP CONSISTENTLY ***
        # Use the same broadcast IP as configured for inter-CH (e.g., 172.16.0.255)
        # Adjust if your CORE setup uses different broadcast addresses per subnet
        cluster_bcast_addr_str = net_conf['inter_ch_bcast_addr']
        # ************************************************
        cluster_bcast_address = (cluster_bcast_addr_str, cluster_bcast_port)

    except KeyError as e:
         print(f"FATAL: Config lookup error: Missing key {e}")
         sys.exit(1)
    except Exception as e:
        print(f"FATAL: Failed to determine CH/Network details: {e}")
        sys.exit(1)

    # Load CH public key
    try:
         #ch_pub_key_path = CONFIG['paths']['ch_pub_key_template'].format(MY_CLUSTER_ID)
         ch_pub_key_path = os.path.join(script_dir, CONFIG['paths']['ch_pub_key_template'].format(MY_CLUSTER_ID))
         
         print(f"Loading CH public key: {ch_pub_key_path}")
         ch_public_key = load_public_key(ch_pub_key_path)
         if not ch_public_key:
              print("FATAL: Failed to load CH public key.")
              sys.exit(1)
    except Exception as e:
         print(f"FATAL: Error determining or loading CH public key path: {e}")
         sys.exit(1)

    print(f"Starting node {MY_ID} as {MY_ROLE} in Cluster {MY_CLUSTER_ID}")
    print(f"My CH is {my_ch_id}. Target CH Address: {my_ch_tcp_address}") # Should now show correct IP
    print(f"Listening for cluster broadcasts on UDP {cluster_bcast_address}")

    connect_to_cluster_head()
# --- END OF FILE member.py ---
