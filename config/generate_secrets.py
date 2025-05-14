# --- START OF FILE generate_secrets.py ---
import json
import secrets
import os
import sys

# Define g and p (as integers for randbelow)
g = 2
p = 89623836882807575898953596264244543572330229444342513348507616139417708009079

def generate_node_ids(num_clusters, initial_members_per_cluster, one_joining_member_per_cluster=True):
    """Generates a list of node IDs based on the structure."""
    node_ids_list = ["sl-0"]
    for i in range(1, num_clusters + 1):
        ch_id = f"ch-{i}"
        node_ids_list.append(ch_id)
        for j in range(1, initial_members_per_cluster + 1):
            member_id = f"m-{i}{str(j).zfill(4)}" # e.g., m-10001, m-10002
            node_ids_list.append(member_id)
        if one_joining_member_per_cluster:
            joining_member_id = f"m-{i}{str(initial_members_per_cluster + 1).zfill(4)}" # e.g., m-10004 if 3 initial
            node_ids_list.append(joining_member_id)
    return node_ids_list

def generate_secrets_file(output_path, node_ids_list, prime_modulus):
    """Generates a JSON file with secret keys for each node."""
    secrets_data = {}
    for node_id in node_ids_list:
        # sk_i should be a random integer less than p
        sk_i = secrets.randbelow(prime_modulus)
        secrets_data[node_id] = str(sk_i) # Store as string

    # Ensure the directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump(secrets_data, f, indent=2)
    print(f"Successfully generated secrets file: {output_path}")

if __name__ == "__main__":
    # --- Configuration for Secrets Generation ---
    # This should match the LARGEST scenario you intend to run
    # e.g., if max is 5000 followers / 5 clusters = 1000 members per cluster
    # Here, members_per_cluster means total members for config generation (initial + joining)
    # For the example of 1000 total followers (5 clusters, 200 members each)
    # where 199 are initial and 1 is joining:
    #NUM_CLUSTERS_FOR_SECRETS = 5
    #MAX_MEMBERS_PER_CLUSTER_FOR_SECRETS = 200 # This is 200 initial + 1 joining
    if len(sys.argv) == 3:  # If arguments are provided
        NUM_CLUSTERS_FOR_SECRETS = int(sys.argv[1])
        MAX_MEMBERS_PER_CLUSTER_FOR_SECRETS = int(sys.argv[2])
    else:  # Fall back to interactive input
        NUM_CLUSTERS_FOR_SECRETS = int(input("Enter number of clusters (e.g., 5): "))
        MAX_MEMBERS_PER_CLUSTER_FOR_SECRETS = int(input("Members per cluster (e.g., 200): "))
    
    print(f"Number of clusters: {NUM_CLUSTERS_FOR_SECRETS}, Members per cluster: {MAX_MEMBERS_PER_CLUSTER_FOR_SECRETS}")
    # Output path relative to the H-SBP project root
    # Assumes this script is run from the directory containing the H-SBP folder
    # or you adjust the path accordingly.
    # For example, if H-SBP is the current dir:
    #script_dir = os.path.dirname(os.path.abspath(__file__))
    #secrets_file_path = os.path.join(script_dir, "hsbp_secrets.json")
    # For now, assume it's run from parent of H-SBP or paths are adjusted
    secrets_file_path = "/mnt/workarea/H-SBP/config/hsbp_secrets.json" # H-SBP/config/


    print(f"Generating secret keys for {NUM_CLUSTERS_FOR_SECRETS} clusters with up to {MAX_MEMBERS_PER_CLUSTER_FOR_SECRETS} members each...")

    all_node_ids = generate_node_ids(NUM_CLUSTERS_FOR_SECRETS, MAX_MEMBERS_PER_CLUSTER_FOR_SECRETS, True)
    generate_secrets_file(secrets_file_path, all_node_ids, p)
# --- END OF FILE generate_secrets.py ---
