# --- START OF FILE generate_config.py ---
import json
import os
import sys

def generate_config_file(output_path, num_clusters, initial_members_per_cluster):
    """
    Generates the hsbp_config.json file.
    'initial_members_per_cluster' defines the M0 set for each cluster.
    One additional 'joining_member' will be defined per cluster.
    """
    config_data = {
      "general": {
        "g": 2,
        "p": 89623836882807575898953596264244543572330229444342513348507616139417708009079
      },
      "network": {
        "sl_tcp_address": "0.0.0.0",
        "sl_tcp_port": 5000,
        "inter_ch_bcast_addr": "172.16.0.255", # Adjust if your CORE network uses a different broadcast
        "inter_ch_bcast_port": 6000,
        "ch_tcp_base_port": 5001,
        "cluster_bcast_base_port": 6001,
        "ch_control_base_port": 5100, # For batch leave trigger
        # "cluster_bcast_subnet": "172.16.0." # Not strictly needed if using global bcast addr
      },
      "paths": {
        "secret_keys_file": "config/hsbp_secrets.json", # Relative to H-SBP script dir
        "sl_priv_key": "keys/sl_private.pem",           # Relative to H-SBP script dir
        "sl_pub_key": "keys/sl_public.pem",            # Relative to H-SBP script dir
        "ch_priv_key_template": "keys/ch{}_private.pem",# Relative to H-SBP script dir
        "ch_pub_key_template": "keys/ch{}_public.pem"   # Relative to H-SBP script dir
      },
      "structure": {
        "sl_id": "sl-0",
        "clusters": {},
        "node_definitions": {
           "sl-0": {"role": "SL"}
        }
      }
    }

    for i in range(1, num_clusters + 1):
        cluster_id_str = str(i)
        ch_id = f"ch-{cluster_id_str}"
        config_data["structure"]["node_definitions"][ch_id] = {"role": "CH", "cluster_id": cluster_id_str}

        current_initial_members = []
        current_all_members = []
        for j in range(1, initial_members_per_cluster + 1):
            member_id = f"m-{cluster_id_str}{str(j).zfill(4)}" # e.g., m-1001, m-1002 ... m-1199
            current_initial_members.append(member_id)
            current_all_members.append(member_id)
            config_data["structure"]["node_definitions"][member_id] = {
                "role": "MEMBER", "cluster_id": cluster_id_str
            }

        joining_member_id = f"m-{cluster_id_str}{str(initial_members_per_cluster + 1).zfill(4)}" # e.g., m-10200
        current_all_members.append(joining_member_id)
        config_data["structure"]["node_definitions"][joining_member_id] = {
            "role": "MEMBER", "cluster_id": cluster_id_str
        }

        config_data["structure"]["clusters"][cluster_id_str] = {
            "ch_id": ch_id,
            "initial_members": current_initial_members,
            "joining_member": joining_member_id,
            "all_members_for_config": current_all_members # For reference
        }

    # Ensure the directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump(config_data, f, indent=2)
    #print(f"Successfully generated config file: {output_path}")
    #print(f"Total followers configured (initial + joining): {num_clusters * (initial_members_per_cluster + 1)}")

if __name__ == "__main__":
    # --- Configuration for Config Generation ---
    # This will be run for each specific total swarm size you want to test.
    # Example: For a total of 1000 followers with 5 clusters:
    # NUM_CLUSTERS = 5
    # INITIAL_MEMBERS_PER_CLUSTER = 199 # (1000 / 5) - 1

    # You would typically call this script multiple times with different values,
    # or wrap it in another script that iterates through your swarm sizes.

    if len(sys.argv) == 3:  # If arguments are provided
        num_total_followers = int(sys.argv[1])
        num_total_clusters = int(sys.argv[2])
    else:  # Fall back to interactive input
        num_total_followers = int(input("Enter total number of followers (e.g., 1000, 2000): "))
        num_total_clusters = int(input("Enter number of clusters (e.g., 5): "))
    
    print(f"Followers: {num_total_followers}, Clusters: {num_total_clusters}")
    # For a single test run, e.g., 1000 total followers:
    #num_total_followers = int(input("Enter total number of followers (e.g., 1000, 2000): "))
    #num_total_clusters = int(input("Enter number of clusters (e.g., 5): "))

    if num_total_followers % num_total_clusters != 0:
        print("Error: Total number of followers must be divisible by the number of clusters.")
    else:
        total_members_per_cluster = num_total_followers // num_total_clusters
        if total_members_per_cluster < 1:
             print("Error: Calculated members per cluster is less than 1 (joining member).")
        else:
            initial_m_per_cluster = total_members_per_cluster # One is reserved for joining
            if initial_m_per_cluster < 0: # At least one joining member, so if total is 1 per cluster, initial is 0.
                 initial_m_per_cluster = 0
                 print(f"Warning: Setting 0 initial members per cluster, only 1 joining member per cluster.")


            # Output path (similar to secrets script)
            config_file_path = "/mnt/workarea/H-SBP/config/hsbp_config.json" # H-SBP/config/

            print(f"\nGenerating hsbp_config.json for:")
            print(f"  Total Followers: {num_total_followers}")
            print(f"  Number of Clusters: {num_total_clusters}")
            print(f"  Initial Members per Cluster (M0): {initial_m_per_cluster}")
            print(f"  Joining Members per Cluster: 1")

            generate_config_file(config_file_path, num_total_clusters, initial_m_per_cluster)
# --- END OF FILE generate_config.py ---
