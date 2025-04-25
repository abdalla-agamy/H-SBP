# --- START OF FILE separate_cluster_network_test.py ---

import time
import logging

from core.api.grpc import client
from core.api.grpc.wrappers import NodeType, Position

# Configure logging
logging.basicConfig(level=logging.INFO)

def main():
    # Interface helpers for different subnets
    iface_helper1 = client.InterfaceHelper(
        ip4_prefix="172.16.1.0/24",
        ip6_prefix="2001:1::/64", # Unique IPv6 prefix per network
    )
    iface_helper2 = client.InterfaceHelper(
        ip4_prefix="172.16.2.0/24",
        ip6_prefix="2001:2::/64", # Unique IPv6 prefix per network
    )

    # create grpc client and connect
    core = client.CoreGrpcClient()
    try:
        core.connect()
    except Exception as e:
        logging.error(f"Failed to connect to CORE gRPC server: {e}")
        return

    # Add session
    try:
        session = core.create_session()
        logging.info(f"Created CORE session {session.id}")
    except Exception as e:
        logging.error(f"Failed to create CORE session: {e}")
        core.close()
        return

    try:
        # Create two separate LAN nodes (representing cluster networks)
        # Use high node IDs to avoid potential clashes with PCs
        lan1_pos = Position(x=150, y=150)
        lan1 = session.add_node(
            101, _type=NodeType.DEFAULT, name="Cluster1_LAN", position=lan1_pos
        )
        logging.info(f"Added LAN node {lan1.id} for Cluster 1")

        lan2_pos = Position(x=350, y=150)
        lan2 = session.add_node(
            102, _type=NodeType.DEFAULT, name="Cluster2_LAN", position=lan2_pos
        )
        logging.info(f"Added LAN node {lan2.id} for Cluster 2")

        # Create nodes for Cluster 1
        node1_pos = Position(x=100, y=250)
        node1 = session.add_node(1, model="PC", name="c1_n1", position=node1_pos)
        iface1 = iface_helper1.create_iface(node1.id, 0)
        session.add_link(node1=node1, node2=lan1, iface1=iface1)
        logging.info(f"Added node {node1.id} ({node1.name}) and linked to LAN {lan1.id}")

        node2_pos = Position(x=200, y=250)
        node2 = session.add_node(2, model="PC", name="c1_n2", position=node2_pos)
        iface2 = iface_helper1.create_iface(node2.id, 0)
        session.add_link(node1=node2, node2=lan1, iface1=iface2)
        logging.info(f"Added node {node2.id} ({node2.name}) and linked to LAN {lan1.id}")

        # Create nodes for Cluster 2
        node3_pos = Position(x=300, y=250)
        node3 = session.add_node(3, model="PC", name="c2_n1", position=node3_pos)
        iface3 = iface_helper2.create_iface(node3.id, 0)
        session.add_link(node1=node3, node2=lan2, iface1=iface3)
        logging.info(f"Added node {node3.id} ({node3.name}) and linked to LAN {lan2.id}")

        node4_pos = Position(x=400, y=250)
        node4 = session.add_node(4, model="PC", name="c2_n2", position=node4_pos)
        iface4 = iface_helper2.create_iface(node4.id, 0)
        session.add_link(node1=node4, node2=lan2, iface1=iface4)
        logging.info(f"Added node {node4.id} ({node4.name}) and linked to LAN {lan2.id}")

        # Start session
        core.start_session(session)
        logging.info("Session started.")

        # --- Verification ---
        logging.info("Waiting 5 seconds for network initialization...")
        time.sleep(5)

        # Get assigned IP addresses (assuming interface 0 for all)
        ip_map = {}
        try:
            for node in [node1, node2, node3, node4]:
                 links = core.get_links(session.id, node.id)
                 if links and links[0].iface1: # Check if link and iface exist
                     ip_map[node.name] = links[0].iface1.ip4
                 else:
                      logging.warning(f"Could not get link/interface info for node {node.name}")
            logging.info(f"Assigned IPs: {ip_map}")
        except Exception as e:
            logging.error(f"Error getting node IPs: {e}")


        input("Press Enter to start ping tests...")

        if "c1_n1" in ip_map and "c1_n2" in ip_map:
            logging.info(f"\n--- Pinging within Cluster 1 ({node1.name} -> {node2.name}) ---")
            core.node_command(session.id, node1.id, f"ping -c 3 {ip_map['c1_n2']}", wait=True)

        if "c2_n1" in ip_map and "c2_n2" in ip_map:
            logging.info(f"\n--- Pinging within Cluster 2 ({node3.name} -> {node4.name}) ---")
            core.node_command(session.id, node3.id, f"ping -c 3 {ip_map['c2_n2']}", wait=True)

        if "c1_n1" in ip_map and "c2_n1" in ip_map:
            logging.info(f"\n--- Pinging between Clusters ({node1.name} -> {node3.name}) ---")
            core.node_command(session.id, node1.id, f"ping -c 3 {ip_map['c2_n1']}", wait=True)


        input("\nPing tests finished. Press Enter to stop the session...")

    except Exception as e:
        logging.error(f"An error occurred during session setup or execution: {e}")
        traceback.print_exc()
    finally:
        # Stop session
        if 'session' in locals() and session:
            try:
                core.stop_session(session.id)
                logging.info(f"Stopped session {session.id}")
            except Exception as e:
                logging.error(f"Error stopping session {session.id}: {e}")
        core.close()
        logging.info("Disconnected from CORE")

if __name__ == "__main__":
    main()

# --- END OF FILE separate_cluster_network_test.py ---
