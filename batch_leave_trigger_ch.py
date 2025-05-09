# batch_leave_trigger_ch.py
import socket
import sys
import time

def send_batch_leave_command(ch_ip, ch_control_port, k_to_leave):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            print(f"Attempting to connect to CH control at {ch_ip}:{ch_control_port}...")
            client.connect((ch_ip, ch_control_port))
            message = f"BATCH_LEAVE {k_to_leave}"
            client.sendall(message.encode('utf-8'))
            print(f"Sent to CH ({ch_ip}:{ch_control_port}): {message}")
    except ConnectionRefusedError:
        print(f"Error: Connection refused by CH at {ch_ip}:{ch_control_port}. Is CH control listener running?")
    except Exception as e:
        print(f"Error sending batch leave command to CH: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python batch_leave_trigger_ch.py <ch_ip> <ch_control_port> <k_to_leave>")
        sys.exit(1)

    ch_ip_arg = sys.argv[1]
    ch_control_port_arg = int(sys.argv[2])
    k_arg = int(sys.argv[3])

    send_batch_leave_command(ch_ip_arg, ch_control_port_arg, k_arg)
