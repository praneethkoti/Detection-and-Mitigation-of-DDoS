
# DDoS Attack Detection and Mitigation in SDN Using POX Controller

*K. Sai Praneeth and A. Meher Sudhakar — SRM Institute of Science and Technology, November 2021. Academic background: [docs/SDN_DDoS_Report.pdf](docs/SDN_DDoS_Report.pdf).*

This project explores an efficient technique for the **detection and mitigation of Distributed Denial of Service (DDoS) attacks** within **Software Defined Networks (SDN)**, using the centralized **POX controller**. The method employs entropy-based analysis to detect abnormal traffic behavior, along with **Principal Component Analysis (PCA)** for enhancing accuracy in identifying new types of attacks. The ultimate aim is to prevent network disruption while improving traffic management in SDN environments.

## Overview

Software Defined Networking (SDN) separates the control plane from the data plane, making the network more flexible and programmable. However, with this flexibility comes vulnerability—especially to **DDoS attacks**, which attempt to overwhelm the network by flooding it with malicious traffic. In SDN, the controller plays a crucial role in managing the network, and attacks targeting the controller can bring the entire network down. This project implements a method to detect DDoS attacks early, thus preventing the controller from getting overwhelmed.

The system makes use of **Mininet** to simulate network topology, while **Scapy** is utilized for generating traffic. The **POX controller** monitors traffic patterns and computes the entropy to detect deviations, which are indicative of DDoS attacks. The entropy-based approach allows for real-time analysis of traffic, ensuring prompt detection and mitigation by blocking IP addresses responsible for attacks.

## Theoretical Background

In networking, **DDoS (Distributed Denial of Service)** attacks are a major threat. These attacks aim to flood the target network with an overwhelming volume of traffic from multiple sources. The result is a depletion of network resources, making the services unavailable to legitimate users. Traditional networks struggle with DDoS detection because of their rigid structure. However, **SDN's centralized control** provides a more strategic way to monitor and defend against such attacks.

By calculating the **entropy** of incoming packets, we can observe changes in network randomness. Under normal conditions, the traffic exhibits a stable entropy value, but during an attack, the entropy significantly drops, signaling abnormal activity. The controller can then block the malicious sources, restoring normal operation. This approach, combined with **PCA**, allows for better identification of novel attack patterns that traditional methods might miss.

## Key Features

- **Real-time DDoS detection**: The POX controller calculates entropy values of traffic to spot deviations in real-time.
- **Enhanced detection accuracy**: Principal Component Analysis (PCA) is integrated to detect new and emerging types of DDoS attacks.
- **Automated IP blocking**: Once the entropy threshold is breached, the controller blocks the suspicious IP addresses to prevent further attacks.
- **Mininet Simulation**: A network topology of 9 switches and 64 hosts is created for testing and simulation.

## Implementation Steps

### 1. Mininet Topology Setup
First, set up a Mininet topology with 9 switches and 64 hosts using the following command:
```bash
$ sudo mn --switch ovsk --topo tree,depth=2,fanout=8 --controller=remote,ip=127.0.0.1,port=6633
```

### 2. Start POX Controller
From another terminal, launch the POX controller with the edited detection script:
```bash
$ cd pox
$ python ./pox.py ddos_sdn.detector.pox_controller
```

### 3. Packet Generation
1. **Normal Traffic**: To generate benign background traffic between hosts, run the benign generator from host `h1`:
   ```bash
   $ python -m ddos_sdn.generators.benign_traffic -s 2 -e 65
   ```

2. **DDoS Attack Traffic**: Simulate a volumetric UDP flood from multiple hosts (e.g., `h1`, `h2`, `h3`) targeting a single host (e.g., `h64`):
   ```bash
   $ python -m ddos_sdn.generators.udp_flood 10.0.0.64
   ```

### 4. DDoS Detection
As the POX controller receives packets, it calculates the entropy value for each set of 250 packets. If the entropy falls below a predefined threshold, the system flags a potential DDoS attack and blocks the malicious IP addresses to mitigate the attack.

### 5. Stopping the Process
After completing the tests and observing the entropy values in the POX controller terminal, terminate the tcpdump process and stop both **Mininet** and the **POX controller**.

---

## Manual Installation and Setup

### 1. Install Scapy
To install Scapy, which is used for generating and sniffing packets:
```bash
sudo apt-get install python-scapy
```

### 2. Create Scripts
a. **Benign Traffic Generator** (`src/ddos_sdn/generators/benign_traffic.py`):
   - Generates randomized-source, randomized-destination UDP traffic to establish the no-attack entropy baseline.

b. **UDP Flood Generator** (`src/ddos_sdn/generators/udp_flood.py`):
   - Generates a single-source, single-destination UDP flood — the volumetric L3/L4 DDoS used to drive entropy below threshold.

c. **Random-Destination Flood** (`src/ddos_sdn/generators/random_dst_flood.py`):
   - Single source, randomized destinations across `10.0.0.[s..e]` — the "new-type DDoS" case from the companion report where destination-IP entropy fails to detect the attack.

d. **Detection Script** (`src/ddos_sdn/detector/entropy.py`):
   - `EntropyAnalyzer` — Shannon entropy of destination IPs over fixed-size packet windows. Imported by the POX controller at `src/ddos_sdn/detector/pox_controller.py`.

d. **Modify l3_learning**:
   - Edit or replace the `l3_learning` script to enable detection of DDoS attacks based on entropy.

---

## Testing the Project

1. **Generate Normal Traffic**:
   - After setting up the Mininet topology, open an xterm window for host `h1` and run the traffic generation script:
   ```bash
   mininet> xterm h1
   # python -m ddos_sdn.generators.benign_traffic -s 2 -e 65
   ```

2. **Launch DDoS Attack**:
   - Open xterm windows for `h1`, `h2`, and `h3` and simulate a DDoS attack targeting `h64`:
   ```bash
   # python -m ddos_sdn.generators.udp_flood 10.0.0.64
   ```

3. **Monitor Entropy**:
   - Monitor the entropy values in the POX controller terminal to detect any deviations that would indicate an attack. If entropy values drop below the set threshold, the system will block the malicious IPs.

---

## Conclusion

This project demonstrates an effective approach for **early detection and mitigation of DDoS attacks** in SDN using a centralized controller. By leveraging **entropy analysis** and **PCA**, the system can quickly detect abnormal traffic patterns, ensuring the SDN controller remains resilient to attacks. This approach provides a reliable method for enhancing network security in modern SDN environments.

---

## Future Enhancements

- **Multi-Controller SDN**: As SDN networks grow, the addition of multiple controllers can enhance scalability and reliability, reducing the risk of single points of failure.
- **Advanced DDoS Detection**: Incorporating more advanced machine learning algorithms could further improve the detection of sophisticated DDoS attacks, particularly in large-scale networks.
