from scapy.all import rdpcap
import matplotlib.pyplot as plt

# ----------- FUNCTION TO CALCULATE BANDWIDTH -----------
def calculate_bandwidth(packets):
    total_bytes = sum(len(pkt) for pkt in packets)
    duration = packets[-1].time - packets[0].time

    bandwidth_bps = (total_bytes * 8) / duration
    bandwidth_kbps = bandwidth_bps / 1000
    bandwidth_mbps = bandwidth_bps / 1000000

    return bandwidth_bps, bandwidth_kbps, bandwidth_mbps, duration


# ----------- FUNCTION TO PLOT BANDWIDTH GRAPH -----------
def plot_bandwidth(packets, title):
    times = []
    bandwidth = []

    start_time = packets[0].time

    # Create time intervals (1 second)
    interval = 1
    current_time = start_time
    end_time = packets[-1].time

    while current_time < end_time:
        interval_bytes = 0

        for pkt in packets:
            if current_time <= pkt.time < current_time + interval:
                interval_bytes += len(pkt)

        times.append(current_time - start_time)
        bandwidth.append((interval_bytes * 8) / interval)  # bits/sec

        current_time += interval

    # Plot graph
    plt.figure()
    plt.plot(times, bandwidth)
    plt.xlabel("Time (seconds)")
    plt.ylabel("Bandwidth (bits/sec)")
    plt.title(title)
    plt.grid()
    plt.show()


# ----------- FUNCTION FOR PROTOCOL FILTERING -----------
def filter_packets(packets, protocol):
    if protocol == "tcp":
        return [pkt for pkt in packets if pkt.haslayer("TCP")]
    elif protocol == "udp":
        return [pkt for pkt in packets if pkt.haslayer("UDP")]
    elif protocol == "icmp":
        return [pkt for pkt in packets if pkt.haslayer("ICMP")]
    elif protocol == "dns":
        return [pkt for pkt in packets if pkt.haslayer("DNS")]
    else:
        return packets


# ----------- MAIN PROGRAM -----------

files = {
    "Low Traffic": "Low_traffic.pcap",
    "Medium Traffic": "Medium_traffic.pcap",
    "High Traffic": "High_traffic.pcap"
}

for name, file in files.items():
    print("\n==============================")
    print("Processing:", name)

    packets = rdpcap(file)

    # Calculate bandwidth
    bps, kbps, mbps, duration = calculate_bandwidth(packets)

    print("Duration:", round(duration, 2), "seconds")
    print("Bandwidth:", round(bps, 2), "bps")
    print("Bandwidth:", round(kbps, 2), "kbps")
    print("Bandwidth:", round(mbps, 4), "Mbps")

    # Plot overall bandwidth
    plot_bandwidth(packets, f"{name} - Total Bandwidth")

    # -------- Protocol-wise Graphs --------
    for proto in ["tcp", "udp", "icmp", "dns"]:
        filtered = filter_packets(packets, proto)

        if len(filtered) > 0:
            plot_bandwidth(filtered, f"{name} - {proto.upper()} Bandwidth")