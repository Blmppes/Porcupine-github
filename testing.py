from scapy.all import sniff, Ether, IP, TCP, UDP, Raw
import pandas as pd
import numpy as np
import time
import statistics
import joblib
from collections import deque
import wmi

ct = joblib.load("ct_model2.pkl")
sc = joblib.load("sc_model2.pkl")
model = joblib.load("rf_model2.pkl")

# Dictionary to keep track of flows
flows = {}

# Dictionary to keep track of counters
counters = {
    'ct_srv_src': {},  # Example: {'http_src_ip': count, 'ftp_src_ip': count, ...}
    'ct_state_ttl': {},  # Example: {'ACC_0-64': count, 'FIN_65-128': count, ...}
    'ct_dst_ltm': {},  # Example: {'dst_ip': count}
    'ct_src_dport_ltm': {},  # Example: {'src_ip_dst_port': count}
    'ct_dst_sport_ltm': {},  # Example: {'dst_ip_src_port': count}
    'ct_dst_src_ltm': {},   # Example: {'src_dst_ip': count}
    'is_ftp_login': {},     # Example: {'ftp_session': 1 or 0}
    'ct_ftp_cmd': {},       # Example: {'ftp_session': count}
    'ct_flw_http_mthd': {}, # Example: {'http_method': count}
    'ct_src_ltm': {},       # Example: {'src_ip': count}
    'ct_srv_dst': {},       # Example: {'service_dst_ip': count}
    'is_sm_ips_ports': {},  # Example: {'src_dst_ip_ports_equal': 1 or 0}
}

# Service mapping based on well-known ports
service_map = {
    80: 'http',
    443: 'ssl',
    21: 'ftp',
    53: 'dns',
    25: 'smtp',
    # Add more mappings as needed
}

global_deque = deque(maxlen=100)

def get_flow_key(packet):
    if IP in packet:
        ip = packet[IP]
        proto = ip.proto
        src = ip.src
        dst = ip.dst
        sport = packet.sport if TCP in packet or UDP in packet else '-'
        dport = packet.dport if TCP in packet or UDP in packet else '-'
        if(dst < src):
            tmp = sport
            sport = dport
            dport = tmp
            tmp = src
            src = dst
            dst = tmp
        return (src, dst, sport, dport, proto)
    return None

TCP_SYN = 0x02   # SYN flag
TCP_ACK = 0x10   # ACK flag
TCP_FIN = 0x01   # FIN flag
TCP_PSH = 0x08   # PSH flag

def get_tcp_state(flags):
    state = []
    if flags & TCP_FIN:
        state.append('FIN')
    elif flags & (TCP_PSH | TCP_ACK):
        state.append('REQ')
    elif flags & TCP_ACK:
        state.append('ACC')
    elif flags & (TCP_SYN | TCP_ACK):
        state.append('CON')
    return ','.join(state) if state else '-'

def get_udp_state(udp):
    state = []
    # Check for UDP conditions (CON, INT, REQ)
    if udp.sport == 53 or udp.dport == 53:
        state.append('REQ')  # Example condition for DNS
    elif udp.sport == 123 or udp.dport == 123:
        state.append('INT')  # Example condition for NTP
    else:
        state.append('CON')  # Default state for UDP

    return ','.join(state) if state else '-'

def update_flow_stats(flow, packet_size, current_time, direction):
    flow['dur'] = current_time - flow['start']
    if direction == 'src2dst':
        if flow['spkts'] == 0:
            flow['smean'] = int(packet_size)
        else:
            flow['smean'] = (flow['smean'] * flow['spkts'] + packet_size) // (flow['spkts'] + 1)
        flow['sbytes'] += packet_size
        flow['spkts'] += 1
        flow['sinpkt_times'].append(current_time)
        if len(flow['sinpkt_times']) > 1:
            inter_arrival_times = [flow['sinpkt_times'][i] - flow['sinpkt_times'][i-1] for i in range(1, len(flow['sinpkt_times']))]
            flow['sinpkt'] = statistics.mean(inter_arrival_times)*1000
            if len(inter_arrival_times) > 1:
                flow['sjit'] = statistics.stdev(inter_arrival_times)*1000
            else:
                flow['sjit'] = 0
    elif direction == 'dst2src':
        if flow['dpkts'] == 0:
            flow['dmean'] = int(packet_size)
        else:
            flow['dmean'] = (flow['dmean'] * flow['dpkts'] + packet_size) // (flow['dpkts'] + 1)
        flow['dbytes'] += packet_size
        flow['dpkts'] += 1
        flow['dinpkt_times'].append(current_time)
        if len(flow['dinpkt_times']) > 1:
            inter_arrival_times = [flow['dinpkt_times'][i] - flow['dinpkt_times'][i-1] for i in range(1, len(flow['dinpkt_times']))]
            flow['dinpkt'] = statistics.mean(inter_arrival_times)*1000
            if len(inter_arrival_times) > 1:
                flow['djit'] = statistics.stdev(inter_arrival_times)*1000
            else:
                flow['djit'] = 0

    if flow['dur'] > 0:
        flow['sload'] = flow['sbytes'] * 8 / flow['dur']
        flow['dload'] = flow['dbytes'] * 8 / flow['dur']
        flow['rate'] = (flow['sbytes'] + flow['dbytes']) / flow['dur']
    else:
        flow['rate'] = 0 


def get_ttl_range(ttl):
    # Define TTL ranges as per your specific requirements
    if ttl <= 64:
        return '0-64'
    elif ttl <= 128:
        return '65-128'
    else:
        return '128+'

cnt = 0

def update_counter(counter, key):
    if key not in counter:
        counter[key] = deque(maxlen=100)
    counter[key].append(time.time())

def count_within_window(counter, global_deque, key):
    current_time = time.time()
    window_start_time = global_deque[0] if global_deque else current_time
    count = 0
    for timestamp in counter[key]:
        count += timestamp >= window_start_time
    return count

def extract_features(packet):
    global flows, global_deque
    flow_key = get_flow_key(packet)

    if flow_key is None:
        return None

    current_time = time.time()
    packet_size = len(packet)

    if flow_key in flows:
        flow = flows[flow_key]
        flow['last_seen'] = current_time
    else:
        flow = {
            'start': current_time,
            'last_seen': current_time,
            'dur': 0,
            'proto': '-',
            'service': '-',
            'state': '-',
            'spkts': 0,
            'dpkts': 0,
            'sbytes': 0,
            'dbytes': 0,
            'rate': 0,
            'sttl': 0,
            'dttl': 0,
            'sload': 0,
            'dload': 0,
            'sloss': 0,
            'dloss': 0,
            'sinpkt': 0,
            'dinpkt': 0,
            'sjit': 0,
            'djit': 0,
            'swin': 0,
            'stcpb': 0,
            'dtcpb': 0,
            'dwin': 0,
            'tcprtt': 0,
            'synack': 0,
            'ackdat': 0,
            'smean': 0,
            'dmean': 0,
            'trans_depth': 0,
            'response_body_len': 0,
            'ct_srv_src': 0,
            'ct_state_ttl': 0,
            'ct_dst_ltm': 0,
            'ct_src_dport_ltm': 0,
            'ct_dst_sport_ltm': 0,
            'ct_dst_src_ltm': 0,
            'is_ftp_login': 0,
            'ct_ftp_cmd': 0,
            'ct_flw_http_mthd': 0,
            'ct_src_ltm': 0,
            'ct_srv_dst': 0,
            'is_sm_ips_ports': 0,
            'sinpkt_times': [],
            'dinpkt_times': [],
            'next_seq_src2dst': None,
            'next_seq_dst2src': None,
            'seen_seq_src2dst': set(),
            'seen_seq_dst2src': set()
        }
        flows[flow_key] = flow

    if Ether in packet:
        eth = packet[Ether]
        if IP in packet:
            ip = packet[IP]
            if ip.proto == 17:
                flow['proto'] = 'udp'
            elif ip.proto == 6:
                flow['proto'] = 'tcp'
            flow['sttl'] = ip.ttl
            flow['dttl'] = ip.ttl
            flow['is_sm_ips_ports'] = int(ip.src == ip.dst and ip.sport == ip.dport)

            # Add the current connection to the global deque
            global_deque.append(current_time)

            # Update ct_src_dport_ltm counter
            src_dport_key = f"{ip.src}_{packet.dport}"
            update_counter(counters['ct_src_dport_ltm'], src_dport_key)
            flow['ct_src_dport_ltm'] = count_within_window(counters['ct_src_dport_ltm'], global_deque, src_dport_key)
            # Update ct_dst_sport_ltm counter
            dst_sport_key = f"{ip.dst}_{packet.sport}"
            update_counter(counters['ct_dst_sport_ltm'], dst_sport_key)
            flow['ct_dst_sport_ltm'] = count_within_window(counters['ct_dst_sport_ltm'], global_deque, dst_sport_key)
            # Update ct_dst_src_ltm counter
            dst_src_key = f"{ip.src}_{ip.dst}"
            update_counter(counters['ct_dst_src_ltm'], dst_src_key)
            flow['ct_dst_src_ltm'] = count_within_window(counters['ct_dst_src_ltm'], global_deque, dst_src_key)
            # Update ct_src_ltm counter
            src_key = ip.src
            update_counter(counters['ct_src_ltm'], src_key)
            flow['ct_src_ltm'] = count_within_window(counters['ct_src_ltm'], global_deque, src_key)
            # Update ct_dst_ltm counter
            dst_key = ip.dst
            update_counter(counters['ct_dst_ltm'], dst_key)
            flow['ct_dst_ltm'] = count_within_window(counters['ct_dst_ltm'], global_deque, dst_key)
            # Update ct_srv_dst counter
            if TCP in packet and packet.dport in service_map:
                service_dst_key = f"{service_map[packet.dport]}_{ip.dst}"
                update_counter(counters['ct_srv_dst'], service_dst_key)
                flow['ct_srv_dst'] = count_within_window(counters['ct_srv_dst'], global_deque, service_dst_key)
            # Update is_ftp_login
            if TCP in packet and packet.dport == 21:
                if 'USER' in str(packet[TCP].payload) or 'PASS' in str(packet[TCP].payload):
                    flow['is_ftp_login'] = 1
                else:
                    flow['is_ftp_login'] = 0

            # Update ct_ftp_cmd
            if TCP in packet and packet.dport == 21:
                flow['ct_ftp_cmd'] += 1

            # Update ct_flw_http_mthd
            if TCP in packet and packet.dport == 80:
                if 'GET' in str(packet[TCP].payload) or 'POST' in str(packet[TCP].payload):
                    flow['ct_flw_http_mthd'] += 1
            # Update is_sm_ips_ports
            if ip.src == ip.dst and packet.sport == packet.dport:
                flow['is_sm_ips_ports'] = 1
            else:
                flow['is_sm_ips_ports'] = 0

            if TCP in packet:
                tcp = packet[TCP]
                # Determine direction based on flow_key properties directly
                if (flow_key[0] == ip.src and flow_key[1] == ip.dst and flow_key[2] == tcp.sport and flow_key[3] == tcp.dport):
                    direction = 'src2dst'
                elif (flow_key[0] == ip.dst and flow_key[1] == ip.src and flow_key[2] == tcp.dport and flow_key[3] == tcp.sport):
                    direction = 'dst2src'
                else:
                    direction = 'unknown'  # Handle cases where direction cannot be determined
             
                # Calculate synack: TCP connection setup time (time between SYN and SYN_ACK)
                if 'synack_time' in flow and direction == 'dst2src':
                    flow['synack'] = current_time - flow['synack_time']
                elif direction == 'src2dst':
                    flow['synack_time'] = current_time  # Record the time when SYN is sent
                
                # Calculate ackdat: TCP connection setup time (time between SYN_ACK and ACK)
                if 'ackdat_time' in flow and direction == 'dst2src':
                    flow['ackdat'] = current_time - flow['ackdat_time']
                elif direction == 'src2dst' and 'synack_time' in flow:
                    flow['ackdat_time'] = current_time  # Record the time when SYN_ACK is received

                if direction == 'src2dst':
                    if tcp.seq in flow['seen_seq_src2dst']:
                        flow['sloss'] += 1
                    flow['seen_seq_src2dst'].add(tcp.seq)
                    
                    if flow['next_seq_src2dst'] is not None and tcp.seq > flow['next_seq_src2dst']:
                        if len(tcp.payload) > 0:
                            flow['sloss'] += (tcp.seq - flow['next_seq_src2dst']) // len(tcp.payload)
                    flow['next_seq_src2dst'] = tcp.seq + len(tcp.payload)  # Update the next expected sequence number
                    
                    flow.update({
                        'state': get_tcp_state(tcp.flags),
                        'swin': tcp.window,
                        'stcpb': tcp.seq,
                        'dtcpb': tcp.ack,
                        'tcprtt': flow['synack'] + flow['ackdat'],
                    })
                elif direction == 'dst2src':
                    if tcp.seq in flow['seen_seq_dst2src']:
                        flow['dloss'] += 1
                    flow['seen_seq_dst2src'].add(tcp.seq)
                    
                    # Check for packet drops (gaps in sequence numbers)
                    if flow['next_seq_dst2src'] is not None and tcp.seq > flow['next_seq_dst2src']:
                        if len(tcp.payload) > 0:
                            flow['dloss'] += (tcp.seq - flow['next_seq_dst2src']) // len(tcp.payload)
                    flow['next_seq_dst2src'] = tcp.seq + len(tcp.payload)  # Update the next expected sequence number
                    
                    flow.update({
                        'state': get_tcp_state(tcp.flags),
                        'dwin': tcp.window,
                        'stcpb': tcp.ack,
                        'dtcpb': tcp.seq,
                        'tcprtt': flow['synack'] + flow['ackdat'],
                    })
                
                # Determine service based on destination port
                if tcp.dport in service_map:
                    flow['service'] = service_map[tcp.dport]

                # Calculate response_body_len, trans_depth
                if tcp.dport == 80 or tcp.sport == 80:
                    if Raw in packet:
                        raw_data = packet[Raw].load.decode('utf-8', 'ignore')

                        if 'GET ' in raw_data or 'POST ' in raw_data:
                            if 'trans_depth' not in flow:
                                flow['trans_depth'] = 1
                            else:
                                flow['trans_depth'] += 1

                        # Parse Content-Length from HTTP response
                        if 'HTTP' in raw_data:
                            lines = raw_data.splitlines()
                            for line in lines:
                                if line.startswith('Content-Length:'):
                                    content_length = line.split(': ')[1].strip()
                                    flow['response_body_len'] = int(content_length)
                                    break
                
                # Update ct_srv_src counter
                if tcp.dport in service_map:
                    service_key = f"{service_map[tcp.dport]}_{ip.src}"
                    update_counter(counters['ct_srv_src'], service_key)
                    flow['ct_srv_src'] = count_within_window(counters['ct_srv_src'], global_deque, service_key)

                # Update ct_state_ttl counter
                ttl_range = get_ttl_range(ip.ttl)
                state_key = f"{get_tcp_state(tcp.flags)}_{ttl_range}"
                update_counter(counters['ct_state_ttl'], state_key)
                flow['ct_state_ttl'] = count_within_window(counters['ct_state_ttl'], global_deque, state_key)

                update_flow_stats(flow, packet_size, current_time, direction)

            elif UDP in packet:
                udp = packet[UDP]
                # Determine direction based on flow_key properties directly
                if (flow_key[0] == ip.src and flow_key[1] == ip.dst and flow_key[2] == udp.sport and flow_key[3] == udp.dport):
                    direction = 'src2dst'
                elif (flow_key[0] == ip.dst and flow_key[1] == ip.src and flow_key[2] == udp.dport and flow_key[3] == udp.sport):
                    direction = 'dst2src'
                else:
                    direction = 'unknown'  # Handle cases where direction cannot be determined

                if direction == 'dst2src':
                    flow['dpkts'] += 1
                    flow['dbytes'] += packet_size
                    flow['dttl'] = ip.ttl
                else:
                    flow['spkts'] += 1
                    flow['sbytes'] += packet_size
                    flow['sttl'] = ip.ttl

                flow.update({
                    'state': get_udp_state(udp),
                })

                # Determine service based on destination port
                if udp.dport in service_map:
                    flow['service'] = service_map[udp.dport]

                update_flow_stats(flow, packet_size, current_time, direction)

    return flow

def capture_packets(interface, count=-1):
    global cnt
    packets = []
    def packet_handler(packet):
        global cnt
        cnt += 1
        # print(packet)
        packet_features = extract_features(packet)
        if packet_features:
            packets.append(packet_features)
            #datapreprocessing
            df = pd.DataFrame([packet_features])
            df.drop(["synack_time", "ackdat_time", "start", "last_seen", "sinpkt_times", "dinpkt_times", "next_seq_src2dst", "next_seq_dst2src", "seen_seq_src2dst", "seen_seq_dst2src"], axis=1, inplace=True, errors='ignore')
            
            for fea in log_transformed_features:
                df[fea] = np.log(df[fea]+1)

            # Apply the same transformations to the packet data as the training data
            X_packet = np.array(ct.transform(df))
            # Apply StandardScaler to the numerical features
            X_packet[:, 19:] = sc.transform(X_packet[:, 19:])
            threshold = 0.75
            probs = model.predict_proba(X_packet)
            predictions = (probs[:, 1] > threshold).astype(int)

            # Now predictions contain the binary predictions based on the custom threshold
            # if(probs[:, 1] >= 0.75):
            print(probs)

    sniff(iface=interface, prn=packet_handler, count=count)
    print(cnt)
    return packets

log_transformed_features = "dur, spkts, dpkts, sbytes, dbytes, rate, sload, dload, sinpkt, dinpkt, sjit, djit, stcpb, dtcpb, tcprtt, synack, ackdat, smean, dmean, response_body_len".split(", ")

if __name__ == '__main__':
    c = wmi.WMI()
    adapters = c.Win32_NetworkAdapter()
    for adapter in adapters:
        if adapter.NetConnectionID == 'Wi-Fi':
            interface = adapter.Description

    print(f"Starting packet capture on {interface}")
    try:
        captured_packets = capture_packets(interface)
        df = pd.DataFrame(captured_packets)
        df.to_csv("test3.csv")
    except KeyboardInterrupt:
        print("Packet capture stopped by user")

