import sys
import struct

def parse_pcap(filepath):
    with open(filepath, 'rb') as f:
        global_header = f.read(24)
        if len(global_header) < 24:
            return None, []
        magic = struct.unpack('<I', global_header[:4])[0]
        if magic == 0xa1b2c3d4:
            endian = '<'
        elif magic == 0xd4c3b2a1:
            endian = '>'
        else:
            raise ValueError("Unsupported PCAP format (magic: 0x{:x})".format(magic))
        
        link_type = struct.unpack(endian + 'I', global_header[20:24])[0]
        
        packets = []
        while True:
            pkt_header = f.read(16)
            if len(pkt_header) < 16:
                break
            cap_len = struct.unpack(endian + 'I', pkt_header[8:12])[0]
            pkt_data = f.read(cap_len)
            packets.append(pkt_data)
        return link_type, packets

def get_ip_packet(link_type, pkt_data):
    if link_type == 1: # Ethernet
        if len(pkt_data) < 14: return None
        eth_type = struct.unpack('>H', pkt_data[12:14])[0]
        if eth_type == 0x0800 or eth_type == 0x86dd:
            return pkt_data[14:]
    elif link_type == 101 or link_type == 12: # Raw IP
        return pkt_data
    elif link_type == 113: # Linux Cooked
        if len(pkt_data) < 16: return None
        protocol = struct.unpack('>H', pkt_data[14:16])[0]
        if protocol == 0x0800 or protocol == 0x86dd:
            return pkt_data[16:]
    return None

def check_fragmentation(link_type, packets):
    fragmented_count = 0
    for pkt in packets:
        ip = get_ip_packet(link_type, pkt)
        if not ip or len(ip) < 20:
            continue
        version = ip[0] >> 4
        if version == 4:
            flags_offset = struct.unpack('>H', ip[6:8])[0]
            if (flags_offset & 0x3fff) != 0:
                fragmented_count += 1
        elif version == 6:
            next_header = ip[6]
            if next_header == 44:
                fragmented_count += 1
    return fragmented_count

def find_tcp_syn_mss(link_type, packets):
    for pkt in packets:
        ip = get_ip_packet(link_type, pkt)
        if not ip or len(ip) < 20:
            continue
        version = ip[0] >> 4
        if version == 4:
            ihl = (ip[0] & 0x0f) * 4
            protocol = ip[9]
            if protocol != 6:
                continue
            tcp = ip[ihl:]
        elif version == 6:
            if len(ip) < 40: continue
            next_hdr = ip[6]
            offset = 40
            while next_hdr in (0, 43, 60):
                if len(ip) < offset + 8: break
                hdr_len = (ip[offset + 1] + 1) * 8
                next_hdr = ip[offset]
                offset += hdr_len
            if next_hdr != 6: continue
            tcp = ip[offset:]
        else:
            continue
        
        if len(tcp) < 20:
            continue
        flags = tcp[13]
        if not (flags & 0x02): # SYN
            continue
        
        data_offset = (tcp[12] >> 4) * 4
        options = tcp[20:data_offset]
        idx = 0
        while idx < len(options):
            kind = options[idx]
            if kind == 0:
                break
            elif kind == 1:
                idx += 1
            else:
                if idx + 1 >= len(options): break
                length = options[idx + 1]
                if length < 2: break
                if kind == 2: # MSS
                    if length == 4 and idx + 4 <= len(options):
                        mss = struct.unpack('>H', options[idx+2:idx+4])[0]
                        return mss
                idx += length
    return None

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: verify_pcap.py <router_pcap> <tun_server_pcap>")
        sys.exit(1)
        
    router_pcap = sys.argv[1]
    tun_server_pcap = sys.argv[2]
    
    lt_r, pkts_r = parse_pcap(router_pcap)
    frags = check_fragmentation(lt_r, pkts_r)
    print("Physical path packets: {}, Fragmented: {}".format(len(pkts_r), frags))
    
    lt_t, pkts_t = parse_pcap(tun_server_pcap)
    mss = find_tcp_syn_mss(lt_t, pkts_t)
    print("TUN server packets: {}, SYN MSS option: {}".format(len(pkts_t), mss))
    
    if frags > 0:
        print("FAIL: Found IP fragmentation on physical path!")
        sys.exit(1)
    if mss is None:
        print("FAIL: No TCP SYN packet with MSS option found on server TUN!")
        sys.exit(1)
    if mss > 1160:
        print("FAIL: MSS option is {} (expected <= 1160)!".format(mss))
        sys.exit(1)
        
    print("SUCCESS: PCAP checks passed!")
    sys.exit(0)
