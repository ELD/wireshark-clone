extern crate pcap;

mod packet_types;

use std::env;
use std::collections::HashSet;
use pcap::Capture;
use packet_types::{LinkLayerType, TransportLayerType, NetworkLayerType, PacketTypes};

fn main() {
    let default_packet_types = PacketTypes {
        link_layer_type: LinkLayerType::Ethernet2,
        network_layer_type: NetworkLayerType::Other,
        transport_layer_type: TransportLayerType::Other,
        packet_length: 0,
        source_mac: [0; 6],
        dest_mac: [0; 6],
        source_ip: [0; 16],
        dest_ip: [0; 16],
        source_port: 0,
        dest_port: 0,
        is_syn: false,
        is_fin: false,
        is_frag: false,
    };

    let cap_file_name = env::args().nth(1).expect("Expected a command line parameter here");

    let mut capture = Capture::from_file(cap_file_name).ok().expect("Expected a valid capture file");

    let mut packets: Vec<PacketTypes> = Vec::new();
    while let Ok(packet) = capture.next() {
        packets.push(PacketTypes::new(packet.data, packet.header.len));
    }

    // Link Layer
    let num_ethernet = packets.iter().filter(|&e| e.link_layer_type == LinkLayerType::Ethernet2).count();
    let num_802_3 = packets.iter().filter(|&e| e.link_layer_type == LinkLayerType::Novell8023).count();

    println!("Link Layer:");
    println!("Number of Ethernet II frames: {}", num_ethernet);
    println!("Number of Novell 802.3 frames: {}", num_802_3);
    println!();

    // Network Layer
    let num_arp = packets.iter().filter(|&e| e.network_layer_type == NetworkLayerType::ARP).count() as u32;
    let arp_total: u32 = packets.iter().filter(|&e| e.network_layer_type == NetworkLayerType::ARP).fold(0, |acc, ref e| acc + e.packet_length);
    let max_arp = packets.iter().filter(|&e| e.network_layer_type == NetworkLayerType::ARP).max().unwrap_or(&default_packet_types).packet_length;
    let min_arp = packets.iter().filter(|&e| e.network_layer_type == NetworkLayerType::ARP).min().unwrap_or(&default_packet_types).packet_length;
    let mut avg_arp = 0;
    if num_arp != 0 {
        avg_arp = arp_total / num_arp
    }

    let num_ipv4 = packets.iter().filter(|&e| e.network_layer_type == NetworkLayerType::IPv4).count() as u32;
    let ipv4_total = packets.iter().filter(|&e| e.network_layer_type == NetworkLayerType::IPv4).fold(0, |acc, ref e| acc + e.packet_length);
    let max_ipv4 = packets.iter().filter(|&e| e.network_layer_type == NetworkLayerType::IPv4).max().unwrap_or(&default_packet_types).packet_length;
    let min_ipv4 = packets.iter().filter(|&e| e.network_layer_type == NetworkLayerType::IPv4).min().unwrap_or(&default_packet_types).packet_length;
    let mut avg_ipv4 = 0;
    if num_ipv4 != 0 {
        avg_ipv4 = ipv4_total / num_ipv4
    }

    let num_ipv6 = packets.iter().filter(|&e| e.network_layer_type == NetworkLayerType::IPv6).count() as u32;
    let ipv6_total = packets.iter().filter(|&e| e.network_layer_type == NetworkLayerType::IPv6).fold(0, |acc, ref e| acc + e.packet_length);
    let max_ipv6 = packets.iter().filter(|&e| e.network_layer_type == NetworkLayerType::IPv6).max().unwrap_or(&default_packet_types).packet_length;
    let min_ipv6 = packets.iter().filter(|&e| e.network_layer_type == NetworkLayerType::IPv6).min().unwrap_or(&default_packet_types).packet_length;
    let mut avg_ipv6 = 0;
    if num_ipv6 != 0 {
        avg_ipv6 = ipv6_total / num_ipv6
    }

    let num_other = packets.iter().filter(|&e| e.network_layer_type == NetworkLayerType::Other).count();

    println!("Network Layer:");
    println!("Number of ARP packets: {}", num_arp);
    println!("Max ARP packet size: {}, min ARP packet size: {}, average ARP packet size: {}", max_arp, min_arp, avg_arp);

    println!("Number of IPv4 packets: {}", num_ipv4);
    println!("Max IPv4 packet size: {}, min IPv4 packet size: {}, average IPv4 packet size: {}", max_ipv4, min_ipv4, avg_ipv4);

    println!("Number of IPv6 packets: {}", num_ipv6);
    println!("Max IPv6 packet size: {}, min IPv6 packet size: {}, average IPv6 packet size: {}", max_ipv6, min_ipv6, avg_ipv6);

    println!("Number of other packets: {}", num_other);

    println!();

    // Transport Layer
    let num_icmp = packets.iter().filter(|&e| e.transport_layer_type == TransportLayerType::ICMP).count() as u32;
    let icmp_total = packets.iter().filter(|&e| e.transport_layer_type == TransportLayerType::ICMP).fold(0, |acc, ref e| acc + e.packet_length);
    let max_icmp = packets.iter().filter(|&e| e.transport_layer_type == TransportLayerType::ICMP).max().unwrap_or(&default_packet_types).packet_length;
    let min_icmp = packets.iter().filter(|&e| e.transport_layer_type == TransportLayerType::ICMP).min().unwrap_or(&default_packet_types).packet_length;
    let mut avg_icmp = 0;
    if num_icmp != 0 {
        avg_icmp = icmp_total / num_icmp
    }

    let num_tcp = packets.iter().filter(|&e| e.transport_layer_type == TransportLayerType::TCP).count() as u32;
    let tcp_total = packets.iter().filter(|&e| e.transport_layer_type == TransportLayerType::TCP).fold(0, |acc, ref e| acc + e.packet_length);
    let max_tcp = packets.iter().filter(|&e| e.transport_layer_type == TransportLayerType::TCP).max().unwrap_or(&default_packet_types).packet_length;
    let min_tcp = packets.iter().filter(|&e| e.transport_layer_type == TransportLayerType::TCP).min().unwrap_or(&default_packet_types).packet_length;
    let mut avg_tcp = 0;
    if num_tcp != 0 {
        avg_tcp = tcp_total / num_tcp
    }

    let num_udp = packets.iter().filter(|&e| e.transport_layer_type == TransportLayerType::UDP).count() as u32;
    let udp_total = packets.iter().filter(|&e| e.transport_layer_type == TransportLayerType::UDP).fold(0, |acc, ref e| acc + e.packet_length);
    let max_udp = packets.iter().filter(|&e| e.transport_layer_type == TransportLayerType::UDP).max().unwrap_or(&default_packet_types).packet_length;
    let min_udp = packets.iter().filter(|&e| e.transport_layer_type == TransportLayerType::UDP).min().unwrap_or(&default_packet_types).packet_length;
    let mut avg_udp = 0;
    if num_udp != 0 {
        avg_udp = udp_total / num_udp
    }

    let num_other = packets.iter().filter(|&e| e.transport_layer_type == TransportLayerType::Other).count();

    println!("Transport Layer:");

    println!("Number of ICMP packets: {}", num_icmp);
    println!("Max ICMP packet size: {}, min ICMP packet size: {}, average ICMP packet size: {}", max_icmp, min_icmp, avg_icmp);

    println!("Number of TCP packets: {}", num_tcp);
    println!("Max TCP packet size: {}, min TCP packet size: {}, average TCP packet size: {}", max_tcp, min_tcp, avg_tcp);

    println!("Number of UDP packets: {}", num_udp);
    println!("Max UDP packet size: {}, min UDP packet size: {}, average UDP packet size: {}", max_udp, min_udp, avg_udp);

    println!("Number of other packets: {}", num_other);
    println!();

    // MAC Addresses
    let mut mac_address: HashSet<[u8; 6]> = HashSet::new();
    let mut ip_address: HashSet<[u8; 16]> = HashSet::new();
    let mut udp_ports: HashSet<u16> = HashSet::new();
    let mut tcp_ports: HashSet<u16> = HashSet::new();
    let empty_ip = [0; 16];
    let mut syn_and_fin = 0;
    let mut frag_count = 0;

    for packet in packets {
        mac_address.insert(packet.source_mac);
        mac_address.insert(packet.dest_mac);

        ip_address.insert(packet.source_ip);
        ip_address.insert(packet.dest_ip);

        match packet.transport_layer_type {
            TransportLayerType::TCP => {
                tcp_ports.insert(packet.source_port);
                tcp_ports.insert(packet.dest_port);
            },
            TransportLayerType::UDP => {
                udp_ports.insert(packet.source_port);
                udp_ports.insert(packet.dest_port);
            },
            _ => {},
        }

        if packet.is_syn || packet.is_fin {
            syn_and_fin += 1;
        }

        if packet.is_frag {
            frag_count += 1;
        }
    }

    println!("Unique MAC addresses: {}", mac_address.len());
    println!("Unique IP addresses: {}", ip_address.iter().filter(|&e| e != &empty_ip).count());
    println!("Unique UDP port numbers: {}", udp_ports.iter().filter(|&e| *e != 0).count());
    println!("Unique TCP port numbers: {}", tcp_ports.iter().filter(|&e| *e != 0).count());
    println!("Number of SYN and FIN packets: {}", syn_and_fin);
    println!("Number of fragmented packets: {}", frag_count);
}
