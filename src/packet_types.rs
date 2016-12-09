use std::cmp::{Ordering};

#[derive(PartialEq, Eq)]
pub enum LinkLayerType {
    Novell8023,
    Ethernet2,
}

#[derive(PartialEq, Eq)]
pub enum NetworkLayerType {
    ARP,
    IPv4,
    IPv6,
    Other,
}

#[derive(PartialEq, Eq)]
pub enum TransportLayerType {
    ICMP,
    TCP,
    UDP,
    Other,
}

#[derive(PartialEq, Eq)]
pub struct PacketTypes {
    pub link_layer_type: LinkLayerType,
    pub network_layer_type: NetworkLayerType,
    pub transport_layer_type: TransportLayerType,
    pub packet_length: u32,
    pub source_mac: [u8; 6],
    pub dest_mac: [u8; 6],
    pub source_ip: [u8; 16],
    pub dest_ip: [u8; 16],
    pub source_port: u16,
    pub dest_port: u16,
    pub is_syn: bool,
    pub is_fin: bool,
    pub is_frag: bool,
}

impl PacketTypes {
    pub fn new(data: &[u8], len: u32) -> Self {
        let mut frame_type = LinkLayerType::Novell8023;
        let mut network_type = NetworkLayerType::Other;
        let mut transport_type = TransportLayerType::Other;
        let mut source_ip: [u8; 16] = [0; 16];
        let mut dest_ip: [u8; 16] = [0; 16];
        let mut source_port = 0;
        let mut dest_port = 0;
        let mut is_syn = false;
        let mut is_fin = false;
        let mut is_frag = false;

        let ethertype = ((data[12] as u16) << 8) | (data[13] as u16);
        if ethertype >= 1536 {
            frame_type = LinkLayerType::Ethernet2;

            if ethertype == 0x0800 {
                network_type = NetworkLayerType::IPv4;
                source_ip[0] = data[26];
                source_ip[1] = data[27];
                source_ip[2] = data[28];
                source_ip[3] = data[29];

                dest_ip[0] = data[30];
                dest_ip[1] = data[31];
                dest_ip[2] = data[32];
                dest_ip[3] = data[33];
            } else if ethertype == 0x0806 {
                network_type = NetworkLayerType::ARP;
                source_ip[0] = data[29];
                source_ip[1] = data[30];
                source_ip[2] = data[31];
                source_ip[3] = data[32];

                dest_ip[0] = data[38];
                dest_ip[1] = data[39];
                dest_ip[2] = data[40];
                dest_ip[3] = data[41];
            } else if ethertype == 0x86DD {
                network_type = NetworkLayerType::IPv6;
                source_ip.clone_from_slice(&data[21..37]);
                dest_ip.clone_from_slice(&data[38..54]);
            }

            match network_type {
                NetworkLayerType::IPv4 => {
                    let protocol_code = data[23];
                    transport_type = get_trans_type(protocol_code);

                    let frag_bits = (data[20] << 2 as u8) >> 7;
                    if frag_bits == 1 {
                        is_frag = true;
                    }
                },
                NetworkLayerType::IPv6 => {
                    let protocol_code = data[20];
                    transport_type = get_trans_type(protocol_code);
                },
                _ => transport_type = TransportLayerType::Other,
            }

            match transport_type {
                TransportLayerType::TCP => {
                    source_port = ((data[34] as u16) << 8) | (data[35] as u16);
                    dest_port = ((data[36] as u16) << 8) | (data[37] as u16);
                    let fin_bit = (data[47] << 7 as u8) >> 7;
                    let syn_bit = (data[47] << 6 as u8) >> 7;
                    if fin_bit == 1 {
                        is_fin = true;
                    }

                    if syn_bit == 1 {
                        is_syn = true;
                    }
                },
                TransportLayerType::UDP => {
                    source_port = ((data[34] as u16) << 8) | (data[35] as u16);
                    dest_port = ((data[36] as u16) << 8) | (data[37] as u16);
                },
                _ => {},
            }
        }

        PacketTypes {
            link_layer_type: frame_type,
            network_layer_type: network_type,
            transport_layer_type: transport_type,
            packet_length: len,
            source_mac: [data[0], data[1], data[2], data[3], data[4], data[5]],
            dest_mac: [data[6], data[7], data[8], data[9], data[10], data[11]],
            source_ip: source_ip,
            dest_ip: dest_ip,
            source_port: source_port,
            dest_port: dest_port,
            is_syn: is_syn,
            is_fin: is_fin,
            is_frag: is_frag,
        }
    }
}

impl PartialOrd for PacketTypes {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PacketTypes {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.packet_length < other.packet_length {
            return Ordering::Less
        } else if self.packet_length > other.packet_length {
            return Ordering::Greater
        } else {
            return Ordering::Equal
        }
    }
}

fn get_trans_type(protocol_code: u8) -> TransportLayerType {
    match protocol_code {
        1 => return TransportLayerType::ICMP,
        6 => TransportLayerType::TCP,
        17 => TransportLayerType::UDP,
        _ => return TransportLayerType::Other,
    }
}
