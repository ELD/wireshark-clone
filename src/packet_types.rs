pub enum LinkLayerType {
    Novell8023,
    Ethernet2,
}

pub enum NetworkLayerType {
    ARP,
    IPv4,
    IPv6,
    Other,
}

pub enum TransportLayerType {
    ICMP,
    TCP,
    UDP,
    Other,
}

pub struct PacketTypes {
    link_layer_type: LinkLayerType,
    network_layer_type: NetworkLayerType,
    transport_layer_type: TransportLayerType,
    packet_length: u32,
}

impl PacketTypes {
    pub fn new(data: &[u8], len: u32) -> Self {
        let mut frame_type = LinkLayerType::Novell8023;
        let mut network_type = NetworkLayerType::Other;
        let mut transport_type = TransportLayerType::Other;

        let ethertype = ((data[12] as u16) << 8) | (data[13] as u16);
        if ethertype >= 1536 {
            frame_type = LinkLayerType::Ethernet2;

            if ethertype == 0x0800 {
                network_type = NetworkLayerType::IPv4;
            } else if ethertype == 0x0806 {
                network_type = NetworkLayerType::ARP;
            } else if ethertype == 0x86DD {
                network_type = NetworkLayerType::IPv6;
            }
        }

        PacketTypes {
            link_layer_type: frame_type,
            network_layer_type: network_type,
            transport_layer_type: transport_type,
            packet_length: len,
        }
    }

    pub fn print_link_layer_type(&self) {
        let string_type: &'static str;

        match self.link_layer_type {
            LinkLayerType::Ethernet2 => string_type = "Ethernet II",
            LinkLayerType::Novell8023 => string_type = "Novell 802.3",
        }

        println!("Packet's link layer type: {}", string_type);
    }

    pub fn print_network_layer_type(&self) {
        let string_type: &'static str;

        match self.network_layer_type {
            NetworkLayerType::IPv4 => string_type = "IPv4",
            NetworkLayerType::IPv6 => string_type = "IPv6",
            NetworkLayerType::ARP => string_type = "ARP",
            NetworkLayerType::Other => string_type = "Other",
        }

        println!("Network layer type: {}", string_type);
    }
}
