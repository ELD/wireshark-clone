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
}

impl PacketTypes {
    pub fn new(data: &[u8]) -> Self {
        let frame_type: u16 = (data[12] as u16) << 8 | data[13] as u16;
        let network_type = 0;
        let transport_type = 0;

        if frame_type <= 1536 {
            return PacketTypes {
                link_layer_type: LinkLayerType::Novell8023,
                network_layer_type: NetworkLayerType::Other,
                transport_layer_type: TransportLayerType::Other
            };
        } else {
            // TODO: Search Network and Transport types
        }

        PacketTypes {
            link_layer_type: LinkLayerType::Ethernet2,
            network_layer_type: NetworkLayerType::ARP,
            transport_layer_type: TransportLayerType::ICMP,
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
}
