extern crate pcap;

mod packet_types;

use std::env;
use pcap::Capture;
use packet_types::PacketTypes;

fn main() {
    let cap_file_name = env::args().nth(1).expect("Expected a command line parameter here");

    let mut capture = Capture::from_file(cap_file_name).ok().expect("Expected a valid capture file");

    let mut packets: Vec<PacketTypes> = Vec::new();
    while let Ok(packet) = capture.next() {
        packets.push(PacketTypes::new(packet.data, packet.header.len));
    }

    for packet in packets.iter() {
        packet.print_link_layer_type();
        packet.print_network_layer_type();
    }

    println!("Number of packets processed: {}", packets.len());
}
