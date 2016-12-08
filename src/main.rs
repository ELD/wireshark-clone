extern crate pcap;

mod packet_types;

use std::env;
use pcap::Capture;
use packet_types::PacketTypes;

fn main() {
    let cap_file_name = env::args().nth(1).expect("Expected a command line parameter here");

    let mut capture = Capture::from_file(cap_file_name).ok().expect("Expected a valid capture file");

    let datalinks = capture.list_datalinks().ok().expect("Something went wrong reading the pcap file");

    let mut packets: Vec<PacketTypes> = Vec::new();
    while let Ok(packet) = capture.next() {
        packets.push(PacketTypes::new(packet.data));
    }

    packets[0].print_link_layer_type();

    println!("Number of packets processed: {}", packets.len());
}
