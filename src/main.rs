extern crate pcap;

mod packet_types;

use std::env;
use pcap::Capture;
use packet_types::PacketTypes;

fn main() {
    let cap_file_name = env::args().nth(1).expect("Expected a command line parameter here");

    let mut capture = Capture::from_file(cap_file_name).ok().expect("Expected a valid capture file");

    let datalinks = capture.list_datalinks().ok().expect("Something went wrong reading the pcap file");

    for datalink in datalinks {
        println!("Datalink: {}", datalink.get_name().unwrap());
        println!("Datalink description: {}", datalink.get_description().unwrap());
    }

    let mut packet_count = 0;
    while let Ok(packet) = capture.next() {
//        println!("Found packet: {:?}", packet);

        // TODO: Classify packets based on data
        let packet_type: u16 = ((packet.data[12] as u16) << 8) | packet.data[13] as u16;

        let packet_struct = PacketTypes::new(packet.data);

        if packet_type >= 1536 {
            println!("This packet is an Ethernet II packet");
        } else {
            println!("This packet is a Novell 802.3 packet");
        }

        packet_count += 1;
    }

    println!("Number of packets processed: {}", packet_count);
}
