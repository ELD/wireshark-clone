extern crate pcap;

use std::env;
use pcap::Capture;

fn main() {
    let cap_file_name = env::args().nth(1).expect("Expected a command line parameter here");

    let mut capture = Capture::from_file(cap_file_name).ok().expect("Expected a valid capture file");

    let datalinks = capture.list_datalinks().ok().expect("Something went wrong reading the pcap file");

    for datalink in datalinks {
        println!("Datalink: {}", datalink.get_name().unwrap());
        println!("Datalink description: {}", datalink.get_description().unwrap());
    }

    while let Ok(packet) = capture.next() {
        println!("Found packet: {:?}", packet);
    }
}
