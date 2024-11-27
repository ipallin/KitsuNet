use pcap::Capture;
use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
use pnet::packet::udp::UdpPacket;
use pnet::packet::{MutablePacket, Packet};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::thread;
use std::time::Duration;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink;
use crate::bin::network::{set_ipv4_checksum, set_tcp_checksum};

pub fn process_pcap(
    file_path: &str,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    interface: &NetworkInterface,
    mut socket: TcpStream,
)  {
    loop {
        let mut cap = match Capture::from_file(file_path) {
            Ok(cap) => cap,
            Err(e) => {
                eprintln!("Failed to open PCAP file: {}. Retrying...", e);
                thread::sleep(Duration::from_secs(5));
                continue;
            }
        };

        let (mut tx, _rx) = match datalink::channel(interface, Default::default()) {
            Ok(Ethernet(tx, _rx)) => (tx, _rx),
            Ok(_) => {
                eprintln!("Unhandled channel type. Retrying...");
                thread::sleep(Duration::from_secs(5));
                continue;
            }
            Err(e) => {
                eprintln!("Failed to create datalink channel: {}. Retrying...", e);
                thread::sleep(Duration::from_secs(5));
                continue;
            }
        };

        while let Ok(packet) = cap.next_packet() {
            let payload = packet.data;

            if payload.len() < EthernetPacket::minimum_packet_size() {
                println!("Packet too small, skipping.");
                continue;
            }

            if let Some(ethernet_packet) = EthernetPacket::new(payload) {
                if ethernet_packet.get_ethertype() == pnet::packet::ethernet::EtherTypes::Ipv4 {
                    if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                        if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                            if tcp_packet.get_destination() == 2404 {
                                let mut ipv4_buffer = vec![
                                    0u8;
                                    Ipv4Packet::minimum_packet_size()
                                        + ipv4_packet.payload().len()
                                ];
                                let mut new_ipv4_packet =
                                    match MutableIpv4Packet::new(&mut ipv4_buffer) {
                                        Some(packet) => packet,
                                        None => {
                                            eprintln!(
                                                "Failed to create mutable IPv4 packet. Retrying..."
                                            );
                                            thread::sleep(Duration::from_secs(5));
                                            continue;
                                        }
                                    };

                                new_ipv4_packet.set_version(4);
                                new_ipv4_packet.set_header_length(5);
                                new_ipv4_packet.set_total_length(
                                    (Ipv4Packet::minimum_packet_size()
                                        + ipv4_packet.payload().len())
                                        as u16,
                                );
                                new_ipv4_packet.set_ttl(64);
                                new_ipv4_packet
                                    .set_next_level_protocol(ipv4_packet.get_next_level_protocol());

                                new_ipv4_packet.clone_from(&ipv4_packet);

                                new_ipv4_packet.set_source(src_ip);
                                new_ipv4_packet.set_destination(dst_ip);
                                set_ipv4_checksum(&mut new_ipv4_packet); // Calculate and set IPv4 checksum

                                println!("--- IPv4 Layer ---");
                                println!("Source IP: {:?}", new_ipv4_packet.get_source());
                                println!("Destination IP: {:?}", new_ipv4_packet.get_destination());
                                println!(
                                    "Protocol: {:?}",
                                    new_ipv4_packet.get_next_level_protocol()
                                );
                                println!("Checksum: {:?}", new_ipv4_packet.get_checksum());

                                if let Some(mut tcp_packet) =
                                    MutableTcpPacket::new(new_ipv4_packet.payload_mut())
                                {
                                    set_tcp_checksum(&ipv4_packet, &mut tcp_packet); // Calculate and set TCP checksum
                                    println!("--- TCP Layer ---");
                                    println!("Source Port: {:?}", tcp_packet.get_source());
                                    println!(
                                        "Destination Port: {:?}",
                                        tcp_packet.get_destination()
                                    );
                                    println!("Sequence Number: {:?}", tcp_packet.get_sequence());
                                    println!(
                                        "Acknowledgment Number: {:?}",
                                        tcp_packet.get_acknowledgement()
                                    );
                                    println!("Flags: {:?}", tcp_packet.get_flags());
                                } else if let Some(udp_packet) =
                                    UdpPacket::new(new_ipv4_packet.payload())
                                {
                                    println!("--- UDP Layer ---");
                                    println!("Source Port: {:?}", udp_packet.get_source());
                                    println!(
                                        "Destination Port: {:?}",
                                        udp_packet.get_destination()
                                    );
                                    println!("Length: {:?}", udp_packet.get_length());
                                    println!("Checksum: {:?}", udp_packet.get_checksum());
                                }

                                println!("IPv4 Packet: {:?}", ipv4_packet);
                                println!("Ethernet Packet: {:?}", ethernet_packet);
                                println!(
                                    "TCP Packet: {:?}",
                                    TcpPacket::new(ipv4_packet.payload()).unwrap()
                                );

                                println!("New IPv4 Packet: {:?}", new_ipv4_packet);

                                // Send
                                if let Some(Err(e)) = tx.send_to(new_ipv4_packet.packet(), None) {
                                    eprintln!("Failed to send packet: {}. Retrying...", e);
                                    thread::sleep(Duration::from_secs(5));
                                    continue;
                                }

                                // Send the packet through the TCP socket
                                if let Err(e) = socket.write_all(new_ipv4_packet.packet()) {
                                    eprintln!(
                                        "Failed to send packet through TCP socket: {}. Retrying...",
                                        e
                                    );
                                    thread::sleep(Duration::from_secs(5));
                                    continue;
                                }

                                // Print the entire sent packet data in hexadecimal format
                                let sent_packet_hex: String = new_ipv4_packet
                                    .packet()
                                    .iter()
                                    .map(|byte| format!("{:02x}", byte))
                                    .collect();
                                println!("Sent Packet Data: {}", sent_packet_hex);
                            } else {
                                // Listen on the socket and skip one PCAP row for each packet received
                                let mut buffer = [0; 1024];
                                socket
                                    .set_read_timeout(Some(Duration::from_secs(10)))
                                    .expect("Failed to set read timeout");
                                match socket.read(&mut buffer) {
                                    Ok(_) => {
                                        println!(
                                            "Received packet on socket, skipping one PCAP row."
                                        );
                                        continue;
                                    }
                                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                        println!("Timeout reached, skipping to the next packet.");
                                        continue;
                                    }
                                    Err(e) => {
                                        eprintln!("Failed to read from socket: {}. Retrying...", e);
                                        thread::sleep(Duration::from_secs(5));
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}