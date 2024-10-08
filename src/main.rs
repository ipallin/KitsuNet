use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::io::{Read, Write};
use pcap::Capture;
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket};
use pnet::datalink::NetworkInterface;
use pnet::datalink::{self, Channel::Ethernet};
use pnet::util::checksum;

fn set_tcp_checksum(ipv4_packet: &Ipv4Packet, tcp_packet: &mut MutableTcpPacket) {
    let checksum = pnet::util::ipv4_checksum(
        tcp_packet.packet(),
        tcp_packet.packet().len(),
        &[],
        &ipv4_packet.get_source(),
        &ipv4_packet.get_destination(),
        pnet::packet::ip::IpNextHeaderProtocols::Tcp,
    );
    tcp_packet.set_checksum(checksum);
}

fn execute_command() {
    println!("Executing 'build/nr-ue' command...");
    Command::new("sudo")
        .arg("ueransim/build/nr-ue")
        .arg("-c")
        .arg("ueransim/config/open5gs-ue.yaml")
        .status()
        .expect("Failed to execute 'build/nr-ue'");
}

fn find_interface(name: &str) -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();
    for iface in interfaces {
        if iface.name == name {
            return Some(iface);
        }
    }
    None
}

fn get_source_ip(interface: &NetworkInterface) -> Option<IpAddr> {
    for ip in &interface.ips {
        if let IpAddr::V4(ipv4) = ip.ip() {
            return Some(IpAddr::V4(ipv4));
        }
    }
    None
}

fn create_socket() -> TcpListener {
    let listener = TcpListener::bind(("0.0.0.0", 2404)).expect("Failed to bind to port 2404");
    listener
}

fn process_pcap(file_path: &str, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, interface: &NetworkInterface, mut socket: TcpStream) {
    loop {
        let mut cap = Capture::from_file(file_path).expect("Failed to open PCAP file");

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
                            // Only process the packet if the source port is 2404
                            if tcp_packet.get_source() == 2404 {
                                let total_length = Ipv4Packet::minimum_packet_size() + ipv4_packet.packet().len();
                                
                                // Check if the packet size is larger than the buffer
                                if total_length > 65535 {
                                    println!("Packet too large, skipping.");
                                    continue;
                                }

                                let mut ipv4_buffer = vec![0u8; total_length];
                                let mut new_ipv4_packet = match MutableIpv4Packet::new(&mut ipv4_buffer) {
                                    Some(packet) => packet,
                                    None => {
                                        println!("Failed to create new IPv4 packet, skipping.");
                                        continue;
                                    }
                                };

                                new_ipv4_packet.set_version(4); 
                                new_ipv4_packet.set_header_length(5);
                                new_ipv4_packet.set_total_length(total_length as u16);
                                new_ipv4_packet.set_ttl(64); 
                                new_ipv4_packet.set_next_level_protocol(ipv4_packet.get_next_level_protocol());

                                // Ensure the new packet buffer is large enough before cloning
                                if new_ipv4_packet.packet().len() < ipv4_packet.packet().len() {
                                    println!("New packet buffer too small, skipping.");
                                    continue;
                                }

                                new_ipv4_packet.clone_from(&ipv4_packet);

                                new_ipv4_packet.set_source(src_ip);
                                new_ipv4_packet.set_destination(dst_ip);  // Now uses client's IP as destination
                                new_ipv4_packet.set_checksum(0); 

                                // Calculate and set the checksum
                                let checksum = pnet::util::ipv4_checksum(
                                    new_ipv4_packet.packet(),
                                    new_ipv4_packet.packet().len(),
                                    &[],
                                    &new_ipv4_packet.get_source(),
                                    &new_ipv4_packet.get_destination(),
                                    new_ipv4_packet.get_next_level_protocol(),
                                );
                                new_ipv4_packet.set_checksum(checksum);

                                println!("--- IPv4 Layer ---");
                                println!("Source IP: {:?}", new_ipv4_packet.get_source());
                                println!("Destination IP: {:?}", new_ipv4_packet.get_destination());
                                println!("Protocol: {:?}", new_ipv4_packet.get_next_level_protocol());
                                println!("Checksum: {:?}", new_ipv4_packet.get_checksum());

                                if let Some(mut tcp_packet) = MutableTcpPacket::new(new_ipv4_packet.payload_mut()) {
                                    set_tcp_checksum(&ipv4_packet, &mut tcp_packet);
                                    println!("--- TCP Layer ---");
                                    println!("Source Port: {:?}", tcp_packet.get_source());
                                    println!("Destination Port: {:?}", tcp_packet.get_destination());
                                    println!("Sequence Number: {:?}", tcp_packet.get_sequence());
                                    println!("Acknowledgment Number: {:?}", tcp_packet.get_acknowledgement());
                                    println!("Flags: {:?}", tcp_packet.get_flags());
                                }

                                println!("New IPv4 Packet: {:?}", new_ipv4_packet);

                                // Send the packet through the TCP socket as a reply
                                if let Err(e) = socket.write_all(new_ipv4_packet.packet()) {
                                    eprintln!("Failed to send packet through TCP socket: {}", e);
                                }

                                // Wait for 1 second before sending the next packet
                                thread::sleep(Duration::from_secs(1));
                            } else {
                                println!("Skipping packet with source port: {:?}", tcp_packet.get_source());
                            }
                        }
                    }
                }
            }
        }
    }
}

fn main() {
    let pcap_file = "industroyer2.pcap";

    thread::sleep(Duration::from_secs(15));

    let interface_name = "ens3";
    let interface = find_interface(interface_name).expect("Network interface not found");
    let source_ip = get_source_ip(&interface).expect("Failed to get source IP");

    let source_ip = match source_ip {
        IpAddr::V4(ipv4) => ipv4,
        _ => panic!("Expected an IPv4 address"),
    };

    // Create the socket
    let listener = create_socket();
    println!("Server listening on port 2404");

    for stream in listener.incoming() {
        match stream {
            Ok(socket) => {
                // Extract the client's IP address from the socket
                let client_ip = match socket.peer_addr() {
                    Ok(addr) => match addr.ip() {
                        IpAddr::V4(ipv4) => ipv4,
                        _ => panic!("Expected an IPv4 address from the client"),
                    },
                    Err(e) => {
                        println!("Failed to get client address: {}", e);
                        continue;
                    }
                };

                println!("New connection from client IP: {}", client_ip);
                // Handle the connection and use client's IP as the destination IP
                process_pcap(pcap_file, source_ip, client_ip, &interface, socket);
            }
            Err(e) => {
                println!("Connection failed: {}", e);
            }
        }
    }
}