use std::process::Command;
use std::thread;
use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr};
use pcap::Capture;
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket};
use pnet::packet::udp::UdpPacket;
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
        ipv4_packet.get_next_level_protocol(),
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

fn process_pcap(file_path: &str, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, interface: &NetworkInterface) {
    let mut cap = Capture::from_file(file_path).expect("Failed to open PCAP file");

    let (mut tx, _rx) = match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => {
            eprintln!("Failed to create datalink channel: {}. Try running with elevated privileges or setting the CAP_NET_RAW capability.", e);
            return;
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
                    let mut ipv4_buffer = vec![0u8; Ipv4Packet::minimum_packet_size() + ipv4_packet.payload().len()];
                    let mut new_ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();

                    new_ipv4_packet.set_version(4); 
                    new_ipv4_packet.set_header_length(5);
                    new_ipv4_packet.set_total_length((Ipv4Packet::minimum_packet_size() + ipv4_packet.payload().len()) as u16);
                    new_ipv4_packet.set_ttl(64); 
                    new_ipv4_packet.set_next_level_protocol(ipv4_packet.get_next_level_protocol());

                    new_ipv4_packet.clone_from(&ipv4_packet);

                    new_ipv4_packet.set_source(src_ip);
                    new_ipv4_packet.set_destination(dst_ip);
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

                    let mut ethernet_buffer = vec![0u8; EthernetPacket::minimum_packet_size() + new_ipv4_packet.packet().len()];
                    let mut new_ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

                    new_ethernet_packet.set_source(ethernet_packet.get_source());
                    new_ethernet_packet.set_destination(ethernet_packet.get_destination());

                    new_ethernet_packet.set_ethertype(pnet::packet::ethernet::EtherTypes::Ipv4);
                    new_ethernet_packet.set_payload(new_ipv4_packet.packet());

                    println!("--- Ethernet Layer ---");
                    println!("Source MAC: {:?}", new_ethernet_packet.get_source());
                    println!("Destination MAC: {:?}", new_ethernet_packet.get_destination());
                    println!("EtherType: {:?}", new_ethernet_packet.get_ethertype());

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
                    } else if let Some(udp_packet) = UdpPacket::new(new_ipv4_packet.payload()) {
                        println!("--- UDP Layer ---");
                        println!("Source Port: {:?}", udp_packet.get_source());
                        println!("Destination Port: {:?}", udp_packet.get_destination());
                        println!("Length: {:?}", udp_packet.get_length());
                        println!("Checksum: {:?}", udp_packet.get_checksum());
                    }

                    println!("IPv4 Packet: {:?}", ipv4_packet);
                    println!("Ethernet Packet: {:?}", ethernet_packet);
                    println!("TCP Packet: {:?}", TcpPacket::new(ipv4_packet.payload()).unwrap());

                    println!("New IPv4 Packet: {:?}", new_ipv4_packet);
                    println!("New Ethernet Packet: {:?}", new_ethernet_packet);

                    thread::sleep(Duration::from_secs(5));
                    // Send 
                    if let Some(Err(e)) = tx.send_to(new_ethernet_packet.packet(), None) {
                        eprintln!("Failed to send packet: {}", e);
                    }
                }
            }
        }
    }
}

fn main() {
    // Esto la verdad que no funciona, hay que hacerlo manual por ahora
   /*Command::new("sudo")
        .arg("setcap")
        .arg("cap_net_raw=eip")
        .arg("target/debug/trafik")
        .status()
        .expect("Failed to grant permissions");
    */
    let pcap_file = "industroyer2.pcap";
    let destination_ip = Ipv4Addr::new(192, 168, 10, 3);

    let ueransim_thread = thread::spawn(|| {
        loop {
            println!("Interface 'uesimtun0' not found. Re-executing 'build/nr-ue'...");
            execute_command();
            thread::sleep(Duration::from_secs(5));
        }
    });

    // Empezar antes de ejecutar el otro hilo
    thread::sleep(Duration::from_secs(15));

    let interface_name = "uesimtun0";
    let interface = find_interface(interface_name).expect("Network interface not found");
    let source_ip = get_source_ip(&interface).expect("Failed to get source IP");

    let source_ip = match source_ip {
        IpAddr::V4(ipv4) => ipv4,
        _ => panic!("Expected an IPv4 address"),
    };

    process_pcap(pcap_file, source_ip, destination_ip, &interface);

    // Esto hay que mejorarlo
    ueransim_thread.join().unwrap();
}
