use pnet::datalink::NetworkInterface;
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
use pnet::packet::udp::UdpPacket;
use pnet::packet::{MutablePacket, Packet};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

pub fn set_ipv4_checksum(packet: &mut MutableIpv4Packet) {
    packet.set_checksum(0);
}

pub fn set_tcp_checksum(ipv4_packet: &Ipv4Packet, tcp_packet: &mut MutableTcpPacket) {
    tcp_packet.set_checksum(0);
}

pub fn find_interface(name: &str) -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();
    for iface in interfaces {
        if iface.name == name {
            return Some(iface);
        }
    }
    None
}

pub fn get_source_ip(interface: &NetworkInterface) -> Option<IpAddr> {
    for ip in &interface.ips {
        if let IpAddr::V4(ipv4) = ip.ip() {
            return Some(IpAddr::V4(ipv4));
        }
    }
    None
}

pub fn create_socket() -> TcpListener {
    TcpListener::bind(("0.0.0.0", 2404)).expect("Failed to bind to port 2404")
}

pub fn create_bound_socket(
    remote_ip: &str,
    remote_port: u16,
    local_iface: &str,
) -> std::io::Result<TcpStream> {
    let remote_addr = format!("{}:{}", remote_ip, remote_port);
    let remote_socket_addr: SocketAddr = remote_addr.parse().unwrap();

    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.bind_device(Some(local_iface.as_bytes()))?;
    socket.connect(&remote_socket_addr.into())?;

    let stream: TcpStream = socket.into();
    Ok(stream)
}