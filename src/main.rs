use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

use etherparse::IpHeader;
use etherparse::PacketHeaders;
use etherparse::TransportHeader;
use structopt::StructOpt;

// To hold user inputs (cli arguments)
#[derive(StructOpt)]
struct Cli {
    path: PathBuf,
    alarm_threshold: u32,
}

#[derive(PartialEq, Eq, Hash, Debug)]
enum Ip {
    V4([u8; 4]),
    V6([u8; 16]),
}

// Implement Display trait to make Ip struct printable
impl fmt::Display for Ip {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str_vec: Vec<String> = match self {
            Ip::V4(a) => a.iter().map(|v| v.to_string()).collect(),
            Ip::V6(a) => a.iter().map(|v| v.to_string()).collect(),
        };
        write!(f, "{}", str_vec.join("."))
    }
}

#[derive(PartialEq, Eq, Hash, Debug)]
struct PacketSrcDst {
    src: Ip,
    dst: Ip,
}

// To build a PacketSrcDst from an IpHeader
impl From<IpHeader> for PacketSrcDst {
    fn from(ip_header: IpHeader) -> Self {
        match ip_header {
            IpHeader::Version4(header) => PacketSrcDst {
                src: Ip::V4(header.source),
                dst: Ip::V4(header.destination),
            },
            IpHeader::Version6(header) => PacketSrcDst {
                src: Ip::V6(header.source),
                dst: Ip::V6(header.destination),
            },
        }
    }
}

fn main() {
    // parse arguments
    let args = Cli::from_args();

    // read the pcap capture from file
    let mut cap = pcap::Capture::from_file(args.path).unwrap();
    let mut nb_req_per_ip = HashMap::new();
    while let Ok(raw_packet) = cap.next() {
        // iterate over all packets
        let packet = PacketHeaders::from_ethernet_slice(raw_packet.data).unwrap();
        if let Some(ip_header) = packet.ip {
            // ignore "connection reset" (TCP) which are just answers from the victim
            if let Some(TransportHeader::Tcp(tcp_header)) = packet.transport {
                if tcp_header.rst {
                    continue;
                }
            }

            // count number of packets for the given connexion
            let key = PacketSrcDst::from(ip_header);
            let entry = nb_req_per_ip.entry(key).or_insert(0);
            *entry += 1;
        }
    }

    for item in nb_req_per_ip {
        if item.1 > args.alarm_threshold {
            println!(
                "{} may have attempted a port scan attack on {} ({} packets sent).",
                item.0.src, item.0.dst, item.1
            );
        }
    }
}
