pub const MIN_GENEVE_HDR: usize = 8;

//   Geneve Packet:
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |       Geneve Header (with or without Option Fields)           |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                    Payload                                    |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(Debug, PartialEq)]
pub struct GenevePacket {
    pub hdr: Header,
    pub payload: Vec<u8>,
}

impl GenevePacket {
    pub fn marshal(&self, buffer: &mut Vec<u8>) {
        self.hdr.marshal(buffer);
        buffer.extend_from_slice(&self.payload[..]);
    }
    pub fn unmarshal(buffer: &[u8]) -> Option<Self> {
        if buffer.len() >= MIN_GENEVE_HDR {
            if let Some((i, cursor)) = Header::unmarshal(buffer) {
                let pckt = GenevePacket {
                    hdr: i,
                    payload: buffer[cursor..].to_vec(),
                };
                return Some(pckt);
            }
            None
        } else {
            None
        }
    }
}

// Zero copy implementation of GenevePacket
pub struct GenevePacketZC<'a> {
    pub hdr: Option<Header>,
    pub offset: usize,
    pub payload: &'a [u8],
}

impl<'a> GenevePacketZC<'a> {
    pub fn new(packet: &'a [u8]) -> GenevePacketZC {
        if let Some((i, k)) = Header::unmarshal(packet) {
            GenevePacketZC {
                hdr: Some(i),
                offset: k,
                payload: packet,
            }
        } else {
            GenevePacketZC {
                hdr: None,
                offset: 0,
                payload: packet,
            }
        }
    }
    pub fn marshal(&self, buffer: &mut Vec<u8>) {
        if let Some(i) = &self.hdr {
            let mut hdr_buffer = vec![];
            i.marshal(&mut hdr_buffer);
            buffer.extend_from_slice(&hdr_buffer[..]);
            buffer.extend_from_slice(&self.payload[self.offset..]);
        }
    }
}

impl<'a> From<&'a [u8]> for GenevePacketZC<'a> {
    fn from(packet: &'a [u8]) -> Self {
        if let Some((i, k)) = Header::unmarshal(packet) {
            GenevePacketZC {
                hdr: Some(i),
                offset: k,
                payload: packet,
            }
        } else {
            GenevePacketZC {
                hdr: None,
                offset: 0,
                payload: packet,
            }
        }
    }
}
//   Geneve Header:
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |        Virtual Network Identifier (VNI)       |    Reserved   |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                    Variable Length Options                    |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(Debug, PartialEq)]
pub struct Header {
    pub version: u8,
    pub control_flag: bool,
    pub critical_flag: bool,
    pub protocol: u16,
    pub vni: u32,
    pub options: Option<Vec<TunnelOption>>,
    pub options_len: u8,
}

impl Header {
    pub fn marshal(&self, buffer: &mut Vec<u8>) {
        let mut opt_buffer = vec![];
        if let Some(i) = &self.options {
            for i in i.iter() {
                i.marshal(&mut opt_buffer);
            }
        }
        buffer.push((&self.version << 6) | (((opt_buffer.len() / 4) as u8) & 0x3f));
        match (&self.control_flag, &self.critical_flag) {
            (false, false) => buffer.push(0x00),
            (true, false) => buffer.push(0x80),
            (false, true) => buffer.push(0x40),
            (true, true) => buffer.push(0xc0),
        }
        buffer.extend_from_slice(&self.protocol.to_be_bytes());
        buffer.extend_from_slice(&self.vni.to_be_bytes()[1..]);
        buffer.push(0x00);
        buffer.extend_from_slice(&opt_buffer[..]);
    }
    pub fn unmarshal(buffer: &[u8]) -> Option<(Self, usize)> {
        if buffer.len() >= MIN_GENEVE_HDR {
            let mut cursor: usize = MIN_GENEVE_HDR;
            let data = Header {
                version: match buffer[0] >> 6 {
                    0 => 0,
                    _ => return None,
                },
                control_flag: matches!(buffer[1] >> 7, 1),
                critical_flag: matches!((buffer[1] & 0x40) >> 6, 1),
                protocol: u16::from_be_bytes([buffer[2], buffer[3]]),
                vni: u32::from_be_bytes([0x00, buffer[4], buffer[5], buffer[6]]),
                options: match ((buffer[0] & 0x3f) * 4) as usize {
                    0 => None,
                    i => {
                        if i <= (buffer.len() - MIN_GENEVE_HDR) {
                            let mut vector: Vec<TunnelOption> = vec![];
                            while let Some(k) = TunnelOption::unmarshal(
                                &buffer[cursor..(((buffer[0] & 0x3f) * 4) + 8).into()],
                            ) {
                                cursor += k.advance();
                                vector.push(k);
                            }
                            Some(vector)
                        } else {
                            None
                        }
                    }
                },
                options_len: (buffer[0] & 0x3f) * 4,
            };
            Some((data, cursor))
        } else {
            None
        }
    }
}

//  Geneve Option:
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |          Option Class         |      Type     |R|R|R| Length  |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                      Variable Option Data                     |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(Debug, PartialEq)]
pub struct TunnelOption {
    pub option_class: u16,
    pub option_type: u8,
    pub c_flag: bool,
    pub data: Option<Vec<u8>>,
}

impl TunnelOption {
    pub fn marshal(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.option_class.to_be_bytes());
        match self.c_flag {
            true => buffer.push(0x80 | self.option_type),
            false => buffer.push(0x7f & self.option_type),
        }
        if let Some(i) = &self.data {
            match &i.len() % 4 {
                0 => {
                    buffer.push((i.len() / 4) as u8);
                    buffer.extend_from_slice(&i[..]);
                }
                _ => {
                    buffer.push(((i.len() + (4 - (i.len() % 4))) / 4) as u8);
                    buffer.extend_from_slice(&i[..]);
                    buffer.extend_from_slice(&vec![0; 4 - (i.len() % 4)]);
                }
            };
        } else {
            buffer.push(0x00);
        }
    }

    pub fn unmarshal(buffer: &[u8]) -> Option<Self> {
        if buffer.len() >= 4 {
            let data = TunnelOption {
                option_class: u16::from_be_bytes([buffer[0], buffer[1]]),
                option_type: 0x7f & buffer[2],
                c_flag: matches!(buffer[2] >> 7, 1),
                data: match ((buffer[3] & 0x1f) * 4) as usize {
                    0 => None,
                    i if i <= (buffer.len() - 4) => Some(buffer[4..4 + i].to_vec()),
                    _ => return None,
                },
            };
            Some(data)
        } else {
            None
        }
    }

    pub fn advance(&self) -> usize {
        match &self.data {
            Some(i) => match &i.len() % 4 {
                0 => i.len() + 4,
                _ => (i.len() + (4 - (i.len() % 4))) / 4,
            },
            None => 4,
        }
    }
}

#[test]
fn tunnel_options_marshal() {
    let decoded = TunnelOption {
        option_class: 0xffff,
        option_type: 0x0a,
        c_flag: false,
        data: Some(vec![0x00, 0x01]),
    };
    let encoded: [u8; 8] = [0xff, 0xff, 0x0a, 0x01, 0x00, 0x01, 0x00, 0x00];
    let mut buffer: Vec<u8> = vec![];
    decoded.marshal(&mut buffer);
    assert_eq!(buffer, encoded);
}

#[test]
fn tunnel_options_unmarshal() {
    let encoded: [u8; 8] = [0xff, 0xff, 0x0a, 0x01, 0x00, 0x01, 0x00, 0x00];
    let decoded = TunnelOption {
        option_class: 0xffff,
        option_type: 0x0a,
        c_flag: false,
        data: Some(vec![0x00, 0x01, 0x00, 0x00]),
    };
    if let Some(i) = TunnelOption::unmarshal(&encoded) {
        assert_eq!(i, decoded);
    }
}

#[test]
fn geneve_header_marshal() {
    let decoded = Header {
        version: 0,
        control_flag: false,
        critical_flag: false,
        protocol: 0x86dd,
        vni: 0x00aaaaee,
        options: Some(vec![
            TunnelOption {
                option_class: 0xffff,
                option_type: 0x0a,
                c_flag: false,
                data: Some(vec![0x00, 0x01, 0x00, 0x00]),
            },
            TunnelOption {
                option_class: 0xffff,
                option_type: 0x0b,
                c_flag: false,
                data: Some(vec![0x00, 0x02, 0x00, 0x00]),
            },
        ]),
        options_len: 0,
    };
    let encoded: [u8; 24] = [
        0x04, 0x00, 0x86, 0xdd, 0xaa, 0xaa, 0xee, 0x00, 0xff, 0xff, 0x0a, 0x01, 0x00, 0x01, 0x00,
        0x00, 0xff, 0xff, 0x0b, 0x01, 0x00, 0x02, 0x00, 0x00,
    ];
    let mut buffer: Vec<u8> = vec![];
    decoded.marshal(&mut buffer);
    assert_eq!(buffer, encoded);
}

#[test]
fn geneve_header_unmarshal() {
    let decoded = Header {
        version: 0,
        control_flag: false,
        critical_flag: false,
        protocol: 0x86dd,
        vni: 0x00aaaaee,
        options: Some(vec![
            TunnelOption {
                option_class: 0xffff,
                option_type: 0x0a,
                c_flag: false,
                data: Some(vec![0x00, 0x01, 0x00, 0x00]),
            },
            TunnelOption {
                option_class: 0xffff,
                option_type: 0x0b,
                c_flag: false,
                data: Some(vec![0x00, 0x02, 0x00, 0x00]),
            },
        ]),
        options_len: 16,
    };
    let encoded: [u8; 24] = [
        0x04, 0x00, 0x86, 0xdd, 0xaa, 0xaa, 0xee, 0x00, 0xff, 0xff, 0x0a, 0x01, 0x00, 0x01, 0x00,
        0x00, 0xff, 0xff, 0x0b, 0x01, 0x00, 0x02, 0x00, 0x00,
    ];
    if let Some((i, _)) = Header::unmarshal(&encoded) {
        assert_eq!(i, decoded);
    }
}

#[test]
fn geneve_packet_zc_unmarshal() {
    let encoded_payload: [u8; 30] = [
        0x04, 0x00, 0x86, 0xdd, 0xaa, 0xaa, 0xee, 0x00, 0xff, 0xff, 0x0a, 0x01, 0x00, 0x01, 0x00,
        0x00, 0xff, 0xff, 0x0b, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let decoded_hdr = Header {
        version: 0,
        control_flag: false,
        critical_flag: false,
        protocol: 0x86dd,
        vni: 0x00aaaaee,
        options: Some(vec![
            TunnelOption {
                option_class: 0xffff,
                option_type: 0x0a,
                c_flag: false,
                data: Some(vec![0x00, 0x01, 0x00, 0x00]),
            },
            TunnelOption {
                option_class: 0xffff,
                option_type: 0x0b,
                c_flag: false,
                data: Some(vec![0x00, 0x02, 0x00, 0x00]),
            },
        ]),
        options_len: 16,
    };
    let packet = GenevePacketZC::from(&encoded_payload[..]);
    //let packet = GenevePacket::new(&encoded_payload);
    if let Some(i) = packet.hdr {
        assert_eq!(i, decoded_hdr);
    }
}

#[test]
fn geneve_packet_zc_marshal() {
    let encoded_payload: [u8; 30] = [
        0x04, 0x00, 0x86, 0xdd, 0xaa, 0xaa, 0xee, 0x00, 0xff, 0xff, 0x0a, 0x01, 0x00, 0x01, 0x00,
        0x00, 0xff, 0xff, 0x0b, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let packet = GenevePacketZC::new(&encoded_payload);
    if packet.hdr.is_some() {
        let mut buffer = vec![];
        packet.marshal(&mut buffer);
        assert_eq!(buffer, encoded_payload);
    }
}

#[test]
fn geneve_packet_unmarshal() {
    let header = Header {
        version: 0,
        control_flag: false,
        critical_flag: false,
        protocol: 0x86dd,
        vni: 0x00aaaaee,
        options: Some(vec![
            TunnelOption {
                option_class: 0xffff,
                option_type: 0x0a,
                c_flag: false,
                data: Some(vec![0x00, 0x01, 0x00, 0x00]),
            },
            TunnelOption {
                option_class: 0xffff,
                option_type: 0x0b,
                c_flag: false,
                data: Some(vec![0x00, 0x02, 0x00, 0x00]),
            },
        ]),
        options_len: 16,
    };
    let decoded = GenevePacket {
        hdr: header,
        payload: [0xff, 0xff, 0xff].to_vec(),
    };
    let encoded: [u8; 27] = [
        0x04, 0x00, 0x86, 0xdd, 0xaa, 0xaa, 0xee, 0x00, 0xff, 0xff, 0x0a, 0x01, 0x00, 0x01, 0x00,
        0x00, 0xff, 0xff, 0x0b, 0x01, 0x00, 0x02, 0x00, 0x00, 0xff, 0xff, 0xff,
    ];
    assert_eq!(decoded, GenevePacket::unmarshal(&encoded).unwrap());
}
