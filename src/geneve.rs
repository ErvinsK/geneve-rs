pub const MIN_GENEVE_HDR: usize = 8;

// Enum for errors
#[derive(Debug)]
pub enum GeneveErr {
    NotGeneve,
    InvalidLength,
}


//   Geneve Packet:
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |       Geneve Header (with or without Option Fields)           |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                    Payload                                    |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// Implementation of GenevePacket
#[derive(Debug, PartialEq)]
pub struct GenevePacket<'a> {
    pub hdr: Header<'a>,
    offset: usize,
    pub payload: &'a [u8],
}

impl<'a> GenevePacket<'a> {
    pub fn new(packet: &[u8]) -> Option<GenevePacket> {
        if let Some((i, k)) = Header::unmarshal(packet) {
            Some(GenevePacket {
                hdr: i,
                offset: k,
                payload: packet,
            })
        } else {
            None
        }
    }
    pub fn marshal(&self, buffer: &mut Vec<u8>) -> Result<(), GeneveErr> {
        let mut hdr_buffer = vec![];
        self.hdr.marshal(&mut hdr_buffer)?;
        buffer.extend_from_slice(&hdr_buffer[..]);
        buffer.extend_from_slice(&self.payload[self.offset..]);

        Ok(())
    }

    pub fn marshal_to_slice(&self, buffer: &mut [u8]) -> Result<usize, GeneveErr> {
        let payload_len = self.payload[self.offset..].len();

        if buffer.len() < self.hdr.header_len() + payload_len {
            return Err(GeneveErr::InvalidLength)
        }

        let pos = self.hdr.marshal_to_slice(buffer)?;
        buffer[pos..(pos+payload_len)].copy_from_slice(&self.payload[self.offset..]);

        Ok(pos + payload_len)
    }

    pub fn unmarshal (buffer: &'a [u8]) -> Result<Self, GeneveErr> {
        if buffer.len() >= MIN_GENEVE_HDR {
            if let Some((i, cur)) = Header::unmarshal(buffer) {
                let pckt = GenevePacket {
                    hdr: i,
                    offset: cur,
                    payload: buffer,
                };
                Ok(pckt)
            } else {
                Err(GeneveErr::NotGeneve)
            }
        } else {
            Err(GeneveErr::InvalidLength)
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for GenevePacket<'a> {
    type Error = GeneveErr;
    fn try_from(packet: &'a [u8]) -> Result<Self, Self::Error> {
        if let Some((i, k)) = Header::unmarshal(packet) {
            Ok(GenevePacket {
                hdr: i,
                offset: k,
                payload: packet,
            })
        } else {
            Err(Self::Error::NotGeneve)
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
pub struct Header<'a> {
    pub version: u8,
    pub control_flag: bool,
    pub critical_flag: bool,
    pub protocol: u16,
    pub vni: u32,
    pub options: Option<Vec<TunnelOption<'a>>>,
    pub options_len: u8,
}

impl<'a> Header<'a> {
    /// Minimum size of a GENEVE header without any options present
    pub const MIN_SIZE: usize = 8;

    pub fn marshal(&self, buffer: &mut Vec<u8>) -> Result<(), GeneveErr> {
        let mut opt_buffer = vec![];
        if let Some(i) = &self.options {
            for i in i.iter() {
                i.marshal(&mut opt_buffer)?;
            }
        }
        buffer.extend_from_slice(&self.encode_header());
        buffer.extend_from_slice(&opt_buffer[..]);

        Ok(())
    }

    pub fn marshal_to_slice(&self, buffer: &mut [u8]) -> Result<usize, GeneveErr> {
        let len = self.header_len();

        if buffer.len() < len {
            return Err(GeneveErr::InvalidLength)
        }

        buffer[..Self::MIN_SIZE].copy_from_slice(&self.encode_header());

        let mut pos = Self::MIN_SIZE;
        if let Some(ref opts) = self.options {
            for opt in opts {
                pos += opt.marshal_to_slice(&mut buffer[pos..])?;
            }
        }

        Ok(pos)
    }

    fn encode_header(&self) -> [u8;8] {
        let mut buffer: [u8;Header::MIN_SIZE] = [0u8;Header::MIN_SIZE];

        buffer[0] = (self.version << 6) | (((self.opt_len() / 4) as u8) & 0x3f);

        let flags = match (&self.control_flag, &self.critical_flag) {
            (false, false) => 0x00,
            (true, false) => 0x80,
            (false, true) => 0x40,
            (true, true) => 0xc0,
        };

        buffer[1] = flags;
        buffer[2..=3].copy_from_slice(&self.protocol.to_be_bytes());
        buffer[4..=6].copy_from_slice(&self.vni.to_be_bytes()[1..]);
        buffer[7] = 0;

        buffer
    }

    pub fn opt_len(&self) -> usize {
        if let Some(ref opts) = self.options {
            opts.iter().fold(0, |acc, o| acc + o.opt_len() )
        } else {
            0
        }
    }

    pub fn header_len(&self) -> usize {
        Self::MIN_SIZE + self.opt_len()
    }

    pub fn unmarshal(buffer: &'a [u8]) -> Option<(Self, usize)> {
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
pub struct TunnelOption<'a> {
    pub option_class: u16,
    pub option_type: u8,
    pub c_flag: bool,
    pub data: Option<&'a [u8]>,
}

impl<'a> TunnelOption<'a> {
    const MIN_OPT_SIZE: usize = 4;
    const MAX_DATA_SIZE: usize = 128;

    pub fn marshal(&self, buffer: &mut Vec<u8>) -> Result<(), GeneveErr>{
        if self.data_len() > Self::MAX_DATA_SIZE {
            return Err(GeneveErr::InvalidLength)
        }

        let opt = self.encode_opt()?;
        buffer.extend_from_slice(&opt);

        let remainder_len = self.opt_len() - Self::MIN_OPT_SIZE - self.data_len();

        if let Some(i) = &self.data {
            match &i.len() % 4 {
                0 => {
                    buffer.extend_from_slice(&i[..]);
                }
                _ => {
                    buffer.extend_from_slice(&i[..]);
                    buffer.extend_from_slice(&vec![0;remainder_len]);
                }
            };
        }

        Ok(())
    }

    /// Encodes this tunnel option to a buffer of at least [`Self::len()`] bytes long, returning
    /// the size in bytes written to the buffer, or [`GeneveErr::InvalidLength`] if the buffer
    /// was of insufficient size, or the data payload of this tunnel option was greater than the
    /// maximum possible size.
    pub fn marshal_to_slice(&self, buffer: &mut [u8]) -> Result<usize, GeneveErr> {
        if self.data_len() > Self::MAX_DATA_SIZE {
            return Err(GeneveErr::InvalidLength)
        }
        if buffer.len() < self.opt_len() {
            return Err(GeneveErr::InvalidLength)
        }

        let opt = self.encode_opt()?;
        buffer[..opt.len()].copy_from_slice(&opt);

        let mut pos = opt.len();

        if let Some(data) = self.data {
            buffer[pos..(pos + data.len())].copy_from_slice(data);
            pos += data.len();

            for i in buffer.iter_mut().take(self.opt_len()).skip(pos) {
                *i = 0;
                pos += 1;
            }
        }

        Ok(pos)
    }

    /// Returns the number of bytes needed to encode this option. Length of GENEVE tunnel options
    /// are measured in 32-bit increments. A data payload size of 3 for example is automatically
    /// rounded up to 4 bytes.
    /// Each option can be between 4 and 128 bytes in length.
    pub fn opt_len(&self) -> usize {
        let data_len = self.data_len();
        let remainder_len = if data_len % 4 != 0 { 4 - (data_len % 4) } else { 0 };

        Self::MIN_OPT_SIZE + data_len + remainder_len
    }

    /// Returns the number of bytes needed to encode the data payload of this tunnel option.
    fn data_len(&self) -> usize {
        self.data.map_or(0, |d| d.len())
    }

    /// Encodes the option header as a 4 length u8 slice.
    fn encode_opt(&self) -> Result<[u8;4], GeneveErr> {
        let mut opt: [u8;4] = [0u8;4];

        opt[..2].copy_from_slice(&self.option_class.to_be_bytes());
        opt[2] = self.option_type | ((self.c_flag as u8) << 7);
        opt[3] = u8::div_ceil(self.data_len() as u8, 4);

        Ok(opt)
    }

    pub fn unmarshal(buffer: &'a [u8]) -> Option<Self> {
        if buffer.len() >= 4 {
            let data = TunnelOption {
                option_class: u16::from_be_bytes([buffer[0], buffer[1]]),
                option_type: 0x7f & buffer[2],
                c_flag: matches!(buffer[2] >> 7, 1),
                data: match ((buffer[3] & 0x1f) * 4) as usize {
                    0 => None,
                    i if i <= (buffer.len() - 4) => Some(&buffer[4..4 + i]),
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
        data: Some(&[0x00, 0x01]),
    };
    let encoded: [u8; 8] = [0xff, 0xff, 0x0a, 0x01, 0x00, 0x01, 0x00, 0x00];
    let mut buffer: Vec<u8> = vec![];
    decoded.marshal(&mut buffer).expect("failed to marshal");
    assert_eq!(buffer, encoded);

    let mut slice_buffer: [u8;128] = [0u8;128];
    let size = decoded.marshal_to_slice(&mut slice_buffer).expect("failed to marshal");
    assert_eq!(size, encoded.len());
    assert_eq!(&slice_buffer[..size], &encoded);

    let decoded_empty_data = TunnelOption {
        option_class: 0xffff,
        option_type: 0x0a,
        c_flag: false,
        data: None,
    };
    let encoded_empty_data: [u8; 4] = [0xff, 0xff, 0x0a, 0x00];
    let mut buffer: Vec<u8> = vec![];
    decoded_empty_data.marshal(&mut buffer).expect("failed to marshal");
    assert_eq!(buffer, encoded_empty_data);

    let mut slice_buffer: [u8;128] = [0u8;128];
    let size = decoded_empty_data.marshal_to_slice(&mut slice_buffer).expect("failed to marshal");
    assert_eq!(size, encoded_empty_data.len());

    let decoded_4_data = TunnelOption {
        option_class: 0xffff,
        option_type: 0x0a,
        c_flag: false,
        data: Some(&[1, 2, 3, 4]),
    };
    let encoded_4_data: [u8; 8] = [0xff, 0xff, 0x0a, 0x01, 1, 2, 3, 4];
    let mut buffer: Vec<u8> = vec![];
    decoded_4_data.marshal(&mut buffer).expect("failed to marshal");
    assert_eq!(buffer, encoded_4_data);

    let mut slice_buffer: [u8;128] = [0u8;128];
    let size = decoded_4_data.marshal_to_slice(&mut slice_buffer).expect("failed to marshal");
    assert_eq!(size, encoded_4_data.len());
    assert_eq!(&slice_buffer[..size], &encoded_4_data);
    assert_eq!(&slice_buffer[..size], &encoded_4_data);
}

#[test]
fn tunnel_option_marshal_invalid_length() {
    let really_long_data: [u8;1024] = [0u8;1024];
    let decoded = TunnelOption {
        option_class: 0xffff,
        option_type: 0x0a,
        c_flag: false,
        data: Some(&really_long_data),
    };

    let mut slice_buffer: [u8;128] = [0u8;128];
    assert!(decoded.marshal_to_slice(&mut slice_buffer).is_err());
}

#[test]
fn tunnel_option_marshal_slice_too_small_buffer() {
    let long_test_data: [u8;64] = [0u8;64];
    let decoded = TunnelOption {
        option_class: 0xffff,
        option_type: 0x0a,
        c_flag: false,
        data: Some(&long_test_data),
    };

    let mut slice_buffer: [u8;32] = [0u8;32];
    assert!(decoded.marshal_to_slice(&mut slice_buffer).is_err());
}

#[test]
fn tunnel_options_unmarshal() {
    let encoded: [u8; 8] = [0xff, 0xff, 0x0a, 0x01, 0x00, 0x01, 0x00, 0x00];
    let decoded = TunnelOption {
        option_class: 0xffff,
        option_type: 0x0a,
        c_flag: false,
        data: Some(&[0x00, 0x01, 0x00, 0x00]),
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
                data: Some(&[0x00, 0x01, 0x00, 0x00]),
            },
            TunnelOption {
                option_class: 0xffff,
                option_type: 0x0b,
                c_flag: false,
                data: Some(&[0x00, 0x02, 0x00, 0x00]),
            },
        ]),
        options_len: 0,
    };
    let encoded: [u8; 24] = [
        0x04, 0x00, 0x86, 0xdd, 0xaa, 0xaa, 0xee, 0x00, 0xff, 0xff, 0x0a, 0x01, 0x00, 0x01, 0x00,
        0x00, 0xff, 0xff, 0x0b, 0x01, 0x00, 0x02, 0x00, 0x00,
    ];
    let mut buffer: Vec<u8> = vec![];
    decoded.marshal(&mut buffer).expect("failed to marshal");
    assert_eq!(buffer, encoded);

    let mut buffer: [u8;128] = [0u8;128];
    let size = decoded.marshal_to_slice(&mut buffer).expect("failed to encode");
    assert_eq!(encoded.len(), size);
    assert_eq!(&buffer[..size], &encoded);
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
                data: Some(&[0x00, 0x01, 0x00, 0x00]),
            },
            TunnelOption {
                option_class: 0xffff,
                option_type: 0x0b,
                c_flag: false,
                data: Some(&[0x00, 0x02, 0x00, 0x00]),
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
fn geneve_packet_unmarshal() {
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
                data: Some(&[0x00, 0x01, 0x00, 0x00]),
            },
            TunnelOption {
                option_class: 0xffff,
                option_type: 0x0b,
                c_flag: false,
                data: Some(&[0x00, 0x02, 0x00, 0x00]),
            },
        ]),
        options_len: 16,
    };
    match GenevePacket::try_from(&encoded_payload[..]) {
        Ok(i) => assert_eq!(i.hdr, decoded_hdr),
        Err(_) => panic!(),
    }
}

#[test]
fn geneve_packet_marshal() {
    let encoded_payload: [u8; 30] = [
        0x04, 0x00, 0x86, 0xdd, 0xaa, 0xaa, 0xee, 0x00, 0xff, 0xff, 0x0a, 0x01, 0x00, 0x01, 0x00,
        0x00, 0xff, 0xff, 0x0b, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    if let Some(packet) = GenevePacket::new(&encoded_payload) {
        let mut buffer = vec![];
        packet.marshal(&mut buffer).expect("failed to marshal");
        assert_eq!(buffer, encoded_payload);

        let mut buffer: [u8;128] = [0u8;128];
        let size = packet.marshal_to_slice(&mut buffer).expect("failed to marshal");
        assert_eq!(size, encoded_payload.len());
        assert_eq!(&buffer[..size], &encoded_payload);
    }
}
