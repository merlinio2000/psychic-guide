use libwifi::FrameSubType;
use libwifi::FrameType;
use libwifi::{frame::components::MacAddress, Addresses};
use radiotap::Radiotap;

const DLT_IEEE802_11_RADIO: i32 = 127;

#[derive(Debug)]
enum FrameCaptureData {
    Beacon(libwifi::frame::Beacon),
    Client(ClientFrameCaptureData),
}

#[derive(Debug)]
struct ClientFrameCaptureData {
    src: Option<MacAddress>,
    dest: MacAddress,
    frame_type: FrameType,
    frame_subtype: FrameSubType,
}

#[derive(Debug)]
struct RadiotapCaptureData {
    antenna_noise: Option<i8>,
    antenna_signal: Option<i8>,
    channel: Option<radiotap::field::Channel>,
}

#[derive(Debug)]
struct CaptureData {
    frame_data: FrameCaptureData,
    radiotap_data: RadiotapCaptureData,
}

impl FrameCaptureData {
    fn from(frame: &libwifi::Frame) -> Option<Self> {
        use libwifi::Frame::*;
        use FrameCaptureData::*;

        match frame {
            libwifi::Frame::Beacon(pack) => Some(Self::Beacon(pack.to_owned())),
            ProbeRequest(pack) => Some(Client(ClientFrameCaptureData {
                src: pack.src().cloned(),
                dest: pack.dest().to_owned(),
                frame_type: pack.header.frame_control.frame_type,
                frame_subtype: pack.header.frame_control.frame_subtype,
            })),
            // ProbeResponse(_) => todo!(),
            AssociationRequest(pack) => Some(Client(ClientFrameCaptureData {
                src: pack.src().cloned(),
                dest: pack.dest().to_owned(),
                frame_type: pack.header.frame_control.frame_type,
                frame_subtype: pack.header.frame_control.frame_subtype,
            })),
            // AssociationResponse(_) => todo!(),
            // Rts(_) => todo!(),
            // Cts(_) => todo!(),
            // Ack(_) => todo!(),
            // BlockAckRequest(_) => todo!(),
            // BlockAck(_) => todo!(),
            Data(pack) => Some(Client(ClientFrameCaptureData {
                src: pack.src().cloned(),
                dest: pack.dest().to_owned(),
                frame_type: pack.header.frame_control.frame_type,
                frame_subtype: pack.header.frame_control.frame_subtype,
            })),
            NullData(pack) => Some(Client(ClientFrameCaptureData {
                src: pack.src().cloned(),
                dest: pack.dest().to_owned(),
                frame_type: pack.header.frame_control.frame_type,
                frame_subtype: pack.header.frame_control.frame_subtype,
            })),
            QosData(pack) => Some(Client(ClientFrameCaptureData {
                src: pack.src().cloned(),
                dest: pack.dest().to_owned(),
                frame_type: pack.header.frame_control.frame_type,
                frame_subtype: pack.header.frame_control.frame_subtype,
            })),
            QosNull(pack) => Some(Client(ClientFrameCaptureData {
                src: pack.src().cloned(),
                dest: pack.dest().to_owned(),
                frame_type: pack.header.frame_control.frame_type,
                frame_subtype: pack.header.frame_control.frame_subtype,
            })),
            _ => None,
        }
    }
}

impl From<Radiotap> for RadiotapCaptureData {
    fn from(radiotap: Radiotap) -> Self {
        Self {
            antenna_noise: radiotap.antenna_noise.map(|e| e.value),
            antenna_signal: radiotap.antenna_signal.map(|e| e.value),
            channel: radiotap.channel,
        }
    }
}

fn handle_capture(dot11frame: libwifi::Frame, radiotap: Radiotap) {
    if let Some(captured_frame) = FrameCaptureData::from(&dot11frame) {
        let capture = CaptureData {
            frame_data: captured_frame,
            radiotap_data: radiotap.into(),
        };

        println!("caught {capture:#?}");
    } else {
        println!("ignoring {dot11frame:?}");
    }
}

fn main() -> Result<(), pcap::Error> {
    let device = std::env::args().nth(1).unwrap_or("wlan0".to_owned());

    println!("going to listen on {device}");

    let mut cap = pcap::Capture::from_device(device.as_str())?
        .rfmon(true)
        .open()?;

    cap.set_datalink(pcap::Linktype(DLT_IEEE802_11_RADIO))?;

    while let Ok(packet) = cap.next_packet() {
        println!("received packet with header {:?}", packet.header);

        if let Ok(radiotap_header) = radiotap::Radiotap::from_bytes(packet.data) {
            // strip away the radiotap data from the 802.11 frame
            let payload = &packet.data[radiotap_header.header.length..];

            match libwifi::parse_frame(payload) {
                Ok(frame) => {
                    println!("successfully parsed 802.11 frame");
                    handle_capture(frame, radiotap_header);
                }
                Err(err) => eprintln!("failed to parse 802.11 frame {err}"),
            }
        }
        println!("\n{:-<50}\n", "");
    }

    Ok(())
}
