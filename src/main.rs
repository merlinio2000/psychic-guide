use pcap::Device;

const DLT_IEEE802_11_RADIO: i32 = 127;

fn main() -> Result<(), pcap::Error> {
    let mut cap = Device::lookup()?.unwrap().open()?;

    cap.set_datalink(pcap::Linktype(DLT_IEEE802_11_RADIO))?;

    while let Ok(packet) = cap.next_packet() {
        println!("received packet {:?}", packet);

        if let Ok(radiotap_header) = radiotap::Radiotap::from_bytes(packet.data) {
            println!("radiotap {radiotap_header:?}");

            // strip away the radiotap data from the 802.11 frame
            let payload = &packet.data[radiotap_header.header.length..];

            match libwifi::parse_frame(payload) {
                Ok(frame) => println!("802.11 frame {frame:?}"),
                Err(err) => eprintln!("failed to parse 802.11 frame {err}"),
            }
        }
    }

    Ok(())
}
