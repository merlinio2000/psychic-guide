use bluer::{Adapter, AdapterEvent, Address, Device};
use futures::{pin_mut, StreamExt};
use std::{fs, io::Write};
use tokio::sync::Mutex;

#[derive(Debug)]
struct KnownDevice {
    addr: Address,
    name: Option<String>,
    class: Option<u32>,
    rssi_hist: Vec<Option<i16>>,
}

impl KnownDevice {
    async fn from(device: Device) -> bluer::Result<Self> {
        Ok(Self {
            addr: device.address(),
            name: device.name().await?,
            class: device.class().await?,
            rssi_hist: vec![device.rssi().await?],
        })
    }
}

async fn handle_discovery(
    adapter: &Adapter,
    known_devices: &Mutex<Vec<KnownDevice>>,
    addr: Address,
) -> bluer::Result<()> {
    let device = adapter.device(addr)?;
    let res = KnownDevice::from(device).await;

    match res {
        Err(err) => println!("    Error: {}", &err),
        Ok(discovered_device) => {
            let device_store = &mut *known_devices.lock().await;

            if let Some(existing_device) = device_store.iter_mut().find(|d| d.addr == addr) {
                existing_device
                    .rssi_hist
                    .push(discovered_device.rssi_hist[0]);
            } else {
                device_store.push(discovered_device);
            }

            let mut new_log =
                fs::File::create("log.tmp").expect("failed to create temporary log file");
            write!(&mut new_log, "{:#?}", device_store).expect("failed to write new_log");
            new_log.sync_all()?;

            match fs::remove_file("log.txt") {
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
                Ok(_) => {}
            }
        }
    }

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> bluer::Result<()> {
    env_logger::init();
    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;
    println!(
        "Discovering devices using default Bluetooth adapter {}\n",
        adapter.name()
    );
    adapter.set_powered(true).await?;

    let known_devices: Mutex<Vec<KnownDevice>> = Default::default();

    let device_events = adapter.discover_devices().await?;
    pin_mut!(device_events);

    loop {
        tokio::select! {
            Some(device_event) = device_events.next() => {
                match device_event {
                    AdapterEvent::DeviceAdded(addr) => {
                        println!("Device added: {addr}");
                        handle_discovery(&adapter, &known_devices, addr).await?;
                    }
                    AdapterEvent::DeviceRemoved(addr) => {
                        println!("Device removed: {addr}");
                    }
                    _ => (),
                }
                println!();
            }
            else => break
        }
    }

    Ok(())
}
