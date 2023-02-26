use btleplug::api::{bleuuid::BleUuid, Central, CentralEvent, Manager as _, ScanFilter};
use btleplug::platform::{Adapter, Manager};
use futures::stream::StreamExt;
use std::error::Error;

async fn get_central(manager: &Manager) -> Adapter {
    let adapters = manager.adapters().await.unwrap();
    adapters.into_iter().nth(0).unwrap()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let manager = Manager::new().await?;

    // get the first bluetooth adapter
    // connect to the adapter
    let central = get_central(&manager).await;

    // Each adapter has an event stream, we fetch via events(),
    // simplifying the type, this will return what is essentially a
    // Future<Result<Stream<Item=CentralEvent>>>.
    let mut events = central.events().await?;

    let start_time = std::time::Instant::now();

    // start scanning for devices
    central.start_scan(ScanFilter::default()).await?;

    // Print based on whatever the event receiver outputs. Note that the event
    // receiver blocks, so in a real program, this should be run in its own
    // thread (not task, as this library does not yet use async channels).
    while let Some(event) = events.next().await {
        match event {
            CentralEvent::DeviceDiscovered(id) => {
                println!("DeviceDiscovered: {:?}", id);
                if start_time.elapsed() > std::time::Duration::from_secs(10) {
                    central.stop_scan().await?;
                }
            }
            // CentralEvent::DeviceConnected(id) => {
            //     println!("DeviceConnected: {:?}", id);
            // }
            // CentralEvent::DeviceDisconnected(id) => {
            //     println!("DeviceDisconnected: {:?}", id);
            // }
            // CentralEvent::ManufacturerDataAdvertisement {
            //     id,
            //     manufacturer_data,
            // } => {
            //     println!(
            //         "ManufacturerDataAdvertisement: {:?}, {:?}",
            //         id, manufacturer_data
            //     );
            // }
            // CentralEvent::ServiceDataAdvertisement { id, service_data } => {
            //     println!("ServiceDataAdvertisement: {:?}, {:?}", id, service_data);
            // }
            // CentralEvent::ServicesAdvertisement { id, services } => {
            //     let services: Vec<String> =
            //         services.into_iter().map(|s| s.to_short_string()).collect();
            //     println!("ServicesAdvertisement: {:?}, {:?}", id, services);
            // }
            _ => {}
        }
    }
    Ok(())
}