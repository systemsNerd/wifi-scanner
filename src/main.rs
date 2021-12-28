extern crate wifiscanner;
extern crate wifi;
extern crate serde;
extern crate ctrlc;

#[macro_use]
extern crate serde_json;
extern crate wifi_rs;

#[macro_use]
extern crate clap;

#[macro_use]
extern crate error_chain;

mod errors {
        error_chain!{}
}

pub use errors::*;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::fs::File;
use std::io::prelude::*;
use std::io::Read;
use wifi_rs::prelude::*;
use wifi_rs::WiFi;
use wifi_rs::prelude::Config;
use wifi_rs::prelude::WifiConnectionError;
use std::process::Command;
use std::process::Output;
use std::collections::HashMap;
use std::{thread, time};
use std::fs::OpenOptions;

fn scan_net(interface: &str) -> std::io::Result<Output> {
    println!("Scanning interface {}", interface);
    Command::new("arp-scan")
        .arg("--localnet")
        .arg("--interface")
        .arg(interface).output()
}

fn connect_to_wifi(ssid : &str, password: &str, interface: &str) -> core::result::Result<bool, WifiConnectionError> {
    println!("Trying to connect to {} with password {}", ssid, password);
    let config = Some(Config {
        interface: Some(interface), 
    });
    let mut wifi =  WiFi::new(config);
    wifi.connect(ssid, password)
}


fn read_json_file(filename: &str) -> Result<(std::vec::Vec<serde_json::value::Value>)> {
    let mut f = File::open(filename)
        .expect("Failed to open filename");
    let mut data = String::new();

    f.read_to_string(&mut data).expect("Failed to read from file");
    let tried_scanned_netws : serde_json::Value = 
                serde_json::from_str(&data).unwrap_or_else(|_error| {
                    json!([])
                });
    Ok(tried_scanned_netws.as_array().unwrap().clone())
}

// TODO logs + prints with adequate text
// TODO manage errors better -> avoid using unwrap
fn main() {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    let args = clap_app!(("Version_checker") =>
                         (author: "Roxana Nicolescu <nicolescu.roxana1996@gmail.com>")
                         (about: "Tool for scanning available networks already broken with wfite")
                         (@arg interface: -i --interface +takes_value + required "(String) : Sets the network interface"))
        .get_matches();

    let interface = args.value_of("interface").unwrap().to_string();

    println!("interface {}", interface);

    // TODO put these two as arguments
    // TODO maybe create it at the beginning
    let mut tried_scanned_netws = read_json_file("tried_scanned_networks").expect("Could not read tried");

    println!("tried_scanned netws at the beginning {:?}", tried_scanned_netws);

    let known_networks = read_json_file("database.json").expect("could not read database");

    let mut unknown_networks: HashMap<String, bool> = HashMap::new();

    while running.load(Ordering::SeqCst) {
        let networks = wifiscanner::scan().expect("Failed to scan wifis");
        println!("Available networks {}", networks.len()); 
        
        for network in networks {
            let first_ssid = &network.ssid;
            if unknown_networks.get(first_ssid).is_some() {
                continue;
            }

            if find_tried_ssid(&tried_scanned_netws, first_ssid) {
                continue;
            }

            let password = find_passwd(&known_networks, first_ssid);
            if password.is_none() {
                unknown_networks.insert(first_ssid.to_string(), true);
                continue;
            }

            let password = password.unwrap();
            let connection_result = connect_to_wifi(first_ssid, &password, &interface).unwrap_or_else(|error| {
                println!("Failed to connect to {} with password {}",  first_ssid, password);
                let real_error = match error {
                    WifiConnectionError::FailedToConnect(msg) => msg,
                    WifiConnectionError::FailedToDisconnect(msg) => msg,
                    _ => "Wireless error".to_string(),
                };

                tried_scanned_netws.push(json!({"ssid": first_ssid.to_string(), 
                "result": real_error}));
                false
            });
            
            if !connection_result {
                println!("Failed to connect to {} with password {}",  first_ssid, password);
                tried_scanned_netws.push(json!({"ssid": first_ssid.to_string(), "result": "Failed to connect"})); 
                break
            }
            
            println!("Connected to {}", first_ssid);
            let scan_result = scan_net(&interface).unwrap_or_else(|_error| {
                panic!("arp-scan not found!")
            });

            println!("Scanned network {}", first_ssid);
            tried_scanned_netws.push(json!({"ssid" : first_ssid.to_string(),
            "result": "scanned with status ".to_string() + &scan_result.status.code().unwrap().to_string()}));
           
            let lines = String::from_utf8(scan_result.stdout).unwrap();
            let lines = lines.split('\n');

            let vec = lines.collect::<Vec<&str>>();
            let mut good_lines = std::vec::Vec::new();

            for line in vec {
                good_lines.push(str::replace(line, "\t", ","));
            }
            
            good_lines.remove(0);
            good_lines.remove(0);
            good_lines.remove(good_lines.len() -1);
            good_lines.remove(good_lines.len() -1);
            good_lines.remove(good_lines.len() -1);
         
            let mut file = OpenOptions::new().append(true).create(true).open("scanned_networks/".to_string() + first_ssid).unwrap();

            for line in good_lines {
                write!(&mut file, "{}\n", line).unwrap();
            }

            break;
        }

        thread::sleep(time::Duration::new(1, 0));
    }

    
    println!("Got it! Exiting...");
    serde_json::to_writer(&File::create("tried_scanned_networks").unwrap(), &tried_scanned_netws).unwrap();

}

fn find_tried_ssid(database: &std::vec::Vec<serde_json::value::Value>, ssid: &str) -> bool {
    for network in database {
        let ssid_d = network["ssid"].as_str().expect("Failed to extract ssid");
        if ssid_d == ssid {
            return true;
        }
    }

    false
}

fn find_passwd(database: &std::vec::Vec<serde_json::value::Value>, ssid: &str) -> std::option::Option<String> {
    for network in database {
        let ssid_d = network["SSID"].as_str().expect("Failed to extract ssid");
        if ssid_d == ssid {
            return Some(network["password"].as_str().expect("Failed to extract password").to_string())
        }
    }

    None
}
