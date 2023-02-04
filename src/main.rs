use std::{collections::HashMap, fs::File, io::Write};

#[derive(Parser, Debug)]
#[command(author, version)]
struct Args {
    /// Path to the xochit binary
    binary_path: String,

    /// Version number from /etc/version
    version_number: u64,

    /// Version string from GUI
    version_string: String,

    /// Output location
    #[arg(short, default_value = "./rm2fb.conf")]
    output: String,
}

#[macro_use]
extern crate r2pipe;
extern crate serde_json;
use clap::Parser;
use r2pipe::R2Pipe;
fn main() {
    let args = Args::parse();

    let path = Some(args.binary_path);

    let mut r2p = open_pipe!(path).unwrap();

    r2p.cmd("aaaa").unwrap();
    r2p.cmd("aae").unwrap();

    let mut out_file = File::create(args.output).unwrap();

    out_file
        .write(
            format!(
                "!{}\nversion str {}\n",
                args.version_number, args.version_string
            )
            .as_bytes(),
        )
        .unwrap();

    // update
    let update_fn = r2p
        .cmdj("axtj @str.Unable_to_complete_update:_invalid_waveform__")
        .unwrap();
    let update_addr = update_fn[0]["fcn_addr"].as_u64().unwrap();
    out_file
        .write(format!("update addr {:#01x}\nupdateType str QRect\n", update_addr).as_bytes())
        .unwrap();

    // create
    let create_fn = r2p
        .cmdj("axtj @str.Unable_to_start_generator_thread")
        .unwrap();
    let create_addr = create_fn[0]["fcn_addr"].as_u64().unwrap();
    out_file
        .write(format!("create addr {:#01x}\n", create_addr).as_bytes())
        .unwrap();

    // shutdown
    let shutdown_fn = r2p.cmdj("axtj @str.Shutting_down...").unwrap();
    let shutdown_addr = shutdown_fn[0]["fcn_addr"].as_u64().unwrap();
    out_file
        .write(format!("shutdown addr {:#01x}\n", shutdown_addr).as_bytes())
        .unwrap();

    // notify
    r2p.cmd(format!("s {update_addr}").as_str()).unwrap();

    let update_fn_dec = r2p.cmdj("pdgj").unwrap();

    let mut fn_map: HashMap<u64, u32> = HashMap::new();

    update_fn_dec["annotations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["name"].as_str().unwrap_or_default().starts_with("fcn."))
        .for_each(|a| {
            let offset = a["offset"].as_u64().unwrap();
            if fn_map.contains_key(&offset) {
                fn_map.insert(offset, *fn_map.get(&offset).unwrap() + 1);
            } else {
                fn_map.insert(offset, 1);
            }
        });

    let (notify_addr, _) = fn_map.iter().find(|(_, &c)| c == 2).unwrap();
    out_file
        .write(format!("notify addr {:#01x}\n", notify_addr).as_bytes())
        .unwrap();

    // wait
    let imports = r2p.cmdj("iij").unwrap();

    let usleep_fn = imports
        .as_array()
        .unwrap()
        .iter()
        .find(|&i| i["name"].as_str().unwrap() == "usleep")
        .unwrap();

    let usleep_addr = usleep_fn["plt"].as_u64().unwrap();

    r2p.cmd(format!("s {usleep_addr}").as_str()).unwrap();

    let mut fn_map: HashMap<u64, u32> = HashMap::new();

    r2p.cmdj("axtj")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .for_each(|c| {
            let offset = c["fcn_addr"].as_u64().unwrap();
            if fn_map.contains_key(&offset) {
                fn_map.insert(offset, *fn_map.get(&offset).unwrap() + 1);
            } else {
                fn_map.insert(offset, 1);
            }
        });

    let (wait_addr, _) = fn_map.iter().max_by(|(_, a), (_, b)| a.cmp(b)).unwrap();

    out_file
        .write(format!("wait addr {:#01x}\n", wait_addr).as_bytes())
        .unwrap();

    // getInstance
    let wait_callers = r2p.cmdj(format!("axtj {wait_addr}").as_str()).unwrap();

    let callers = wait_callers
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            let caller_addr = c["fcn_addr"].as_u64().unwrap();
            r2p.cmdj(format!("axtj, {caller_addr}").as_str())
                .unwrap()
                .as_array()
                .unwrap()
                .to_owned()
        })
        .find(|c| !c.is_empty())
        .unwrap();

    let get_instance_addr = callers[0]["fcn_addr"].as_u64().unwrap();

    out_file
        .write(format!("getInstance addr {:#01x}\n", get_instance_addr).as_bytes())
        .unwrap();

    r2p.close();
}
