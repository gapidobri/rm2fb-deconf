use anyhow::Result;
use clap::Parser;
use r2pipe::R2Pipe;
use radare::Radare;
use std::{fs::File, io::Write};

#[macro_use]
extern crate r2pipe;

pub mod radare;

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

fn main() -> Result<()> {
    let args = Args::parse();

    let path = Some(args.binary_path);

    let r2p = open_pipe!(path)?;

    let mut radare = Radare::new(r2p);

    radare.analyze()?;

    let update_addr = radare.get_update_address()?;
    let create_addr = radare.get_create_address()?;
    let shutdown_addr = radare.get_shutdown_address()?;
    let notify_addr = radare.get_notify_address()?;
    let wait_addr = radare.get_wait_address()?;
    let get_instance_addr = radare.get_instance_address()?;

    let mut out_file = File::create(args.output)?;

    out_file.write_fmt(format_args!("!{}\n", args.version_number))?;
    out_file.write_fmt(format_args!("version str {}\n", args.version_string))?;
    out_file.write_fmt(format_args!("update addr {:#01x}\n", update_addr))?;
    out_file.write_fmt(format_args!("updateType str QRect\n"))?;
    out_file.write_fmt(format_args!("create addr {:#01x}\n", create_addr))?;
    out_file.write_fmt(format_args!("shutdown addr {:#01x}\n", shutdown_addr))?;
    out_file.write_fmt(format_args!("notify addr {:#01x}\n", notify_addr))?;
    out_file.write_fmt(format_args!("wait addr {:#01x}\n", wait_addr))?;
    out_file.write_fmt(format_args!(
        "getInstance addr {:#01x}\n",
        get_instance_addr
    ))?;

    Ok(())
}
