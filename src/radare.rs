use std::collections::HashMap;

use anyhow::{Context, Ok, Result};
use r2pipe::R2Pipe;
use serde::{Deserialize, Serialize};

pub struct Radare {
    pipe: R2Pipe,
    update_addr: Option<u64>,
    create_addr: Option<u64>,
    shutdown_addr: Option<u64>,
    notify_addr: Option<u64>,
    wait_addr: Option<u64>,
    get_instance_addr: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Reference {
    from: u64,
    #[serde(rename = "type")]
    ref_type: String,
    perm: String,
    opcode: String,
    fcn_addr: u64,
    fcn_name: String,
    refname: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Decompile {
    code: String,
    annotations: Vec<Annotation>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Annotation {
    start: u32,
    end: u32,
    #[serde(rename = "type")]
    a_type: String,
    syntax_highlight: Option<String>,
    offset: Option<u64>,
    name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Import {
    ordinal: u32,
    bind: String,
    #[serde(rename = "type")]
    i_type: String,
    name: String,
    plt: u64,
}

impl Radare {
    pub fn new(pipe: R2Pipe) -> Self {
        Self {
            pipe,
            update_addr: None,
            create_addr: None,
            shutdown_addr: None,
            notify_addr: None,
            wait_addr: None,
            get_instance_addr: None,
        }
    }

    pub fn analyze(&mut self) -> Result<()> {
        self.pipe.cmd("aaaa").context("Analysis failed")?;
        self.pipe.cmd("aae").context("Esil analysis failed")?;
        Ok(())
    }

    pub fn get_update_address(&mut self) -> Result<u64> {
        match self.update_addr {
            Some(addr) => return Ok(addr),
            None => (),
        }

        let refs = self
            .axtj("@str.Unable_to_complete_update:_invalid_waveform__")
            .context("Failed to get update function reference")?;

        let addr = refs.first().context("No update references found")?.fcn_addr;

        self.update_addr = Some(addr);

        Ok(addr)
    }

    pub fn get_create_address(&mut self) -> Result<u64> {
        match self.create_addr {
            Some(addr) => return Ok(addr),
            None => (),
        }

        let refs = self
            .axtj("@str.Unable_to_start_generator_thread")
            .context("Failed to get create function reference")?;

        let addr = refs.first().context("No create references found")?.fcn_addr;

        self.create_addr = Some(addr);

        Ok(addr)
    }

    pub fn get_shutdown_address(&mut self) -> Result<u64> {
        match self.shutdown_addr {
            Some(addr) => return Ok(addr),
            None => (),
        }

        let refs = self
            .axtj("@str.Shutting_down...")
            .context("Failed to get shutdown function reference")?;

        let addr = refs
            .first()
            .context("No shutdown references found")?
            .fcn_addr;

        self.shutdown_addr = Some(addr);

        Ok(addr)
    }

    pub fn get_notify_address(&mut self) -> Result<u64> {
        match self.notify_addr {
            Some(addr) => return Ok(addr),
            None => (),
        }

        let update_addr = self.get_update_address()?;

        let dec = self
            .pdgj(update_addr.to_string().as_str())
            .context("Failed to decompile notify function")?;

        let mut fn_map: HashMap<u64, u32> = HashMap::new();

        dec.annotations
            .iter()
            .filter(|a| match a.name.as_ref() {
                Some(name) => name.starts_with("fcn."),
                None => false,
            })
            .for_each(|a| {
                let offset = match a.offset {
                    Some(offset) => offset,
                    None => return,
                };
                match fn_map.get(&offset) {
                    Some(count) => fn_map.insert(offset, count + 1),
                    None => fn_map.insert(offset, 1),
                };
            });

        let (addr, _) = fn_map
            .iter()
            .find(|(_, &c)| c == 2)
            .context("No notify address found")?;

        self.notify_addr = Some(*addr);

        Ok(*addr)
    }

    pub fn get_wait_address(&mut self) -> Result<u64> {
        match self.wait_addr {
            Some(addr) => return Ok(addr),
            None => (),
        }

        let imports = self.iij().context("Failed to list imports")?;

        let usleep_fn = imports
            .iter()
            .find(|&i| i.name.as_str() == "usleep")
            .context("No usleep function found")?;

        let mut fn_map: HashMap<u64, u32> = HashMap::new();

        self.axtj(usleep_fn.plt.to_string().as_str())?
            .iter()
            .for_each(|c| {
                let offset = c.fcn_addr;
                match fn_map.get(&offset) {
                    Some(count) => fn_map.insert(offset, count + 1),
                    None => fn_map.insert(offset, 1),
                };
            });

        let (addr, _) = fn_map
            .iter()
            .max_by(|(_, a), (_, b)| a.cmp(b))
            .context("Failed to find function with max calls")?;

        self.wait_addr = Some(*addr);

        Ok(*addr)
    }

    pub fn get_instance_address(&mut self) -> Result<u64> {
        match self.get_instance_addr {
            Some(addr) => return Ok(addr),
            None => (),
        }

        let wait = self
            .get_wait_address()
            .context("Failed to get wait address")?;

        let callers = self
            .axtj(wait.to_string().as_str())?
            .iter()
            .filter_map(|c| self.axtj(&c.fcn_name.to_string().as_str()).ok())
            .find(|c| !c.is_empty())
            .context("Failed to find getInstance caller")?;

        let addr = callers
            .first()
            .context("No getInstance callers found")?
            .fcn_addr;

        self.get_instance_addr = Some(addr);

        Ok(addr)
    }

    fn axtj(&mut self, addr: &str) -> Result<Vec<Reference>> {
        let json = self
            .pipe
            .cmdj(format!("axtj {addr}").as_str())
            .context("Failed to find references")?;

        let references = serde_json::from_value::<Vec<Reference>>(json)
            .context("Failed to deserialize response")?;

        Ok(references)
    }

    fn pdgj(&mut self, addr: &str) -> Result<Decompile> {
        self.pipe
            .cmd(format!("s {addr}").as_str())
            .context("Failed to jump to address")?;

        let json = self.pipe.cmdj("pdgj").context("Failed to decompile code")?;

        let decompile =
            serde_json::from_value::<Decompile>(json).context("Failed to deserialize response")?;

        Ok(decompile)
    }

    fn iij(&mut self) -> Result<Vec<Import>> {
        let json = self.pipe.cmdj("iij").context("Failed to list imports")?;

        let imports = serde_json::from_value::<Vec<Import>>(json)
            .context("Failed to deserialize response")?;

        Ok(imports)
    }
}
