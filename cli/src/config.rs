use anyhow::format_err;
use p2p::Info;
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct TwoPartyConfig {
    infos: Vec<Info>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MultiPartyConfig {
    pub share_count: usize,
    pub threshold: usize,
    infos: Vec<Info>,
}

impl TwoPartyConfig {
    pub fn new_from_file(file_name: &String) -> Result<Self, anyhow::Error> {
        let input_path = Path::new(file_name);
        let reader = fs::read_to_string(input_path)
            .map_err(|why| format_err!("Couldn't open {}: {}", input_path.display(), why))?;

        log::info!("config info: {}", reader);

        let config: TwoPartyConfig = serde_json::from_str(&reader)
            .map_err(|why| format_err!("Couldn't deserialize config: {}", why))?;

        Ok(config)
    }

    pub fn get_my_info(&self, my_index: usize) -> Result<Info, anyhow::Error> {
        let info = self.infos.iter().find(|e| e.index == my_index);
        match info {
            Some(ret) => Ok(ret.clone()),
            None => Err(anyhow::Error::msg("Can not find my info in conifg")),
        }
    }

    pub fn get_peer_info(&self, my_index: usize) -> Vec<Info> {
        self.infos
            .clone()
            .into_iter()
            .filter(|e| e.index != my_index)
            .collect()
    }
}

impl MultiPartyConfig {
    pub fn new_from_file(file_name: &String) -> Result<Self, anyhow::Error> {
        let input_path = Path::new(file_name);
        let reader = fs::read_to_string(input_path)
            .map_err(|why| format_err!("Couldn't open {}: {}", input_path.display(), why))?;

        log::info!("config info: {}", reader);

        let config: MultiPartyConfig = serde_json::from_str(&reader)
            .map_err(|why| format_err!("Couldn't deserialize config: {}", why))?;

        Ok(config)
    }

    pub fn get_my_info(&self, my_index: usize) -> Result<Info, anyhow::Error> {
        let info = self.infos.iter().find(|e| e.index == my_index);
        match info {
            Some(ret) => Ok(ret.clone()),
            None => Err(anyhow::Error::msg("Can not find my info in conifg")),
        }
    }

    pub fn get_peers_info_keygen(&self, my_index: usize) -> Vec<Info> {
        self.infos
            .clone()
            .into_iter()
            .filter(|e| e.index != my_index)
            .collect()
    }

    pub fn get_peers_info_sign(&self, my_index: usize, subset: Vec<usize>) -> Vec<Info> {
        self.infos
            .clone()
            .into_iter()
            .filter(|e| e.index != my_index && subset.contains(&e.index))
            .collect()
    }
}
