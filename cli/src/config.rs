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
    pub fn new_from_file(file_name: &String) -> Result<Self, String> {
        let input_path = Path::new(file_name);
        let reader = fs::read_to_string(input_path)
            .map_err(|why| format!("Couldn't open {}: {}", input_path.display(), why))?;
        let config: TwoPartyConfig = serde_json::from_str(&reader)
            .map_err(|why| format!("Couldn't deserialize config: {}", why))?;

        Ok(config)
    }

    pub fn get_my_info(&self, my_index: usize) -> Info {
        self.infos
            .iter()
            .find(|e| e.index == my_index)
            .unwrap()
            .clone()
    }

    pub fn get_peer_info(&self, my_index: usize) -> Info {
        self.infos
            .iter()
            .find(|e| e.index != my_index)
            .unwrap()
            .clone()
    }
}

impl MultiPartyConfig {
    pub fn new_from_file(file_name: &String) -> Result<Self, String> {
        let input_path = Path::new(file_name);
        let reader = fs::read_to_string(input_path)
            .map_err(|why| format!("Couldn't open {}: {}", input_path.display(), why))?;
        let config: MultiPartyConfig = serde_json::from_str(&reader)
            .map_err(|why| format!("Couldn't deserialize config: {}", why))?;

        Ok(config)
    }

    pub fn get_my_info(&self, my_index: usize) -> Info {
        self.infos
            .iter()
            .find(|e| e.index == my_index)
            .unwrap()
            .clone()
    }

    pub fn get_peer_infos(&self, my_index: usize) -> Vec<Info> {
        self.infos
            .clone()
            .into_iter()
            .filter(|e| e.index != my_index)
            .collect()
    }
}
