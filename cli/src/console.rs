use message::message::Message;
use multi_party_ecdsa::communication::receiving_messages::ReceivingMessages;
use p2p::{Info, NodeHandle, PeerID};
use std::fs;
use std::path::Path;
use tokio::io;
use tokio::prelude::*;
use tokio::task;

enum UserCommand {
    Nop,
    Connect,
    KeyGen,
    Sign,
    TwoSignRefresh(String, String),
    MultiSignRefresh(String, String, Vec<usize>),
    Disconnect(PeerID), // peer id
    ListPeers,
    Exit,
}

pub struct Console {
    node: NodeHandle<Message>,
    peers_info: Vec<Info>,
}

impl Console {
    pub fn spawn(
        node: NodeHandle<Message>,
        peers_info: Vec<Info>,
    ) -> task::JoinHandle<Result<(), String>> {
        task::spawn_local(async move {
            let mut stdin = io::BufReader::new(io::stdin());
            let mut console = Console { node, peers_info };
            loop {
                let mut line = String::new();
                io::stderr().write_all(">> ".as_ref()).await.unwrap();
                let n = stdin
                    .read_line(&mut line)
                    .await
                    .map_err(|_| "Failed to read UTF-8 line.".to_string())?;
                if n == 0 {
                    // reached EOF
                    break;
                }
                let result = async {
                    let cmd = Console::parse_command(&line)?;
                    console.process_command(cmd).await
                }
                .await;

                match result {
                    Err(e) => {
                        if e == "Command::Exit" {
                            // exit gracefully
                            return Ok(());
                        } else {
                            // print error
                            println!("!> {}", e);
                        }
                    }
                    Ok(_) => {}
                };
            }
            Ok(())
        })
    }

    /// Processes a single command.
    async fn process_command(&mut self, command: UserCommand) -> Result<(), String> {
        match command {
            UserCommand::Nop => {}
            UserCommand::Exit => {
                self.node.exit().await;
                return Err("Command::Exit".into());
            }
            UserCommand::Connect => {
                for peer_info in self.peers_info.iter() {
                    self.node
                        .connect_to_peer(&peer_info.address, None, peer_info.index)
                        .await
                        .map_err(|e| {
                            format!("Handshake error with {}. {:?}", peer_info.address, e)
                        })?;
                }
            }
            UserCommand::Disconnect(peer_id) => {
                self.node.remove_peer(peer_id).await;
            }
            UserCommand::ListPeers => {
                let peer_infos = self.node.list_peers().await;
                println!("=> {} peers:", peer_infos.len());
                for peer_info in peer_infos.iter() {
                    println!("  {}", peer_info);
                }
            }
            UserCommand::KeyGen => {
                println!("=> KeyGen Begin...");
                let msg = bincode::serialize(&ReceivingMessages::KeyGenBegin).unwrap();
                self.node.broadcast(Message(msg.clone())).await;
                self.node.sendself(Message(msg)).await;
            }
            UserCommand::Sign => {
                let msg = bincode::serialize(&ReceivingMessages::SignBegin).unwrap();
                self.node.broadcast(Message(msg.clone())).await;
                self.node.sendself(Message(msg)).await;
            }
            UserCommand::TwoSignRefresh(message, keygen_result_json) => {
                let msg = bincode::serialize(&ReceivingMessages::TwoPartySignRefresh(
                    message,
                    keygen_result_json,
                ))
                .unwrap();
                self.node.sendself(Message(msg)).await;
            }
            UserCommand::MultiSignRefresh(message, keygen_result_json, subset) => {
                let msg = bincode::serialize(&ReceivingMessages::MultiPartySignRefresh(
                    message,
                    keygen_result_json,
                    subset,
                ))
                .unwrap();
                self.node.sendself(Message(msg)).await;
            }
        }
        Ok(())
    }

    fn parse_command(line: &str) -> Result<UserCommand, String> {
        let line = line.trim().to_string();
        if line == "" {
            return Ok(UserCommand::Nop);
        }
        let mut head_tail = line.splitn(8, " ");
        let command = head_tail
            .next()
            .ok_or_else(|| {
                "Missing command. Try `connect <addr:port>` or `broadcast <text>`".to_string()
            })?
            .to_lowercase();
        let rest = head_tail.next();

        if command == "connect" {
            Ok(UserCommand::Connect)
        } else if command == "peers" {
            Ok(UserCommand::ListPeers)
        } else if command == "disconnect" {
            let s: String = rest.unwrap_or("").into();
            if let Some(id) = PeerID::from_string(&s) {
                Ok(UserCommand::Disconnect(id))
            } else {
                Err(format!("Invalid peer ID `{}`", s))
            }
        } else if command == "keygen" {
            Ok(UserCommand::KeyGen)
        } else if command == "sign" {
            Ok(UserCommand::Sign)
        } else if command == "tworefresh" {
            let message = rest.ok_or_else(|| "Missing message".to_string())?;
            let keygen_result_file = head_tail
                .next()
                .ok_or_else(|| "Missing keygen result file".to_string())?;
            let keygen_path = Path::new(keygen_result_file);
            let keygen_result_json = fs::read_to_string(keygen_path).unwrap();
            Ok(UserCommand::TwoSignRefresh(
                message.to_owned(),
                keygen_result_json,
            ))
        } else if command == "multirefresh" {
            let message = rest.ok_or_else(|| "Missing message".to_string())?;
            let keygen_result_file = head_tail
                .next()
                .ok_or_else(|| "Missing keygen result file".to_string())?;
            let keygen_path = Path::new(keygen_result_file);
            let keygen_result_json = fs::read_to_string(keygen_path).unwrap();
            let mut subset = Vec::new();
            while let Some(s) = head_tail.next() {
                let index: usize = s.parse().unwrap();
                subset.push(index);
            }
            Ok(UserCommand::MultiSignRefresh(
                message.to_owned(),
                keygen_result_json,
                subset,
            ))
        } else if command == "exit" || command == "quit" || command == "q" {
            Ok(UserCommand::Exit)
        } else {
            Err(format!("Unknown command `{}`", command))
        }
    }
}
