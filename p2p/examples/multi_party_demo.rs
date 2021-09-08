use curv::arithmetic::Converter;
use std::collections::HashMap;

use tokio::io;
use tokio::prelude::*;
use tokio::task;

use p2p::{Message, MsgProcess, Node, NodeHandle, PeerID, ProcessMessage};

use curv::BigInt;
use multi_party_ecdsa::communication::receiving_messages::ReceivingMessages;
use multi_party_ecdsa::communication::sending_messages::SendingMessages;
use multi_party_ecdsa::protocols::multi_party::ours::keygen::*;
use multi_party_ecdsa::protocols::multi_party::ours::message::{
    MultiKeyGenMessage, MultiSignMessage,
};
use multi_party_ecdsa::protocols::multi_party::ours::sign::*;
use serde::Deserialize;
use std::path::Path;
use std::{env, fs};

#[derive(Debug, Deserialize)]
struct JsonConfig {
    pub share_count: usize,
    pub threshold: usize,
    pub infos: Vec<PeerInfo>,
    pub message: String,    // message to sign
    pub subset: Vec<usize>, // sign parties
}

#[derive(Debug, Deserialize, Clone)]
pub struct MyInfo {
    pub index: usize,
    pub ip: String,
    pub port: u16,
}
impl MyInfo {
    pub fn new(index: usize, ip: String, port: u16) -> Self {
        Self { index, ip, port }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct PeerInfo {
    pub index: usize,
    pub address: String,
}
impl PeerInfo {
    pub fn new(index: usize, address: String) -> Self {
        Self { index, address }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct JsonConfigInternal {
    pub share_count: usize,
    pub threshold: usize,
    pub my_info: MyInfo,
    pub peers_info: Vec<PeerInfo>,
    pub message: String,
    pub subset: Vec<usize>,
}

impl JsonConfigInternal {
    pub fn init_with(party_id: usize, json_config_file: String) -> Self {
        let file_path = Path::new(&json_config_file);
        let json_str = fs::read_to_string(file_path).unwrap();
        let json_config: JsonConfig =
            serde_json::from_str(&json_str).expect("JSON was not well-formatted");

        let index_ = party_id;
        let mut ip_: String = String::new();
        let mut port_: u16 = 8888;
        let mut peers_info_: Vec<PeerInfo> = Vec::new();
        for info in json_config.infos.iter() {
            if info.index == index_ {
                let s = info.address.clone();
                let vs: Vec<&str> = s.splitn(2, ":").collect();
                ip_ = vs[0].to_string();
                port_ = vs[1].to_string().parse::<u16>().unwrap();
            } else {
                peers_info_.push(PeerInfo::new(info.index, info.address.clone()));
            }
        }

        Self {
            share_count: json_config.share_count,
            threshold: json_config.threshold,
            my_info: MyInfo::new(index_, ip_, port_),
            peers_info: peers_info_,
            message: json_config.message,
            subset: json_config.subset,
        }
    }
}

pub struct InitMessage {
    my_info: MyInfo,
    peers_info: Vec<PeerInfo>,
    subset: Vec<usize>,
    multi_party_info: MultiParty,
}
impl InitMessage {
    pub fn init_message() -> Self {
        let party_id_str = env::args().nth(1).unwrap();
        let party_id = party_id_str.parse::<usize>().unwrap();
        let json_config_file = env::args().nth(2).unwrap();

        //Load config from file
        let json_config_internal = JsonConfigInternal::init_with(party_id, json_config_file);
        let json_config = json_config_internal.clone();

        let params = Parameters {
            threshold: json_config.threshold,
            share_count: json_config.share_count,
        };

        let seed: BigInt = BigInt::from_hex(
            "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
        ).unwrap();

        // discriminant: 1348, lambda: 112
        let qtilde: BigInt = BigInt::from_hex("23893039587891638565297401593924273169825964283558231612167738384238313917887833945225898199741584873627027859268757281540231029139309613219716874418588517495558290624716349383746651319918936091587965845797835593810764676322501564946526995033976417223598945838942128878559190581681834232455419055873026991107437602524121085617731").unwrap();

        // TBD: add a new func, init it latter.
        let keygen =
            KeyGen::init(&seed, &qtilde, json_config.my_info.index, params.clone()).unwrap();
        let subset = json_config.subset.clone();
        let message = json_config.message.clone();
        let mut sign = SignPhase::new(
            &seed,
            &qtilde,
            json_config.my_info.index,
            params.clone(),
            &subset,
            &message,
        )
        .unwrap();
        sign.init();
        let multi_party_info = MultiParty {
            keygen: keygen,
            sign: sign,
        };
        let init_messages = InitMessage {
            my_info: json_config.my_info,
            peers_info: json_config.peers_info,
            subset: json_config.subset,
            multi_party_info: multi_party_info,
        };
        return init_messages;
    }
}
struct MultiParty {
    keygen: KeyGen,
    sign: SignPhase,
}

impl MsgProcess<Message> for MultiParty {
    fn process(&mut self, index: usize, msg: Message) -> ProcessMessage<Message> {
        let received_msg: ReceivingMessages = bincode::deserialize(&msg).unwrap();
        let sending_msg = match received_msg {
            ReceivingMessages::MultiKeyGenMessage(msg) => {
                self.keygen.msg_handler(index, &msg).unwrap()
            }
            ReceivingMessages::MultiSignMessage(msg) => self.sign.msg_handler(index, &msg).unwrap(),
            _ => SendingMessages::EmptyMsg,
        };
        match sending_msg {
            SendingMessages::NormalMessage(index, msg) => {
                return ProcessMessage::SendMessage(index, Message(msg))
            }
            SendingMessages::P2pMessage(msgs) => {
                //TBD: handle vector to Message
                let mut msgs_to_send: HashMap<usize, Message> = HashMap::new();
                for (key, value) in msgs {
                    msgs_to_send.insert(key, Message(value));
                }
                return ProcessMessage::SendMultiMessage(msgs_to_send);
                //println!("Sending p2p msg");
            }
            SendingMessages::BroadcastMessage(msg) => {
                return ProcessMessage::BroadcastMessage(Message(msg));
                //println!("Sending broadcast msg");
            }
            SendingMessages::KeyGenSuccess => {
                println!("keygen Success!");
                return ProcessMessage::Default();
            }
            SendingMessages::SignSuccess => {
                println!("Sign Success!");
                return ProcessMessage::Default();
            }
            SendingMessages::EmptyMsg => {
                println!("no msg to send");
                return ProcessMessage::Default();
            }
            SendingMessages::KeyGenSuccessWithResult(res) => {
                println!("keygen Success! {}", res);
                return ProcessMessage::Default();
            }
            SendingMessages::SignSuccessWithResult(res) => {
                println!("Sign Success! {}", res);
                return ProcessMessage::Default();
            }
        }
    }
}
fn main() {
    if env::args().count() < 3 {
        println!(
            "Usage:\n\t{} <parties> <party-id> <port> <config-file>",
            env::args().nth(0).unwrap()
        );
        panic!("Need Config File")
    }

    let init_messages = InitMessage::init_message();

    // Create the runtime.
    let mut rt = tokio::runtime::Runtime::new().expect("Should be able to init tokio::Runtime.");
    let local = task::LocalSet::new();
    local
        .block_on(&mut rt, async move {
            // Creating a random private key instead of reading from a file.
            let (mut node_handle, notifications_channel) = Node::<Message>::node_init(
                init_messages.my_info.index,
                init_messages.my_info.ip.parse().unwrap(),
                init_messages.my_info.port,
            )
            .await;

            // Begin the UI.
            let interactive_loop = Console::spawn(
                node_handle.clone(),
                init_messages.peers_info,
                init_messages.subset,
            );

            let mut message_process = init_messages.multi_party_info;
            // Spawn the notifications loop
            let notifications_loop = {
                task::spawn_local(async move {
                    node_handle
                        .receive_(notifications_channel, &mut message_process)
                        .await;
                    Result::<(), String>::Ok(())
                })
            };

            notifications_loop.await.expect("panic on JoinError")?;
            interactive_loop.await.expect("panic on JoinError")
        })
        .unwrap()
}

enum UserCommand {
    Nop,
    MultiKeyGenConnect,
    MultiSignConnect,
    KeyGen,
    Sign,
    Broadcast(String),
    SendMsg(PeerID, String),
    Disconnect(PeerID), // peer id
    ListPeers,
    Exit,
}

pub struct Console {
    node: NodeHandle<Message>,
    peers_info: Vec<PeerInfo>,
    subset: Vec<usize>,
}

impl Console {
    pub fn spawn(
        node: NodeHandle<Message>,
        peers_info: Vec<PeerInfo>,
        subset: Vec<usize>,
    ) -> task::JoinHandle<Result<(), String>> {
        task::spawn_local(async move {
            let mut stdin = io::BufReader::new(io::stdin());
            let mut console = Console {
                node,
                peers_info,
                subset,
            };
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
            UserCommand::MultiKeyGenConnect => {
                for peer_info in self.peers_info.iter() {
                    self.node
                        .connect_to_peer(&peer_info.address, None, peer_info.index)
                        .await
                        .map_err(|e| {
                            format!("Handshake error with {}. {:?}", peer_info.address, e)
                        })?;
                }
            }
            UserCommand::MultiSignConnect => {
                for peer_info in self.peers_info.iter() {
                    if self.subset.contains(&peer_info.index) {
                        self.node
                            .connect_to_peer(&peer_info.address, None, peer_info.index)
                            .await
                            .map_err(|e| {
                                format!("Handshake error with {}. {:?}", peer_info.address, e)
                            })?;
                    }
                }
            }
            UserCommand::Disconnect(peer_id) => {
                self.node.remove_peer(peer_id).await;
            }
            UserCommand::Broadcast(msg) => {
                println!("=> Broadcasting: {:?}", &msg);
                self.node.broadcast(Message(msg.as_bytes().to_vec())).await;
            }
            UserCommand::SendMsg(peer_id, msg) => {
                println!("=> Send: {:?}, to {}", &msg, peer_id);
                self.node
                    .sendmsg(peer_id, Message(msg.as_bytes().to_vec()))
                    .await;
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
                let msg = bincode::serialize(&ReceivingMessages::MultiKeyGenMessage(
                    MultiKeyGenMessage::KeyGenBegin,
                ))
                .unwrap();
                let msg_clone = msg.clone();
                self.node.broadcast(Message(msg)).await;
                self.node.sendself(Message(msg_clone)).await;
            }
            UserCommand::Sign => {
                println!("=> Signature Begin...");
                let msg = bincode::serialize(&ReceivingMessages::MultiSignMessage(
                    MultiSignMessage::SignBegin,
                ))
                .unwrap();
                let msg_clone = msg.clone();
                self.node.broadcast(Message(msg)).await;
                self.node.sendself(Message(msg_clone)).await;
            }
        }
        Ok(())
    }

    fn parse_command(line: &str) -> Result<UserCommand, String> {
        let line = line.trim().to_string();
        if line == "" {
            return Ok(UserCommand::Nop);
        }
        let mut head_tail = line.splitn(2, " ");
        let command = head_tail
            .next()
            .ok_or_else(|| {
                "Missing command. Try `connect <addr:port>` or `broadcast <text>`".to_string()
            })?
            .to_lowercase();
        let rest = head_tail.next();

        if command == "multikeygenconnect" {
            Ok(UserCommand::MultiKeyGenConnect)
        } else if command == "multisignconnect" {
            Ok(UserCommand::MultiSignConnect)
        } else if command == "broadcast" {
            Ok(UserCommand::Broadcast(rest.unwrap_or("").into()))
        } else if command == "sendmsg" {
            let s = rest.unwrap_or("").to_string();
            let mut ss = s.splitn(2, " ");
            let spid = ss.next().ok_or_else(|| "Invalid peer ID".to_string())?;
            let msg = ss.next();
            if let Some(id) = PeerID::from_string(&spid) {
                Ok(UserCommand::SendMsg(id, msg.unwrap_or("").into()))
            } else {
                Err(format!("Invalid peer ID `{}`", spid))
            }
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
        } else if command == "exit" || command == "quit" || command == "q" {
            Ok(UserCommand::Exit)
        } else {
            Err(format!("Unknown command `{}`", command))
        }
    }
}
