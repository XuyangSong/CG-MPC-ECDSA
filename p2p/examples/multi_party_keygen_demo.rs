use curve25519_dalek::scalar::Scalar;
use rand::thread_rng;

use tokio::io;
use tokio::prelude::*;
use tokio::task;

use p2p::cybershake;
use p2p::{Message, Node, NodeConfig, NodeHandle, NodeNotification, PeerID};

use curv::BigInt;
use multi_party_ecdsa::communication::receiving_messages::ReceivingMessages;
use multi_party_ecdsa::communication::sending_messages::SendingMessages;
use multi_party_ecdsa::protocols::multi_party::ours::keygen::*;
use multi_party_ecdsa::protocols::multi_party::ours::message::{
    MultiKeyGenMessage, MultiSignMessage,
};
// use multi_party_ecdsa::protocols::multi_party::ours::sign::*;
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
    pub fn new(index_: usize, ip_: String, port_: u16) -> Self {
        Self {
            index: index_,
            ip: ip_,
            port: port_,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct PeerInfo {
    pub index: usize,
    pub address: String,
}
impl PeerInfo {
    pub fn new(index_: usize, address_: String) -> Self {
        Self {
            index: index_,
            address: address_,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct JsonConfigInternal {
    pub http_port: u16,
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
            http_port: 8000,
            share_count: json_config.share_count,
            threshold: json_config.threshold,
            my_info: MyInfo::new(index_, ip_, port_),
            peers_info: peers_info_,
            message: json_config.message,
            subset: json_config.subset,
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

    let party_id_str = env::args().nth(1).unwrap();
    //let port_str = env::args().nth(2).unwrap();
    //let port = port_str.parse::<u16>().unwrap();
    let party_id = party_id_str.parse::<usize>().unwrap();
    let json_config_file = env::args().nth(2).unwrap();
    let json_config_internal = JsonConfigInternal::init_with(party_id, json_config_file);
    //json_config_internal.http_port = port;
    let json_config = json_config_internal.clone();

    // Create the runtime.
    let mut rt = tokio::runtime::Runtime::new().expect("Should be able to init tokio::Runtime.");
    let local = task::LocalSet::new();
    local
        .block_on(&mut rt, async move {
            // Creating a random private key instead of reading from a file.
            let host_privkey = cybershake::PrivateKey::from(Scalar::random(&mut thread_rng()));

            // Read config info from file
            let party_index = json_config.my_info.index;
            let params = Parameters {
                threshold: json_config.threshold,
                share_count: json_config.share_count,
            };
            // let subset = json_config.subset;
            // let message = json_config.message;

            let config = NodeConfig {
                index: party_index,
                listen_ip: json_config.my_info.ip.parse().unwrap(),
                listen_port: json_config.my_info.port,
                inbound_limit: 100,
                outbound_limit: 100,
                heartbeat_interval_sec: 3600,
            };

            let (node, mut notifications_channel) = Node::<Message>::spawn(host_privkey, config)
                .await
                .expect("Should bind normally.");

            println!(
                "Listening on {} with peer ID: {} with index: {}",
                node.socket_address(),
                node.id(),
                party_index,
            );

            let mut node2 = node.clone();

            // Connect, just for performance test
            // for peer_info in json_config.peers_info.iter() {
            //     if peer_info.index > party_index {
            //         node2
            //         .connect_to_peer(&peer_info.address, None, peer_info.index)
            //         .await;
            //     }
            // }

            // Begin the UI.
            let interactive_loop = Console::spawn(node, json_config.peers_info);

            // Spawn the notifications loop
            let notifications_loop = {
                task::spawn_local(async move {
                    let seed: BigInt = str::parse(
                        "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
                    ).unwrap();

                    // discriminant: 1348, lambda: 112
                    let qtilde: BigInt = str::parse("23893039587891638565297401593924273169825964283558231612167738384238313917887833945225898199741584873627027859268757281540231029139309613219716874418588517495558290624716349383746651319918936091587965845797835593810764676322501564946526995033976417223598945838942128878559190581681834232455419055873026991107437602524121085617731").unwrap();

                    // discriminant: 1827, lambda: 128
                    // let qtilde: BigInt = str::parse("23134629277267369792843354241183585965289672542849276532207430015120455980466994354663282525744929223097771940566085692607836906398587331469747248600524817812682304621106507179764371100444437141969242248158429617082063052414988242667563996070192147160738941577591048902446543474661282744240565430969463246910793975505673398580796242020117195767211576704240148858827298420892993584245717232048052900060035847264121684747571088249105643535567823029086931610261875021794804631").unwrap();

                    // let group = CLGroup::new_from_qtilde(&seed, &qtilde);
                    // let group = CLGroup::new_from_setup(&1348, &seed); //discriminant 1348

                    // TBD: add a new func, init it latter.
                    let mut keygen = KeyGen::init(&seed, &qtilde, party_index, params.clone()).unwrap();
                    // let mut sign = SignPhase::new(&seed, &qtilde, party_index, params.clone(), &subset, &message);
                    // sign.init();

                    let mut time = time::now();

                    while let Some(notif) = notifications_channel.recv().await {
                        match notif {
                            NodeNotification::PeerAdded(_pid, index) => {
                                println!("\n=>    Peer connected to index: {}", index)
                            }
                            NodeNotification::PeerDisconnected(pid, index) => {
                                println!("\n=> Peer disconnected pid: {} index: {}", pid, index)
                            }
                            NodeNotification::MessageReceived(index, msg) => {
                                println!("\n=> Receiving message from {}", index);

                                // Decode msg
                                let received_msg: ReceivingMessages = bincode::deserialize(&msg).unwrap();

                                let mut sending_msg = SendingMessages::EmptyMsg;
                                if let ReceivingMessages::MultiKeyGenMessage(msg) = received_msg {
                                    sending_msg = keygen.msg_handler(index, &msg).unwrap();
                                }
                                // let sending_msg = match received_msg {
                                //     ReceivingMessages::MultiKeyGenMessage(msg) => {
                                //         keygen.msg_handler(index, &msg)
                                //     }
                                //     ReceivingMessages::MultiSignMessage(msg) => {
                                //         // sign.msg_handler(index, &msg)
                                //     }
                                // };

                                match sending_msg {
                                    SendingMessages::NormalMessage(index, msg) => {
                                        node2.sendmsgbyindex(index, Message(msg)).await;
                                    }
                                    SendingMessages::P2pMessage(msgs) => {
                                        for (index, msg) in msgs.iter() {
                                            node2.sendmsgbyindex(*index, Message(msg.to_vec())).await;
                                        }
                                        println!("Sending p2p msg");
                                    }
                                    SendingMessages::BroadcastMessage(msg) => {
                                        node2.broadcast(Message(msg)).await;
                                        println!("Sending broadcast msg");
                                    }
                                    SendingMessages::KeyGenSuccess => {
                                        if party_index == 0 {
                                            println!("KeyGen time: {:?}", time::now() - time);
                                        }

                                        println!("keygen Success!");
                                    }
                                    SendingMessages::SignSuccess => {
                                        if party_index == 0 {
                                            println!("Sign time: {:?}", time::now() - time);
                                        }

                                        println!("Sign Success!");
                                    }
                                    SendingMessages::EmptyMsg => {
                                        println!("no msg to send");
                                    }
                                    SendingMessages::KeyGenSuccessWithResult(res) => {
                                        if party_index == 0 {
                                            println!("KeyGen time: {:?}", time::now() - time);
                                        }
                                        println!("keygen Success! {}", res);
                                    }
                                    SendingMessages::SignSuccessWithResult(res) => {
                                        if party_index == 0 {
                                            println!("Sign time: {:?}", time::now() - time);
                                        }

                                        println!("Sign Success! {}", res);
                                    }
                                }
                                println!("\n")
                            }
                            NodeNotification::KeyGen => {
                                if party_index == 0 {
                                    time = time::now();
                                    let sending_msg = ReceivingMessages::MultiKeyGenMessage(MultiKeyGenMessage::KeyGenBegin);
                                    let sending_msg_bytes = bincode::serialize(&sending_msg).unwrap();
                                    node2.broadcast(Message(sending_msg_bytes)).await;
                                    println!("KeyGen...")
                                } else {
                                    println!("Only index 0 can start keygen!")
                                }
                            }
                            NodeNotification::Sign => {
                                time = time::now();
                                let sending_msg = ReceivingMessages::MultiSignMessage(MultiSignMessage::SignBegin);
                                let sending_msg_bytes = bincode::serialize(&sending_msg).unwrap();
                                node2.broadcast(Message(sending_msg_bytes)).await;
                                println!("Sign...")
                            }
                            NodeNotification::InboundConnectionFailure(err) => {
                                println!("\n=> Inbound connection failure: {:?}", err)
                            }
                            NodeNotification::OutboundConnectionFailure(err) => {
                                println!("\n=> Outbound connection failure: {:?}", err)
                            }
                            NodeNotification::Shutdown => {
                                println!("\n=> Node did shutdown.");
                                break;
                            }
                            _=>{
                                println!("Unsupported parse NodeNotification")
                            }
                        }
                    }
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
    // subset: Vec<usize>,
}

impl Console {
    pub fn spawn(
        node: NodeHandle<Message>,
        peers_info: Vec<PeerInfo>,
        // subset: Vec<usize>,
    ) -> task::JoinHandle<Result<(), String>> {
        task::spawn_local(async move {
            let mut stdin = io::BufReader::new(io::stdin());
            let mut console = Console {
                node,
                peers_info,
                // subset,
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
                // for peer_info in self.peers_info.iter() {
                //     if self.subset.contains(&peer_info.index) {
                //         self.node
                //             .connect_to_peer(&peer_info.address, None, peer_info.index)
                //             .await
                //             .map_err(|e| {
                //                 format!("Handshake error with {}. {:?}", peer_info.address, e)
                //             })?;
                //     }
                // }
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
                self.node.keygen(Message(msg)).await;
            }
            UserCommand::Sign => {
                // println!("=> Signature Begin...");
                // let msg = bincode::serialize(&ReceivingMessages::MultiSignMessage(
                //     MultiSignMessage::SignBegin,
                // ))
                // .unwrap();
                // self.node.sign(Message(msg)).await;
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
