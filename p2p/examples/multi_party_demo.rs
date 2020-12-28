use curve25519_dalek::scalar::Scalar;
use rand::thread_rng;

use tokio::io;
use tokio::prelude::*;
use tokio::task;

use p2p::cybershake;
use p2p::{Message, Node, NodeConfig, NodeHandle, NodeNotification, PeerID};

use class_group::primitives::cl_dl_public_setup::CLGroup;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE, GE};
use multi_party_ecdsa::communication::receiving_messages::ReceivingMessages;
use multi_party_ecdsa::communication::sending_messages::SendingMessages;
use multi_party_ecdsa::protocols::multi_party::ours::party_i::MultiKeyGenMessage;
use multi_party_ecdsa::protocols::multi_party::ours::party_i::*;
use multi_party_ecdsa::utilities::clkeypair::ClKeyPair;
use multi_party_ecdsa::utilities::eckeypair::EcKeyPair;
use serde::Deserialize;
use std::{env,fs};
use std::path::Path;

#[derive(Debug, Deserialize)]
struct JsonConfig {
    pub share_count: usize,
    pub threshold: usize,
    pub my_info: MyInfo,
    pub peers_info: Vec<PeerInfo>,
    pub message: String,    // message to sign
    pub subset: Vec<usize>,  // sign parties
}

#[derive(Debug, Deserialize)]
struct MyInfo {
    pub index: usize,
    pub ip: String,
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct PeerInfo {
    pub index: usize,
    pub address: String,
}

fn main() {
    if env::args().nth(1).is_none() {
        panic!("Need Config File")
    }
    let path_str = env::args().nth(1).unwrap();

    // Create the runtime.
    let mut rt = tokio::runtime::Runtime::new().expect("Should be able to init tokio::Runtime.");
    let local = task::LocalSet::new();
    local
        .block_on(&mut rt, async move {
            // Creating a random private key instead of reading from a file.
            let host_privkey = cybershake::PrivateKey::from(Scalar::random(&mut thread_rng()));

            // Read config info from file
            let file_path = Path::new(&path_str);
            let json_str = fs::read_to_string(file_path).unwrap();
            let json_config: JsonConfig = serde_json::from_str(&json_str).expect("JSON was not well-formatted");

            let index = json_config.my_info.index;
            let params = Parameters {
                threshold: json_config.threshold,
                share_count: json_config.share_count,
            };
            let subset = json_config.subset;
            let message = json_config.message;

            let config = NodeConfig {
                index: index,
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
                index,
            );

            let mut node2 = node.clone();

            // Begin the UI.
            let interactive_loop = Console::spawn(node, json_config.peers_info, subset.clone());

            // Spawn the notifications loop
            let notifications_loop = {
                task::spawn_local(async move {
                    let seed: BigInt = str::parse(
                        "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
                    ).unwrap();
                    let qtilde: BigInt = str::parse("23893039587891638565297401593924273169825964283558231612167738384238313917887833945225898199741584873627027859268757281540231029139309613219716874418588517495558290624716349383746651319918936091587965845797835593810764676322501564946526995033976417223598945838942128878559190581681834232455419055873026991107437602524121085617731").unwrap();
                    let group = CLGroup::new_from_qtilde(&seed, &qtilde);
                    // let group = CLGroup::new_from_setup(&1348, &seed); //discriminant 1348

                    // TBD: add a new func, init it latter.
                    let mut keygen = KeyGen::phase_one_init(&group, index, params.clone());
                    let mut sign = SignPhase::new();

                    while let Some(notif) = notifications_channel.recv().await {
                        match notif {
                            NodeNotification::PeerAdded(_pid, index) => {
                                println!("\n=>    Peer connected to index: {}", index)
                            }
                            NodeNotification::PeerDisconnected(pid) => {
                                println!("\n=> Peer disconnected: {}", pid)
                            }
                            NodeNotification::MessageReceived(index, msg) => {
                                println!("\n=> Receiving message from {}", index);

                                // Decode msg
                                let received_msg: ReceivingMessages = bincode::deserialize(&msg).unwrap();

                                let sending_msg = match received_msg {
                                    ReceivingMessages::MultiKeyGenMessage(msg) => {
                                        keygen.msg_handler(index, &msg)
                                    }
                                    ReceivingMessages::MultiSignMessage(msg) => {
                                        sign.msg_handler(&group, index, &msg)
                                    }
                                };

                                match sending_msg {
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
                                        // Save keygen to file
                                        let keygen_path = Path::new("./keygen_result.json");
                                        let keygen_json = serde_json::to_string(&(
                                            keygen.ec_keypair.clone(),
                                            keygen.cl_keypair.clone(),
                                            keygen.public_signing_key.clone(),
                                            keygen.share_private_key.clone(),
                                            keygen.share_public_key.clone(),
                                            keygen.vss_scheme_vec.clone(),
                                        ))
                                        .unwrap();
                                        fs::write(keygen_path, keygen_json).expect("Unable to save !");

                                        println!("keygen Success!");
                                    }
                                    SendingMessages::SignSuccess => {
                                        println!("Sign Success!");
                                    }
                                    SendingMessages::EmptyMsg => {
                                        println!("no msg to send");
                                    }
                                }
                                println!("\n\n\n")
                            }
                            NodeNotification::KeyGen => {
                                let msg = keygen.phase_two_generate_dl_com_msg();
                                let msg_bytes = bincode::serialize(&msg).unwrap();
                                node2.broadcast(Message(msg_bytes)).await;
                                println!("KeyGen...")
                            }
                            NodeNotification::Sign => {
                                // read key file
                                let data = fs::read_to_string("./keygen_result.json")
                                    .expect("Unable to load keys, did you run keygen first? ");
                                let (ec_keypair, cl_keypair, public_signing_key, share_private_key, share_public_key, vss_scheme_vec): (
                                    EcKeyPair,
                                    ClKeyPair,
                                    GE,
                                    FE,
                                    Vec<GE>,
                                    Vec<VerifiableSS>,
                                    ) = serde_json::from_str(&data).unwrap();

                                // Init Sign
                                let message_hash = HSha256::create_hash_from_slice(message.as_bytes());
                                let message_to_sign: FE = ECScalar::from(&message_hash);
                                sign.init_msg(index, params.clone(), cl_keypair.get_secret_key().clone(), &vss_scheme_vec, &subset, &share_public_key, &share_private_key, subset.len(), public_signing_key.clone(), message_to_sign);

                                let msg = sign.phase_one_generate_promise_sigma_and_com_msg(&group, &cl_keypair, &ec_keypair);
                                let sending_msg = ReceivingMessages::MultiSignMessage(
                                    MultiSignMessage::PhaseOneMsg(msg),
                                );
                                let msg_bytes = bincode::serialize(&sending_msg).unwrap();
                                node2.broadcast(Message(msg_bytes)).await;
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
            let mut console = Console { node, peers_info, subset };
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
                self.node.keygen(Message(msg)).await;
            }
            UserCommand::Sign => {
                println!("=> Signature Begin...");
                let msg = bincode::serialize(&ReceivingMessages::MultiSignMessage(
                    MultiSignMessage::SignBegin,
                ))
                .unwrap();
                self.node.sign(Message(msg)).await;
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
        } else if  command == "multisignconnect" {
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
