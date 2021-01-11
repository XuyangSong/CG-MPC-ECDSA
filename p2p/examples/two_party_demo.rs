use curve25519_dalek::scalar::Scalar;
use rand::thread_rng;

use tokio::io;
use tokio::prelude::*;
use tokio::task;

use p2p::cybershake;
use p2p::{Message, Node, NodeConfig, NodeHandle, NodeNotification, PeerID};

use class_group::primitives::cl_dl_public_setup::CLGroup;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE};
use multi_party_ecdsa::protocols::two_party::message::TwoPartyMsg;
use multi_party_ecdsa::protocols::two_party::party_one;
use multi_party_ecdsa::protocols::two_party::party_two;
use multi_party_ecdsa::utilities::hsmcl::{HSMCLPublic, HSMCL};
use serde::Deserialize;
use std::path::Path;
use std::{env, fs};

#[derive(Debug, Deserialize)]
struct JsonConfig {
    pub my_info: MyInfo,
    pub peer_info: PeerInfo,
    pub message: String, // message to sign
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
            // let message = json_config.message;
            let message_hash = HSha256::create_hash_from_slice(json_config.message.as_bytes());
            let message_to_sign: FE = ECScalar::from(&message_hash);

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
            let interactive_loop = Console::spawn(node, json_config.peer_info);

            // Spawn the notifications loop
            let notifications_loop = {
                task::spawn_local(async move {
                    let seed: BigInt = str::parse(
                        "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
                    ).unwrap();
                    let qtilde: BigInt = str::parse("23893039587891638565297401593924273169825964283558231612167738384238313917887833945225898199741584873627027859268757281540231029139309613219716874418588517495558290624716349383746651319918936091587965845797835593810764676322501564946526995033976417223598945838942128878559190581681834232455419055873026991107437602524121085617731").unwrap();
                    let group = CLGroup::new_from_qtilde(&seed, &qtilde);
                    // let group = CLGroup::new_from_setup(&1348, &seed); //discriminant 1348

                    let mut party_one_keygen = party_one::KeyGenInit::new(&group);
                    let mut party_two_keygen = party_two::KeyGenInit::new();

                    let mut party_one_sign = party_one::SignPhase::new();
                    let mut party_two_sign = party_two::SignPhase::new(&group, &message_to_sign);

                    let mut time = time::now();

                    while let Some(notif) = notifications_channel.recv().await {
                        match notif {
                            NodeNotification::PeerAdded(_pid, index) => {
                                println!("\n=> Peer connected to index: {}\n", index)
                            }
                            NodeNotification::PeerDisconnected(pid) => {
                                println!("\n=> Peer disconnected: {}", pid)
                            }
                            NodeNotification::MessageReceived(index, msg) => {
                                // Decode msg
                                let received_msg: TwoPartyMsg = bincode::deserialize(&msg).unwrap();

                                match received_msg {
                                    TwoPartyMsg::KegGenBegin => {
                                        if index == 0 {
                                            // Party one time begin
                                            time = time::now();
                                            let msg_send = TwoPartyMsg::KeyGenPartyOneRoundOneMsg(party_one_keygen.round_one_msg.clone());
                                            let msg_bytes = bincode::serialize(&msg_send).unwrap();
                                            node2.broadcast(Message(msg_bytes)).await;
                                        } else {
                                            println!("Please use index 0 party begin the keygen...");
                                        }
                                    }
                                    TwoPartyMsg::KeyGenPartyOneRoundOneMsg(dlcom) => {
                                        println!("\n=>    KeyGen: Receiving RoundOneMsg from index 0");
                                        // Party two time begin
                                        time = time::now();

                                        party_two_keygen.set_dl_com(dlcom);
                                        let msg_send = TwoPartyMsg::KenGenPartyTwoRoundOneMsg(party_two_keygen.msg.clone());
                                        let msg_bytes = bincode::serialize(&msg_send).unwrap();
                                        node2.broadcast(Message(msg_bytes)).await;
                                    }
                                    TwoPartyMsg::KenGenPartyTwoRoundOneMsg(msg) => {
                                        println!("\n=>    KeyGen: Receiving RoundOneMsg from index 1");

                                        let witness = party_one_keygen.verify_and_get_next_msg(&msg).unwrap();
                                        party_one_keygen.compute_public_key(&msg.pk);

                                        // let (hsmcl_private, hsmcl_public) = HSMCL::generate_keypair_and_encrypted_share_and_proof(
                                        //     &party_one_keygen.keypair,
                                        //     &group,
                                        // );
                                        let msg_send = TwoPartyMsg::KeyGenPartyOneRoundTwoMsg(witness, party_one_keygen.hsmcl_public.clone());
                                        let msg_bytes = bincode::serialize(&msg_send).unwrap();
                                        node2.broadcast(Message(msg_bytes)).await;

                                        // Party one time end
                                        println!("keygen party one time: {:?}", time::now() - time);

                                        // Party one save keygen to file
                                        let keygen_path = Path::new("./keygen_result.json");
                                        let keygen_json = serde_json::to_string(&(
                                            party_one_keygen.hsmcl_private.clone(),
                                            party_one_keygen.keypair.get_secret_key().clone(),
                                        ))
                                        .unwrap();
                                        fs::write(keygen_path, keygen_json).expect("Unable to save !");
                                        println!("##    KeyGen finish!");

                                    }
                                    TwoPartyMsg::KeyGenPartyOneRoundTwoMsg(witness, hsmcl_public) => {
                                        println!("\n=>    KeyGen: Receiving RoundTwoMsg from index 0");

                                        // TBD: Party two, Simulate CL check
                                        let q = FE::q();
                                        group.gq.exp(&q);

                                        party_two::KeyGenInit::verify_received_dl_com_zk(
                                            &party_two_keygen.received_msg,
                                            &witness,
                                        )
                                        .unwrap();

                                        party_two::KeyGenInit::verify_setup_and_zkcldl_proof(
                                            &group,
                                            &hsmcl_public,
                                            witness.get_public_key(),
                                        )
                                        .unwrap();
                                        party_two_keygen.compute_public_key(witness.get_public_key());

                                        // Party two time end
                                        println!("keygen party two time: {:?}", time::now() - time);

                                        // Party two save keygen to file
                                        let keygen_path = Path::new("./keygen_result.json");
                                        let keygen_json = serde_json::to_string(&(
                                            hsmcl_public,
                                            party_two_keygen.keypair.get_secret_key().clone(),
                                        ))
                                        .unwrap();
                                        fs::write(keygen_path, keygen_json).expect("Unable to save !");

                                        println!("##    KeyGen succuss!");
                                    }
                                    TwoPartyMsg::SignBegin => {
                                        if index == 0 {
                                            time = time::now();
                                            let msg_send = TwoPartyMsg::SignPartyOneRoundOneMsg(party_one_sign.round_one_msg.clone());
                                            let msg_bytes = bincode::serialize(&msg_send).unwrap();
                                            node2.broadcast(Message(msg_bytes)).await;
                                        } else {
                                            println!("Please use index 0 party begin the sign...");
                                        }

                                    }
                                    TwoPartyMsg::SignPartyOneRoundOneMsg(dlcom) => {
                                        println!("\n=>    Sign: Receiving RoundOneMsg from index 0");
                                        time = time::now();

                                        party_two_sign.set_dl_com(dlcom);
                                        let msg_send = TwoPartyMsg::SignPartyTwoRoundOneMsg(party_two_sign.msg.clone());
                                        let msg_bytes = bincode::serialize(&msg_send).unwrap();
                                        node2.broadcast(Message(msg_bytes)).await;
                                    }
                                    TwoPartyMsg::SignPartyTwoRoundOneMsg(msg) => {
                                        println!("\n=>    Sign: Receiving RoundOneMsg from index 1");

                                        let witness = party_one_sign
                                            .verify_and_get_next_msg(&msg)
                                            .unwrap();
                                        party_one_sign.set_received_msg(msg);

                                        let msg_send = TwoPartyMsg::SignPartyOneRoundTwoMsg(witness);
                                        let msg_bytes = bincode::serialize(&msg_send).unwrap();
                                        node2.broadcast(Message(msg_bytes)).await;
                                    }
                                    TwoPartyMsg::SignPartyOneRoundTwoMsg(witness) => {
                                        println!("\n=>    Sign: Receiving RoundTwoMsg from index 0");

                                        party_two::SignPhase::verify_received_dl_com_zk(
                                            &party_two_sign.received_round_one_msg,
                                            &witness,
                                        )
                                        .unwrap();

                                        // read key file
                                        let data = fs::read_to_string("./keygen_result.json")
                                            .expect("Unable to load keys, did you run keygen first? ");
                                        let (hsmcl_public, secret_key): (
                                            HSMCLPublic,
                                            FE,
                                            ) = serde_json::from_str(&data).unwrap();

                                        let ephemeral_public_share =
                                            party_two_sign.compute_public_share_key(witness.get_public_key());
                                        let (cipher, t_p) = party_two_sign.sign(
                                            &group,
                                            &hsmcl_public,
                                            &ephemeral_public_share,
                                            &secret_key,
                                            // &message_to_sign,
                                        );

                                        let msg_send = TwoPartyMsg::SignPartyTwoRoundTwoMsg(cipher, t_p);
                                        let msg_bytes = bincode::serialize(&msg_send).unwrap();
                                        node2.broadcast(Message(msg_bytes)).await;

                                        // Party two time end
                                        println!("Sign party two time: {:?}", time::now() - time);
                                        println!("##    Sign Finish!");
                                    }
                                    TwoPartyMsg::SignPartyTwoRoundTwoMsg(cipher, t_p) => {
                                        println!("\n=>    Sign: Receiving RoundTwoMsg from index 1");

                                        // read key file
                                        let data = fs::read_to_string("./keygen_result.json")
                                            .expect("Unable to load keys, did you run keygen first? ");
                                        let (hsmcl_private, secret_key): (
                                            HSMCL,
                                            FE,
                                            ) = serde_json::from_str(&data).unwrap();

                                        let ephemeral_public_share =
                                            party_one_sign.compute_public_share_key(&party_one_sign.received_msg.pk);
                                        let signature = party_one_sign.sign(
                                            &group,
                                            &hsmcl_private,
                                            &cipher,
                                            &ephemeral_public_share,
                                            &secret_key,
                                            &t_p,
                                        );

                                        // Party one time end
                                        println!("Sign party one time: {:?}", time::now() - time);
                                        println!("##    Sign finish! \n signature: {:?}", signature);
                                    }
                                }

                                // println!("\n")
                            }
                            NodeNotification::KeyGen => {
                            }
                            NodeNotification::Sign => {
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
    Connect,
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
    peer_info: PeerInfo,
}

impl Console {
    pub fn spawn(
        node: NodeHandle<Message>,
        peer_info: PeerInfo,
    ) -> task::JoinHandle<Result<(), String>> {
        task::spawn_local(async move {
            let mut stdin = io::BufReader::new(io::stdin());
            let mut console = Console { node, peer_info };
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
                self.node
                    .connect_to_peer(&self.peer_info.address, None, self.peer_info.index)
                    .await
                    .map_err(|e| {
                        format!("Handshake error with {}. {:?}", self.peer_info.address, e)
                    })?;
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
                let msg = bincode::serialize(&TwoPartyMsg::KegGenBegin).unwrap();
                self.node.keygen(Message(msg)).await;
            }
            UserCommand::Sign => {
                let msg = bincode::serialize(&TwoPartyMsg::SignBegin).unwrap();
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

        if command == "connect" {
            Ok(UserCommand::Connect)
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
