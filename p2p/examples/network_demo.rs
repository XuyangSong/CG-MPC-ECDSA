use curve25519_dalek::scalar::Scalar;
use rand::thread_rng;
use std::net::{IpAddr, Ipv4Addr};

use tokio::io;
use tokio::prelude::*;
use tokio::task;

use p2p::cybershake;
use p2p::{Message, Node, NodeConfig, NodeHandle, NodeNotification, PeerID};

use class_group::primitives::cl_dl_public_setup::CLGroup;
use curv::BigInt;
use multi_party_ecdsa::communication::receiving_messages::ReceivingMessages;
use multi_party_ecdsa::communication::sending_messages::SendingMessages;
use multi_party_ecdsa::protocols::multi_party::ours::party_i::MultiKeyGenMessage;
use multi_party_ecdsa::protocols::multi_party::ours::party_i::*;

fn main() {
    // Create the runtime.
    let mut rt = tokio::runtime::Runtime::new().expect("Should be able to init tokio::Runtime.");
    let local = task::LocalSet::new();
    local
        .block_on(&mut rt, async move {
            // Creating a random private key instead of reading from a file.
            let host_privkey = cybershake::PrivateKey::from(Scalar::random(&mut thread_rng()));

            // TBD: Read config file. Including ip, port, index and (t, n).

            let config = NodeConfig {
                index: 2,
                listen_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                listen_port: 0,
                inbound_limit: 100,
                outbound_limit: 100,
                heartbeat_interval_sec: 3600,
            };

            let index = config.index;

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
            let interactive_loop = Console::spawn(node, index);

            // Spawn the notifications loop
            let notifications_loop = {
                task::spawn_local(async move {
                    let seed: BigInt = str::parse(
                        "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
                    ).unwrap();
                    let group = CLGroup::new_from_setup(&1348, &seed); //discriminant 1348
                    let params = Parameters {
                        threshold: 2,
                        share_count: 3,
                    };
                    // TBD: add a new func, init it latter.
                    let mut keygen = KeyGen::phase_one_init(&group, index, params);
                    // let mut sign: SignPhase;

                    while let Some(notif) = notifications_channel.recv().await {
                        match notif {
                            NodeNotification::PeerAdded(_pid, index) => {
                                println!("\n=>    Peer connected to index: {}", index)
                            }
                            NodeNotification::PeerDisconnected(pid) => {
                                println!("\n=> Peer disconnected: {}", pid)
                            }
                            NodeNotification::MessageReceived(pid, index, msg) => {
                                // Decode msg
                                let received_msg: ReceivingMessages = bincode::deserialize(&msg).unwrap();
                                let sending_msg;
                                match received_msg {
                                    ReceivingMessages::MultiKeyGenMessage(msg) => {
                                        sending_msg = keygen.msg_handler(index, &msg);
                                    }
                                }

                                match sending_msg {
                                    SendingMessages::P2pMessage(msgs) => {
                                        for (index, msg) in msgs.iter() {
                                            node2.sendmsgbyindex(*index, Message(msg.to_vec())).await;
                                        }
                                        println!("sending p2p msg");
                                    }
                                    SendingMessages::BroadcastMessage(msg) => {
                                        node2.broadcast(Message(msg)).await;
                                        println!("sending broadcast msg");
                                    }
                                    SendingMessages::EmptyMsg => {
                                        println!("no msg to send");
                                    }

                                }
                                // handle msg
                                println!(
                                    "\n=> Received: from {}",
                                    // String::from_utf8_lossy(&msg).into_owned(),
                                    index
                                )
                            }
                            NodeNotification::KeyGen(index) => {
                                let msg = keygen.phase_two_generate_dl_com_msg();
                                // // Broadcast first msg
                                let msg_bytes = bincode::serialize(&msg).unwrap();
                                node2.broadcast(Message(msg_bytes)).await;
                                println!("KeyGen...")
                            }
                            NodeNotification::Sign => {
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
    Connect(Vec<String>),
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
    index: usize,
}

impl Console {
    pub fn spawn(node: NodeHandle<Message>, index: usize) -> task::JoinHandle<Result<(), String>> {
        task::spawn_local(async move {
            let mut stdin = io::BufReader::new(io::stdin());
            let mut console = Console { node, index };
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

                // println!("log: {:?}", result);
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
            UserCommand::Connect(addrs) => {
                for (i, addr) in addrs.iter().enumerate() {
                    // skip connect myself
                    if i != self.index {
                        // println!("\n=>    Peer i: {}, index: {}", i, self.index);
                        self.node
                            .connect_to_peer(&addr, None, i)
                            .await
                            .map_err(|e| format!("Handshake error with {}. {:?}", addr, e))?;
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
                self.node.sign().await;
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
            let addrs = rest
                .unwrap_or("")
                .to_string()
                .trim()
                .split_whitespace()
                .map(|a| a.to_string())
                .collect::<Vec<_>>();
            if addrs.len() == 0 {
                return Err("Address is not specified. Use `connect <addr:port>`. Multiple addresses are allowed.".into());
            }
            Ok(UserCommand::Connect(addrs))
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
            // println!("log: {:?}", command);
            Ok(UserCommand::Exit)
        } else {
            Err(format!("Unknown command `{}`", command))
        }
    }
}
