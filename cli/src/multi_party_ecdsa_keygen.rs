use cli::config::MultiPartyConfig;
use curv::arithmetic::Converter;
use curv::BigInt;
use multi_party_ecdsa::communication::receiving_messages::ReceivingMessages;
use multi_party_ecdsa::communication::sending_messages::SendingMessages;
use multi_party_ecdsa::protocols::multi_party::ours::keygen::*;
use multi_party_ecdsa::protocols::multi_party::ours::message::MultiKeyGenMessage;
use p2p::{Info, Message, MsgProcess, Node, NodeHandle, PeerID, ProcessMessage};
use std::collections::HashMap;
use std::fs;
use structopt::StructOpt;
use tokio::io;
use tokio::prelude::*;
use tokio::task;

#[derive(StructOpt, Debug)]
#[structopt(
    name = "multi-ecdsa-keygen",
    author = "songxuyang",
    rename_all = "snake_case"
)]
struct Opt {
    /// My index
    #[structopt(short, long)]
    index: usize,

    /// Config Path
    #[structopt(short, long)]
    config_path: String,
}

pub struct InitMessage {
    my_info: Info,
    peers_info: Vec<Info>,
    multi_party_keygen_info: MultiPartyKeygen,
}

struct MultiPartyKeygen {
    keygen: KeyGenPhase,
}

enum UserCommand {
    Nop,
    Connect,
    KeyGen,
    Disconnect(PeerID), // peer id
    ListPeers,
    Exit,
}

pub struct Console {
    node: NodeHandle<Message>,
    peers_info: Vec<Info>,
}

impl InitMessage {
    pub fn init_message() -> Self {
        let opt = Opt::from_args();
        let index = opt.index;
        let config = MultiPartyConfig::new_from_file(&opt.config_path).unwrap();

        let my_info = config.get_my_info(index);

        let peers_info: Vec<Info> = config.get_peers_info(index);
        let params = Parameters {
            threshold: config.threshold,
            share_count: config.share_count,
        };

        //Init group params
        let seed: BigInt = BigInt::from_hex(
            "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
        ).unwrap();
        // discriminant: 1348, lambda: 112
        let qtilde: BigInt = BigInt::from_hex("23893039587891638565297401593924273169825964283558231612167738384238313917887833945225898199741584873627027859268757281540231029139309613219716874418588517495558290624716349383746651319918936091587965845797835593810764676322501564946526995033976417223598945838942128878559190581681834232455419055873026991107437602524121085617731").unwrap();

        // TBD: add a new func, init it latter.
        //Init multi party info
        let keygen = KeyGenPhase::new(&seed, &qtilde, index, params.clone()).unwrap();
        let multi_party_keygen_info = MultiPartyKeygen { keygen: keygen };
        let init_messages = InitMessage {
            my_info,
            peers_info,
            multi_party_keygen_info: multi_party_keygen_info,
        };
        return init_messages;
    }
}

impl MsgProcess<Message> for MultiPartyKeygen {
    fn process(&mut self, index: usize, msg: Message) -> ProcessMessage<Message> {
        let received_msg: ReceivingMessages = bincode::deserialize(&msg).unwrap();
        let mut sending_msg = SendingMessages::EmptyMsg;
        if let ReceivingMessages::MultiKeyGenMessage(msg) = received_msg {
            sending_msg = self.keygen.msg_handler(index, &msg).unwrap();
        }
        match sending_msg {
            SendingMessages::P2pMessage(msgs) => {
                //TBD: handle vector to Message
                let mut msgs_to_send: HashMap<usize, Message> = HashMap::new();
                for (key, value) in msgs {
                    msgs_to_send.insert(key, Message(value));
                }
                return ProcessMessage::SendMultiMessage(msgs_to_send);
            }
            SendingMessages::BroadcastMessage(msg) => {
                return ProcessMessage::BroadcastMessage(Message(msg));
            }
            SendingMessages::KeyGenSuccessWithResult(res) => {
                println!("keygen Success! {}", res);

                // Save keygen result to file
                let file_name =
                    "./keygen_result".to_string() + &self.keygen.party_index.to_string() + ".json";
                fs::write(file_name, res).expect("Unable to save !");
                return ProcessMessage::Default();
            }
            SendingMessages::EmptyMsg => {
                return ProcessMessage::Default();
            }
            _ => {
                println!("Undefined Message Process");
                return ProcessMessage::Default();
            }
        }
    }
}

fn main() {
    let init_messages = InitMessage::init_message();

    // Create the runtime.
    let mut rt = tokio::runtime::Runtime::new().expect("Should be able to init tokio::Runtime.");
    let local = task::LocalSet::new();
    local
        .block_on(&mut rt, async move {
            // Setup a node
            let (mut node_handle, notifications_channel) =
                Node::<Message>::node_init(&init_messages.my_info).await;

            // Begin the UI.
            let interactive_loop = Console::spawn(node_handle.clone(), init_messages.peers_info);

            // Spawn the notifications loop
            let mut message_process = init_messages.multi_party_keygen_info;
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
                let msg = bincode::serialize(&ReceivingMessages::MultiKeyGenMessage(
                    MultiKeyGenMessage::KeyGenBegin,
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
        } else if command == "exit" || command == "quit" || command == "q" {
            Ok(UserCommand::Exit)
        } else {
            Err(format!("Unknown command `{}`", command))
        }
    }
}
