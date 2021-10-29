use curv::arithmetic::Converter;

use tokio::io;
use tokio::prelude::*;
use tokio::task;

use p2p::{Info, Message, MsgProcess, Node, NodeHandle, PeerID, ProcessMessage};
use multi_party_ecdsa::communication::receiving_messages::ReceivingMessages;
use multi_party_ecdsa::communication::sending_messages::SendingMessages;

use class_group::primitives::cl_dl_public_setup::CLGroup;
use cli::config::TwoPartyConfig;
use curv::BigInt;
use multi_party_ecdsa::protocols::two_party::message::PartyTwoMsg;
use multi_party_ecdsa::protocols::two_party::party_one;
use multi_party_ecdsa::utilities::class::update_class_group_by_p;
use structopt::StructOpt;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(StructOpt, Debug)]
#[structopt(
    name = "two-party-ecdsa",
    author = "songxuyang",
    rename_all = "snake_case"
)]
struct Opt {
    /// Message to sign
    #[structopt(short, long)]
    message: String,

    /// Config Path
    #[structopt(short, long)]
    config_path: String,
}

struct PartyOne {
    party_one_keygen: party_one::KeyGenInit,
    party_one_sign: party_one::SignPhase,
}

pub struct InitMessage {
    my_info: Info,
    peer_info: Info,
    party_one_info: PartyOne,
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
    peer_info: Info,
}

impl InitMessage {
    pub fn init_message() -> Self {
        let opt = Opt::from_args();
        let index = 0;
        let message = opt.message;
        let config = TwoPartyConfig::new_from_file(&opt.config_path).unwrap();
        let my_info = config.get_my_info(index);
        let peer_info = config.get_peer_info(index);

        // Init group params
        let seed: BigInt = BigInt::from_hex(
            "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
        ).unwrap();
        let qtilde: BigInt = BigInt::from_hex("23893039587891638565297401593924273169825964283558231612167738384238313917887833945225898199741584873627027859268757281540231029139309613219716874418588517495558290624716349383746651319918936091587965845797835593810764676322501564946526995033976417223598945838942128878559190581681834232455419055873026991107437602524121085617731").unwrap();
        let group = CLGroup::new_from_qtilde(&seed, &qtilde);
        // let group = CLGroup::new_from_setup(&1348, &seed); //discriminant 1348

        // Init party one info
        let party_one_keygen = party_one::KeyGenInit::new(&group);
        let new_class_group = update_class_group_by_p(&group);
        let mut party_one_sign = party_one::SignPhase::new(new_class_group.clone(), &message);

        // Load keygen result
        let keygen_path = Path::new("./keygen_result0.json");
        if keygen_path.exists() {
            let keygen_json = fs::read_to_string(keygen_path).unwrap();
            party_one_sign.load_keygen_result(&keygen_json);
        } else {
            // If keygen successes, party_one_sign will load keygen result automally.
            println!("Can not load keygen result! Please keygen first");
        }

        let party_one_info = PartyOne {
            party_one_keygen,
            party_one_sign,
        };

        InitMessage {
            my_info,
            peer_info,
            party_one_info,
        }
    }
}

impl MsgProcess<Message> for PartyOne {
    fn process(&mut self, index: usize, msg: Message) -> ProcessMessage<Message> {
        let received_msg: ReceivingMessages = bincode::deserialize(&msg).unwrap();
        let mut sending_msg = SendingMessages::EmptyMsg;
        match received_msg {
            ReceivingMessages::TwoKeyGenMessagePartyTwo(msg) => {
                sending_msg = self.party_one_keygen.msg_handler_keygen(index, &msg);
            }
            ReceivingMessages::TwoSignMessagePartyTwo(msg) => {
                sending_msg = self.party_one_sign.msg_handler_sign(index, &msg);
            }
            _ => {}
        }
        
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
            }
            SendingMessages::BroadcastMessage(msg) => {
                return ProcessMessage::BroadcastMessage(Message(msg));
            }
            SendingMessages::EmptyMsg => {
                return ProcessMessage::Default();
            }
            SendingMessages::KeyGenSuccessWithResult(res) => {
                println!("keygen Success! {}", res);

                // Load keygen result for signphase
                self.party_one_sign.load_keygen_result(&res);

                let file_name = "./keygen_result0".to_string() + ".json";
                fs::write(file_name, res).expect("Unable to save !");
                return ProcessMessage::Default();
            }
            SendingMessages::SignSuccessWithResult(res) => {
                println!("Sign Success! {}", res);
                return ProcessMessage::Default();
            }
            _ => {return ProcessMessage::Default();}
        }
    }
}

fn main() {
    let init_messages = InitMessage::init_message();

    // Create the runtime.
    let mut rt: tokio::runtime::Runtime =
        tokio::runtime::Runtime::new().expect("Should be able to init tokio::Runtime.");
    let local: task::LocalSet = task::LocalSet::new();
    local
        .block_on(&mut rt, async move {
            // Setup a node
            let (mut node_handle, notifications_channel) =
                Node::<Message>::node_init(&init_messages.my_info).await;

            // Begin the UI.
            let interactive_loop: task::JoinHandle<Result<(), String>> =
                Console::spawn(node_handle.clone(), init_messages.peer_info);

            // Spawn the notifications loop
            let mut message_process = init_messages.party_one_info;
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
        peer_info: Info,
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
                let msg = bincode::serialize(&ReceivingMessages::TwoKeyGenMessagePartyTwo(PartyTwoMsg::KegGenBegin)).unwrap();
                self.node.sendself(Message(msg)).await;
            }
            UserCommand::Sign => {
                let msg = bincode::serialize(&ReceivingMessages::TwoSignMessagePartyTwo(PartyTwoMsg::SignBegin)).unwrap();
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
