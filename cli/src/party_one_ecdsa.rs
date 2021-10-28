use curv::arithmetic::Converter;

use tokio::io;
use tokio::prelude::*;
use tokio::task;

use p2p::{Info, Message, MsgProcess, Node, NodeHandle, PeerID, ProcessMessage};

use class_group::primitives::cl_dl_public_setup::{CLGroup, SK};
use cli::config::TwoPartyConfig;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use curv::BigInt;
use multi_party_ecdsa::protocols::two_party::message::{PartyOneMsg, PartyTwoMsg};
use multi_party_ecdsa::protocols::two_party::party_one;
use multi_party_ecdsa::utilities::class::update_class_group_by_p;
use std::path::Path;
use std::fs;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(
    name = "two-party-ecdsa",
    author = "songxuyang",
    rename_all = "snake_case"
)]
struct Opt {
    /// My index
    #[structopt(short, long)]
    index: usize,

    /// Message to sign
    #[structopt(short, long)]
    message: String,

    /// Config Path
    #[structopt(short, long)]
    config_path: String,
}

struct PartyOne {
    party_index: usize,
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
        let index = opt.index;
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
        let party_one_sign = party_one::SignPhase::new(new_class_group.clone(), &message);
        let party_one_info = PartyOne {
            party_index: index,
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
        let received_msg: PartyTwoMsg = bincode::deserialize(&msg).unwrap();
        match received_msg {
            PartyTwoMsg::KegGenBegin => {
                if index == 0 {
                    // Party one time begin
                    let msg_send: PartyOneMsg = PartyOneMsg::KeyGenPartyOneRoundOneMsg(
                        self.party_one_keygen.round_one_msg.clone(),
                    );
                    let msg_bytes: Vec<u8> = bincode::serialize(&msg_send).unwrap();
                    return ProcessMessage::BroadcastMessage(Message(msg_bytes));
                } else {
                    println!("Please use index 0 party begin the keygen...");
                    return ProcessMessage::Default();
                }
            }
            PartyTwoMsg::KenGenPartyTwoRoundOneMsg(msg) => {
                println!("\n=>    KeyGen: Receiving RoundOneMsg from index 1");
                let com_open = self.party_one_keygen.verify_and_get_next_msg(&msg).unwrap();
                self.party_one_keygen.compute_public_key(&msg.pk);

                // Get pk and pk'
                let (h_caret, h, gp) = self.party_one_keygen.get_class_group_pk();

                let msg_send = PartyOneMsg::KeyGenPartyOneRoundTwoMsg(
                    com_open,
                    h_caret,
                    h,
                    gp,
                    self.party_one_keygen.promise_state.clone(),
                    self.party_one_keygen.promise_proof.clone(),
                );
                let msg_bytes = bincode::serialize(&msg_send).unwrap();

                // Party one save keygen to file
                let file_name =
                    "./keygen_result".to_string() + &self.party_index.to_string() + ".json";
                let keygen_path = Path::new(&file_name);
                let keygen_json = serde_json::to_string(&(
                    self.party_one_keygen.cl_keypair.get_secret_key().clone(),
                    self.party_one_keygen.keypair.get_secret_key().clone(),
                    self.party_one_keygen.public_signing_key,
                ))
                .unwrap();
                fs::write(keygen_path, keygen_json).expect("Unable to save !");
                println!("##    KeyGen finish!");
                return ProcessMessage::BroadcastMessage(Message(msg_bytes));
            }
            PartyTwoMsg::SignBegin => {
                if index == 0 {
                    let msg_send = PartyOneMsg::SignPartyOneRoundOneMsg(
                        self.party_one_sign.round_one_msg.clone(),
                    );
                    let msg_bytes = bincode::serialize(&msg_send).unwrap();
                    return ProcessMessage::BroadcastMessage(Message(msg_bytes));
                } else {
                    println!("Please use index 0 party begin the sign...");
                    return ProcessMessage::Default();
                }
            }
            PartyTwoMsg::SignPartyTwoRoundOneMsg(msg) => {
                println!("\n=>    Sign: Receiving RoundOneMsg from index 1");

                let witness = self.party_one_sign.verify_and_get_next_msg(&msg).unwrap();
                self.party_one_sign.set_received_msg(msg);

                let msg_send = PartyOneMsg::SignPartyOneRoundTwoMsg(witness);
                let msg_bytes = bincode::serialize(&msg_send).unwrap();
                return ProcessMessage::BroadcastMessage(Message(msg_bytes));
            }
            PartyTwoMsg::SignPartyTwoRoundTwoMsg(cipher, t_p) => {
                println!("\n=>    Sign: Receiving RoundTwoMsg from index 1");

                // read key file
                let file_name =
                    "./keygen_result".to_string() + &self.party_index.to_string() + ".json";
                let data = fs::read_to_string(file_name)
                    .expect("Unable to load keys, did you run keygen first? ");
                let (cl_sk, secret_key, public_signing_key): (SK, FE, GE) = serde_json::from_str(&data).unwrap();

                let ephemeral_public_share = self
                    .party_one_sign
                    .compute_public_share_key(&self.party_one_sign.received_msg.pk);
                let signature = self.party_one_sign.sign(
                    &cl_sk,
                    &cipher,
                    &ephemeral_public_share,
                    &secret_key,
                    &t_p,
                );
                party_one::SignPhase::verify(&signature.clone().unwrap(), &public_signing_key, &self.party_one_sign.message).unwrap();
                // Party one time end
                println!("##    Sign finish! \n signature: {:?}", signature);
                return ProcessMessage::Default();
            }
            _ => {
                println!("Unsupported parse Received MessageType");
                return ProcessMessage::Default();
            }
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
                let msg = bincode::serialize(&PartyTwoMsg::KegGenBegin).unwrap();
                self.node.sendself(Message(msg)).await;
            }
            UserCommand::Sign => {
                let msg = bincode::serialize(&PartyTwoMsg::SignBegin).unwrap();
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
