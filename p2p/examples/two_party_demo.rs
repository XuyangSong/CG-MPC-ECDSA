use curv::arithmetic::Converter;
// use std::net::IpAddr;

use tokio::io;
use tokio::prelude::*;
use tokio::task;

use p2p::{Message, MsgProcess, Node, NodeHandle, PeerID, ProcessMessage};

use class_group::primitives::cl_dl_public_setup::{CLGroup, SK};
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::elliptic::curves::secp256_k1::FE;
use curv::elliptic::curves::traits::*;
use curv::BigInt;
use multi_party_ecdsa::protocols::two_party::message::TwoPartyMsg;
use multi_party_ecdsa::protocols::two_party::party_one;
use multi_party_ecdsa::protocols::two_party::party_two;
use multi_party_ecdsa::utilities::class::update_class_group_by_p;
use multi_party_ecdsa::utilities::promise_sigma::PromiseState;
use serde::Deserialize;
use std::path::Path;
use std::{env, fs};

#[derive(Debug, Deserialize)]
struct JsonConfig {
    pub infos: Vec<PeerInfo>,
    pub message: String, // message to sign
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
    pub my_info: MyInfo,
    pub peer_info: PeerInfo,
    pub message: String,
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
        let mut peers_info_: PeerInfo = PeerInfo::new(0, " ".to_string());
        for info in json_config.infos.iter() {
            if info.index == index_ {
                let s = info.address.clone();
                let vs: Vec<&str> = s.splitn(2, ":").collect();
                ip_ = vs[0].to_string();
                port_ = vs[1].to_string().parse::<u16>().unwrap();
            } else {
                peers_info_ = PeerInfo::new(info.index, info.address.clone());
            }
        }

        Self {
            my_info: MyInfo::new(index_, ip_, port_),
            peer_info: peers_info_,
            message: json_config.message,
        }
    }
}

pub struct InitMessage {
    my_info: MyInfo,
    peer_info: PeerInfo,
    two_party_info: TwoParty,
}
impl InitMessage {
    pub fn init_message() -> Self {
        let party_id_str: String = env::args().nth(1).unwrap();
        let party_id: usize = party_id_str.parse::<usize>().unwrap();
        let json_config_file: String = env::args().nth(2).unwrap();

        // Load config from file
        let json_config: JsonConfigInternal =
            JsonConfigInternal::init_with(party_id, json_config_file);

        // Get msg hash
        let message_hash: BigInt = HSha256::create_hash_from_slice(json_config.message.as_bytes());
        let message_to_sign: FE = ECScalar::from(&message_hash);

        // Init group params
        let seed: BigInt = BigInt::from_hex(
            "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
        ).unwrap();
        let qtilde: BigInt = BigInt::from_hex("23893039587891638565297401593924273169825964283558231612167738384238313917887833945225898199741584873627027859268757281540231029139309613219716874418588517495558290624716349383746651319918936091587965845797835593810764676322501564946526995033976417223598945838942128878559190581681834232455419055873026991107437602524121085617731").unwrap();
        let group = CLGroup::new_from_qtilde(&seed, &qtilde);
        // let group = CLGroup::new_from_setup(&1348, &seed); //discriminant 1348

        // Init two party info
        let party_one_keygen = party_one::KeyGenInit::new(&group);
        let party_two_keygen = party_two::KeyGenInit::new(&group);
        let new_class_group = update_class_group_by_p(&group);
        let party_one_sign = party_one::SignPhase::new(new_class_group.clone());
        let party_two_sign = party_two::SignPhase::new(new_class_group, &message_to_sign);
        let two_party_info = TwoParty {
            party_index: json_config.my_info.index,
            party_one_keygen,
            party_two_keygen,
            party_one_sign,
            party_two_sign,
        };

        InitMessage {
            my_info: json_config.my_info,
            peer_info: json_config.peer_info,
            two_party_info,
        }
    }
}
struct TwoParty {
    party_index: usize,
    party_one_keygen: party_one::KeyGenInit,
    party_two_keygen: party_two::KeyGenInit,
    party_one_sign: party_one::SignPhase,
    party_two_sign: party_two::SignPhase,
}
impl MsgProcess<Message> for TwoParty {
    fn process(&mut self, index: usize, msg: Message) -> ProcessMessage<Message> {
        let received_msg: TwoPartyMsg = bincode::deserialize(&msg).unwrap();
        match received_msg {
            TwoPartyMsg::KegGenBegin => {
                if index == 0 {
                    // Party one time begin
                    let msg_send: TwoPartyMsg = TwoPartyMsg::KeyGenPartyOneRoundOneMsg(
                        self.party_one_keygen.round_one_msg.clone(),
                    );
                    let msg_bytes: Vec<u8> = bincode::serialize(&msg_send).unwrap();
                    return ProcessMessage::BroadcastMessage(Message(msg_bytes));
                } else {
                    println!("Please use index 0 party begin the keygen...");
                    return ProcessMessage::Default();
                }
            }
            TwoPartyMsg::KeyGenPartyOneRoundOneMsg(dlcom) => {
                println!("\n=>    KeyGen: Receiving RoundOneMsg from index 0");
                // Party two time begin
                self.party_two_keygen.set_dl_com(dlcom);
                let msg_send =
                    TwoPartyMsg::KenGenPartyTwoRoundOneMsg(self.party_two_keygen.msg.clone());
                let msg_bytes = bincode::serialize(&msg_send).unwrap();
                return ProcessMessage::BroadcastMessage(Message(msg_bytes));
            }
            TwoPartyMsg::KenGenPartyTwoRoundOneMsg(msg) => {
                println!("\n=>    KeyGen: Receiving RoundOneMsg from index 1");
                let com_open = self.party_one_keygen.verify_and_get_next_msg(&msg).unwrap();
                self.party_one_keygen.compute_public_key(&msg.pk);

                // Get pk and pk'
                let (h_caret, h, gp) = self.party_one_keygen.get_class_group_pk();

                let msg_send = TwoPartyMsg::KeyGenPartyOneRoundTwoMsg(
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
                ))
                .unwrap();
                fs::write(keygen_path, keygen_json).expect("Unable to save !");
                println!("##    KeyGen finish!");
                return ProcessMessage::BroadcastMessage(Message(msg_bytes));
            }
            TwoPartyMsg::KeyGenPartyOneRoundTwoMsg(
                com_open,
                h_caret,
                h,
                gp,
                promise_state,
                promise_proof,
            ) => {
                println!("\n=>    KeyGen: Receiving RoundTwoMsg from index 0");
                // Verify commitment
                party_two::KeyGenInit::verify_received_dl_com_zk(
                    &self.party_two_keygen.received_msg,
                    &com_open,
                )
                .unwrap();

                // Verify pk and pk's
                self.party_two_keygen
                    .verify_class_group_pk(&h_caret, &h, &gp)
                    .unwrap();

                // Verify promise proof
                self.party_two_keygen
                    .verify_promise_proof(&promise_state, &promise_proof)
                    .unwrap();
                self.party_two_keygen
                    .compute_public_key(com_open.get_public_key());

                // Party two save keygen to file
                let file_name = "./keygen_result".to_string() + ".json";
                let keygen_path = Path::new(&file_name);
                let keygen_json = serde_json::to_string(&(
                    promise_state,
                    self.party_two_keygen.keypair.get_secret_key().clone(),
                ))
                .unwrap();
                fs::write(keygen_path, keygen_json).expect("Unable to save !");

                println!("##    KeyGen succuss!");
                return ProcessMessage::Default();
            }
            TwoPartyMsg::SignBegin => {
                if index == 0 {
                    let msg_send = TwoPartyMsg::SignPartyOneRoundOneMsg(
                        self.party_one_sign.round_one_msg.clone(),
                    );
                    let msg_bytes = bincode::serialize(&msg_send).unwrap();
                    return ProcessMessage::BroadcastMessage(Message(msg_bytes));
                } else {
                    println!("Please use index 0 party begin the sign...");
                    return ProcessMessage::Default();
                }
            }
            TwoPartyMsg::SignPartyOneRoundOneMsg(dlcom) => {
                println!("\n=>    Sign: Receiving RoundOneMsg from index 0");
                self.party_two_sign.set_dl_com(dlcom);
                let msg_send =
                    TwoPartyMsg::SignPartyTwoRoundOneMsg(self.party_two_sign.msg.clone());
                let msg_bytes = bincode::serialize(&msg_send).unwrap();
                return ProcessMessage::BroadcastMessage(Message(msg_bytes));
            }
            TwoPartyMsg::SignPartyTwoRoundOneMsg(msg) => {
                println!("\n=>    Sign: Receiving RoundOneMsg from index 1");

                let witness = self.party_one_sign.verify_and_get_next_msg(&msg).unwrap();
                self.party_one_sign.set_received_msg(msg);

                let msg_send = TwoPartyMsg::SignPartyOneRoundTwoMsg(witness);
                let msg_bytes = bincode::serialize(&msg_send).unwrap();
                return ProcessMessage::BroadcastMessage(Message(msg_bytes));
            }
            TwoPartyMsg::SignPartyOneRoundTwoMsg(witness) => {
                println!("\n=>    Sign: Receiving RoundTwoMsg from index 0");

                party_two::SignPhase::verify_received_dl_com_zk(
                    &self.party_two_sign.received_round_one_msg,
                    &witness,
                )
                .unwrap();

                // read key file
                let file_name = "./keygen_result".to_string() + ".json";
                let data = fs::read_to_string(file_name)
                    .expect("Unable to load keys, did you run keygen first? ");
                let (promise_state, secret_key): (PromiseState, FE) =
                    serde_json::from_str(&data).unwrap();

                let ephemeral_public_share = self
                    .party_two_sign
                    .compute_public_share_key(witness.get_public_key());
                let (cipher, t_p) = self
                    .party_two_sign
                    .sign(&ephemeral_public_share, &secret_key, &promise_state.cipher)
                    .unwrap();

                let msg_send = TwoPartyMsg::SignPartyTwoRoundTwoMsg(cipher, t_p);
                let msg_bytes = bincode::serialize(&msg_send).unwrap();

                // Party two time end
                println!("##    Sign Finish!");
                return ProcessMessage::BroadcastMessage(Message(msg_bytes));
            }
            TwoPartyMsg::SignPartyTwoRoundTwoMsg(cipher, t_p) => {
                println!("\n=>    Sign: Receiving RoundTwoMsg from index 1");

                // read key file
                let file_name =
                    "./keygen_result".to_string() + &self.party_index.to_string() + ".json";
                let data = fs::read_to_string(file_name)
                    .expect("Unable to load keys, did you run keygen first? ");
                let (cl_sk, secret_key): (SK, FE) = serde_json::from_str(&data).unwrap();

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
    if env::args().count() < 3 {
        println!(
            "Usage:\n\t{} <parties> <party-id> <port> <config-file>",
            env::args().nth(0).unwrap()
        );
        panic!("Need Config File")
    }
    let init_messages = InitMessage::init_message();

    // Create the runtime.
    let mut rt: tokio::runtime::Runtime =
        tokio::runtime::Runtime::new().expect("Should be able to init tokio::Runtime.");
    let local: task::LocalSet = task::LocalSet::new();
    local
        .block_on(&mut rt, async move {
            //Setup a node
            let (mut node_handle, notifications_channel) = Node::<Message>::node_init(
                init_messages.my_info.index,
                init_messages.my_info.ip.parse().unwrap(),
                init_messages.my_info.port,
            )
            .await;

            // Begin the UI.
            let interactive_loop: task::JoinHandle<Result<(), String>> =
                Console::spawn(node_handle.clone(), init_messages.peer_info);

            // Spawn the notifications loop
            let mut message_process = init_messages.two_party_info;
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
                self.node.sendself(Message(msg)).await;
            }
            UserCommand::Sign => {
                let msg = bincode::serialize(&TwoPartyMsg::SignBegin).unwrap();
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
