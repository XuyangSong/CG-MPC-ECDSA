use cli::console::Console;
use curv::arithmetic::Converter;

use tokio::task;

use multi_party_ecdsa::communication::receiving_messages::ReceivingMessages;
use multi_party_ecdsa::communication::sending_messages::SendingMessages;
use p2p::{Info, Message, MsgProcess, Node, ProcessMessage};

use class_group::primitives::cl_dl_public_setup::CLGroup;
use cli::config::TwoPartyConfig;
use curv::BigInt;
use multi_party_ecdsa::protocols::two_party::party_one;
use multi_party_ecdsa::utilities::class::update_class_group_by_p;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use structopt::StructOpt;

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
    party_one_keygen: party_one::KeyGenPhase,
    party_one_sign: party_one::SignPhase,
}

pub struct InitMessage {
    my_info: Info,
    peer_info: Vec<Info>,
    party_one_info: PartyOne,
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
        let party_one_keygen = party_one::KeyGenPhase::new(&group);
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
                sending_msg = self.party_one_keygen.msg_handler_keygen(&msg);
            }
            ReceivingMessages::TwoSignMessagePartyTwo(msg) => {
                sending_msg = self.party_one_sign.msg_handler_sign(&msg);
            }
            ReceivingMessages::KeyGenBegin => {
                sending_msg = self.party_one_keygen.process_begin_keygen(index);
            }
            ReceivingMessages::SignBegin => {
                sending_msg = self.party_one_sign.process_begin_sign(index);
            }
            _ => {
                println!("Undefined Message Process: {:?}", received_msg);
            }
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
            _ => {
                println!("Undefined Message Process: {:?}", sending_msg);
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

