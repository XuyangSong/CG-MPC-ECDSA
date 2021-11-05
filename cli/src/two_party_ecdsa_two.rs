use anyhow::format_err;
use cli::config::TwoPartyConfig;
use cli::console::Console;
use message::message::Message;
use message::message_process::{MsgProcess, ProcessMessage};
use multi_party_ecdsa::communication::receiving_messages::ReceivingMessages;
use multi_party_ecdsa::communication::sending_messages::SendingMessages;
use multi_party_ecdsa::protocols::two_party::message::PartyTwoMsg;
use multi_party_ecdsa::protocols::two_party::party_two;
use p2p::{Info, Node};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use structopt::StructOpt;
use tokio::task;

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

struct PartyTwo {
    party_two_keygen: party_two::KeyGenPhase,
    party_two_sign: party_two::SignPhase,
}

pub struct InitMessage {
    my_info: Info,
    peer_info: Vec<Info>,
    party_two_info: PartyTwo,
}

impl InitMessage {
    pub fn init_message() -> Result<Self, anyhow::Error> {
        let opt = Opt::from_args();
        let index = 1;
        let message = opt.message;
        let config = TwoPartyConfig::new_from_file(&opt.config_path)?;
        let my_info = config.get_my_info(index)?;
        let peer_info = config.get_peer_info(index);

        // Init two party info
        let party_two_keygen = party_two::KeyGenPhase::new();
        let mut party_two_sign = party_two::SignPhase::new(&message)?;

        // Load keygen result
        let keygen_path = Path::new("./keygen_result1.json");
        if keygen_path.exists() {
            let keygen_json = fs::read_to_string(keygen_path)
                .map_err(|why| format_err!("Read to string err: {}", why))?;
            party_two_sign.load_keygen_result(&keygen_json)?;
        } else {
            // If keygen successes, party_one_sign will load keygen result automally.
            println!("Can not load keygen result! Please keygen first");
        }

        let party_two_info = PartyTwo {
            party_two_keygen,
            party_two_sign,
        };

        Ok(Self {
            my_info,
            peer_info,
            party_two_info,
        })
    }
}

impl MsgProcess<Message> for PartyTwo {
    fn process(
        &mut self,
        _index: usize,
        msg: Message,
    ) -> Result<ProcessMessage<Message>, anyhow::Error> {
        let received_msg: ReceivingMessages = bincode::deserialize(&msg)
            .map_err(|why| format_err!("bincode deserialize error: {}", why))?;
        let mut sending_msg = SendingMessages::EmptyMsg;
        match received_msg {
            ReceivingMessages::TwoKeyGenMessagePartyOne(msg) => {
                sending_msg = self.party_two_keygen.msg_handler_keygen(&msg)?;
            }
            ReceivingMessages::TwoSignMessagePartyOne(msg) => {
                sending_msg = self.party_two_sign.msg_handler_sign(&msg)?;
            }
            ReceivingMessages::TwoPartySignRefresh(message, keygen_result_json) => {
                self.party_two_sign.refresh(&message, &keygen_result_json)?;
                println!("Refresh Success!");
            }
            ReceivingMessages::SignBegin => {
                if self.party_two_sign.need_refresh {
                    let msg_bytes = bincode::serialize(&ReceivingMessages::NeedRefresh)
                        .map_err(|why| format_err!("bincode serialize error: {}", why))?;
                    sending_msg = SendingMessages::BroadcastMessage(msg_bytes);
                    println!("Need refresh");
                }
            }
            ReceivingMessages::NeedRefresh => {
                println!("Index {} need refresh", _index);
            }
            _ => {
                println!("Undefined Message Process: {:?}", received_msg);
            }
        }

        match sending_msg {
            SendingMessages::NormalMessage(index, msg) => {
                return Ok(ProcessMessage::SendMessage(index, Message(msg)));
            }
            SendingMessages::P2pMessage(msgs) => {
                //TBD: handle vector to Message
                let mut msgs_to_send: HashMap<usize, Message> = HashMap::new();
                for (key, value) in msgs {
                    msgs_to_send.insert(key, Message(value));
                }
                return Ok(ProcessMessage::SendMultiMessage(msgs_to_send));
            }
            SendingMessages::BroadcastMessage(msg) => {
                return Ok(ProcessMessage::BroadcastMessage(Message(msg)));
            }
            SendingMessages::EmptyMsg => {
                return Ok(ProcessMessage::Default());
            }
            SendingMessages::KeyGenSuccessWithResult(res) => {
                println!("keygen Success! {}", res);

                // Load keygen result for signphase
                self.party_two_sign.load_keygen_result(&res)?;

                let file_name = "./keygen_result1".to_string() + ".json";
                fs::write(file_name, res).expect("Unable to save !");

                // Send KeyGenFinish to party0
                let msg_send =
                    ReceivingMessages::TwoKeyGenMessagePartyTwo(PartyTwoMsg::KeyGenFinish);
                let msg_bytes = bincode::serialize(&msg_send)
                    .map_err(|why| format_err!("bincode serialize error: {}", why))?;
                return Ok(ProcessMessage::BroadcastMessage(Message(msg_bytes)));
            }
            SendingMessages::SignSuccessWithResult(res) => {
                println!("Sign Success! {}", res);
                return Ok(ProcessMessage::Default());
            }
            _ => {
                println!("Undefined Message Process: {:?}", sending_msg);
                return Ok(ProcessMessage::Default());
            }
        }
    }
}
fn main() {
    let init_messages = InitMessage::init_message().expect("Init message failed!");

    // Create the runtime.
    let mut rt: tokio::runtime::Runtime =
        tokio::runtime::Runtime::new().expect("Should be able to init tokio::Runtime.");
    let local: task::LocalSet = task::LocalSet::new();
    local
        .block_on(&mut rt, async move {
            // Setup a node
            let (mut node_handle, notifications_channel) =
                Node::<Message>::node_init(&init_messages.my_info)
                    .await
                    .expect("node init error");

            // Begin the UI.
            let interactive_loop: task::JoinHandle<Result<(), String>> =
                Console::spawn(node_handle.clone(), init_messages.peer_info);

            // Spawn the notifications loop
            let mut message_process = init_messages.party_two_info;
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
        .expect("panic")
}
