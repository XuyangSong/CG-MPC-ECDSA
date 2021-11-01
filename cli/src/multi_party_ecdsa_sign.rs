use cli::console::Console;
use cli::config::MultiPartyConfig;
use multi_party_ecdsa::communication::receiving_messages::ReceivingMessages;
use multi_party_ecdsa::communication::sending_messages::SendingMessages;
use multi_party_ecdsa::protocols::multi_party::ours::keygen::*;
use multi_party_ecdsa::protocols::multi_party::ours::sign::*;
use p2p::{Info, Node};
use message::message_process::{ProcessMessage, MsgProcess};
use message::message::Message;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use structopt::StructOpt;
use tokio::task;

#[derive(StructOpt, Debug)]
#[structopt(
    name = "multi-ecdsa-sign",
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

    /// Participants index
    #[structopt(short, long)]
    subset: Vec<usize>,

    /// Config path
    #[structopt(short, long)]
    config_path: String,

    /// Keygen result path
    #[structopt(short, long)]
    keygen_path: String,
}

// TBD: After resovled #19(Message), use SignPhase directly
struct MultiPartySign {
    sign: SignPhase,
}

pub struct InitMessage {
    my_info: Info,
    peers_info: Vec<Info>,
    multi_party_sign_info: MultiPartySign,
}

impl InitMessage {
    pub fn init_message() -> Self {
        let opt = Opt::from_args();

        // Process config
        let config = MultiPartyConfig::new_from_file(&opt.config_path).unwrap();
        assert!(
            opt.subset.len() > config.threshold,
            "PartyLessThanThreshold"
        );
        let my_info = config.get_my_info(opt.index);
        let peers_info: Vec<Info> = config.get_peers_info_sign(opt.index, opt.subset.clone());
        let params = Parameters {
            threshold: config.threshold,
            share_count: config.share_count,
        };

        // Load keygen result
        let input_path = Path::new(&opt.keygen_path);
        let keygen_json_string = fs::read_to_string(input_path).unwrap();

        // Sign init
        let sign = SignPhase::new(
            opt.index,
            params,
            &opt.subset,
            &opt.message,
            &keygen_json_string,
        )
        .unwrap();
        let multi_party_sign_info = MultiPartySign { sign: sign };
        let init_messages = InitMessage {
            my_info,
            peers_info,
            multi_party_sign_info: multi_party_sign_info,
        };
        return init_messages;
    }
}

impl MsgProcess<Message> for MultiPartySign {
    fn process(&mut self, index: usize, msg: Message) -> ProcessMessage<Message> {
        // Decode msg
        let received_msg: ReceivingMessages = bincode::deserialize(&msg).unwrap();
        let mut sending_msg = SendingMessages::EmptyMsg;
        match received_msg {
            ReceivingMessages::SignBegin => {
                sending_msg = self.sign.process_begin(index).unwrap();
            }
            ReceivingMessages::MultiSignMessage(msg) => {
                sending_msg = self.sign.msg_handler(index, &msg).unwrap();
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
            SendingMessages::SubsetMessage(msg) => {
                let mut msgs_to_send: HashMap<usize, Message> = HashMap::new();
                for index in self.sign.subset.iter() {
                    if index != &self.sign.party_index {
                        msgs_to_send.insert(*index, Message(msg.clone()));
                    }
                }
                return ProcessMessage::SendMultiMessage(msgs_to_send);
            }
            SendingMessages::SignSuccessWithResult(res) => {
                println!("Sign Success! {}", res);
                return ProcessMessage::Default();
            }
            SendingMessages::EmptyMsg => {
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
    let mut rt = tokio::runtime::Runtime::new().expect("Should be able to init tokio::Runtime.");
    let local = task::LocalSet::new();
    local
        .block_on(&mut rt, async move {
            // Setup a node
            let (mut node_handle, notifications_channel) =
                Node::<Message>::node_init(&init_messages.my_info).await;

            // Begin the UI.
            let interactive_loop = Console::spawn(
                node_handle.clone(),
                init_messages.peers_info,
            );

            let mut message_process = init_messages.multi_party_sign_info;
            // Spawn the notifications loop
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
