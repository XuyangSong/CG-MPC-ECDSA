use anyhow::format_err;
use cli::config::MultiPartyConfig;
use cli::console::Console;
use message::message::Message;
use message::message_process::{MsgProcess, ProcessMessage};
use multi_party_ecdsa::communication::receiving_messages::ReceivingMessages;
use multi_party_ecdsa::communication::sending_messages::SendingMessages;
use multi_party_ecdsa::protocols::multi_party::ours::keygen::*;
use p2p::{Info, Node};
use std::collections::HashMap;
use std::fs;
use structopt::StructOpt;
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

impl InitMessage {
    pub fn init_message() -> Result<Self, anyhow::Error> {
        let opt = Opt::from_args();
        let index = opt.index;
        let config = MultiPartyConfig::new_from_file(&opt.config_path)?;

        let my_info = config.get_my_info(index)?;

        let peers_info: Vec<Info> = config.get_peers_info_keygen(index);
        let params = Parameters {
            threshold: config.threshold,
            share_count: config.share_count,
        };

        // Init multi party info
        let keygen = KeyGenPhase::new(index, params)?;
        let multi_party_keygen_info = MultiPartyKeygen { keygen: keygen };
        let init_messages = InitMessage {
            my_info,
            peers_info,
            multi_party_keygen_info: multi_party_keygen_info,
        };
        return Ok(init_messages);
    }
}

impl MsgProcess<Message> for MultiPartyKeygen {
    fn process(
        &mut self,
        index: usize,
        msg: Message,
    ) -> Result<ProcessMessage<Message>, anyhow::Error> {
        let received_msg: ReceivingMessages = bincode::deserialize(&msg)
            .map_err(|why| format_err!("bincode deserialize error: {}", why))?;
        let mut sending_msg = SendingMessages::EmptyMsg;
        match received_msg {
            ReceivingMessages::KeyGenBegin => {
                sending_msg = self.keygen.process_begin()?;
            }
            ReceivingMessages::MultiKeyGenMessage(msg) => {
                sending_msg = self.keygen.msg_handler(index, &msg)?;
            }
            _ => {
                println!("Undefined Message Process: {:?}", received_msg);
            }
        }
        match sending_msg {
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
            SendingMessages::KeyGenSuccessWithResult(res) => {
                println!("keygen Success! {}", res);

                // Save keygen result to file
                let file_name =
                    "./keygen_result".to_string() + &self.keygen.party_index.to_string() + ".json";
                fs::write(file_name, res).map_err(|why| format_err!("result save err: {}", why))?;
                return Ok(ProcessMessage::Default());
            }
            SendingMessages::EmptyMsg => {
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
    let mut rt = tokio::runtime::Runtime::new().expect("Should be able to init tokio::Runtime.");
    let local = task::LocalSet::new();
    local
        .block_on(&mut rt, async move {
            // Setup a node
            let (mut node_handle, notifications_channel) =
                Node::<Message>::node_init(&init_messages.my_info)
                    .await
                    .expect("node init error");

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
        .expect("panic")
}
