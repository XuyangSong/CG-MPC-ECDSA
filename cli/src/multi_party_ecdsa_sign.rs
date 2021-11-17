use anyhow::format_err;
use cli::config::MultiPartyConfig;
use cli::console::Console;
use message::message::Message;
use message::message_process::{MsgProcess, ProcessMessage};
use multi_party_ecdsa::communication::receiving_messages::ReceivingMessages;
use multi_party_ecdsa::communication::sending_messages::SendingMessages;
use multi_party_ecdsa::protocols::multi_party::ours::keygen::*;
use multi_party_ecdsa::protocols::multi_party::ours::sign::*;
use p2p::{Info, Node};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::option::Option;
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

    /// Sign Model
    #[structopt(short, long)]
    online_offline: bool,

    /// Message to sign
    #[structopt(short, long)]
    message: Option<String>,

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
    pub fn init_message() -> Result<Self, anyhow::Error> {
        let opt = Opt::from_args();

        // Process config
        let config = MultiPartyConfig::new_from_file(&opt.config_path)?;
        if opt.subset.len() <= config.threshold {
            return Err(anyhow::Error::msg("Subset is less than threshold"));
        }

        let my_info = config.get_my_info(opt.index)?;
        let peers_info: Vec<Info> = config.get_peers_info_sign(opt.index, opt.subset.clone());
        let params = Parameters {
            threshold: config.threshold,
            share_count: config.share_count,
        };

        // Load keygen result
        let input_path = Path::new(&opt.keygen_path);
        let keygen_json_string = fs::read_to_string(input_path)
            .map_err(|why| format_err!("Read to string err: {}", why))?;

        // Sign init
        let sign = SignPhase::new(
            opt.index,
            params,
            &opt.subset,
            opt.online_offline,
            &opt.message,
            &keygen_json_string,
        )?;
        let multi_party_sign_info = MultiPartySign { sign: sign };
        let init_messages = InitMessage {
            my_info,
            peers_info,
            multi_party_sign_info: multi_party_sign_info,
        };
        return Ok(init_messages);
    }
}

impl MsgProcess<Message> for MultiPartySign {
    fn process(
        &mut self,
        index: usize,
        msg: Message,
    ) -> Result<ProcessMessage<Message>, anyhow::Error> {
        // Decode msg
        let received_msg: ReceivingMessages = bincode::deserialize(&msg)
            .map_err(|why| format_err!("bincode deserialize error: {}", why))?;
        let mut sending_msg = SendingMessages::EmptyMsg;
        match received_msg {
            ReceivingMessages::SignBegin => {
                if self.sign.need_refresh {
                    let msg_bytes = bincode::serialize(&ReceivingMessages::NeedRefresh)
                        .map_err(|why| format_err!("bincode serialize error: {}", why))?;
                    sending_msg = SendingMessages::SubsetMessage(msg_bytes);
                    println!("Need refresh");
                } else {
                    sending_msg = self.sign.process_begin(index)?;
                }
            }
            ReceivingMessages::SetMessage(msg) => {
                self.sign.set_msg(msg)?;
            }
            ReceivingMessages::SignOnlineBegin => {
                sending_msg = self.sign.process_online_begin(index)?;
            }
            ReceivingMessages::MultiSignMessage(msg) => {
                sending_msg = self.sign.msg_handler(index, &msg)?;
            }
            ReceivingMessages::MultiPartySignRefresh(message, keygen_result_json, subset) => {
                self.sign.refresh(subset, &message, &keygen_result_json)?;
                println!("Refresh Success!");
            }
            ReceivingMessages::NeedRefresh => {
                println!("Index {} need refresh", index);
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
            SendingMessages::SubsetMessage(msg) => {
                let mut msgs_to_send: HashMap<usize, Message> = HashMap::new();
                for index in self.sign.subset.iter() {
                    if index != &self.sign.party_index {
                        msgs_to_send.insert(*index, Message(msg.clone()));
                    }
                }
                return Ok(ProcessMessage::SendMultiMessage(msgs_to_send));
            }
            SendingMessages::SignSuccessWithResult(res) => {
                println!("Sign Success! {}", res);
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
        .expect("panic")
}
