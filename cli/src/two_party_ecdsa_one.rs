use anyhow::format_err;
use cli::config::TwoPartyConfig;
use cli::console::Console;
use cli::log::init_log;
use log::Level;
use message::message::Message;
use message::message_process::{MsgProcess, ProcessMessage};
use multi_party_ecdsa::communication::receiving_messages::ReceivingMessages;
use multi_party_ecdsa::communication::sending_messages::SendingMessages;
use multi_party_ecdsa::protocols::two_party::party_one;
use p2p::{Info, Node};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
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
    message: Option<String>,

    /// Config Path
    #[structopt(short, long)]
    config_path: String,

    /// Sign Model
    #[structopt(short, long)]
    online_offline: bool,

    /// Log path
    #[structopt(long, default_value = "/tmp")]
    log: PathBuf,

    /// Log level
    #[structopt(short, long, default_value = "DEBUG")]
    level: Level,
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
    pub fn init_message() -> Result<Self, anyhow::Error> {
        let opt = Opt::from_args();
        let index = 0;

        // Init log
        let mut path = opt.log;
        path.push(format!("ecdsa_log_{}.log", index));
        init_log(path, opt.level)?;

        let config = TwoPartyConfig::new_from_file(&opt.config_path)?;
        let my_info = config.get_my_info(index)?;
        let peer_info = config.get_peer_info(index);

        // Init party one info
        let party_one_keygen = party_one::KeyGenPhase::new();
        let mut party_one_sign = party_one::SignPhase::new(&opt.message, opt.online_offline)?;

        // Load keygen result
        let keygen_path = Path::new("./keygen_result0.json");
        if keygen_path.exists() {
            let keygen_json = fs::read_to_string(keygen_path)
                .map_err(|why| format_err!("Read to string err: {}", why))?;
            party_one_sign.load_keygen_result(&keygen_json)?;
        } else {
            // If keygen successes, party_one_sign will load keygen result automally.
            log::error!("Can not load keygen result! Please keygen first");
        }

        let party_one_info = PartyOne {
            party_one_keygen,
            party_one_sign,
        };

        log::info!("Config loading success!");

        Ok(Self {
            my_info,
            peer_info,
            party_one_info,
        })
    }
}

impl MsgProcess<Message> for PartyOne {
    fn process(
        &mut self,
        index: usize,
        msg: Message,
    ) -> Result<ProcessMessage<Message>, anyhow::Error> {
        let received_msg: ReceivingMessages = bincode::deserialize(&msg)
            .map_err(|why| format_err!("bincode deserialize error: {}", why))?;
        let mut sending_msg = SendingMessages::EmptyMsg;
        match received_msg {
            ReceivingMessages::TwoKeyGenMessagePartyTwo(msg) => {
                sending_msg = self.party_one_keygen.msg_handler_keygen(&msg)?;
            }
            ReceivingMessages::TwoSignMessagePartyTwo(msg) => {
                sending_msg = self.party_one_sign.msg_handler_sign(&msg)?;
            }
            ReceivingMessages::KeyGenBegin => {
                sending_msg = self.party_one_keygen.process_begin_keygen(index)?;
            }
            ReceivingMessages::SetMessage(msg) => {
                self.party_one_sign.set_msg(msg)?;
                log::info!("Set Message Succeed");
            }
            ReceivingMessages::SignBegin => {
                if self.party_one_sign.need_refresh {
                    let msg_bytes = bincode::serialize(&ReceivingMessages::NeedRefresh)
                        .map_err(|why| format_err!("bincode serialize error: {}", why))?;
                    sending_msg = SendingMessages::BroadcastMessage(msg_bytes);
                    log::error!("Need refresh first!!!");
                } else {
                    sending_msg = self.party_one_sign.process_begin_sign(index)?;
                }
            }
            ReceivingMessages::TwoPartySignRefresh(message, keygen_result_json) => {
                self.party_one_sign.refresh(&message, &keygen_result_json)?;
                log::info!("Refresh Success!");
            }
            ReceivingMessages::NeedRefresh => {
                log::error!("Index {} need refresh", index);
            }
            _ => {
                log::warn!("Undefined Receiving Message Process: {:?}", received_msg);
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
                log::debug!("KeyGen: {}", res);

                // Load keygen result for signphase
                self.party_one_sign.load_keygen_result(&res)?;

                let file_name = "./keygen_result0".to_string() + ".json";
                fs::write(file_name, res).map_err(|why| format_err!("result save err: {}", why))?;

                println!("KeyGen Success!");
                log::info!("KeyGen Success!");
                return Ok(ProcessMessage::Default());
            }
            SendingMessages::SignSuccessWithResult(res) => {
                println!("Sign Success!");
                log::info!("Sign Success!");
                log::debug!("Signature: {}", res);
                return Ok(ProcessMessage::Default());
            }
            _ => {
                log::warn!("Undefined Sending Message Process: {:?}", sending_msg);
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
        .expect("panic")
}
