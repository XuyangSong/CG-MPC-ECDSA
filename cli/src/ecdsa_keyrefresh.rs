use anyhow::format_err;
use cli::config::MultiPartyConfig;
use cli::console::Console;
use cli::log::init_log;
use log::Level;
use message::message::Message;
use message::message_process::{MsgProcess, ProcessMessage};
use multi_party_ecdsa::communication::receiving_messages::ReceivingMessages;
use multi_party_ecdsa::communication::sending_messages::SendingMessages;
use multi_party_ecdsa::protocols::multi_party::ours::keygen::Parameters;
use multi_party_ecdsa::protocols::multi_party::ours::keyrefresh::*;
use p2p::{Info, Node};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use structopt::StructOpt;
use tokio::task;

#[derive(StructOpt, Debug)]
#[structopt(
    name = "ecdsa-keyrefresh",
    author = "wangxueli",
    rename_all = "snake_case"
)]
struct Opt {
    /// My index
    #[structopt(short, long)]
    index: usize,

     /// Participants index
     #[structopt(short, long)]
     threshold_set: Vec<usize>,

    /// Config Path
    #[structopt(short, long, default_value = "./configs/config_3pc.json")]
    config_file: PathBuf,

    /// Keygen result path
    #[structopt(short, long, default_value = "./")]
    keygen_path: PathBuf,

    /// Keygen result path
    #[structopt(short, long, default_value = "./")]
    pub_keygen_path: PathBuf,

    /// Log path
    #[structopt(long, default_value = "/tmp")]
    log: PathBuf,

    /// Log level
    #[structopt(long, default_value = "DEBUG")]
    level: Level,
}

pub struct InitMessage {
    my_info: Info,
    peers_info: Vec<Info>,
    keyrefresh_info: KeyRefresh,
}

struct KeyRefresh {
    keyrefresh: KeyRefreshPhase,
}

impl InitMessage {
    pub fn init_message() -> Result<Self, anyhow::Error> {
        let opt = Opt::from_args();

        // Init log
        let mut path = opt.log;
        path.push(format!("ecdsa_log_{}.log", opt.index));
        init_log(path, opt.level)?;

        // Process config
        let config = MultiPartyConfig::new_from_file(&opt.config_file)?;
        if opt.threshold_set.len() <= config.threshold {
          return Err(anyhow::Error::msg("Subset is less than threshold"));
        }

        let my_info = config.get_my_info(opt.index)?;

        let peers_info: Vec<Info> = config.get_peers_info_keygen(opt.index);
        let params = Parameters {
            threshold: config.threshold,
            share_count: config.share_count,
        };

        let mut private_key_old: Option<String> = None;
        if opt.threshold_set.contains(&opt.index){
            // Load keygen result
            let mut keygen_priv_file = opt.keygen_path;
            keygen_priv_file.push(format!("keygen_priv_result{}.json", opt.index));
            private_key_old = Some(fs::read_to_string(keygen_priv_file)
            .map_err(|why| format_err!("Read to string err: {}", why))?);
        }
         
        //Load public key result
        let mut keygen_pub_file = opt.pub_keygen_path;
        keygen_pub_file.push(format!("keygen_pub_result{}.json", opt.index));
        let keygen_pub_result = fs::read_to_string(keygen_pub_file)
        .map_err(|why| format_err!("Read to string err: {}", why))?;

        // Init multi party info
        let keyrefresh = KeyRefreshPhase::new(opt.index, private_key_old, params, opt.threshold_set, keygen_pub_result)?;
        let keyrefresh_info = KeyRefresh { keyrefresh: keyrefresh };
        let init_messages = InitMessage {
            my_info,
            peers_info,
            keyrefresh_info: keyrefresh_info,
        };

        log::info!("Config loading success!");
        return Ok(init_messages);
    }
}

impl MsgProcess<Message> for KeyRefresh {
    fn process(
        &mut self,
        index: usize,
        msg: Message,
    ) -> Result<ProcessMessage<Message>, anyhow::Error> {
        let received_msg: ReceivingMessages = bincode::deserialize(&msg)
            .map_err(|why| format_err!("bincode deserialize error: {}", why))?;
        let mut sending_msg = SendingMessages::EmptyMsg;
        match received_msg {
            ReceivingMessages::KeyRefreshBegin => {
                sending_msg = self.keyrefresh.process_begin()?;
            }
            ReceivingMessages::KeyRefreshMessage(msg) => {
                sending_msg = self.keyrefresh.msg_handler(index, &msg)?;
            }
            _ => {
                log::warn!("Undefined Receiving Message Process: {:?}", received_msg);
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
            SendingMessages::KeyRefreshSuccessWithResult(res) => { //res[0] stores public_key_json, res[1] stores private_key_json by default
               println!("Keyrefresh Success");
               log::info!("Keyrefresh Success");
               log::debug!("public keyrefresh ret: {}, private keyrefresh ret: {}", res[0], res[1]);

               // Save public keygen result to file
               let file_name =
                   "./keyrefresh_pub_result".to_string() + &self.keyrefresh.party_index.to_string() + ".json";
               fs::write(file_name, res[0].clone()).map_err(|why| format_err!("public result save err: {}", why))?;

               // Save private keygen result to file
               let file_name =
                   "./keyrefresh_priv_result".to_string() + &self.keyrefresh.party_index.to_string() + ".json";
               fs::write(file_name, res[1].clone()).map_err(|why| format_err!("private result save err: {}", why))?;
               return Ok(ProcessMessage::Default());
           }
            SendingMessages::EmptyMsg => {
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
            let mut message_process = init_messages.keyrefresh_info;
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
