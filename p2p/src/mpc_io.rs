use crate::mpc_io::ProcessMessage::*;
use crate::Node;
use crate::NodeConfig;
use crate::NodeHandle;
use crate::{Message, NodeNotification, PeerInfo};
use curve25519_dalek::scalar::Scalar;
use rand::thread_rng;
use std::collections::HashMap;
use std::net::IpAddr;
//use crate::{PeerID, PeerMessage};
use crate::cybershake;
use std::{thread, time};

use tokio::sync;
use tokio::task;

#[derive(Clone, Debug)]
pub enum ProcessMessage {
    BroadcastMessage(Message),
    SendMessage(usize, Message),
    SendMultiMessage(HashMap<usize, Vec<u8>>),
    Quit(),
    Default(),
}

pub trait MsgProcess {
    fn process(&mut self, index: usize, msg: Message) -> ProcessMessage;
}

pub async fn node_init(
    index: usize,
    ip: IpAddr,
    port: u16,
) -> (
    NodeHandle<Message>,
    sync::mpsc::Receiver<NodeNotification<Message>>,
) {
    let config = NodeConfig {
        index: index,
        listen_ip: ip,
        listen_port: port,
        inbound_limit: 100,
        outbound_limit: 100,
        heartbeat_interval_sec: 3600,
    };

    let host_privkey = cybershake::PrivateKey::from(Scalar::random(&mut thread_rng()));

    let (node_handle, notifications_channel) = Node::<Message>::spawn(host_privkey, config)
        .await
        .expect("Should bind normally.");
    println!(
        "Listening on {} with peer ID: {} with index: {}",
        node_handle.socket_address(),
        node_handle.id(),
        index,
    );

    return (node_handle, notifications_channel);
}
pub async fn connect_(mut node_handle: &mut NodeHandle<Message>, address: String, index: usize) {
    let mut count: usize = 0;
    loop {
        let result = NodeHandle::connect_to_peer(&mut node_handle, &address, None, index).await;
        match result {
            Ok(()) => {
                println!("Connect Succeed!");
                break;
            }
            Err(_e) => {
                //TBD output e
                println!("{}", _e);
                let ten_millis = time::Duration::from_millis(100);
                thread::sleep(ten_millis);
            }
        }
        count += 1;
        if count == 3 {
            println!("Connect Failed, Please make sure node has been init ");
            //TBD return error
            assert!(false);
            //break;
        }
    }
}
pub async fn send_(mut node_handle: &mut NodeHandle<Message>, index: usize, msg: Message) {
    let pid = NodeHandle::indexidpeer(&mut node_handle, index).await;
    NodeHandle::sendmsg(&mut node_handle, pid, msg).await;
}

pub async fn multi_send_(
    node_handle: &mut NodeHandle<Message>,
    send_list: HashMap<usize, Vec<u8>>,
) {
    for (index, msg) in send_list.iter() {
        send_(node_handle, *index, Message(msg.to_vec())).await;
    }
}

pub async fn quit_(mut node_handle: &mut NodeHandle<Message>) {
    NodeHandle::exit(&mut node_handle).await;
}
pub async fn broadcast_(mut node_handle: &mut NodeHandle<Message>, msg: Message) {
    NodeHandle::broadcast(&mut node_handle, msg).await;
}
pub async fn receive_(
    node_handle: &mut NodeHandle<Message>,
    mut notifications_channel: sync::mpsc::Receiver<NodeNotification<Message>>,
    message_process: &mut impl MsgProcess,
) {
    while let Some(notif) = notifications_channel.recv().await {
        match notif {
            NodeNotification::PeerAdded(_pid, index) => {
                println!("\n=> Peer connected to index: {}\n", index)
            }
            NodeNotification::PeerDisconnected(pid, index) => {
                println!("\n=> Peer disconnected pid: {} index: {}", pid, index)
            }
            NodeNotification::MessageReceived(index, msg) => {
                let result = message_process.process(index, msg);
                match result {
                    BroadcastMessage(msg) => broadcast_(node_handle, msg).await,
                    SendMessage(index, msg) => send_(node_handle, index, msg).await,
                    SendMultiMessage(send_list) => multi_send_(node_handle, send_list).await,
                    Quit() => quit_(node_handle).await,
                    Default() => {}
                    _ => println!("Unsupported parse Received MessageType"),
                }
            }
            NodeNotification::InboundConnectionFailure(err) => {
                println!("\n=> Inbound connection failure: {:?}", err)
            }
            NodeNotification::OutboundConnectionFailure(err) => {
                println!("\n=> Outbound connection failure: {:?}", err)
            }
            NodeNotification::Shutdown => {
                println!("\n=> Node did shutdown.");
                break;
            }
            _ => println!("Unsupported parse NodeNotification"),
        }
    }
}
pub async fn list_peers_(mut node_handle: &mut NodeHandle<Message>) -> Vec<PeerInfo> {
    let result = NodeHandle::list_peers(&mut node_handle).await;
    return result;
}
pub async fn disconnect_(mut node_handle: &mut NodeHandle<Message>, index: usize) {
    let peer_id = NodeHandle::indexidpeer(&mut node_handle, index).await;
    NodeHandle::remove_peer(&mut node_handle, peer_id).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    //use tokio::time;

    #[tokio::test]
    async fn connect() {
        struct TestConnect {}
        impl MsgProcess for TestConnect {
            fn process(&mut self, index: usize, msg: Message) -> ProcessMessage {
                return Quit();
            }
        }
        let index: usize = 1;
        let ip = "127.0.0.1".parse().unwrap();
        let port = 64001;
        let local: task::LocalSet = task::LocalSet::new();
        local
            .run_until(async move {
                //setup a node
                let (mut node_handle, notifications_channel) = node_init(index, ip, port).await;
                let address = "127.0.0.1:64000".to_string();
                //connect to another node
                connect_(&mut node_handle, address, 0).await;
                //disconnect from another node
                disconnect_(&mut node_handle, 0).await;
                let mut message_process = TestConnect {};
                quit_(&mut node_handle).await;
                receive_(
                    &mut node_handle,
                    notifications_channel,
                    &mut message_process,
                )
                .await;
            })
            .await;
    }

    #[tokio::test]
    async fn send() {
        struct TestSend {}
        impl MsgProcess for TestSend {
            fn process(&mut self, index: usize, msg: Message) -> ProcessMessage {
                println!("Message send succeed! Returned message is {:?}", msg);
                return Quit();
            }
        }
        let index: usize = 1;
        let ip = "127.0.0.1".parse().unwrap();
        let port = 64001;
        let local: task::LocalSet = task::LocalSet::new();
        local
            .run_until(async move {
                //setup a node
                let (mut node_handle, notifications_channel) = node_init(index, ip, port).await;
                let mut node_handle_clone = node_handle.clone();
                let address = "127.0.0.1:64000".to_string();
                //connect to another node
                connect_(&mut node_handle, address, 0).await;
                let msg_send = "test---";
                let msg_bytes: Vec<u8> = bincode::serialize(&msg_send).unwrap();
                //send to another node
                send_(&mut node_handle, 0, Message(msg_bytes)).await;
                let mut message_process = TestSend {};
                //receive messages from other nodes
                receive_(
                    &mut node_handle_clone,
                    notifications_channel,
                    &mut message_process,
                )
                .await;
            })
            .await;
    }
}
