//! Node manages its own state and the state of its peers, and orchestrates messages between them.
use curve25519_dalek::scalar::Scalar;
use core::time::Duration;
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use futures::future::FutureExt;
use futures::select;
use futures::stream::StreamExt;

use tokio::io;
use tokio::net;
use tokio::sync;
use tokio::task;
use tokio::time;

use rand::thread_rng;
use std::{thread};

use crate::codec::{MessageDecoder, MessageEncoder};
use crate::cybershake;
use crate::peer::{PeerAddr, PeerID, PeerLink, PeerMessage, PeerNotification};
use crate::priority::{Priority, PriorityTable, HIGH_PRIORITY, LOW_PRIORITY};
use readerwriter::Codable;

use crate::errors::MpcIOError;
type Reply<T> = sync::oneshot::Sender<T>;

#[derive(Clone, Debug)]
pub enum ProcessMessage <Custom: Codable> {
    BroadcastMessage(Custom),
    SendMessage(usize, Custom),
    SendMultiMessage(HashMap<usize, Custom>),
    Quit(),
    Default(),
}

pub trait MsgProcess <Custom: Codable> {
    fn process(&mut self, index: usize, msg: Custom) -> ProcessMessage<Custom>;
}

/// State of the node.
/// This is a handle that can be copied to send messages to the node from different tasks.
/// When the handle is dropped, the Node is shut down.
#[derive(Clone)]
pub struct NodeHandle<Custom: Codable> {
    peer_id: PeerID,
    socket_address: SocketAddr,
    channel: sync::mpsc::Sender<NodeMessage<Custom>>,
}

pub struct NodeConfig {
    pub index: usize,
    pub listen_ip: IpAddr,
    pub listen_port: u16,
    pub inbound_limit: usize,
    pub outbound_limit: usize,
    pub heartbeat_interval_sec: u64,
}

pub struct Node<Custom: Codable> {
    index: usize,
    listener: net::TcpListener,
    cybershake_identity: cybershake::PrivateKey,
    peer_notification_channel: sync::mpsc::Sender<PeerNotification<Custom>>,
    peers: HashMap<PeerID, PeerState<Custom>>,
    index_peer: HashMap<usize, PeerID>,
    config: NodeConfig,
    inbound_semaphore: sync::Semaphore,
    peer_priorities: PriorityTable<PeerID>, // priorities of peers
    notifications_channel: sync::mpsc::Sender<NodeNotification<Custom>>,
}

/// Direction of connection
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// State of the peer
struct PeerState<T: Codable> {
    link: PeerLink<T>,
    listening_addr: Option<SocketAddr>,
    socket_addr: SocketAddr,
    direction: Direction,
    duplicates: usize,
    peer_addrs: Vec<PeerAddr>, // addresses of all the peers
    index: usize,
}

#[derive(Debug)]
pub enum NodeNotification<Custom: Codable> {
    PeerAdded(PeerID, usize),
    PeerDisconnected(PeerID, usize),
    MessageReceived(usize, Custom),
    InboundConnectionFailure(io::Error),
    OutboundConnectionFailure(io::Error),
    Shutdown,
}

#[derive(Debug)]
pub struct PeerInfo {
    pub id: PeerID,
    pub address: SocketAddr,
    pub public: bool,
    pub priority: Priority,
    pub direction: Direction,
    pub index: usize,
}

/// Internal representation of messages sent by `NodeHandle` to `Node`.
pub enum NodeMessage<Custom: Codable> {
    ConnectPeer(net::TcpStream, Option<PeerID>, usize),
    RemovePeer(PeerID),
    Broadcast(Custom),
    SendMsg(PeerID, Custom),
    SendMsgByIndex(usize, Custom),
    CountPeers(Reply<usize>),
    ListPeers(Reply<Vec<PeerInfo>>),
    SendSelf(Custom),
    Indextoidpeer(usize, Reply<PeerID>),
    Exit,
}

impl NodeConfig {
    fn listen_addr(&self) -> SocketAddr {
        SocketAddr::new(self.listen_ip, self.listen_port)
    }
}

impl<Custom> Node<Custom>
where
    Custom: Codable + Clone + Unpin + 'static,
{
    /// Creates a node and returns a handle for communicating with it.
    /// TODO: add the listening loop and avoid doing .accept when we are out of inbound slots.
    pub async fn spawn(
    cybershake_identity: cybershake::PrivateKey,
    config: NodeConfig,
) -> Result<
    (
        NodeHandle<Custom>,
        sync::mpsc::Receiver<NodeNotification<Custom>>,
    ),
    io::Error,
> {
    // Prepare listening socket.
    let listener = net::TcpListener::bind(config.listen_addr()).await?;
    let mut local_addr = listener.local_addr()?;
    if local_addr.ip().is_unspecified() {
        local_addr.set_ip(Ipv4Addr::LOCALHOST.into());
    }

    let inbound_semaphore = sync::Semaphore::new(config.inbound_limit);

    let (cmd_sender, mut cmd_receiver) = sync::mpsc::channel::<NodeMessage<Custom>>(100);
    let (peer_sender, mut peer_receiver) = sync::mpsc::channel::<PeerNotification<Custom>>(100);
    let (notif_sender, notif_receiver) = sync::mpsc::channel::<NodeNotification<Custom>>(100);

    let mut node = Node {
        index: config.index,
        cybershake_identity,
        peer_notification_channel: peer_sender,
        peers: HashMap::new(),
        index_peer: HashMap::new(),
        listener,
        config,
        inbound_semaphore,
        peer_priorities: PriorityTable::new(1000),
        notifications_channel: notif_sender,
    };

    let node_handle = NodeHandle {
        peer_id: node.peer_id(),
        channel: cmd_sender,
        socket_address: local_addr,
    };

    task::spawn_local(async move {
        let mut heartbeat =
            time::interval(Duration::from_secs(node.config.heartbeat_interval_sec));
        loop {
            select! {
                maybe_cmd = cmd_receiver.next().fuse() => {
                    if let Some(cmd) = maybe_cmd {
                        match cmd {
                            NodeMessage::Exit => break,
                            _ => node.handle_command(cmd).await,
                        }
                    } else {
                        // node handle wasnotifications_channel dropped, shut down the node.
                        break;
                    }
                },
                maybe_peer_notif = peer_receiver.next().fuse() => {
                    if let Some(notif) = maybe_peer_notif {
                        node.handle_peer_notification(notif).await;
                    } else {
                        // Never happens until shutdown because Node holds one copy of the sender
                        // for spawning new peers from within.
                    }
                },
                _ = heartbeat.tick().fuse() => {
                    node.heartbeat_tick().await
                },
                _ = node.try_accept().fuse() => {}
            }
        }
        node.notify(NodeNotification::Shutdown).await
    });

    Ok((node_handle, notif_receiver))
}
    pub async fn node_init(
        index: usize,
        ip: IpAddr,
        port: u16,
    ) -> (
        NodeHandle<Custom>,
        sync::mpsc::Receiver<NodeNotification<Custom>>,
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

        let (node_handle, notifications_channel) = Node::<Custom>::spawn(host_privkey, config)
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
}

impl<Custom: Codable> NodeHandle<Custom> {
    /// Attempts to open a connection to a peer.
    /// Returns error if cannot establish the connection.
    /// If connection is established, returns Ok(), but can fail later to perform handshake -
    /// in which case you will receive a `NodeNotification::OutboundConnectionFailure` notification.
    ///
    /// TODO: maybe pass `Box<dyn ToSocketAddrs>` to the node, so all errors are handled in one place?
    pub async fn connect_to_peer(
        &mut self,
        addr: impl net::ToSocketAddrs,
        expected_pid: Option<PeerID>,
        peer_index: usize,
    ) -> Result<(), io::Error> {
        let stream = net::TcpStream::connect(&addr).await?;
        self.send_internal(NodeMessage::ConnectPeer(stream, expected_pid, peer_index))
            .await;
        Ok(())
    }

    pub async fn exit(&mut self) {
        self.send_internal(NodeMessage::Exit).await
    }

    /// Disconnects from a peer with a given ID.
    pub async fn remove_peer(&mut self, peer_id: PeerID) {
        self.send_internal(NodeMessage::RemovePeer(peer_id)).await
    }

    /// Returns the PeerID of the node.
    pub fn id(&self) -> PeerID {
        self.peer_id
    }

    /// Returns the listening socket address of the node.
    pub fn socket_address(&self) -> SocketAddr {
        self.socket_address
    }

    /// Broadcasts a message to all peers.
    pub async fn broadcast(&mut self, msg: Custom) {
        self.send_internal(NodeMessage::Broadcast(msg)).await
    }

    /// Send a message to a peer.
    pub async fn sendmsg(&mut self, peer_id: PeerID, msg: Custom) {
        self.send_internal(NodeMessage::SendMsg(peer_id, msg)).await
    }

    /// Send a message to a peer.
    pub async fn sendmsgbyindex(&mut self, index: usize, msg: Custom) {
        self.send_internal(NodeMessage::SendMsgByIndex(index, msg))
            .await
    }

    //Send msg to self notification channel
    pub async fn sendself(&mut self, msg: Custom) {
        self.send_internal(NodeMessage::SendSelf(msg)).await;
    }

    pub async fn list_peers(&mut self) -> Vec<PeerInfo> {
        let (tx, rx) = sync::oneshot::channel::<Vec<PeerInfo>>();
        self.send_internal(NodeMessage::ListPeers(tx)).await;
        rx.await
            .expect("should never fail because Node must exist as long as all NodeHandles exist")
    }

    pub async fn count_peers(&mut self) -> usize {
        let (tx, rx) = sync::oneshot::channel::<usize>();
        self.send_internal(NodeMessage::CountPeers(tx)).await;
        rx.await
            .expect("should never fail because Node must exist as long as all NodeHandles exist")
    }

    /// Implements sending a message to a node over a channel
    async fn send_internal(&mut self, msg: NodeMessage<Custom>) {
        // We intentionally ignore the error because it's only returned if the recipient has disconnected,
        // but even Ok is of no guarantee that the message will be delivered, so we simply ignore the error entirely.
        // Specifically, in this implementation, Node's task does not stop until all senders disappear,
        // so we will never have an error condition here.
        self.channel.send(msg).await.unwrap_or(())
    }

    pub async fn indexidpeer(&mut self, index: usize) -> PeerID {
        let (tx, rx) = sync::oneshot::channel::<PeerID>();
        self.send_internal(NodeMessage::Indextoidpeer(index, tx))
            .await;
        rx.await.expect("can not obtain peerid")
    }
}

impl<Custom: Codable> NodeHandle<Custom>{
    pub async fn connect_(&mut self, address: String, index: usize) {
        let mut count: usize = 0;
        loop {
            let result = self.connect_to_peer(&address, None, index).await;
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
    pub async fn send_by_msg_(&mut self, index: usize, msg: Custom) {
        let pid = self.indexidpeer(index).await;
        self.sendmsg(pid, msg).await;
    }
    pub async fn receive_(
        &mut self,
        mut notifications_channel: sync::mpsc::Receiver<NodeNotification<Custom>>,
        message_process: &mut  impl MsgProcess<Custom>,
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
                        ProcessMessage::BroadcastMessage(msg) => self.broadcast(msg).await,
                        ProcessMessage::SendMessage(index, msg) => self.send_by_msg_(index, msg).await,
                        ProcessMessage::SendMultiMessage(send_list) => {
                            for (index, msg) in send_list {
                                self.send_by_msg_(index, msg).await;
                            }
                        },
                        ProcessMessage::Quit() => self.exit().await,
                        ProcessMessage::Default() => {},
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
                },
            }
        }
    }
}

impl<Custom> Node<Custom>
where
    Custom: Codable + Clone + Unpin + 'static,
{
    /// Handles the command and returns false if it needs to shutdown.
    async fn handle_command(&mut self, msg: NodeMessage<Custom>) {
        match msg {
            NodeMessage::ConnectPeer(stream, expected_pid, peer_index) => {
                self.connect_peer_or_notify(stream, expected_pid, HIGH_PRIORITY, peer_index)
                    .await
            }
            NodeMessage::RemovePeer(peer_id) => self.remove_peer(&peer_id).await,
            NodeMessage::Broadcast(msg) => self.broadcast(msg).await,
            NodeMessage::SendMsg(pid, msg) => self.send_to_peer(&pid, PeerMessage::Data(msg)).await,
            NodeMessage::SendMsgByIndex(index, msg) => {
                self.send_to_peer_by_index(index, PeerMessage::Data(msg))
                    .await
            }
            NodeMessage::CountPeers(reply) => self.count_peers(reply).await,
            NodeMessage::ListPeers(reply) => self.list_peers(reply).await,
            NodeMessage::SendSelf(msg) => self.send_to_self(msg).await,
            NodeMessage::Indextoidpeer(index, reply) => self.index_to_peer(index, reply),
            NodeMessage::Exit => {}
        }
    }

    /// Perform periodic update about yourself and your peers.
    async fn heartbeat_tick(&mut self) {
        // Broadcast a list of your peers to everyone.
        // TODO: make this more efficient to avoid copying the list of peers all the time,
        // but instead sending a shared read-only buffer.
        // We can do this by changing how the Peer works from being its own task, to a Stream,
        // and then polling `select_all` of them.
        // let listed_peers = self.sorted_peers();
        // for (_pid, peerstate) in self.peers.iter_mut() {
        //     peerstate
        //         .link
        //         .send(PeerMessage::Peers(listed_peers.clone()))
        //         .await
        // }
    }

    async fn try_accept(&mut self) {
        let result = async {
            let permit = self.inbound_semaphore.acquire().await;
            let (stream, addr) = self.listener.accept().await?;
            let peer_link = PeerLink::spawn(
                &self.cybershake_identity,
                None,
                self.peer_notification_channel.clone(),
                stream,
                &mut thread_rng(),
                MessageEncoder::new(),
                MessageDecoder::new(),
            )
            .await?;
            // If the handshake did not fail, forget the semaphore permit,
            // so it's consumed until the peer disconnects. When we get about actually
            // removing the peer, then we'll add a new permit to the semaphore.
            permit.forget();

            // TBD: fake index, No ues
            let peer_index = 1;

            self.register_peer(
                peer_link,
                addr,
                Direction::Inbound,
                LOW_PRIORITY,
                peer_index,
            )
            .await;

            Ok(())
        }
        .await;
        self.notify_on_error(result, |e| NodeNotification::InboundConnectionFailure(e))
            .await;
    }

    async fn connect_peer_or_notify(
        &mut self,
        stream: net::TcpStream,
        expected_pid: Option<PeerID>,
        min_priority: Priority,
        peer_index: usize,
    ) {
        let result = self
            .connect_peer(stream, expected_pid, min_priority, peer_index)
            .await;
        self.notify_on_error(result, |e| NodeNotification::OutboundConnectionFailure(e))
            .await;
    }

    async fn connect_peer(
        &mut self,
        stream: net::TcpStream,
        expected_pid: Option<PeerID>,
        min_priority: Priority,
        peer_index: usize,
    ) -> Result<(), io::Error> {
        let addr = stream.peer_addr()?;
        let peer_link = PeerLink::spawn(
            &self.cybershake_identity,
            expected_pid,
            self.peer_notification_channel.clone(),
            stream,
            &mut thread_rng(),
            MessageEncoder::new(),
            MessageDecoder::new(),
        )
        .await?;

        self.register_peer(
            peer_link,
            addr,
            Direction::Outbound,
            min_priority,
            peer_index,
        )
        .await;

        Ok(())
    }

    async fn register_peer(
        &mut self,
        peer_link: PeerLink<Custom>,
        addr: SocketAddr,
        direction: Direction,
        min_priority: Priority,
        peer_index: usize,
    ) {
        let id = *peer_link.id();

        self.peer_priorities.insert(id, min_priority);

        if let Some(mut existing_peer) = self.peers.get_mut(&id) {
            // mark the existing peer as having duplicates,
            // so when the current peer is dropped, we don't remove it.
            existing_peer.duplicates += 1;

            // if the duplicate connection is outbound, upgrade the status of the existing one.
            if direction == Direction::Outbound && existing_peer.direction == Direction::Inbound {
                existing_peer.direction = Direction::Outbound;
                existing_peer.listening_addr = Some(addr);
                // restore the semaphore since we have just overriden the direction.
                self.inbound_semaphore.add_permits(1);
            }

            return;
        }

        let peer = PeerState {
            link: peer_link,
            listening_addr: match &direction {
                &Direction::Inbound => None,
                &Direction::Outbound => Some(addr),
            },
            socket_addr: addr,
            direction,
            duplicates: 0,
            peer_addrs: Vec::new(),
            index: peer_index,
        };
        // The peer did not exist - simply add it.
        let _ = self.peers.insert(id, peer);
        if direction == Direction::Outbound {
            self.index_peer.insert(peer_index, id);
        }

        // If this is an outbound connection, tell our port.
        if direction == Direction::Outbound {
            self.notify(NodeNotification::PeerAdded(id, peer_index))
                .await;

            self.send_to_peer(
                &id,
                PeerMessage::Hello(self.listener.local_addr().unwrap().port(), self.index),
            )
            .await
        }

    }

    async fn remove_peer(&mut self, peer_id: &PeerID) {
        // First, check if this peer has duplicates - then silently decrement the count
        // and keep it in place.
        if let Some(mut peer) = self.peers.get_mut(&peer_id) {
            if peer.duplicates > 0 {
                peer.duplicates -= 1;
                return;
            }
        }
        if let Some(peer) = self.peers.remove(peer_id) {
            if peer.direction == Direction::Inbound {
                // if that was an inbound peer, restore the permit it consumed.
                self.inbound_semaphore.add_permits(1);
            }
            self.notify(NodeNotification::PeerDisconnected(
                *peer.link.id(),
                peer.index,
            ))
            .await;
        }

        // self.connect_to_more_peers_if_needed().await;
    }

    async fn broadcast(&mut self, msg: Custom) {
        for (_id, peer_link) in self.peers.iter_mut() {
            peer_link.link.send(PeerMessage::Data(msg.clone())).await;
        }
    }

    async fn count_peers(&mut self, reply: Reply<usize>) {
        reply.send(self.peers.len()).unwrap_or(())
    }

    async fn list_peers(&mut self, reply: Reply<Vec<PeerInfo>>) {
        reply.send(self.peer_infos()).unwrap_or(())
    }

    async fn send_to_peer(&mut self, pid: &PeerID, msg: PeerMessage<Custom>) {
        if let Some(peer) = self.peers.get_mut(&pid) {
            peer.link.send(msg).await;
        }
    }

    async fn send_to_peer_by_index(&mut self, index: usize, msg: PeerMessage<Custom>) {
        for (_id, peer_link) in self.peers.iter_mut() {
            if index == peer_link.index {
                peer_link.link.send(msg.clone()).await;
            }
        }
    }

    async fn send_to_self(&mut self, msg: Custom) {
        let index = self.index;
        self.notify(NodeNotification::MessageReceived(index, msg))
            .await;
    }

    async fn handle_peer_notification(&mut self, notif: PeerNotification<Custom>) {
        let (id, peermsg) = match notif {
            PeerNotification::Received(id, peermsg) => (id, peermsg),
            PeerNotification::Disconnected(id) => {
                self.remove_peer(&id).await;
                return;
            }
        };

        match peermsg {
            PeerMessage::Hello(port, index) => {
                if let Some(peer) = self.peers.get_mut(&id) {
                    let mut addr = peer.socket_addr;
                    addr.set_port(port);
                    peer.listening_addr = Some(addr);
                    peer.index = index;
                    self.index_peer.insert(index, id);
                    println!("\n=>    Peer connected from: index: {}", index);
                    self.notify(NodeNotification::PeerAdded(id, index)).await;
                }
            }
            PeerMessage::Data(msg) => {
                // TBD: handle msg here
                if let Some(peer) = self.peers.get_mut(&id) {
                    let index = peer.index;
                    self.notify(NodeNotification::MessageReceived(index, msg))
                        .await
                }
            }
            PeerMessage::Peers(mut list) => {
                list.truncate(self.peer_list_limit());
                self.peers.get_mut(&id).map(|peer| {
                    peer.peer_addrs = list;
                });
            }
        }
    }

    async fn notify_on_error<E>(
        &mut self,
        result: Result<(), E>,
        mapper: impl FnOnce(E) -> NodeNotification<Custom>,
    ) -> () {
        if let Err(e) = result {
            self.notify(mapper(e)).await;
        }
    }

    async fn notify(&mut self, notif: NodeNotification<Custom>) {
        let _ = self.notifications_channel.send(notif).await.unwrap_or(());
    }

    /// Inspectable list of peers for debugging.
    fn peer_infos(&self) -> Vec<PeerInfo> {
        self.peers
            .iter()
            .map(|(pid, peerstate)| PeerInfo {
                id: *pid,
                address: peerstate.listening_addr.unwrap_or(peerstate.socket_addr),
                public: peerstate.listening_addr.is_some(),
                direction: peerstate.direction,
                priority: self.peer_priorities.get(pid).unwrap_or(LOW_PRIORITY),
                index: peerstate.index,
            })
            .collect::<Vec<_>>()
    }

    // Limit amount of peers we send out and receive to the outbound limit.
    fn peer_list_limit(&self) -> usize {
        self.config.outbound_limit
    }

    fn peer_id(&self) -> PeerID {
        PeerID::from(self.cybershake_identity.to_public_key())
    }

    fn index_to_peer(&self, index: usize, reply: Reply<PeerID>) {
        let peerid = self
            .index_peer
            .get(&index)
            .ok_or(MpcIOError::ObtainValueFailed)
            .unwrap();
        reply.send(*peerid).unwrap_or(())
    }
}

impl fmt::Display for PeerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}   priority: {}   public: {} index: {}",
            match self.direction {
                Direction::Inbound => " [in]",
                Direction::Outbound => "[out]",
            },
            self.address,
            self.id,
            self.priority,
            self.public,
            self.index
        )
    }
}
