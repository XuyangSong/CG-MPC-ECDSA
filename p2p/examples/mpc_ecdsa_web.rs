#![deny(warnings)]
use curv::arithmetic::Converter;
use curve25519_dalek::scalar::Scalar;
use rand::thread_rng;

use std::collections::HashMap;
use tokio::task;
use url::form_urlencoded;

use p2p::cybershake;
use p2p::{Message, Node, NodeConfig, NodeHandle, NodeNotification, PeerID};

// multi party
use curv::BigInt;
use multi_party_ecdsa::communication::receiving_messages::ReceivingMessages;
use multi_party_ecdsa::communication::sending_messages::SendingMessages;
use multi_party_ecdsa::protocols::multi_party::ours::keygen::*;
use multi_party_ecdsa::protocols::multi_party::ours::message::{
    MultiKeyGenMessage, MultiSignMessage,
};
use multi_party_ecdsa::protocols::multi_party::ours::sign::*;
use multi_party_ecdsa::utilities::class::update_class_group_by_p;
use multi_party_ecdsa::utilities::promise_sigma::PromiseState;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::{env, fs, thread};

// two party
use class_group::primitives::cl_dl_public_setup::{CLGroup, SK};
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::elliptic::curves::traits::*;
// use curv::{BigInt, FE};
// use curv::FE;
use curv::elliptic::curves::secp256_k1::FE;
use multi_party_ecdsa::protocols::two_party::message::TwoPartyMsg;
use multi_party_ecdsa::protocols::two_party::party_one;
use multi_party_ecdsa::protocols::two_party::party_two;

// hyper
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use tokio::fs::File;

// global variables
static mut G_MESSAGE: String = String::new();
static mut G_KEY_RESP: String = String::new();
static mut G_SIGN_RESP: String = String::new();

// connect,keygeninit,signinit first
static mut STATE_CONNECTS: Vec<KMSState> = Vec::new();
static mut STATE_SIGNS: Vec<KMSState> = Vec::new();
static mut STATE_KEYGENS: Vec<KMSState> = Vec::new();

fn init_global_vars() {
    unsafe {
        G_MESSAGE = String::new();
        G_KEY_RESP = String::new();
        G_SIGN_RESP = String::new();
    }
}
fn init_global_states(parties: usize) {
    unsafe {
        STATE_CONNECTS = Vec::new();
        STATE_SIGNS = Vec::new();
        STATE_KEYGENS = Vec::new();
        for _ in 0..parties {
            STATE_CONNECTS.push(KMSState::Disconnected);
            STATE_KEYGENS.push(KMSState::KeyGenerated);
            STATE_SIGNS.push(KMSState::Signed);
        }
    }
}
fn init_globals(parties: usize) {
    init_global_vars();
    init_global_states(parties);
}
fn get_states() -> String {
    unsafe {
        let s = serde_json::to_string(&(
            STATE_CONNECTS.clone(),
            STATE_KEYGENS.clone(),
            STATE_SIGNS.clone(),
        ))
        .unwrap();
        return s;
    }
}
#[derive(Debug, Deserialize, Clone)]
pub struct JsonConfig {
    pub share_count: usize,
    pub threshold: usize,
    pub infos: Vec<PeerInfo>,
    pub message: String,
    pub subset: Vec<usize>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MyInfo {
    pub index: usize,
    pub ip: String,
    pub port: u16,
}
impl MyInfo {
    pub fn new(index_: usize, ip_: String, port_: u16) -> Self {
        Self {
            index: index_,
            ip: ip_,
            port: port_,
        }
    }
}
#[derive(Debug, Deserialize, Clone)]
pub struct PeerInfo {
    pub index: usize,
    pub address: String,
}
impl PeerInfo {
    pub fn new(index_: usize, address_: String) -> Self {
        Self {
            index: index_,
            address: address_,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct JsonConfigInternal {
    pub http_port: u16,
    pub parties: usize,
    pub share_count: usize,
    pub threshold: usize,
    pub my_info: MyInfo,
    pub peers_info: Vec<PeerInfo>,
    pub message: String,
    pub subset: Vec<usize>,
}

impl JsonConfigInternal {
    pub fn init_with(parties: usize, party_id: usize, json_config_file: String) -> Self {
        let file_path = Path::new(&json_config_file);
        let json_str = fs::read_to_string(file_path).unwrap();
        let json_config: JsonConfig =
            serde_json::from_str(&json_str).expect("JSON was not well-formatted");

        let parites_ = parties;
        let index_ = party_id;
        let mut ip_: String = String::new();
        let mut port_: u16 = 8888;
        let mut peers_info_: Vec<PeerInfo> = Vec::new();
        for info in json_config.infos.iter() {
            if info.index == index_ {
                let s = info.address.clone();
                let vs: Vec<&str> = s.splitn(2, ":").collect();
                ip_ = vs[0].to_string();
                port_ = vs[1].to_string().parse::<u16>().unwrap();
            } else {
                peers_info_.push(PeerInfo::new(info.index, info.address.clone()));
            }
        }

        Self {
            http_port: 8000,
            parties: parites_,
            share_count: json_config.share_count,
            threshold: json_config.threshold,
            my_info: MyInfo::new(index_, ip_, port_),
            peers_info: peers_info_,
            message: json_config.message,
            subset: json_config.subset,
        }
    }
}

/// HTTP status code 404
fn not_foundx() -> Result<Response<Body>, hyper::Error> {
    let mut not_found = Response::default();
    *not_found.status_mut() = StatusCode::NOT_FOUND;
    Ok(not_found)
}

async fn simple_file_send(
    filename: &str,
    parties: usize,
    party_id: usize,
) -> Result<Response<Body>, hyper::Error> {
    if let Err(_file) = File::open(filename).await {
        return not_foundx();
    }

    let mut sdisabled = "";
    if parties == 2 && party_id == 1 {
        sdisabled = "disabled=\"disabled\"";
    }
    let text = fs::read_to_string(filename).unwrap();
    let mut content = text.replace("DISABLED", sdisabled);
    content = content.replace("PARTYID", party_id.to_string().as_str());
    return Ok(Response::new(Body::from(content)));
}

#[derive(Debug, Serialize, Deserialize, Clone)]
enum KMSState {
    Uninited,
    Connecting,
    Connected,
    Disconnecting,
    Disconnected,
    KeyGenIniting,
    KeyGenInited,
    KeyGenerating,
    KeyGenerated,
    SignIniting,
    SignInited,
    Signing,
    Signed,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct KMSResponse {
    code: i32,
    desc: String,
    data: String,
    //state: KMSState,
}
impl KMSResponse {
    pub fn make(code_: i32, desc_: &str, data_: &str) -> Self {
        Self {
            code: code_,
            desc: desc_.to_string(),
            data: data_.to_string(),
            //state: KMSState::Uninited,
        }
    }
    fn to_json_string(&self) -> String {
        let mut x = self.clone();
        x.data = "SPECIAL_FOR_REPLACED".to_string();
        let s = serde_json::to_string(&x.clone()).unwrap();
        let ss = s.replace("\"SPECIAL_FOR_REPLACED\"", self.data.as_str());
        return ss;
    }
}

macro_rules! simple_response {
    ($code:expr, $desc:expr, $data:expr) => {{
        Ok(Response::new(Body::from({
            KMSResponse::make($code, $desc, $data).to_json_string()
        })))
    }};
    ($code:expr, $desc:expr) => {{
        Ok(Response::new(Body::from({
            KMSResponse::make($code, $desc, "[]").to_json_string()
        })))
    }};
}

async fn http_handler(
    req: Request<Body>,
    nodex: NodeHandle<Message>,
    json_config: JsonConfigInternal,
) -> Result<Response<Body>, hyper::Error> {
    let parties = json_config.parties;
    let index = json_config.my_info.index;
    // let subset = json_config.subset.clone();
    let uri = req.uri().path();
    if !(uri == "/" || uri == "/getkey" || uri == "/getsignature") {
        println!("test before request uri:{} state:{}", uri, get_states());
    }
    if uri == "/" {
        return simple_file_send("index.html", parties, index).await;
    }

    let mut node = nodex.clone();
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/getstate") => {
            simple_response!(0, "GetState", &get_states().as_str())
        }
        (&Method::GET, "/getkey") => unsafe {
            simple_response!(0, "GetKey", G_KEY_RESP.clone().as_str())
        },
        (&Method::GET, "/getsignature") => unsafe {
            simple_response!(0, "GetSignature", G_SIGN_RESP.clone().as_str())
        },

        (&Method::GET, "/connect") | (&Method::POST, "/connect") => {
            unsafe {
                STATE_CONNECTS[index] = KMSState::Connecting;
            }

            println!("=> Request Connect Begin ...");
            for peer_info in json_config.peers_info.iter() {
                let _ = node
                    .connect_to_peer(&peer_info.address, None, peer_info.index)
                    .await
                    .map_err(|e| format!("Handshake error with {}. {:?}", peer_info.address, e));
            }

            unsafe {
                STATE_CONNECTS[index] = KMSState::Connected;
            }

            simple_response!(0, "Connecting")
        }

        (&Method::GET, "/signconnect") | (&Method::POST, "/signconnect") => {
            unsafe {
                STATE_CONNECTS[index] = KMSState::Connecting;
            }

            println!("=> Request Connect Begin ...");
            for peer_info in json_config.peers_info.iter() {
                if parties > 2 && !json_config.subset.contains(&index) {
                    continue;
                }
                let _ = node
                    .connect_to_peer(&peer_info.address, None, peer_info.index)
                    .await
                    .map_err(|e| format!("Handshake error with {}. {:?}", peer_info.address, e));
            }

            unsafe {
                STATE_CONNECTS[index] = KMSState::Connected;
                for i in 0..parties {
                    STATE_KEYGENS[i] = KMSState::KeyGenerated;
                }
            }

            simple_response!(0, "SignConnecting")
        }

        (&Method::GET, "/disconnect") | (&Method::POST, "/disconnect") => {
            unsafe {
                STATE_CONNECTS[index] = KMSState::Disconnecting;
            }
            init_global_vars();

            println!("=> Request Disconnect Begin ...");
            let peer_infos = node.list_peers().await;
            let mut peerids: Vec<PeerID> = Vec::new();
            for peer_info in peer_infos.iter() {
                peerids.push(peer_info.id);
            }
            for id in peerids.iter() {
                let xid = id.clone();
                node.remove_peer(xid).await;
            }

            unsafe {
                STATE_CONNECTS[index] = KMSState::Disconnected;
            }

            simple_response!(0, "Disconnecting")
        }

        (&Method::GET, "/keygeninit") | (&Method::POST, "/keygeninit") => {
            unsafe {
                for s in STATE_KEYGENS.iter() {
                    if let KMSState::KeyGenIniting | KMSState::KeyGenerating = s {
                        return simple_response!(2, "KeyGenIniting|KeyGenerating ...");
                    }
                }
                for s in STATE_SIGNS.iter() {
                    if let KMSState::SignIniting | KMSState::Signing = s {
                        return simple_response!(2, "SignIniting|Signing ...");
                    }
                }
            }

            unsafe {
                G_KEY_RESP = String::new();
                G_SIGN_RESP = String::new();
                STATE_KEYGENS[index] = KMSState::KeyGenIniting;
            }

            println!("=> Request KeyInit Begin ...");
            node.keygen_init().await;

            simple_response!(0, "KeyGenIniting")
        }

        (&Method::GET, "/keygen") | (&Method::POST, "/keygen") => {
            if parties == 2 && index != 0 {
                return simple_response!(2, "Only index 0 can keygen!");
            }

            unsafe {
                for s in STATE_KEYGENS.iter() {
                    if let KMSState::KeyGenerated = s {
                        return simple_response!(2, "call keygen init first");
                    }
                }

                for s in STATE_KEYGENS.iter() {
                    if let KMSState::KeyGenIniting | KMSState::KeyGenerating = s {
                        return simple_response!(2, "KeyGenIniting|KeyGenerating ...");
                    }
                }

                for s in STATE_SIGNS.iter() {
                    if let KMSState::SignIniting | KMSState::Signing = s {
                        return simple_response!(2, "SignIniting|Signing ...");
                    }
                }
            }

            unsafe {
                G_KEY_RESP = String::new();
                G_SIGN_RESP = String::new();
                STATE_KEYGENS[index] = KMSState::KeyGenerating;
            }

            println!("=> Request KeyGen Begin ...");
            if parties == 2 {
                let msg = bincode::serialize(&TwoPartyMsg::KegGenBegin).unwrap();
                node.keygen(Message(msg)).await;
            } else {
                let msg = bincode::serialize(&ReceivingMessages::MultiKeyGenMessage(
                    MultiKeyGenMessage::KeyGenBegin,
                ))
                .unwrap();
                node.keygen(Message(msg)).await;
            }

            let loops = 30;
            for _ in 0..loops {
                unsafe {
                    let mut ok = true;
                    for s in STATE_KEYGENS.iter() {
                        if let KMSState::KeyGenerated = s {
                        } else {
                            ok &= false;
                        }
                    }
                    if ok {
                        return simple_response!(0, "KeyGenerating", G_KEY_RESP.clone().as_str());
                    }
                }
                thread::sleep(std::time::Duration::from_secs(1));
            }

            simple_response!(0, "Please call /getkey later")
        }

        (&Method::GET, "/signinit") | (&Method::POST, "/signinit") => {
            if parties == 3 && !json_config.subset.contains(&index) {
                return simple_response!(2, "Not in subset...");
            }

            unsafe {
                for (i, s) in STATE_KEYGENS.iter().enumerate() {
                    if !json_config.subset.contains(&i) {
                        continue;
                    }
                    if let KMSState::KeyGenIniting | KMSState::KeyGenerating = s {
                        return simple_response!(2, "KeyGenIniting|KeyGenerating ...");
                    }
                }

                for (i, s) in STATE_SIGNS.iter().enumerate() {
                    if !json_config.subset.contains(&i) {
                        continue;
                    }
                    if let KMSState::SignIniting | KMSState::Signing = s {
                        return simple_response!(2, "SignIniting|Signing ...");
                    }
                }
            }

            unsafe {
                G_SIGN_RESP = String::new();
                STATE_SIGNS[index] = KMSState::SignIniting;
            }

            println!("=> Request SignInit Begin ...");

            if parties != 2 || index == 0 {
                let b = hyper::body::to_bytes(req).await?;
                let params = form_urlencoded::parse(b.as_ref())
                    .into_owned()
                    .collect::<HashMap<String, String>>();
                if let Some(m) = params.get("msg") {
                    unsafe {
                        G_MESSAGE = m.clone();
                    }
                } else {
                    return simple_response!(3, "Missing field");
                };
            }

            node.sign_init().await;

            simple_response!(0, "SignIniting")
        }

        (&Method::GET, "/sign") | (&Method::POST, "/sign") => {
            if parties == 2 && index != 0 {
                return simple_response!(2, "Only index 0 can sign!");
            }

            if !json_config.subset.contains(&index) {
                return simple_response!(2, "Not in subset. Not supportted...");
            }

            unsafe {
                for (i, s) in STATE_SIGNS.iter().enumerate() {
                    if !json_config.subset.contains(&i) {
                        continue;
                    }
                    if let KMSState::Signed = s {
                        return simple_response!(2, "call sign init first");
                    }
                }

                for (i, s) in STATE_KEYGENS.iter().enumerate() {
                    if !json_config.subset.contains(&i) {
                        continue;
                    }
                    if let KMSState::KeyGenIniting | KMSState::KeyGenerating = s {
                        return simple_response!(2, "KeyGenIniting|KeyGenerating ...");
                    }
                }

                for (i, s) in STATE_SIGNS.iter().enumerate() {
                    if !json_config.subset.contains(&i) {
                        continue;
                    }
                    if let KMSState::SignIniting | KMSState::Signing = s {
                        return simple_response!(2, "SignIniting|Signing ...");
                    }
                }
            }

            unsafe {
                G_SIGN_RESP = String::new();
                STATE_SIGNS[index] = KMSState::Signing;
            }

            println!("=> Request Sign Begin ...");

            if parties == 2 {
                let msg = bincode::serialize(&TwoPartyMsg::SignBegin).unwrap();
                node.sign(Message(msg)).await;
            } else {
                let msg = bincode::serialize(&ReceivingMessages::MultiSignMessage(
                    MultiSignMessage::SignBegin,
                ))
                .unwrap();
                node.sign(Message(msg)).await;
            }

            let loops = 30;
            for _ in 0..loops {
                unsafe {
                    let mut ok = true;
                    for (i, s) in STATE_SIGNS.iter().enumerate() {
                        if !json_config.subset.contains(&i) {
                            continue;
                        }
                        if let KMSState::Signed = s {
                        } else {
                            ok &= false;
                        }
                    }
                    if ok {
                        return simple_response!(0, "Signing", G_SIGN_RESP.clone().as_str());
                    }
                }
                thread::sleep(std::time::Duration::from_secs(1));
            }

            simple_response!(0, "Please call /getsignature later")
        }

        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

pub struct HTTPServer {}
impl HTTPServer {
    pub fn spawn_monitor(json_config: JsonConfigInternal) -> task::JoinHandle<Result<(), String>> {
        //todo
        task::spawn(async move {
            for i in 0..10000000 {
                println!("index:{} -->i:{} ", json_config.my_info.index, i);
                let d = std::time::Duration::from_secs(5);
                thread::sleep(d);
            }
            Ok(())
        })
    }
}

impl HTTPServer {
    pub fn spawn_server(
        node: NodeHandle<Message>,
        json_config: JsonConfigInternal,
    ) -> task::JoinHandle<Result<(), String>> {
        task::spawn(async move {
            let port = json_config.http_port;
            let addr = ([0, 0, 0, 0], port).into();
            let service = make_service_fn(move |_| {
                let clientnode = node.clone();
                let json_config_clone = json_config.clone();
                async {
                    Ok::<_, hyper::Error>(service_fn(move |req| {
                        http_handler(req, clientnode.to_owned(), json_config_clone.to_owned())
                    }))
                }
            });
            let server = Server::bind(&addr).serve(service);

            println!("Listening on http://{}", addr);
            server.await.expect("Http Server Error");
            ///////////////////////////////////////////////////
            Ok(())
        })
    }
}

async fn two_party_f(json_config: JsonConfigInternal) -> Result<(), std::string::String> {
    let json_config_clone = json_config.clone();
    let json_config_clone2 = json_config.clone();
    let my_index = json_config.my_info.index;
    let parties = json_config.parties;
    let message_hash = HSha256::create_hash_from_slice(json_config.message.as_bytes());
    let message_to_sign: FE = ECScalar::from(&message_hash);
    let config = NodeConfig {
        index: my_index,
        listen_ip: json_config.my_info.ip.parse().unwrap(),
        listen_port: json_config.my_info.port,
        inbound_limit: 100,
        outbound_limit: 100,
        heartbeat_interval_sec: 3600,
    };

    // Creating a random private key instead of reading from a file.
    let host_privkey = cybershake::PrivateKey::from(Scalar::random(&mut thread_rng()));
    let (node, mut notifications_channel) = Node::<Message>::spawn(host_privkey, config)
        .await
        .expect("Should bind normally.");

    println!(
        "Listening on {} with peer ID: {} with index: {}",
        node.socket_address(),
        node.id(),
        my_index,
    );

    let mut node2 = node.clone();
    let interactive_loop = HTTPServer::spawn_server(node, json_config_clone);
    let _spawn_monitor_loop = HTTPServer::spawn_monitor(json_config_clone2);

    // Spawn the notifications loop
    let notifications_loop = {
        task::spawn_local(async move {
            /////////////////////////////
            let seed: BigInt = BigInt::from_hex("314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848").unwrap();
            let qtilde: BigInt = BigInt::from_hex("23893039587891638565297401593924273169825964283558231612167738384238313917887833945225898199741584873627027859268757281540231029139309613219716874418588517495558290624716349383746651319918936091587965845797835593810764676322501564946526995033976417223598945838942128878559190581681834232455419055873026991107437602524121085617731").unwrap();
            let group = CLGroup::new_from_qtilde(&seed, &qtilde);
            // let group = CLGroup::new_from_setup(&1348, &seed); //discriminant 1348

            let mut party_one_keygen = party_one::KeyGenInit::new(&group);
            let mut party_two_keygen = party_two::KeyGenInit::new(&group);

            let new_class_group = update_class_group_by_p(&group);
            let mut party_one_sign = party_one::SignPhase::new(new_class_group.clone());
            let mut party_two_sign =
                party_two::SignPhase::new(new_class_group.clone(), &message_to_sign);

            let mut time = time::now();

            while let Some(notif) = notifications_channel.recv().await {
                match notif {
                    NodeNotification::PeerAdded(_pid, index) => {
                        println!("\n=> Peer connected to index: {}", index);
                        unsafe {
                            STATE_CONNECTS[my_index] = KMSState::Connected;
                            STATE_CONNECTS[index] = KMSState::Connected;
                        }
                    }
                    NodeNotification::PeerDisconnected(pid, index) => {
                        println!("\n=> Peer disconnected: {}", pid);
                        unsafe {
                            STATE_CONNECTS[my_index] = KMSState::Disconnected;
                            STATE_CONNECTS[index] = KMSState::Disconnected;
                        }
                    }
                    NodeNotification::KeyGenInit => {
                        unsafe {
                            STATE_KEYGENS[my_index] = KMSState::KeyGenIniting;
                        }
                        println!("\n=> Peer KeyGenInit");
                        party_one_keygen = party_one::KeyGenInit::new(&group);
                        party_two_keygen = party_two::KeyGenInit::new(&group);

                        let msg_send = TwoPartyMsg::KeyGenInitSync(my_index);
                        let msg_bytes = bincode::serialize(&msg_send).unwrap();
                        node2.broadcast(Message(msg_bytes)).await;

                        unsafe {
                            STATE_KEYGENS[my_index] = KMSState::KeyGenInited;
                        }
                    }

                    NodeNotification::SignInit => {
                        unsafe {
                            STATE_SIGNS[my_index] = KMSState::SignIniting;
                        }
                        let mmsg: String;
                        unsafe {
                            mmsg = G_MESSAGE.clone();
                        }
                        println!("\n=> SignInit {}", mmsg.clone());
                        let message_hash = HSha256::create_hash_from_slice(mmsg.as_bytes());
                        let message_to_sign: FE = ECScalar::from(&message_hash);

                        party_one_sign = party_one::SignPhase::new(new_class_group.clone());
                        party_two_sign =
                            party_two::SignPhase::new(new_class_group.clone(), &message_to_sign);

                        let msg_send = TwoPartyMsg::SignInitSync(my_index);
                        let msg_bytes = bincode::serialize(&msg_send).unwrap();
                        node2.broadcast(Message(msg_bytes)).await;

                        unsafe {
                            STATE_SIGNS[my_index] = KMSState::SignInited;
                        }
                    }
                    NodeNotification::MessageReceived(index, msg) => {
                        println!("\n=>MessageReceived Receiving message from {}", index);
                        let received_msg: TwoPartyMsg = bincode::deserialize(&msg).unwrap();
                        match received_msg {
                            TwoPartyMsg::KegGenBegin => {
                                unsafe {
                                    STATE_KEYGENS[index] = KMSState::KeyGenerating;
                                }
                                if index == 0 {
                                    // Party one time begin
                                    time = time::now();
                                    let msg_send = TwoPartyMsg::KeyGenPartyOneRoundOneMsg(
                                        party_one_keygen.round_one_msg.clone(),
                                    );
                                    let msg_bytes = bincode::serialize(&msg_send).unwrap();
                                    node2.broadcast(Message(msg_bytes)).await;
                                } else {
                                    println!("Please use index 0 party begin the keygen...");
                                }
                            }
                            TwoPartyMsg::KeyGenPartyOneRoundOneMsg(dlcom) => {
                                println!("\n=>    KeyGen: Receiving RoundOneMsg from index 0");
                                // Party two time begin
                                time = time::now();

                                party_two_keygen.set_dl_com(dlcom);
                                let msg_send = TwoPartyMsg::KenGenPartyTwoRoundOneMsg(
                                    party_two_keygen.msg.clone(),
                                );
                                let msg_bytes = bincode::serialize(&msg_send).unwrap();
                                node2.broadcast(Message(msg_bytes)).await;
                            }
                            TwoPartyMsg::KenGenPartyTwoRoundOneMsg(msg) => {
                                println!("\n=>    KeyGen: Receiving RoundOneMsg from index 1");

                                let com_open =
                                    party_one_keygen.verify_and_get_next_msg(&msg).unwrap();
                                party_one_keygen.compute_public_key(&msg.pk);

                                // Get pk and pk'
                                let (h_caret, h, gp) = party_one_keygen.get_class_group_pk();

                                let msg_send = TwoPartyMsg::KeyGenPartyOneRoundTwoMsg(
                                    com_open,
                                    h_caret,
                                    h,
                                    gp,
                                    party_one_keygen.promise_state.clone(),
                                    party_one_keygen.promise_proof.clone(),
                                );
                                let msg_bytes = bincode::serialize(&msg_send).unwrap();
                                node2.broadcast(Message(msg_bytes)).await;

                                // Party one time end
                                println!("keygen party one time: {:?}", time::now() - time);

                                // Party one save keygen to file
                                let keygen_path = Path::new("./keygen_result.json");
                                let keygen_json = serde_json::to_string(&(
                                    party_one_keygen.cl_keypair.get_secret_key().clone(),
                                    party_one_keygen.keypair.get_secret_key().clone(),
                                ))
                                .unwrap();
                                unsafe {
                                    G_KEY_RESP = keygen_json.clone();
                                    for i in 0..parties {
                                        //[simply, todo maybe need p0 notify p1]
                                        STATE_KEYGENS[i] = KMSState::KeyGenerated;
                                    }
                                }
                                fs::write(keygen_path, keygen_json).expect("Unable to save !");
                                println!("##    KeyGen finish!");
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
                                    &party_two_keygen.received_msg,
                                    &com_open,
                                )
                                .unwrap();

                                // Verify pk and pk's
                                party_two_keygen
                                    .verify_class_group_pk(&h_caret, &h, &gp)
                                    .unwrap();

                                // Verify promise proof
                                party_two_keygen
                                    .verify_promise_proof(&promise_state, &promise_proof)
                                    .unwrap();
                                party_two_keygen.compute_public_key(com_open.get_public_key());

                                // Party two time end
                                println!("keygen party two time: {:?}", time::now() - time);

                                // Party two save keygen to file
                                let keygen_path = Path::new("./keygen_result.json");
                                let keygen_json = serde_json::to_string(&(
                                    promise_state,
                                    party_two_keygen.keypair.get_secret_key().clone(),
                                ))
                                .unwrap();
                                unsafe {
                                    G_KEY_RESP = keygen_json.clone();
                                    for i in 0..parties {
                                        STATE_KEYGENS[i] = KMSState::KeyGenerated;
                                    }
                                }
                                fs::write(keygen_path, keygen_json).expect("Unable to save !");

                                println!("##    KeyGen succuss!");
                            }
                            TwoPartyMsg::SignBegin => {
                                unsafe {
                                    STATE_SIGNS[index] = KMSState::Signing;
                                }
                                if index == 0 {
                                    time = time::now();
                                    let msg_send = TwoPartyMsg::SignPartyOneRoundOneMsg(
                                        party_one_sign.round_one_msg.clone(),
                                    );
                                    let msg_bytes = bincode::serialize(&msg_send).unwrap();
                                    node2.broadcast(Message(msg_bytes)).await;
                                } else {
                                    println!("Please use index 0 party begin the sign...");
                                }
                            }
                            TwoPartyMsg::SignPartyOneRoundOneMsg(dlcom) => {
                                println!("\n=>    Sign: Receiving RoundOneMsg from index 0");
                                time = time::now();

                                party_two_sign.set_dl_com(dlcom);
                                let msg_send = TwoPartyMsg::SignPartyTwoRoundOneMsg(
                                    party_two_sign.msg.clone(),
                                );
                                let msg_bytes = bincode::serialize(&msg_send).unwrap();
                                node2.broadcast(Message(msg_bytes)).await;
                            }
                            TwoPartyMsg::SignPartyTwoRoundOneMsg(msg) => {
                                println!("\n=>    Sign: Receiving RoundOneMsg from index 1");

                                let witness = party_one_sign.verify_and_get_next_msg(&msg).unwrap();
                                party_one_sign.set_received_msg(msg);

                                let msg_send = TwoPartyMsg::SignPartyOneRoundTwoMsg(witness);
                                let msg_bytes = bincode::serialize(&msg_send).unwrap();
                                node2.broadcast(Message(msg_bytes)).await;
                            }
                            TwoPartyMsg::SignPartyOneRoundTwoMsg(witness) => {
                                println!("\n=>    Sign: Receiving RoundTwoMsg from index 0");

                                party_two::SignPhase::verify_received_dl_com_zk(
                                    &party_two_sign.received_round_one_msg,
                                    &witness,
                                )
                                .unwrap();

                                // read key file
                                let data = fs::read_to_string("./keygen_result.json")
                                    .expect("Unable to load keys, did you run keygen first? ");
                                let (promise_state, secret_key): (PromiseState, FE) =
                                    serde_json::from_str(&data).unwrap();

                                let ephemeral_public_share = party_two_sign
                                    .compute_public_share_key(witness.get_public_key());
                                let (cipher, t_p) = party_two_sign
                                    .sign(
                                        &ephemeral_public_share,
                                        &secret_key,
                                        &promise_state.cipher,
                                        // &message_to_sign,
                                    )
                                    .unwrap();

                                let msg_send = TwoPartyMsg::SignPartyTwoRoundTwoMsg(cipher, t_p);
                                let msg_bytes = bincode::serialize(&msg_send).unwrap();
                                node2.broadcast(Message(msg_bytes)).await;

                                // Party two time end
                                println!("Sign party two time: {:?}", time::now() - time);
                                println!("##    Sign Finish!");
                                unsafe {
                                    for i in 0..parties {
                                        STATE_SIGNS[i] = KMSState::Signed; //[simply, todo maybe need p0 notify p1]
                                    }
                                }
                            }
                            TwoPartyMsg::SignPartyTwoRoundTwoMsg(cipher, t_p) => {
                                println!("\n=>    Sign: Receiving RoundTwoMsg from index 1");

                                // read key file
                                let data = fs::read_to_string("./keygen_result.json")
                                    .expect("Unable to load keys, did you run keygen first? ");
                                let (cl_sk, secret_key): (SK, FE) =
                                    serde_json::from_str(&data).unwrap();

                                let ephemeral_public_share = party_one_sign
                                    .compute_public_share_key(&party_one_sign.received_msg.pk);
                                let signature = party_one_sign
                                    .sign(
                                        &cl_sk,
                                        &cipher,
                                        &ephemeral_public_share,
                                        &secret_key,
                                        &t_p,
                                    )
                                    .unwrap();

                                let mut _res = String::new();
                                {
                                    // Save signature to file
                                    let signature_path = Path::new("./sign_result.json");
                                    let signature_json =
                                        serde_json::to_string(&(signature,)).unwrap();
                                    fs::write(signature_path, signature_json.clone())
                                        .expect("Unable to save !");
                                    _res = signature_json.clone();
                                }

                                unsafe {
                                    G_SIGN_RESP = _res.clone();
                                    for i in 0..parties {
                                        STATE_SIGNS[i] = KMSState::Signed;
                                    }
                                }

                                // Party one time end
                                println!("Sign party one time: {:?}", time::now() - time);
                                println!("##    Sign finish! \n signature: {:}", _res);
                            }
                            TwoPartyMsg::KeyGenInitSync(index) => unsafe {
                                println!("KeyGenInitSync {}", index);
                                STATE_KEYGENS[index] = KMSState::KeyGenInited;
                            },
                            TwoPartyMsg::SignInitSync(index) => unsafe {
                                println!("SignInitSync {}", index);
                                STATE_SIGNS[index] = KMSState::SignInited;
                            },
                        }
                    }
                    NodeNotification::KeyGen => unsafe {
                        STATE_KEYGENS[my_index] = KMSState::KeyGenerating;
                    },
                    NodeNotification::Sign => unsafe {
                        STATE_SIGNS[my_index] = KMSState::SignIniting;
                    },
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
                }
            }
            Result::<(), String>::Ok(())
        })
    };

    notifications_loop.await.expect("panic on JoinError")?;
    interactive_loop.await.expect("panic on JoinError")
}

async fn multi_party_f(json_config: JsonConfigInternal) -> Result<(), std::string::String> {
    let json_config_clone = json_config.clone();
    let json_config_clone2 = json_config.clone();
    let my_index = json_config.my_info.index;
    let parties = json_config.parties;
    let params = Parameters {
        threshold: json_config.threshold,
        share_count: json_config.share_count,
    };
    let subset = json_config.subset;
    // let message = json_config.message;

    let config = NodeConfig {
        index: my_index,
        listen_ip: json_config.my_info.ip.parse().unwrap(),
        listen_port: json_config.my_info.port,
        inbound_limit: 100,
        outbound_limit: 100,
        heartbeat_interval_sec: 3600,
    };

    // Creating a random private key instead of reading from a file.
    let host_privkey = cybershake::PrivateKey::from(Scalar::random(&mut thread_rng()));
    let (node, mut notifications_channel) = Node::<Message>::spawn(host_privkey, config)
        .await
        .expect("Should bind normally.");

    println!(
        "Listening on {} with peer ID: {} with index: {}",
        node.socket_address(),
        node.id(),
        my_index,
    );

    let mut node2 = node.clone();
    let interactive_loop = HTTPServer::spawn_server(node, json_config_clone);
    let _spawn_monitor_loop = HTTPServer::spawn_monitor(json_config_clone2);

    // Spawn the notifications loop
    let notifications_loop = {
        task::spawn_local(async move {
            let seed: BigInt = BigInt::from_hex("314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848").unwrap();

            // discriminant: 1348, lambda: 112
            let qtilde: BigInt = BigInt::from_hex("23893039587891638565297401593924273169825964283558231612167738384238313917887833945225898199741584873627027859268757281540231029139309613219716874418588517495558290624716349383746651319918936091587965845797835593810764676322501564946526995033976417223598945838942128878559190581681834232455419055873026991107437602524121085617731").unwrap();

            // discriminant: 1827, lambda: 128
            // let qtilde: BigInt = str::parse("23134629277267369792843354241183585965289672542849276532207430015120455980466994354663282525744929223097771940566085692607836906398587331469747248600524817812682304621106507179764371100444437141969242248158429617082063052414988242667563996070192147160738941577591048902446543474661282744240565430969463246910793975505673398580796242020117195767211576704240148858827298420892993584245717232048052900060035847264121684747571088249105643535567823029086931610261875021794804631").unwrap();

            // let group = CLGroup::new_from_qtilde(&seed, &qtilde);
            // let group = CLGroup::new_from_setup(&1348, &seed); //discriminant 1348

            // TBD: add a new func, init it latter.
            let mut keygen = KeyGen::init(&seed, &qtilde, my_index, params.clone()).unwrap();
            let mut sign: SignPhase = SignPhase::new_default(&seed, &qtilde, params.clone());

            let mut time = time::now();

            while let Some(notif) = notifications_channel.recv().await {
                match notif {
                    NodeNotification::PeerAdded(_pid, index) => {
                        println!("\n=> Peer connected to index: {}", index);
                        unsafe {
                            STATE_CONNECTS[my_index] = KMSState::Connected;
                            STATE_CONNECTS[index] = KMSState::Connected;
                        }
                    }
                    NodeNotification::PeerDisconnected(pid, index) => {
                        println!("\n=> Peer disconnected: {}", pid);
                        unsafe {
                            STATE_CONNECTS[my_index] = KMSState::Disconnected;
                            STATE_CONNECTS[index] = KMSState::Disconnected;
                        }
                    }
                    NodeNotification::KeyGenInit => {
                        unsafe {
                            STATE_KEYGENS[my_index] = KMSState::KeyGenIniting;
                        }
                        println!("\n=> Peer KeyGenInit");
                        keygen = KeyGen::init(&seed, &qtilde, my_index, params.clone()).unwrap();

                        let msg_send = ReceivingMessages::MultiKeyGenInitSync(my_index);
                        let msg_bytes = bincode::serialize(&msg_send).unwrap();
                        node2.broadcast(Message(msg_bytes)).await;

                        unsafe {
                            STATE_KEYGENS[my_index] = KMSState::KeyGenInited;
                        }
                    }
                    NodeNotification::SignInit => {
                        unsafe {
                            STATE_SIGNS[my_index] = KMSState::SignIniting;
                        }
                        let mmsg: String;
                        unsafe {
                            mmsg = G_MESSAGE.clone();
                        }
                        println!("\n=> SignInit {}", mmsg.clone());
                        sign = SignPhase::new(
                            &seed,
                            &qtilde,
                            my_index,
                            params.clone(),
                            &subset,
                            &mmsg,
                        )
                        .unwrap();
                        sign.init();

                        let msg_send = ReceivingMessages::MultiSignInitSync(my_index);
                        let msg_bytes = bincode::serialize(&msg_send).unwrap();
                        node2.broadcast(Message(msg_bytes)).await;

                        unsafe {
                            STATE_SIGNS[my_index] = KMSState::SignInited;
                        }
                    }

                    NodeNotification::MessageReceived(index, msg) => {
                        println!("\n=> Receiving message from {}", index);
                        let received_msg: ReceivingMessages = bincode::deserialize(&msg).unwrap();
                        let sending_msg = match received_msg {
                            ReceivingMessages::MultiKeyGenInitSync(index) => {
                                unsafe {
                                    STATE_KEYGENS[index] = KMSState::KeyGenInited;
                                }
                                SendingMessages::EmptyMsg
                            }
                            ReceivingMessages::MultiSignInitSync(index) => {
                                unsafe {
                                    STATE_SIGNS[index] = KMSState::SignInited;
                                }
                                SendingMessages::EmptyMsg
                            }
                            ReceivingMessages::MultiKeyGenMessage(msg) => {
                                unsafe {
                                    STATE_KEYGENS[index] = KMSState::KeyGenerating;
                                }
                                keygen.msg_handler(index, &msg).unwrap()
                            }
                            ReceivingMessages::MultiSignMessage(msg) => {
                                unsafe {
                                    STATE_SIGNS[index] = KMSState::Signing;
                                }
                                sign.msg_handler(index, &msg, subset.clone()).unwrap()
                            }
                        };

                        match sending_msg {
                            SendingMessages::NormalMessage(index, msg) => {
                                node2.sendmsgbyindex(index, Message(msg)).await;
                            }
                            SendingMessages::P2pMessage(msgs) => {
                                for (index, msg) in msgs.iter() {
                                    node2.sendmsgbyindex(*index, Message(msg.to_vec())).await;
                                }
                                println!("Sending p2p msg");
                            }
                            SendingMessages::SubsetMessage(msg) => {
                                for index in subset.iter() {
                                    node2.sendmsgbyindex(*index, Message(msg.clone())).await;
                                    println!("Sending subset msg");
                                }
                            }
                            SendingMessages::BroadcastMessage(msg) => {
                                node2.broadcast(Message(msg)).await;
                                println!("Sending broadcast msg");
                            }
                            SendingMessages::KeyGenSuccess => {
                                if my_index == 0 {
                                    println!("KeyGen time: {:?}", time::now() - time);
                                }
                                println!("KeyGen Success!");
                            }
                            SendingMessages::SignSuccess => {
                                if my_index == 0 {
                                    println!("Sign time: {:?}", time::now() - time);
                                }

                                println!("Sign Success!");
                            }
                            SendingMessages::EmptyMsg => {
                                println!("no msg to send");
                            }
                            SendingMessages::KeyGenSuccessWithResult(res) => {
                                unsafe {
                                    G_KEY_RESP = res.clone();
                                    for i in 0..parties {
                                        STATE_KEYGENS[i] = KMSState::KeyGenerated;
                                    }
                                }
                                println!("KeyGen time: {:?}", time::now() - time);
                                println!("KeyGenSuccessWithResult => KeyGen Success!");
                            }
                            SendingMessages::SignSuccessWithResult(res) => {
                                unsafe {
                                    G_SIGN_RESP = res.clone();
                                    for i in 0..parties {
                                        STATE_SIGNS[i] = KMSState::Signed;
                                    }
                                }
                                println!("Sign time: {:?}", time::now() - time);
                                println!("SignSuccessWithResult => Sign Success!");
                            }
                        }
                        println!("\n")
                    }
                    NodeNotification::KeyGen => {
                        unsafe {
                            STATE_KEYGENS[my_index] = KMSState::KeyGenerating;
                        }
                        time = time::now();
                        let sending_msg =
                            ReceivingMessages::MultiKeyGenMessage(MultiKeyGenMessage::KeyGenBegin);
                        let sending_msg_bytes = bincode::serialize(&sending_msg).unwrap();
                        node2.broadcast(Message(sending_msg_bytes)).await;
                        println!("KeyGen...")
                    }
                    NodeNotification::Sign => {
                        unsafe {
                            STATE_SIGNS[my_index] = KMSState::SignIniting;
                        }
                        time = time::now();
                        let sending_msg =
                            ReceivingMessages::MultiSignMessage(MultiSignMessage::SignBegin);
                        let sending_msg_bytes = bincode::serialize(&sending_msg).unwrap();
                        // node2.broadcast(Message(sending_msg_bytes)).await;
                        for index in subset.iter() {
                            node2
                                .sendmsgbyindex(*index, Message(sending_msg_bytes.clone()))
                                .await;
                        }
                        println!("Sign...")
                    }
                    NodeNotification::InboundConnectionFailure(err) => {
                        println!("\n=> Inbound connection failure: {:?}", err)
                    }
                    NodeNotification::OutboundConnectionFailure(err) => {
                        println!("\n=> -Outbound connection failure: {:?}", err)
                    }
                    NodeNotification::Shutdown => {
                        println!("\n=> Node did shutdown.");
                        break;
                    }
                }
            }
            Result::<(), String>::Ok(())
        })
    };

    notifications_loop.await.expect("panic on JoinError")?;
    interactive_loop.await.expect("panic on JoinError")
}

fn main() {
    // println!("env::args().count():{}", env::args().count());
    if env::args().count() < 5 {
        println!(
            "Usage:\n\t{} <parties> <party-id> <port> <config-file>",
            env::args().nth(0).unwrap()
        );
        panic!("Need Config File")
    }

    ///////////////////////////////////////////////////////////////////////////////
    let parties_str = env::args().nth(1).unwrap();
    let parties = parties_str.parse::<usize>().unwrap();
    let party_id_str = env::args().nth(2).unwrap();
    let port_str = env::args().nth(3).unwrap();
    let port = port_str.parse::<u16>().unwrap();
    let party_id = party_id_str.parse::<usize>().unwrap();
    let json_config_file = env::args().nth(4).unwrap();
    let mut json_config_internal =
        JsonConfigInternal::init_with(parties, party_id, json_config_file);
    json_config_internal.http_port = port;
    let json_config = json_config_internal.clone();
    ///////////////////////////////////////////////////////////////////////////////
    init_globals(parties);
    ///////////////////////////////////////////////////////////////////////////////
    let mut rt = tokio::runtime::Runtime::new().expect("Should be able to init tokio::Runtime.");
    let local = task::LocalSet::new();
    if parties == 2 {
        local.block_on(&mut rt, two_party_f(json_config)).unwrap()
    } else if parties > 2 {
        local.block_on(&mut rt, multi_party_f(json_config)).unwrap()
    } else {
        panic!("Invalid parties:{}", parties)
    }
    ///////////////////////////////////////////////////////////////////////////////
}
