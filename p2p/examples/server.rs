use p2p::mpc_io::MsgProcess;
use p2p::mpc_io::ProcessMessage;
use p2p::mpc_io::{broadcast_, connect_, disconnect_, list_peers_, node_init, receive_, send_};
use p2p::Message;
use tokio::task;
struct TestReceive {}
impl MsgProcess for TestReceive {
    fn process(&mut self, index: usize, msg: Message) -> ProcessMessage {
        let msg = ProcessMessage::SendMessage(1, msg);
        return msg;
    }
}

fn main() {
    let mut rt = tokio::runtime::Runtime::new().expect("Should be able to init tokio::Runtime.");
    let local = task::LocalSet::new();
    local.block_on(&mut rt, async move {
        let index: usize = 0;
        let ip = "127.0.0.1".parse().unwrap();
        let port = 64000;

        //Init a node as server
        let (mut node_handle, notifications_channel) = node_init(index, ip, port).await;

        let mut message_process = TestReceive {};
        //Receive messages
        receive_(
            &mut node_handle,
            notifications_channel,
            &mut message_process,
        )
        .await;
    })
}
