use p2p::Message;
use p2p::{MsgProcess, Node, ProcessMessage};
use tokio::task;
struct TestReceive {}
impl MsgProcess<Message> for TestReceive {
    fn process(&mut self, index: usize, msg: Message) -> ProcessMessage<Message> {
        let msg = ProcessMessage::SendMessage(index, msg);
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
        let (mut node_handle, notifications_channel) =
            Node::<Message>::node_init(index, ip, port).await;

        let mut message_process = TestReceive {};
        //Receive messages
        node_handle
            .receive_(notifications_channel, &mut message_process)
            .await;
    })
}
