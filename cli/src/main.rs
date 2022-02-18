use structopt::StructOpt;

use cli::xax21_party_one::Opt as XAXPartyOneOpt;
use cli::xax21_party_two::Opt as XAXPartyTwoOpt;
use cli::ecdsa_keyrefresh::Opt as KeyRefreshOpt;
use cli::dmz21_multi_party_keygen::Opt as DMZKeygenOpt;
use cli::dmz21_multi_party_sign::Opt as DMZSignOpt;
use cli::dmz21_party_one::Opt as DMZPartyOneOpt;
use cli::dmz21_party_two::Opt as DMZPartyTwoOpt;

#[derive(Debug, StructOpt)]
pub enum Opt {
    XAXPartyOne(XAXPartyOneOpt),
    XAXPartyTwo(XAXPartyTwoOpt),
    DMZPartyOne(DMZPartyOneOpt),
    DMZPartyTwo(DMZPartyTwoOpt),
    DMZMultiKeygen(DMZKeygenOpt),
    DMZMultiSign(DMZSignOpt),
    KeyRefresh(KeyRefreshOpt),
}

impl Opt {
    pub async fn execute(self) {
        match self {
            Self::XAXPartyOne(opt) => opt.execute().await,
            Self::XAXPartyTwo(opt) => opt.execute().await,
            Self::DMZPartyOne(opt) => opt.execute().await,
            Self::DMZPartyTwo(opt) => opt.execute().await,
            Self::DMZMultiKeygen(opt) => opt.execute().await,
            Self::DMZMultiSign(opt) => opt.execute().await,
            Self::KeyRefresh(opt) => opt.execute().await,
        }
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "mpc-ecdsa", about = "mpc-ecdsa demo")]
struct Arguments {
    #[structopt(subcommand)]
    opt: Opt,
}
#[async_std::main]
async fn main() {
    let args: Arguments = Arguments::from_args();
    args.opt.execute().await
}
