use structopt::StructOpt;

use cli::ccs21_party_one::Opt as CCSPartyOneOpt;
use cli::ccs21_party_two::Opt as CCSPartyTwoOpt;
use cli::ecdsa_keyrefresh::Opt as KeyRefreshOpt;
use cli::multi_party_ecdsa_keygen::Opt as AsiaKeygenOpt;
use cli::multi_party_ecdsa_sign::Opt as AsiaSignOpt;
use cli::two_party_ecdsa_one::Opt as AsiaPartyOneOpt;
use cli::two_party_ecdsa_two::Opt as AsiaPartyTwoOpt;

#[derive(Debug, StructOpt)]
pub enum Opt {
    CCSPartyOne(CCSPartyOneOpt),
    CCSPartyTwo(CCSPartyTwoOpt),
    AsiaPartyOne(AsiaPartyOneOpt),
    AsiaPartyTwo(AsiaPartyTwoOpt),
    AsiaMultiKeygen(AsiaKeygenOpt),
    AsiaMultiSign(AsiaSignOpt),
    KeyRefresh(KeyRefreshOpt),
}

impl Opt {
    pub async fn execute(self) {
        match self {
            Self::CCSPartyOne(opt) => opt.execute().await,
            Self::CCSPartyTwo(opt) => opt.execute().await,
            Self::AsiaPartyOne(opt) => opt.execute().await,
            Self::AsiaPartyTwo(opt) => opt.execute().await,
            Self::AsiaMultiKeygen(opt) => opt.execute().await,
            Self::AsiaMultiSign(opt) => opt.execute().await,
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
