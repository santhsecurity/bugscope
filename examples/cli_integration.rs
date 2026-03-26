use bugscope::BugscopeArgs;
use clap::Parser;

#[derive(Debug, Parser)]
struct Cli {
    #[command(flatten)]
    bugscope: BugscopeArgs,

    #[arg(long)]
    target: String,
}

fn main() {
    let cli = if std::env::args_os().len() > 1 {
        Cli::parse()
    } else {
        Cli::parse_from(["cli_integration", "--target", "https://example.com"])
    };
    println!(
        "target={} scope_file={:?} platform={:?} rate_limit={:?}",
        cli.target,
        cli.bugscope.scope_file,
        cli.bugscope.bounty_platform,
        cli.bugscope.rate_limit_override()
    );
}
