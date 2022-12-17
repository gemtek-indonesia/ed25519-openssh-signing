#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub(crate) mod cli;

use cli::cli_get_key;

fn main() -> anyhow::Result<()> {
    let keysets = cli_get_key()?;
    let (message, sig_ring, sig_substrate) = keysets.prompt_sign_message()?;
    println!("[Signing Result]");
    println!("* Secret Seed   : 0x{}", keysets.get_hex_secret_seed());
    println!("* Public Key    : 0x{}", keysets.get_hex_public_key());
    println!("* Message       : {}", message);
    println!("* Sig Ring      : {}", sig_ring);
    println!("* Sig Substrate : {}", sig_substrate);

    Ok(())
}
