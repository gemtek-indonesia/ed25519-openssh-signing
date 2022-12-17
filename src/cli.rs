use anyhow::{anyhow, Result};
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Input, Password, Select};
use directories::UserDirs;
use hex::ToHex;
use rand::thread_rng;
use sp_core::Pair;
use std::fs::read_dir;
use std::path::{Path, PathBuf};

pub(crate) fn cli_get_key() -> Result<KeyPairSets> {
    if let Ok(openssh_keys) = list_openssh_keys() {
        if openssh_keys.is_empty() {
            decide_ephemeral_key()
        } else {
            let openssh_keys_str = openssh_keys
                .iter()
                .map(|x| x.to_str().unwrap())
                .collect::<Vec<&str>>();
            let selected_id = Select::with_theme(&ColorfulTheme::default())
                .items(&openssh_keys_str)
                .with_prompt("Select SSH key")
                .interact()?;
            let selected_path = openssh_keys.get(selected_id).unwrap();

            KeyPairSets::load_from_file(selected_path)
        }
    } else {
        decide_ephemeral_key()
    }
}

pub(crate) struct KeyPairSets {
    openssh: ssh_key::PrivateKey,
    ring: ring::signature::Ed25519KeyPair,
    substrate: sp_core::ed25519::Pair,
}

impl KeyPairSets {
    fn get_other_from_openssh(
        openssh: &ssh_key::PrivateKey,
    ) -> Result<(ring::signature::Ed25519KeyPair, sp_core::ed25519::Pair)> {
        if !openssh.key_data().is_ed25519() {
            return Err(anyhow!("The key is not a Ed25519!"));
        }

        let keypair = openssh.key_data().ed25519().unwrap();
        let seed = keypair.private.to_bytes();
        let public_key = keypair.public.0;
        let ring = ring::signature::Ed25519KeyPair::from_seed_and_public_key(&seed, &public_key)?;
        let substrate = sp_core::ed25519::Pair::from_seed_slice(&seed)
            .map_err(|_| anyhow!("Incompatible seed!"))?;

        Ok((ring, substrate))
    }

    pub(crate) fn load_from_file(path: &Path) -> Result<Self> {
        let openssh = match ssh_key::PrivateKey::read_openssh_file(path) {
            Err(err) => Err(err),
            Ok(openssh) => {
                if openssh.is_encrypted() {
                    let pass = Password::with_theme(&ColorfulTheme::default())
                        .report(false)
                        .with_prompt("The key is encrypted, please input password")
                        .interact()?;
                    Ok(openssh.decrypt(pass.as_bytes())?)
                } else {
                    Ok(openssh)
                }
            }
        }?;

        let (ring, substrate) = Self::get_other_from_openssh(&openssh)?;

        Ok(Self {
            openssh,
            ring,
            substrate,
        })
    }

    pub(crate) fn new() -> Result<Self> {
        let rng = thread_rng();
        let openssh = ssh_key::PrivateKey::random(rng, ssh_key::Algorithm::Ed25519)?;
        let (ring, substrate) = Self::get_other_from_openssh(&openssh)?;

        Ok(Self {
            openssh,
            ring,
            substrate,
        })
    }

    pub(crate) fn get_hex_secret_seed(&self) -> String {
        self.openssh
            .key_data()
            .ed25519()
            .unwrap()
            .private
            .to_bytes()
            .encode_hex()
    }

    pub(crate) fn get_hex_public_key(&self) -> String {
        self.openssh
            .key_data()
            .ed25519()
            .unwrap()
            .public
            .0
            .encode_hex()
    }

    pub(crate) fn prompt_sign_message(&self) -> Result<(String, String, String)> {
        let message = Input::<String>::with_theme(&ColorfulTheme::default())
            .allow_empty(false)
            .with_prompt("Input a message to sign")
            .interact_text()?;
        let message_bytes = message.as_bytes();
        let sig_ring = self.ring.sign(message_bytes).encode_hex();
        let sig_substrate = self.substrate.sign(message_bytes).encode_hex();

        Ok((message, sig_ring, sig_substrate))
    }
}

fn list_openssh_keys() -> Result<Vec<PathBuf>> {
    let mut results = Vec::new();

    if let Some(user_dir) = UserDirs::new() {
        let ssh_dir = user_dir.home_dir().join(".ssh");
        let ssh_files = read_dir(ssh_dir)?;

        for dir_entry in ssh_files.flatten() {
            let pathbuf = dir_entry.path();
            let filename = pathbuf.to_str().unwrap().to_owned();

            if filename.contains("authorized_keys")
                | filename.contains("config")
                | filename.contains("known_hosts")
            {
                continue;
            }

            results.push(pathbuf);
        }
    }

    Ok(results)
}

fn decide_ephemeral_key() -> Result<KeyPairSets> {
    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("No SSH keys found, generate ephemeral key")
        .interact()?
    {
        KeyPairSets::new()
    } else {
        Err(anyhow!("No key to proceed"))
    }
}
