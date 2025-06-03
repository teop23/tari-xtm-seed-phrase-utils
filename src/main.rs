use std::io::Write;

use anyhow::anyhow;
use keyring::Entry;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Credential {
    pub tari_seed_passphrase: Option<SafePassword>,
    pub monero_seed: Option<[u8; 32]>,
}

use seed_decoder::{
    cipher_seed::CipherSeed,
    mnemonic::{Mnemonic, MnemonicLanguage},
    SeedWords,
};
use tari_utilities::encoding::MBase58;
use tari_utilities::password::SafePassword;

fn get_passphrase_from_credential_manager() -> Option<SafePassword> {
    let service = "com.tari.universe";
    let username = "inner_wallet_credentials_mainnet";

    let entry = Entry::new(service, username).expect("Failed to access keyring entry");

    let secret = match entry.get_secret() {
        Ok(secret) => secret,
        Err(e) => {
            eprintln!("❌ Error getting secret: {:?}", e);
            std::process::exit(1);
        }
    };

    let credential: Credential = match serde_cbor::from_slice(&secret) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ Failed to deserialize credential: {:?}", e);
            std::process::exit(1);
        }
    };

    println!("Passphrase retrieved successfully!");
    credential.tari_seed_passphrase
}

fn get_encrypted_seed() -> Result<String, Box<dyn std::error::Error>> {
    let encrypted_base58 = get_user_input("Enter encrypted base58 seed: ");
    println!("Encrypted seed (base58): {}", encrypted_base58);
    Ok(encrypted_base58)
}

fn generate_seed_phrase() {
    let cipher_seed = CipherSeed::new();
    let mnemonic = match cipher_seed.to_mnemonic(MnemonicLanguage::English, None) {
        Ok(mnemonic) => mnemonic,
        Err(e) => {
            eprintln!("Failed to generate seed phrase: {}", e);
            return;
        }
    };

    let seed_phrase = mnemonic.join(" ").reveal().to_string();
    println!("Generated seed phrase: {}", seed_phrase);
    let should_encrypt = get_user_input("Do you want to encrypt this seed phrase? (y/n): ");
    match should_encrypt.to_lowercase().as_str() {
        "y" | "yes" => {
            let passphrase = get_user_input("Enter passphrase to encrypt the seed phrase: ");
            let safe_passphrase = if passphrase.is_empty() {
                eprintln!("❌ Passphrase cannot be empty. Please try again.");
                return;
            } else {
                Some(SafePassword::from(passphrase.clone()))
            };

            let encrypted_seed_words_base58: String =
                match cipher_seed.encipher(safe_passphrase.clone()) {
                    Ok(encrypted) => encrypted.to_monero_base58(),
                    Err(e) => {
                        eprintln!("Failed to encrypt seed phrase: {}", e);
                        return;
                    }
                };
            println!(
                "Encrypted seed phrase (base58): {:}",
                encrypted_seed_words_base58
            );
            test_decrypt_seed_phrase(mnemonic, &encrypted_seed_words_base58, safe_passphrase);
        }
        "n" | "no" => {
            println!("Seed phrase not encrypted.");
        }
        _ => {
            println!("Invalid input. Seed phrase not encrypted.");
        }
    }
}
fn decrypt_seed_phrase() {
    let seed_words_encrypted_base58 = match get_encrypted_seed() {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };
    let recover_passphrase = get_user_input(
        "Do you want to recover the passphrase from the credential manager? (y/n): ",
    );
    let passphrase =
        if recover_passphrase.to_lowercase() == "y" || recover_passphrase.to_lowercase() == "yes" {
            println!("Attempting to recover passphrase from credential manager...");
            get_passphrase_from_credential_manager()
        } else {
            let passphrase_input = get_user_input("Enter passphrase to decrypt the seed phrase: ");
            if passphrase_input.is_empty() {
                eprintln!("❌ Passphrase cannot be empty. Please try again.");
                return;
            }
            Some(SafePassword::from(passphrase_input))
        };

    if passphrase.is_none() {
        eprintln!("❌ No passphrase found in the credential manager. Unable to decrypt seed phrase");
        return;
    }

    println!("Attempting to decrypt seed phrase...");
    let seed_binary = Vec::<u8>::from_monero_base58(&seed_words_encrypted_base58)
        .map_err(|e| anyhow!(e.to_string()));
    match seed_binary {
        Ok(bytes) => {
            let cipher_seed = match CipherSeed::from_enciphered_bytes(&bytes, passphrase.clone()) {
                Ok(cipher_seed) => {
                    println!("Cipher seed decrypted successfully!");
                    cipher_seed
                }
                Err(e) => {
                    eprintln!("Failed to decrypt cipher seed: {}", e);
                    return;
                }
            };
            println!("Converting to seed phrase...");
            match cipher_seed.to_mnemonic(MnemonicLanguage::English, None) {
                Ok(mnemonic) => {
                    let seed_phrase: String = mnemonic.join(" ").reveal().to_string();
                    println!("Seed phrase: {}", seed_phrase);
                }
                Err(e) => {
                    eprintln!("Failed to decode mnemonic from bytes: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to decode seed binary from base58: {}", e);
            return;
        }
    }
}

fn test_decrypt_seed_phrase(
    mnemonic: SeedWords,
    encrypted_seed_words_base58: &str,
    passphrase: Option<SafePassword>,
) {
    println!("Testing decryption of seed phrase...");
    let seed_binary = Vec::<u8>::from_monero_base58(encrypted_seed_words_base58)
        .map_err(|e| anyhow!(e.to_string()));
    match seed_binary {
        Ok(bytes) => {
            let cipher_seed = match CipherSeed::from_enciphered_bytes(&bytes, passphrase.clone()) {
                Ok(cipher_seed) => {
                    println!("Cipher seed decrypted successfully!");
                    cipher_seed
                }
                Err(e) => {
                    eprintln!("Failed to decrypt cipher seed: {}", e);
                    return;
                }
            };
            println!("Checking if decrypted seed phrase matches the original...");
            match cipher_seed.to_mnemonic(MnemonicLanguage::English, None) {
                Ok(decoded_mnemonic) => {
                    let seed_phrase: String = decoded_mnemonic.join(" ").reveal().to_string();
                    if seed_phrase == mnemonic.join(" ").reveal().to_string() {
                        println!("✅ Seed phrase matches the original mnemonic.");
                    } else {
                        println!("❌ Seed phrase does not match the original mnemonic.");
                    }
                }
                Err(e) => {
                    eprintln!("Failed to decode mnemonic from bytes: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to decode seed binary from base58: {}", e);
        }
    }
}

fn test_seed_phrase_generation() {
    println!("Testing seed phrase generation...");
    println!("Generating 100 seed phrases and counting the first words...");
    let mut first_word_count = std::collections::HashMap::new();
    for i in 0..100 {
        let cipher_seed = CipherSeed::new();
        let mnemonic = match cipher_seed.to_mnemonic(MnemonicLanguage::English, None) {
            Ok(mnemonic) => mnemonic,
            Err(e) => {
                eprintln!("Failed to generate seed phrase: {}", e);
                continue;
            }
        };
        match mnemonic.get_word(0) {
            Ok(word) => {
                let word_owned = word.to_string();
                *first_word_count.entry(word_owned).or_insert(0) += 1;
                let stats: String = first_word_count
                    .iter()
                    .map(|(word, count)| format!("{}: {}", word, count))
                    .collect::<Vec<_>>()
                    .join(", ");
                print!(
                    "\rGenerated {} phrases with first word frequencies: {}",
                    i + 1,
                    stats
                );
                std::io::stdout().flush().unwrap();
            }
            Err(e) => {
                eprintln!("Failed to get first word: {}", e);
                continue;
            }
        }
    }
    println!("\nSeed phrase generation test completed.");
    let stats: String = first_word_count
        .iter()
        .map(|(word, count)| format!("{}: {}", word, count))
        .collect::<Vec<_>>()
        .join(", ");
    println!(
        "Final stats for first words in generated seed phrases: {}",
        stats
    );
    std::io::stdout().flush().unwrap();
}
fn main() {
    loop {
        println!("##################################");
        println!("##### Tari Seed Phrase Tools #####");
        println!("##################################");
        println!("");
        println!("What would you like to do?");
        println!("(G)enerate a new seed phrase");
        println!("(D)ecrypt an existing seed phrase");
        println!("(T)est seed phrase generation");
        println!("(E)xit");
        let choice = get_user_input("Enter your choice (G/D/T/E): ").to_uppercase();
        match choice.as_str() {
            "G" => {
                generate_seed_phrase();
            }
            "D" => {
                decrypt_seed_phrase();
            }
            "T" => {
                test_seed_phrase_generation();
            }
            "E" => {
                println!("Exiting...");
                break;
            }
            _ => {
                println!("Invalid choice. Please try again.");
            }
        }
        let _unused = get_user_input("Press Enter to continue...");
    }
}

fn get_user_input(prompt: &str) -> String {
    use std::io::{self, Write};
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}
