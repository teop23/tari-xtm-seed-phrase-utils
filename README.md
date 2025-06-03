A simple console tool for generating/decrypting seed phrases for [Tari/XTM](www.tari.com) wallets

## How To Use
### 1. Install Rust
##### Follow the tutorial on the Rust [website](https://www.rust-lang.org/tools/install)

### 2. Clone the project
Clone via git:
```
git clone https://github.com/teop23/tari-xtm-seed-phrase-utils.git
```
### 3. Navigate to the project directory
```
cd tari-xtm-seed-phrase-utils
```
### 4. Run using cargo
```
cargo run
```
## Notes: 
This tool attempts to decrypt your seed phrase by either using the passphrase you provided in the terminal, or by attempting to retrieve it from your operating system's credential manager. In no way, shape or form do the seed phrase or passphrase get stored, the seed phrase is only shown to you in the terminal as a means for you to copy it and restore your wallet. DO NOT SHARE YOUR SEED PHRASE, ENCRYPTED SEED PHRASE OR ENCRYPTION PASSPHRASE WITH ANYONE, INCLUDING THE AUTHOR OF THIS CODE

If enough people are interested and if the tari team checks and approves this source, binaries will be released for easier use

