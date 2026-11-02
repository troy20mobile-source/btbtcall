import os
import csv
import subprocess
import threading
import time
import requests
from datetime import datetime
from flask import Flask, jsonify
from dotenv import load_dotenv
from tqdm import tqdm

load_dotenv()

# ============================================================
# CONFIG
# ============================================================
PRIVATE_KEYS_PER_ITERATION = int(os.getenv("PRIVATE_KEYS_PER_ITERATION", 100000))
CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", 400000))
CLEAR_AFTER_CHECK = os.getenv("CLEAR_AFTER_CHECK", "true").lower() == "true"
SHOW_PROGRESS_BAR = os.getenv("SHOW_PROGRESS_BAR", "false").lower() == "true"

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
DATABASE_URL = os.getenv("DATABASE_URL")
PIXELDRAIN_TARGET_URL = os.getenv("PIXELDRAIN_TARGET_URL")

BASE_DIR = os.path.join(os.getcwd(), "data")
CSV_PATH = os.path.join(BASE_DIR, "Rust_btc_addresses.csv")
TARGET_FILE = os.path.join(BASE_DIR, "BTCtoMatch.txt")
FOUND_FOLDER = os.path.join(BASE_DIR, "found")

os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs(FOUND_FOLDER, exist_ok=True)

TOTAL_MATCHES = 0
app = Flask(__name__)


# ============================================================
# DOWNLOAD TARGET FILE (only once)
# ============================================================
def download_target_file():
    if os.path.exists(TARGET_FILE) and os.path.getsize(TARGET_FILE) > 1_000_000:
        size_mb = os.path.getsize(TARGET_FILE) / (1024 * 1024)
        print(f"✅ Target file already exists ({size_mb:.1f} MB)")
        return

    print("⬇️  Downloading BTCtoMatch.txt from Pixeldrain...")
    try:
        with requests.get(PIXELDRAIN_TARGET_URL, stream=True, timeout=180) as r:
            r.raise_for_status()
            total = int(r.headers.get("content-length", 0))
            with open(TARGET_FILE, "wb") as f, tqdm(
                total=total, unit="B", unit_scale=True, desc="Downloading"
            ) as pbar:
                for chunk in r.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        f.write(chunk)
                        pbar.update(len(chunk))
        size_mb = os.path.getsize(TARGET_FILE) / (1024 * 1024)
        print(f"✅ Download complete: {size_mb:.1f} MB")
    except Exception as e:
        print(f"❌ Failed to download target file: {e}")
        raise


# ============================================================
# TELEGRAM
# ============================================================
def send_telegram(message: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        requests.post(url, json=payload, timeout=15)
        print("📨 Telegram notification sent")
    except Exception as e:
        print(f"❌ Telegram failed: {e}")


# ============================================================
# NEON POSTGRES
# ============================================================
def save_match_to_db(address: str, key_line: str):
    if not DATABASE_URL:
        return
    try:
        import psycopg2
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS btc_matches (
                id SERIAL PRIMARY KEY,
                address TEXT,
                key_line TEXT,
                found_at TIMESTAMP DEFAULT NOW()
            )
        """)
        cur.execute(
            "INSERT INTO btc_matches (address, key_line) VALUES (%s, %s)",
            (address, key_line),
        )
        conn.commit()
        cur.close()
        conn.close()
        print("💾 Saved to Neon Postgres")
    except Exception as e:
        print(f"❌ Postgres error: {e}")


# ============================================================
# RUST GENERATOR
# ============================================================
def run_generator(num_private_keys: int):
    print("\n" + "=" * 70)
    print(f"STEP 1: GENERATING {num_private_keys:,} private keys")
    print("=" * 70)

    rust_source = r'''
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha2::{Sha256, Digest};
use bitcoin_hashes::ripemd160;
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashSet;
use std::fs::File;
use std::io::BufWriter;
use csv::Writer;
use num_bigint::BigUint;
use num_traits::One;
use bech32::{ToBase32, Variant};

fn parse_hex_to_biguint(s: &str) -> Option<BigUint> {
    let s = if s.starts_with("0x") { &s[2..] } else { s };
    BigUint::parse_bytes(s.as_bytes(), 16)
}
fn biguint_to_32_bytes(n: &BigUint) -> Option<[u8; 32]> {
    let bytes = n.to_bytes_be();
    if bytes.len() > 32 { return None; }
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);
    Some(padded)
}
fn sample_in_range(start: &BigUint, end: &BigUint, rng: &mut OsRng) -> BigUint {
    let range = end - start + BigUint::one();
    let bits = range.bits();
    let byte_len = ((bits + 7) / 8) as usize;
    loop {
        let mut buf = vec![0u8; byte_len];
        rng.fill_bytes(&mut buf);
        let excess = (byte_len * 8) - bits as usize;
        if excess > 0 {
            let mask = 0xFFu8 >> excess;
            buf[0] &= mask;
        }
        let candidate = BigUint::from_bytes_be(&buf);
        if candidate < range {
            return start + candidate;
        }
    }
}
fn base58check(payload: &[u8]) -> String {
    let checksum = Sha256::digest(&Sha256::digest(payload));
    let mut data = Vec::with_capacity(payload.len() + 4);
    data.extend_from_slice(payload);
    data.extend_from_slice(&checksum[..4]);
    bs58::encode(data).into_string()
}
fn p2pkh_address(pubkey_bytes: &[u8]) -> String {
    let sha = Sha256::digest(pubkey_bytes);
    let rip = ripemd160::Hash::hash(&sha);
    let hash_bytes: &[u8] = rip.as_ref();
    let mut payload = Vec::with_capacity(21);
    payload.push(0x00);
    payload.extend_from_slice(hash_bytes);
    base58check(&payload)
}
fn p2sh_p2wpkh_address(pubkey_bytes: &[u8]) -> String {
    let sha = Sha256::digest(pubkey_bytes);
    let rip = ripemd160::Hash::hash(&sha);
    let hash_bytes: &[u8] = rip.as_ref();
    let mut redeem = Vec::with_capacity(22);
    redeem.push(0x00);
    redeem.push(0x14);
    redeem.extend_from_slice(hash_bytes);
    let redeem_sha = Sha256::digest(&redeem);
    let redeem_rip = ripemd160::Hash::hash(&redeem_sha);
    let redeem_hash: &[u8] = redeem_rip.as_ref();
    let mut payload = Vec::with_capacity(21);
    payload.push(0x05);
    payload.extend_from_slice(redeem_hash);
    base58check(&payload)
}
fn p2wpkh_address(pubkey_bytes: &[u8]) -> String {
    use bech32::u5;
    let sha = Sha256::digest(pubkey_bytes);
    let rip = ripemd160::Hash::hash(&sha);
    let hash_bytes: &[u8] = rip.as_ref();
    let mut data: Vec<u5> = Vec::with_capacity(1 + 32);
    data.push(u5::try_from_u8(0).expect("witness v0 fits in u5"));
    data.extend_from_slice(&hash_bytes.to_base32());
    bech32::encode("bc", data, Variant::Bech32).expect("bech32 encode failed")
}
fn main() {
    const RANGE_START: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const RANGE_END: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let args: Vec<String> = std::env::args().collect();
    let limit: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(100000);
    let output_path: String = args.get(2).cloned().unwrap_or_else(|| "Rust_btc_addresses.csv".to_string());
    let start = parse_hex_to_biguint(RANGE_START).expect("Invalid start");
    let end = parse_hex_to_biguint(RANGE_END).expect("Invalid end");
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let mut seen: HashSet<[u8; 32]> = HashSet::with_capacity(limit + 16);
    let file = File::create(&output_path).expect("File create failed");
    let mut writer = Writer::from_writer(BufWriter::new(file));
    writer.write_record(&["private_key_hex", "compressed_btc_address"]).unwrap();
    let mut keys_done = 0usize;
    let mut rows_written = 0usize;
    let mut attempts = 0usize;
    let max_attempts = limit.saturating_mul(100).max(1_000_000);
    while keys_done < limit {
        attempts += 1;
        if attempts > max_attempts { break; }
        let candidate = sample_in_range(&start, &end, &mut rng);
        let priv_bytes = match biguint_to_32_bytes(&candidate) {
            Some(b) => b,
            None => continue,
        };
        if !seen.insert(priv_bytes) { continue; }
        let secret = match SecretKey::from_slice(&priv_bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let pub_compressed = PublicKey::from_secret_key(&secp, &secret).serialize();
        let pub_uncompressed = PublicKey::from_secret_key(&secp, &secret).serialize_uncompressed();
        let pk_hex = hex::encode(priv_bytes);
        writer.write_record(&[pk_hex.as_str(), p2pkh_address(&pub_uncompressed).as_str()]).unwrap();
        rows_written += 1;
        writer.write_record(&[pk_hex.as_str(), p2pkh_address(&pub_compressed).as_str()]).unwrap();
        rows_written += 1;
        writer.write_record(&[pk_hex.as_str(), p2sh_p2wpkh_address(&pub_compressed).as_str()]).unwrap();
        rows_written += 1;
        writer.write_record(&[pk_hex.as_str(), p2wpkh_address(&pub_compressed).as_str()]).unwrap();
        rows_written += 1;
        keys_done += 1;
        if keys_done % 25000 == 0 {
            eprintln!("  ⛏  {} keys → {} rows", keys_done, rows_written);
        }
    }
    writer.flush().expect("Flush failed");
    println!("✅ Generator finished: {} keys → {} rows", keys_done, rows_written);
}
'''

    script = f'''
set -e
mkdir -p "$(dirname "{CSV_PATH}")"
if ! command -v cargo &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi
source "$HOME/.cargo/env" || true
mkdir -p btc_range/src
cat > btc_range/Cargo.toml << 'EOF'
[package]
name = "btc_range"
version = "0.1.0"
edition = "2021"
[dependencies]
secp256k1 = "0.21"
sha2 = "0.10"
bitcoin_hashes = "0.16"
hex = "0.4"
bs58 = "0.4"
rand = "0.8"
csv = "1.2"
num-bigint = "0.4"
num-traits = "0.2"
bech32 = "0.9"
EOF
cat > btc_range/src/main.rs << 'RUST_EOF'
{rust_source}
RUST_EOF
cd btc_range
cargo build --release
./target/release/btc_range {num_private_keys} "{CSV_PATH}"
'''
    process = subprocess.Popen(
        ["bash", "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    for line in process.stdout:
        print(line, end="")
    process.wait()
    if process.returncode != 0:
        raise RuntimeError(f"Generator failed with code {process.returncode}")


# ============================================================
# OPTIMIZED CHECK (does NOT load full target file into memory)
# ============================================================
def check_matches():
    global TOTAL_MATCHES

    print("\n" + "=" * 70)
    print("STEP 2: CHECKING MATCHES (memory efficient)")
    print("=" * 70)

    if not os.path.exists(CSV_PATH):
        raise FileNotFoundError("Generated CSV not found")

    # 1. Load only the generated addresses into a set (small)
    generated = {}
    with open(CSV_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            addr = row["compressed_btc_address"].strip().lower()
            key = row["private_key_hex"].strip()
            generated[addr] = f"{addr} , {key}"

    print(f"📦 Loaded {len(generated):,} generated addresses into memory")

    # 2. Stream through the large target file line by line
    matches_found = 0
    with open(TARGET_FILE, "r", encoding="utf-8") as f:
        for line in f:
            addr = line.strip().lower()
            if not addr:
                continue
            if addr in generated:
                matches_found += 1
                TOTAL_MATCHES += 1
                key_line = generated[addr]

                # Save locally
                with open(os.path.join(FOUND_FOLDER, "Bfound_match.txt"), "a", encoding="utf-8") as out:
                    out.write(key_line + "\n")

                # Telegram
                msg = (
                    f"🎯 <b>BTC MATCH FOUND!</b>\n\n"
                    f"<b>Address:</b> <code>{addr}</code>\n"
                    f"<b>Key line:</b>\n<code>{key_line}</code>\n\n"
                    f"Total matches this run: <b>{TOTAL_MATCHES}</b>\n"
                    f"Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"
                )
                send_telegram(msg)

                # Neon
                save_match_to_db(addr, key_line)

                print("\n" + "🎯" * 25)
                print(f"MATCH #{TOTAL_MATCHES}")
                print(f"Address : {addr}")
                print(f"Key     : {key_line}")
                print("🎯" * 25 + "\n")

    print(f"✅ Check complete → {matches_found} match(es) in this batch")

    # Clean up big CSV
    if os.path.exists(CSV_PATH):
        os.remove(CSV_PATH)
        print("🧹 Generated CSV deleted")


# ============================================================
# BACKGROUND WORKER
# ============================================================
def worker():
    global TOTAL_MATCHES
    iteration = 0

    download_target_file()

    while True:
        iteration += 1
        print("\n" + "#" * 70)
        print(f"# ITERATION {iteration}  |  Total matches so far: {TOTAL_MATCHES}")
        print("#" * 70)

        try:
            run_generator(PRIVATE_KEYS_PER_ITERATION)
            check_matches()
            print(f"\n✅ Iteration {iteration} finished")
        except Exception as e:
            error_msg = str(e)[:800]
            print(f"❌ Iteration failed: {error_msg}")
            send_telegram(f"⚠️ <b>Pipeline error</b> on iteration {iteration}:\n<code>{error_msg}</code>")
            time.sleep(60)

        time.sleep(3)


# ============================================================
# FLASK
# ============================================================
@app.route("/health")
def health():
    return jsonify({"status": "ok", "matches": TOTAL_MATCHES}), 200


@app.route("/")
def home():
    return jsonify({
        "service": "BTC Generator + Checker (Optimized)",
        "matches_found": TOTAL_MATCHES,
        "health": "/health"
    })


if __name__ == "__main__":
    print("╔" + "═" * 68 + "╗")
    print("║" + " BTC PIPELINE — OPTIMIZED (Low Memory) ".center(68) + "║")
    print("╠" + "═" * 68 + "╣")
    print(f"║  Keys per iteration : {PRIVATE_KEYS_PER_ITERATION:,}")
    print(f"║  Telegram           : {'✅' if TELEGRAM_BOT_TOKEN else '❌'}")
    print(f"║  Neon Postgres      : {'✅' if DATABASE_URL else '❌'}")
    print(f"║  Pixeldrain Target  : {'✅' if PIXELDRAIN_TARGET_URL else '❌'}")
    print("╚" + "═" * 68 + "╝")

    t = threading.Thread(target=worker, daemon=True)
    t.start()

    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
