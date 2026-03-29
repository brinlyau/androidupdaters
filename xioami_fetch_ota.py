#!/usr/bin/env python3
"""
Xiaomi OTA Fetcher — POCO X8 Pro Max (dash / dash_global)

Queries Xiaomi's MIOTA v3 endpoint for available OTA packages and downloads them.
Uses the same AES-128-CBC encrypted protocol as the real Updater.apk.

Usage:
    ./fetch_ota.py                          # check for updates (default: current version)
    ./fetch_ota.py --current OS3.0.2.0.WPLMIXM   # check from a specific version
    ./fetch_ota.py --download               # check and download if available
    ./fetch_ota.py --device dash_global     # override device codename
    ./fetch_ota.py --cota                   # check carrier OTA (COTA) packages
    ./fetch_ota.py --list-versions          # query known ROM types (stable/dev/beta)
    ./fetch_ota.py --json                   # dump raw server response
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlencode

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding
except ImportError:
    sys.exit("Missing dependency: pip install cryptography")


# ---------------------------------------------------------------------------
# AES-128-CBC encryption — matches com.android.updater (Updater.apk v9.1.7)
#
# Key: b"miuiotavalided11"  (from res/values/strings.xml "e_key" + hardcoded prefix)
# IV:  b"0102030405060708"  (from n1.AbstractC0575b.a())
# Mode: AES/CBC/PKCS5Padding, Base64 flag 2 = URL_SAFE
#
#
# ---------------------------------------------------------------------------
DEFAULT_KEY = b"miuiotavalided11"
DEFAULT_IV = b"0102030405060708"


def aes_encrypt(plaintext: str, key: bytes = DEFAULT_KEY) -> str:
    """AES/CBC/PKCS7 encrypt, return URL-safe Base64."""
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(DEFAULT_IV))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return base64.urlsafe_b64encode(ct).decode()


def aes_decrypt(ciphertext_b64: str, key: bytes = DEFAULT_KEY) -> str:
    """AES/CBC/PKCS7 decrypt from URL-safe Base64."""
    ct = base64.urlsafe_b64decode(ciphertext_b64)
    cipher = Cipher(algorithms.AES(key), modes.CBC(DEFAULT_IV))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()


# ---------------------------------------------------------------------------
# Device defaults — extracted from firmware build.prop files
# ---------------------------------------------------------------------------
DEFAULTS = {
    "device": "dash_global",
    "version": "OS3.0.3.0.WPLMIXM",
    "miui_ui_version": "816",
    "os_incremental": "OS3.0.3.0.WPLMIXM",
    "os_version_name": "3.0.3.0.WPLMIXM",
    "android_version": "16",
    "sdk": "36",
    "board": "dash",
    "product_name": "missi",
    "region": "GLOBAL",
    "carrier": "GLOBAL",
    "brand": "POCO",
    "model": "2602BPC18G",
    "market_name": "POCO X8 Pro Max",
}

MIOTA_INTL = "https://update.intl.miui.com"
MIOTA_CN = "https://update.miui.com"
MIOTA_V3_PATH = "/updates/miotaV3.php"
COTA_PATH = "/api/v1/cota"

ROM_TYPE_STABLE = "1"
ROM_TYPE_DEV = "0"
ROM_TYPE_BETA = "2"
ROM_TYPE_OS_BETA = "7"


def generate_guid():
    guid_file = Path(__file__).parent / ".ota_guid"
    if guid_file.exists():
        return guid_file.read_text().strip()
    g = str(uuid.uuid4())
    guid_file.write_text(g)
    return g


def version_to_v_param(version):
    """Convert version to the 'v' parameter format.
    HyperOS versions (OS1.x) use V816 prefix per reference implementation."""
    if version.startswith("OS1"):
        return "miui-" + version.replace("OS1", "V816", 1)
    return "miui-" + version


def build_miota_json(device, current_version, rom_type, region, carrier,
                     android_ver, board, product, sdk, miui_ui, os_inc,
                     os_ver_name, brand):
    """Build the JSON body for MIOTA v3.
    Uses the minimal proven format (id/c/d/f/ov/l/r/v) that works for all
    devices, plus optional extra fields for the target device."""
    is_global = "_global" in device
    data = {
        "id": "",
        "c": android_ver,
        "d": device,
        "f": str(rom_type),
        "ov": current_version,
        "l": "en_US" if is_global else "zh_CN",
        "r": "GL" if is_global else "CN",
        "v": version_to_v_param(current_version),
    }
    # Include extended fields only when querying for the default device,
    # since they contain device-specific build.prop values
    if device == DEFAULTS["device"]:
        data.update({
            "bv": miui_ui,
            "sv": os_inc,
            "obv": os_ver_name,
            "pb": brand,
            "g": generate_guid(),
            "pn": product,
            "b": current_version,
            "n": carrier,
            "a": "0",
            "isR": "1",
            "unlock": "0",
            "sdk": str(sdk),
            "options": {
                "zone": region,
                "ab": "1",
                "previewPlan": "0",
            },
        })
    return json.dumps(data, separators=(",", ":"))


def build_cota_json(device, current_version, rom_type, region, android_ver,
                    miui_ui, os_inc, mcc="", mnc=""):
    data = {
        "c": android_ver.split(".")[0],
        "d": device,
        "g": generate_guid(),
        "b": current_version,
        "f": str(rom_type),
        "r": region,
        "bv": miui_ui,
        "sv": os_inc,
    }
    if mcc:
        data["mcc"] = mcc
    if mnc:
        data["mnc"] = mnc
    return json.dumps(data, separators=(",", ":"))


def query_miota(server, json_body, key=DEFAULT_KEY, timeout=30):
    """POST to MIOTA v3: body = q=AES(json)&t=token&s=version."""
    url = server + MIOTA_V3_PATH
    post_data = {
        "q": aes_encrypt(json_body, key),
        "t": "",
        "s": "1",
    }
    resp = requests.post(url, data=post_data, timeout=timeout)
    resp.raise_for_status()

    raw = resp.text.strip()
    if not raw:
        return {}
    # response may be plaintext JSON or encrypted
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    try:
        return json.loads(aes_decrypt(raw, key))
    except Exception as e:
        print(f"  Decrypt failed ({e}), raw[0:200]: {raw[:200]}")
        return {"_raw": raw}


def query_cota(server, json_body, key=DEFAULT_KEY, timeout=30):
    url = server + COTA_PATH
    ts = str(int(time.time() * 1000))
    nonce = hashlib.sha1((generate_guid() + ts).encode()).hexdigest()[:16]
    full_url = f"{url}?{urlencode({'ts': ts, 'n': nonce, 'sid': '1'})}"

    post_data = {
        "q": aes_encrypt(json_body, key),
        "t": "",
        "s": "1",
    }
    resp = requests.post(full_url, data=post_data, timeout=timeout)
    resp.raise_for_status()

    raw = resp.text.strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    try:
        return json.loads(aes_decrypt(raw, key))
    except Exception:
        return {"_raw": raw}


def print_rom_info(label, rom):
    if not rom:
        return
    print(f"\n  [{label}]")
    for key in ("version", "bigversion", "osbigversion", "codebase", "branch",
                "filename", "filesize", "md5", "type", "device", "name"):
        val = rom.get(key)
        if val:
            print(f"    {key:20s}: {val}")
    desc = rom.get("description") or rom.get("descriptionUrl")
    if desc:
        print(f"    {'description':20s}: {desc[:200]}{'...' if len(desc) > 200 else ''}")


def download_rom(rom, mirror_list, out_dir):
    filename = rom.get("filename")
    if not filename:
        print("  No filename in ROM info, cannot download.")
        return None

    md5_expected = rom.get("md5", "")
    filesize = rom.get("filesize", "?")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, os.path.basename(filename))

    if os.path.exists(out_path) and md5_expected:
        h = hashlib.md5()
        with open(out_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() == md5_expected:
            print(f"  Already downloaded and verified: {out_path}")
            return out_path
        print(f"  File exists but MD5 mismatch, re-downloading...")

    mirrors = mirror_list or [
        "https://ultimateota.d.miui.com",
        "https://bigota.d.miui.com",
    ]

    for mirror in mirrors:
        url = mirror.rstrip("/") + "/" + filename.lstrip("/")
        print(f"  Downloading: {url}")
        print(f"  Size: {filesize}")
        try:
            resp = requests.get(url, stream=True, timeout=30)
            if resp.status_code == 404:
                print(f"  404 on {mirror}, trying next...")
                continue
            resp.raise_for_status()

            total = int(resp.headers.get("content-length", 0))
            downloaded = 0
            h = hashlib.md5()

            with open(out_path + ".part", "wb") as f:
                for chunk in resp.iter_content(chunk_size=1 << 20):
                    f.write(chunk)
                    h.update(chunk)
                    downloaded += len(chunk)
                    if total:
                        pct = downloaded * 100 // total
                        bar = "#" * (pct // 2) + "-" * (50 - pct // 2)
                        print(f"\r  [{bar}] {pct}% ({downloaded >> 20}/{total >> 20} MB)",
                              end="", flush=True)

            print()

            if md5_expected and h.hexdigest() != md5_expected:
                print(f"  MD5 MISMATCH! Expected {md5_expected}, got {h.hexdigest()}")
                os.unlink(out_path + ".part")
                continue

            os.rename(out_path + ".part", out_path)
            print(f"  Saved: {out_path}")
            if md5_expected:
                print(f"  MD5 verified: {md5_expected}")
            return out_path

        except requests.RequestException as e:
            print(f"  Mirror {mirror} failed: {e}")
            continue

    print("  All mirrors exhausted, download failed.")
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Xiaomi OTA Fetcher — POCO X8 Pro Max (dash)")
    parser.add_argument("--device", default=DEFAULTS["device"],
                        help=f"Device codename (default: {DEFAULTS['device']})")
    parser.add_argument("--current", default=DEFAULTS["version"],
                        help=f"Current ROM version (default: {DEFAULTS['version']})")
    parser.add_argument("--region", default=DEFAULTS["region"],
                        help=f"Region (default: {DEFAULTS['region']})")
    parser.add_argument("--carrier", default=DEFAULTS["carrier"],
                        help=f"Carrier (default: {DEFAULTS['carrier']})")
    parser.add_argument("--android", default=DEFAULTS["android_version"],
                        help=f"Android version (default: {DEFAULTS['android_version']})")
    parser.add_argument("--rom-type", choices=["stable", "dev", "beta", "os_beta"],
                        default="stable", help="ROM type to query (default: stable)")
    parser.add_argument("--server", choices=["intl", "cn"], default="intl",
                        help="Server region (default: intl)")
    parser.add_argument("--download", action="store_true",
                        help="Download the OTA package if available")
    parser.add_argument("--out-dir", default="./ota_downloads",
                        help="Output directory for downloads")
    parser.add_argument("--cota", action="store_true",
                        help="Query COTA (carrier OTA) instead of MIOTA")
    parser.add_argument("--mcc", default="", help="Mobile Country Code for COTA")
    parser.add_argument("--mnc", default="", help="Mobile Network Code for COTA")
    parser.add_argument("--list-versions", action="store_true",
                        help="Query all ROM types (stable/dev/beta/os_beta)")
    parser.add_argument("--json", action="store_true",
                        help="Dump raw JSON response")

    args = parser.parse_args()

    server = MIOTA_INTL if args.server == "intl" else MIOTA_CN
    rom_type_map = {
        "stable": ROM_TYPE_STABLE,
        "dev": ROM_TYPE_DEV,
        "beta": ROM_TYPE_BETA,
        "os_beta": ROM_TYPE_OS_BETA,
    }

    print(f"Xiaomi OTA Fetcher")
    print(f"  Device:  {args.device} ({DEFAULTS['market_name']})")
    print(f"  Current: {args.current}")
    print(f"  Region:  {args.region}")
    print(f"  Server:  {server}")

    def do_query(rtype_flag):
        json_body = build_miota_json(
            args.device, args.current, rtype_flag, args.region, args.carrier,
            args.android, DEFAULTS["board"], DEFAULTS["product_name"],
            DEFAULTS["sdk"], DEFAULTS["miui_ui_version"],
            DEFAULTS["os_incremental"], DEFAULTS["os_version_name"],
            DEFAULTS["brand"],
        )
        try:
            return query_miota(server, json_body)
        except Exception as e:
            print(f"  Error: {e}")
            return None

    # --list-versions
    if args.list_versions:
        for rtype_name, rtype_flag in rom_type_map.items():
            print(f"\n{'='*60}")
            print(f"Querying: {rtype_name} (f={rtype_flag})")
            print(f"{'='*60}")
            data = do_query(rtype_flag)
            if data is None:
                continue
            if args.json:
                print(json.dumps(data, indent=2, ensure_ascii=False))
            else:
                print(f"  AuthResult: {data.get('AuthResult', 'N/A')}")
                print(f"  UserLevel:  {data.get('UserLevel', 'N/A')}")
                print_rom_info("LatestRom", data.get("LatestRom"))
                print_rom_info("IncrementRom", data.get("IncrementRom"))
                print_rom_info("CrossRom", data.get("CrossRom"))
                mirrors = data.get("MirrorList", [])
                if mirrors:
                    print(f"\n  Mirrors: {', '.join(mirrors[:3])}")
                if not data.get("LatestRom") and not data.get("IncrementRom"):
                    print("  (no update available)")
        return

    # --cota
    if args.cota:
        print(f"\nQuerying COTA...")
        json_body = build_cota_json(
            args.device, args.current, rom_type_map[args.rom_type], args.region,
            args.android, DEFAULTS["miui_ui_version"], DEFAULTS["os_incremental"],
            args.mcc, args.mnc,
        )
        try:
            data = query_cota(server, json_body)
        except Exception as e:
            print(f"  Error: {e}")
            return

        if args.json:
            print(json.dumps(data, indent=2, ensure_ascii=False))
            return

        code = data.get("code")
        print(f"  Response code: {code}")
        d = data.get("data", {})
        if isinstance(d, str):
            try:
                d = json.loads(aes_decrypt(d))
            except Exception:
                print(f"  Encrypted response (needs device/account key to decrypt)")
                print(f"  Raw: {d[:120]}...")
                return
        if isinstance(d, dict):
            print(f"  Carrier: {d.get('carrierName', 'N/A')}")
            print(f"  SPN: {d.get('spn', 'N/A')}")
            files = d.get("latestFiles", [])
            mirrors = d.get("mirrorList", [])
            for f in files:
                print(f"\n  [{f.get('module', '?')}]")
                print(f"    Package:  {f.get('pkgName', 'N/A')}")
                print(f"    Version:  {f.get('verName', 'N/A')} (code {f.get('verCode', '?')})")
                print(f"    Size:     {f.get('fileSize', 'N/A')}")
                print(f"    MD5:      {f.get('md5', 'N/A')}")
                print(f"    URL path: {f.get('urlString', 'N/A')}")
                if args.download and f.get("urlString"):
                    for mirror in (mirrors or ["https://bigota.d.miui.com"]):
                        url = mirror.rstrip("/") + "/" + f["urlString"].lstrip("/")
                        print(f"    Full URL: {url}")
        return

    # Default: single ROM type query
    rom_flag = rom_type_map[args.rom_type]
    print(f"\nQuerying {args.rom_type} ROM (f={rom_flag})...\n")

    data = do_query(rom_flag)
    if data is None:
        sys.exit(1)

    if args.json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return

    if "_raw" in data:
        print(f"  Could not parse response. Raw: {data['_raw'][:300]}")
        return

    print(f"  AuthResult: {data.get('AuthResult', 'N/A')}")
    print(f"  UserLevel:  {data.get('UserLevel', 'N/A')}")

    latest = data.get("LatestRom")
    incremental = data.get("IncrementRom")
    cross = data.get("CrossRom")
    mirrors = data.get("MirrorList", [])

    print_rom_info("LatestRom (full)", latest)
    print_rom_info("IncrementRom (delta)", incremental)
    print_rom_info("CrossRom", cross)

    if mirrors:
        print(f"\n  Mirrors: {', '.join(mirrors[:3])}")

    if not latest and not incremental:
        print("\n  No update available for this configuration.")
        print("  Try --rom-type dev/beta, --list-versions, or a different --current version.")
        return

    if args.download:
        target = incremental or latest
        label = "incremental" if incremental else "full"
        print(f"\n  Downloading {label} package...")
        result = download_rom(target, mirrors, args.out_dir)
        if result:
            print(f"\n  Done! Package saved to: {result}")
        else:
            print(f"\n  Download failed.")
            sys.exit(1)
    else:
        print(f"\n  Use --download to fetch the package.")


if __name__ == "__main__":
    main()
