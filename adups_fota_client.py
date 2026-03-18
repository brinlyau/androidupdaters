#!/usr/bin/env python3
"""
Adups FOTA Client for OUKITEL C62
Reverse-engineered from com.oukitel.update (FotaApp v5.30)

Checks for firmware updates on the Adups FOTA server and downloads them.
Device parameters are extracted from the firmware's build.prop.

Usage:
    python3 adups_fota_client.py check [--imei IMEI]
    python3 adups_fota_client.py download [--imei IMEI] [-o OUTPUT]
    python3 adups_fota_client.py check-full [--imei IMEI]
"""

import argparse
import hashlib
import io
import json
import os
import random
import struct
import sys
import time
from datetime import datetime
from urllib.parse import urljoin

import requests


# ---------------------------------------------------------------------------
# Server configuration (from n1.b / MyApplication)
# ---------------------------------------------------------------------------
SERVERS = [
    "https://fota5p.adups.com",
    "https://fota5p.adups.cn",
]
ACTIVATION_URL = "https://fruet.adups.com/euft/redsecon"
REPORT_STATUS_URL = "https://fruet.adups.com/euft/repsta"

API_BASE = "/otainter-5.0/fota5/"
ENDPOINT_CHECK_DELTA = API_BASE + "detectSchedule.do"
ENDPOINT_CHECK_FULL = API_BASE + "fullDetectSchedule.do"
ENDPOINT_REPORT = API_BASE + "submitReport.do"
ENDPOINT_FCM_REPORT = API_BASE + "fcmReport.do"


# ---------------------------------------------------------------------------
# Device profile (from build.prop of OUKITEL_C62_172E_EEA_V03_20260313)
# ---------------------------------------------------------------------------
DEVICE = {
    "ro.fota.oem": "jezehuk_Sprd_16.0",
    "ro.fota.device": "C62_A16",
    "ro.fota.version": "OUKITEL_C62_172E_EEA_V03_20260313",
    "ro.fota.platform": "Sprd_15.0",
    "ro.fota.type": "phone",
    "ro.fota.id": "imei",
    "ro.fota.language": "en-US",
    "ro.product.model": "C62",
    "ro.product.brand": "OUKITEL",
    "ro.product.name": "C62_A15_EEA",
    "ro.product.device": "C62",
    "ro.product.board": "ums9230_6h10",
    "ro.product.manufacturer": "OUKITEL",
    "ro.product.platform": "",
    "ro.product.product": "",
    "ro.operator.optr": "",
    "ro.build.version.sdk": "36",
    "ro.build.version.release": "16",
    "ro.build.display.id": "OUKITEL_C62_172E_EEA_V03_20260313",
}

APP_VERSION = "5.30.0.221777.006_2025-04-14 12:15"
APP_CODE = "216"
SEND_ID = "1075259712158"


# ---------------------------------------------------------------------------
# Encryption: v1.f.j() — custom XOR + rotate cipher
# ---------------------------------------------------------------------------
def encrypt_params(plaintext: str) -> str:
    """
    Reimplements v1.f.j(): encrypts the query-string params.

    Format of the output byte stream:
      [1 byte header]  [padding bytes]  [rotated key]  [XOR'd ciphertext]

    Header byte = (random_high_nibble << 4) | key_length
    Padding = random_high_nibble bytes (first byte = 0x08, rest = 0x00)
    Key = key_length random bytes, each rotated left by 3 bits before output
    Ciphertext = plaintext XOR'd with key (repeating)

    Result is hex-encoded (uppercase).
    """
    data = plaintext.encode("utf-8")

    # Random parameters matching the Java ranges
    high_nibble = random.randint(0, 14)        # (int)(Math.random() * 15)
    key_len = random.randint(3, 14)            # (int)(Math.random() * 12) + 3

    # Generate random key
    key = bytes(random.randint(0, 254) for _ in range(key_len))

    # Header byte
    header = (high_nibble << 4) | key_len

    buf = io.BytesIO()
    buf.write(struct.pack("B", header))

    # Padding
    if high_nibble > 0:
        padding = bytearray(high_nibble)
        padding[0] = 0x08
        buf.write(bytes(padding))

    # Rotated key: each byte rotated left by 3 within 8 bits
    rotated_key = bytes(((b << 3) | (b >> 5)) & 0xFF for b in key)
    buf.write(rotated_key)

    # XOR ciphertext
    cipher = bytearray(len(data))
    ki = 0
    for i in range(len(data)):
        cipher[i] = (data[i] & 0xFF) ^ (key[ki] & 0xFF)
        ki += 1
        if ki == key_len:
            ki = 0
    buf.write(bytes(cipher))

    return buf.getvalue().hex().upper()


def sha256_hex(data: str) -> str:
    """SHA-256 of a string, returned as lowercase hex (v1.f.p)."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# MID generation (v1.i) — timestamp-based device ID
# ---------------------------------------------------------------------------
def generate_mid() -> str:
    """
    Generate a MID the same way the app does: sync time from a URL,
    format as yyyyMMddHHmmss, append 2 random letters + 4 random digits.
    """
    ts = datetime.now().strftime("%Y%m%d%H%M%S")
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    suffix = "".join(random.choice(letters) for _ in range(2))
    digits = str(random.randint(1000, 9999))
    return ts + suffix + digits


# ---------------------------------------------------------------------------
# Project string (v1.c.F) — device fingerprint for server
# ---------------------------------------------------------------------------
def build_project() -> str:
    """
    Builds the 'project' param: oem_device_language_carrier
    From v1.c.F():
      oem = ro.fota.oem  (underscores → $)
      device = ro.fota.device  (underscores → $)
      language = ro.fota.language
      carrier = based on ro.operator.optr (OP01→CMCC, OP02→CU, else "other")
    """
    def escape(s):
        return s.replace("_", "$")

    oem = escape(DEVICE["ro.fota.oem"]) if DEVICE["ro.fota.oem"] else "unknownoem"
    dev = escape(DEVICE["ro.fota.device"]) if DEVICE["ro.fota.device"] else "unknownproduct"
    lang = escape(DEVICE.get("ro.fota.language", "en"))

    optr = escape(DEVICE.get("ro.operator.optr", ""))
    if optr.upper() == "OP01":
        carrier = "CMCC"
    elif optr.upper() == "OP02":
        carrier = "CU"
    else:
        carrier = "other"

    return f"{oem}_{dev}_{lang}_{carrier}"


def build_devicesinfo_ext() -> str:
    """
    v1.c.i(): model_brand_name_device_board_manufacturer_platform_product
    """
    def escape(s):
        return s.replace("_", "$")

    parts = [
        DEVICE["ro.product.model"],
        DEVICE["ro.product.brand"],
        DEVICE["ro.product.name"],
        DEVICE["ro.product.device"],
        DEVICE["ro.product.board"],
        DEVICE["ro.product.manufacturer"],
        DEVICE.get("ro.product.platform", ""),
        DEVICE.get("ro.product.product", ""),
    ]
    return "_".join(escape(p) for p in parts)


# ---------------------------------------------------------------------------
# Build request parameters
# ---------------------------------------------------------------------------
def build_check_params(imei: str, mid: str, query_type: int = 1) -> dict:
    """
    Build the parameter map for detectSchedule.do / fullDetectSchedule.do.

    Combines t1.c.a() base params + t1.c.e() extended params.
    query_type: 1 = scheduled auto-check, 2 = manual user check
    """
    resolution = "1080#2400"  # FHD+ from firmware BMP filename
    fingerprint = (
        f"OUKITEL/C62_A15_EEA/C62:16/BP2A.250605.031.A3/20260313:user/release-keys"
    )

    params = {
        # Base params (t1.c.a)
        "device_type": DEVICE["ro.fota.type"],
        "connect_type": "-2",  # WiFi
        "platform": DEVICE["ro.fota.platform"],
        "project": build_project(),
        "version": DEVICE["ro.fota.version"],
        "devicesinfoExt": build_devicesinfo_ext(),
        "swFingerprint": fingerprint,
        "sdk_level": DEVICE["ro.build.version.sdk"],
        "sdk_release": DEVICE["ro.build.version.release"],
        "resolution": resolution,
        "mid": mid,
        "isNewMid": "0",
        # Extended params (t1.c.e)
        "appVersion": APP_VERSION,
        "appCode": APP_CODE,
        "local": DEVICE.get("ro.fota.language", "en").replace("_", "$"),
        "operator": "",
        "spn1": "",
        "spn2": "",
        "sendId": SEND_ID,
        "fotaSign": "",
        "androidId": hashlib.md5(imei.encode()).hexdigest()[:16],
        "fcmId": "",
        "agreeType": "true",
        "upgradeAgreement": "true",
        "isActive": str(query_type == 2).lower(),
        # IMEI / device IDs
        "imei1": imei,
        "imei2": "",
        "mac": "02:00:00:00:00:00",
        "esn": "",
    }
    return params


def encode_params_to_query(params: dict) -> str:
    """
    From t1.b.b(): joins params as &key=value (leading &, no ?).
    This raw string is what gets encrypted.
    """
    parts = []
    for k, v in params.items():
        parts.append(f"&{k}={v}")
    return "".join(parts)


# ---------------------------------------------------------------------------
# HTTP request
# ---------------------------------------------------------------------------
def do_check(server: str, endpoint: str, params: dict, timeout: int = 30) -> dict:
    """
    Perform an OTA check request.

    The app (t1.b.b) does:
      1. Build query string: &key1=val1&key2=val2...
      2. Encrypt it with v1.f.j() → "key" field
      3. SHA-256 the encrypted string → "shaKey" field
      4. POST as form-encoded to the endpoint
    """
    url = server + endpoint
    raw_query = encode_params_to_query(params)

    encrypted = encrypt_params(raw_query)
    sha_key = sha256_hex(encrypted)

    form_data = {
        "key": encrypted,
        "shaKey": sha_key,
    }

    print(f"[*] POST {url}")
    print(f"    Encrypted payload: {len(encrypted)} chars")

    resp = requests.post(
        url,
        data=form_data,
        timeout=timeout,
        headers={
            "User-Agent": "okhttp/2.7.5",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        verify=True,
    )

    print(f"    HTTP {resp.status_code}")
    return {
        "status_code": resp.status_code,
        "ok": resp.ok,
        "body": resp.text,
    }


def parse_check_response(body: str) -> dict | None:
    """
    Parse the JSON response from detectSchedule.do.

    Expected structure (CheckBean):
    {
        "status": 1001|1002|1003,
        "flag": { "mid": "...", "check_freq": ..., ... },
        "version": {
            "versionName": "...",
            "deltaurl": "https://...",
            "filesize": 123456789,
            "md5sum": "...",
            "sha": "...",
            "releasenotes": [...],
            "policy": [...],
            "issilent": 0|1,
            "isOldPkg": 0|1
        }
    }

    Status codes:
        1001 = new version available
        1002 = same version (up to date)
        1003 = no version info
        1004 = new version (different delta URL)
        1005 = same version but forced
    """
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        print(f"[!] Failed to parse response as JSON")
        print(f"    Raw body: {body[:500]}")
        return None
    return data


# ---------------------------------------------------------------------------
# Download firmware
# ---------------------------------------------------------------------------
def download_firmware(url: str, output_path: str, expected_size: int = 0,
                      md5sum: str = "", sha256sum: str = ""):
    """Download the firmware OTA zip with progress, resume, and verification."""
    print(f"[*] Downloading: {url}")
    print(f"    Output: {output_path}")

    # Support resume
    downloaded = 0
    mode = "wb"
    headers = {"User-Agent": "okhttp/2.7.5"}

    if os.path.exists(output_path):
        downloaded = os.path.getsize(output_path)
        if downloaded > 0 and (expected_size == 0 or downloaded < expected_size):
            print(f"    Resuming from byte {downloaded}")
            headers["Range"] = f"bytes={downloaded}-"
            mode = "ab"
        elif expected_size > 0 and downloaded >= expected_size:
            print(f"    File already complete ({downloaded} bytes)")
            verify_file(output_path, md5sum, sha256sum)
            return

    resp = requests.get(url, headers=headers, stream=True, timeout=60)

    if resp.status_code not in (200, 206):
        print(f"[!] Download failed: HTTP {resp.status_code}")
        return

    total = expected_size or int(resp.headers.get("content-length", 0)) + downloaded

    md5_ctx = hashlib.md5()
    sha_ctx = hashlib.sha256()

    # If resuming, we need to hash what we already have
    if downloaded > 0 and mode == "ab":
        print(f"    Hashing existing {downloaded} bytes for verification...")
        with open(output_path, "rb") as ef:
            while True:
                chunk = ef.read(102400)
                if not chunk:
                    break
                md5_ctx.update(chunk)
                sha_ctx.update(chunk)

    with open(output_path, mode) as f:
        chunk_size = 102400
        last_pct = -1
        for chunk in resp.iter_content(chunk_size=chunk_size):
            if not chunk:
                continue
            f.write(chunk)
            md5_ctx.update(chunk)
            sha_ctx.update(chunk)
            downloaded += len(chunk)

            if total > 0:
                pct = int(downloaded * 100 / total)
                if pct != last_pct and pct % 5 == 0:
                    bar_len = 40
                    filled = int(bar_len * pct / 100)
                    bar = "=" * filled + "-" * (bar_len - filled)
                    size_mb = downloaded / (1024 * 1024)
                    total_mb = total / (1024 * 1024)
                    print(f"\r    [{bar}] {pct}%  {size_mb:.1f}/{total_mb:.1f} MB",
                          end="", flush=True)
                    last_pct = pct

    print()
    print(f"    Download complete: {downloaded} bytes")

    # Verify
    if md5sum:
        got = md5_ctx.hexdigest()
        ok = "OK" if got.lower() == md5sum.lower() else "MISMATCH"
        print(f"    MD5:    {got} [{ok}]")
    if sha256sum:
        got = sha_ctx.hexdigest()
        ok = "OK" if got.lower() == sha256sum.lower() else "MISMATCH"
        print(f"    SHA256: {got} [{ok}]")


def verify_file(path: str, md5sum: str, sha256sum: str):
    """Verify an already-downloaded file."""
    md5_ctx = hashlib.md5()
    sha_ctx = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(102400)
            if not chunk:
                break
            md5_ctx.update(chunk)
            sha_ctx.update(chunk)
    if md5sum:
        got = md5_ctx.hexdigest()
        ok = "OK" if got.lower() == md5sum.lower() else "MISMATCH"
        print(f"    MD5:    {got} [{ok}]")
    if sha256sum:
        got = sha_ctx.hexdigest()
        ok = "OK" if got.lower() == sha256sum.lower() else "MISMATCH"
        print(f"    SHA256: {got} [{ok}]")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def cmd_check(args, endpoint=ENDPOINT_CHECK_DELTA):
    """Check for firmware update."""
    imei = args.imei
    mid = args.mid or generate_mid()
    server = args.server or SERVERS[0]

    print(f"[*] Device: OUKITEL C62 (EEA)")
    print(f"    Current version: {DEVICE['ro.fota.version']}")
    print(f"    IMEI: {imei}")
    print(f"    MID:  {mid}")
    print(f"    Server: {server}")
    print()

    params = build_check_params(imei, mid)
    result = do_check(server, endpoint, params)

    if not result["ok"]:
        print(f"[!] Server returned HTTP {result['status_code']}")
        if result["body"]:
            print(f"    Body: {result['body'][:500]}")

        # Failover
        if server == SERVERS[0] and len(SERVERS) > 1:
            print(f"\n[*] Trying fallback server: {SERVERS[1]}")
            result = do_check(SERVERS[1], endpoint, params)

    if result["ok"]:
        parsed = parse_check_response(result["body"])
        if parsed:
            print(f"\n[+] Response:")
            print(json.dumps(parsed, indent=2, ensure_ascii=False))

            status = parsed.get("status")
            if status in (1001, 1004):
                version = parsed.get("version", {})
                print(f"\n[+] UPDATE AVAILABLE")
                print(f"    Version:  {version.get('versionName', 'N/A')}")
                print(f"    URL:      {version.get('deltaurl', 'N/A')}")
                print(f"    Size:     {version.get('filesize', 0)} bytes "
                      f"({version.get('filesize', 0) / 1024 / 1024:.1f} MB)")
                print(f"    MD5:      {version.get('md5sum', 'N/A')}")
                print(f"    SHA256:   {version.get('sha', 'N/A')}")
                print(f"    Silent:   {version.get('issilent', 'N/A')}")

                notes = version.get("releasenotes", [])
                if notes:
                    print(f"    Release notes:")
                    for note in notes:
                        lang = note.get("lang", note.get("language", "??"))
                        text = note.get("content", note.get("text", ""))
                        print(f"      [{lang}] {text[:200]}")
            elif status == 1002:
                print(f"\n[=] Device is up to date (same version)")
            elif status == 1003:
                print(f"\n[=] No update available")
            elif status == 1005:
                print(f"\n[=] Same version but forced update available")
                version = parsed.get("version", {})
                if version:
                    print(f"    URL: {version.get('deltaurl', 'N/A')}")
            elif status == 1010:
                print(f"\n[!] Status 1010 — device not recognized or IMEI rejected")
                print(f"    The server accepted the request but returned no update.")
                print(f"    Try with a valid IMEI (--imei).")
                flag = parsed.get("flag", {})
                if flag:
                    print(f"    check_freq: {flag.get('check_freq')} min")
                    print(f"    isupgrade:  {flag.get('isupgrade')}")
            else:
                print(f"\n[?] Unknown status: {status}")

            return parsed
        else:
            print(f"    Raw: {result['body'][:500]}")
    return None


def cmd_download(args):
    """Check for update and download if available."""
    # If a direct URL is given, just download it
    if args.url:
        output = args.output or "update.zip"
        download_firmware(args.url, output)
        return

    # Otherwise, check first
    parsed = cmd_check(args)
    if not parsed:
        print("[!] No response from server, cannot download")
        return

    status = parsed.get("status")
    if status not in (1001, 1004, 1005):
        print("[!] No update available to download")
        return

    version = parsed.get("version", {})
    delta_url = version.get("deltaurl")
    if not delta_url:
        print("[!] No download URL in response")
        return

    output = args.output or "update.zip"
    download_firmware(
        url=delta_url,
        output_path=output,
        expected_size=version.get("filesize", 0),
        md5sum=version.get("md5sum", ""),
        sha256sum=version.get("sha", ""),
    )


def cmd_check_full(args):
    """Check for a full firmware update (not delta)."""
    cmd_check(args, endpoint=ENDPOINT_CHECK_FULL)


def main():
    parser = argparse.ArgumentParser(
        description="Adups FOTA Client — OUKITEL C62",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s check --imei 123456789012345\n"
            "  %(prog)s check-full --imei 123456789012345\n"
            "  %(prog)s download --imei 123456789012345 -o firmware.zip\n"
            "  %(prog)s download --url https://... -o firmware.zip\n"
        ),
    )

    parser.add_argument(
        "--imei",
        default="000000000000000",
        help="IMEI to identify as (default: zeros — server may reject)",
    )
    parser.add_argument(
        "--mid",
        default="",
        help="Machine ID (auto-generated if not set)",
    )
    parser.add_argument(
        "--server",
        default="",
        help=f"FOTA server URL (default: {SERVERS[0]})",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check", help="Check for delta OTA update")
    sub.add_parser("check-full", help="Check for full OTA update")

    dl = sub.add_parser("download", help="Check and download OTA update")
    dl.add_argument("-o", "--output", default="update.zip", help="Output file path")
    dl.add_argument("--url", default="", help="Direct download URL (skip check)")

    args = parser.parse_args()

    if args.command == "check":
        cmd_check(args)
    elif args.command == "check-full":
        cmd_check_full(args)
    elif args.command == "download":
        cmd_download(args)


if __name__ == "__main__":
    main()
