#!/usr/bin/env python3
"""
Samsung Firmware Downloader
Reverse-engineered from the FUS (Firmware Update Server) protocol
used by Samsung Smart Switch and Kies.

Checks for the latest firmware version for a Samsung device (by model
and region/CSC code) and downloads the encrypted firmware archive.
Downloaded .enc2/.enc4 files are decrypted with an AES key derived
from the firmware version string.

No Samsung account required — FUS uses nonce-based session auth.

Flow: generate-nonce → binary-inform → binary-init → download → decrypt

Usage:
    python3 samsung_fw_download.py check --model SM-S926B --region EUX
    python3 samsung_fw_download.py download --model SM-S926B --region EUX
    python3 samsung_fw_download.py decrypt file.enc4 --version PDA/CSC/PHONE/DATA
"""

import argparse
import base64
import hashlib
import os
import struct
import sys
import xml.etree.ElementTree as ET

import requests


# ---------------------------------------------------------------------------
# FUS server configuration
# ---------------------------------------------------------------------------
FUS_BASE_URL = "https://fota-cloud-dn.ospserver.net"
NONCE_ENDPOINT = "/NF_DownloadGenerateNonce.do"
BINARY_INFORM_ENDPOINT = "/NF_DownloadBinaryInform.do"
BINARY_INIT_ENDPOINT = "/NF_DownloadBinaryInitForMass.do"

# Alternative CDN for binary downloads
CDN_BASE_URL = "https://cloud-neofus.sslcs.cdngc.net"

USER_AGENT = "Kies2.0_FUS"
CLIENT_PRODUCT = "Smart Switch"


# ---------------------------------------------------------------------------
# Nonce authentication keys (from Smart Switch 4.3 / FUS client)
#
# The FUS protocol authenticates via a nonce exchange:
#   1. Server returns encrypted nonce in NONCE response header
#   2. Client decrypts with KEY_1 (AES-128-CBC, IV=KEY_1)
#   3. Client re-encrypts with KEY_2 (AES-128-CBC, IV=KEY_2)
#   4. Encrypted nonce sent back in Authorization header
# ---------------------------------------------------------------------------
NONCE_KEY_1 = bytes([
    0x08, 0xD7, 0xB2, 0xD0, 0x9A, 0x4B, 0xCE, 0x0F,
    0xD0, 0xC8, 0xB2, 0x4F, 0xB8, 0xE4, 0xF5, 0xB8,
])
NONCE_KEY_2 = bytes([
    0x68, 0xC8, 0x98, 0xF6, 0x4F, 0x28, 0xC7, 0x86,
    0xB0, 0xF2, 0x6A, 0x9E, 0x4E, 0x79, 0xC2, 0xA2,
])


# ---------------------------------------------------------------------------
# AES helpers (pycryptodomex or fallback pure-Python for ECB)
# ---------------------------------------------------------------------------
try:
    from Cryptodome.Cipher import AES as _AES

    def aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        return _AES.new(key, _AES.MODE_CBC, iv).decrypt(data)

    def aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        return _AES.new(key, _AES.MODE_CBC, iv).encrypt(data)

    def aes_ecb_decrypt(data: bytes, key: bytes) -> bytes:
        return _AES.new(key, _AES.MODE_ECB).decrypt(data)

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

    def aes_cbc_decrypt(data, key, iv):
        raise RuntimeError("pycryptodomex required: pip install pycryptodomex")

    def aes_cbc_encrypt(data, key, iv):
        raise RuntimeError("pycryptodomex required: pip install pycryptodomex")

    def aes_ecb_decrypt(data, key):
        raise RuntimeError("pycryptodomex required: pip install pycryptodomex")


# ---------------------------------------------------------------------------
# Nonce crypto
# ---------------------------------------------------------------------------
def decrypt_nonce(encrypted_nonce: str) -> bytes:
    """Decrypt the server's nonce using KEY_1 (AES-128-CBC, IV=KEY_1)."""
    raw = base64.b64decode(encrypted_nonce)
    return aes_cbc_decrypt(raw, NONCE_KEY_1, NONCE_KEY_1)


def encrypt_nonce(nonce: bytes) -> str:
    """Re-encrypt the nonce using KEY_2 (AES-128-CBC, IV=KEY_2) for auth."""
    # Pad to 16-byte boundary
    pad_len = 16 - (len(nonce) % 16) if len(nonce) % 16 != 0 else 0
    padded = nonce + bytes(pad_len)
    encrypted = aes_cbc_encrypt(padded, NONCE_KEY_2, NONCE_KEY_2)
    return base64.b64encode(encrypted).decode()


def logic_check(input_str: str, nonce: bytes) -> str:
    """
    Compute the LOGIC_CHECK value.

    For each byte in the decrypted nonce, use (byte & 0xF) as an index
    into input_str to build the check string.

    input_str is typically the firmware version or binary filename,
    padded to at least 16 characters.
    """
    if len(input_str) < 16:
        input_str = input_str + "0" * (16 - len(input_str))
    result = ""
    for b in nonce:
        idx = b & 0x0F
        if idx < len(input_str):
            result += input_str[idx]
    return result


# ---------------------------------------------------------------------------
# Firmware decryption key derivation
# ---------------------------------------------------------------------------
def get_v2_key(version: str, model: str, region: str) -> bytes:
    """
    Derive the AES-128-ECB key for .enc2 files.
    key = MD5(region + ":" + model + ":" + version)
    """
    raw = f"{region}:{model}:{version}"
    return hashlib.md5(raw.encode()).digest()


def get_v4_key(version: str, model: str, region: str, nonce: bytes) -> bytes:
    """
    Derive the AES-128-ECB key for .enc4 files.

    The v4 key incorporates the decrypted nonce from the FUS session
    via the logic_check of the version string.

    key = MD5(version_lc + ":" + region + ":" + model)
    where version_lc = logic_check(version, nonce)
    """
    lc = logic_check(version, nonce)
    raw = f"{lc}:{region}:{model}"
    return hashlib.md5(raw.encode()).digest()


# ---------------------------------------------------------------------------
# FUS XML request/response helpers
# ---------------------------------------------------------------------------
def build_fus_xml(fields: dict) -> str:
    """
    Build a FUS XML request body.

    Format:
        <FUSMsg>
          <FUSHdr><ProtoVer>1.0</ProtoVer></FUSHdr>
          <FUSBody>
            <Put>
              <KEY><Data>VALUE</Data></KEY>
              ...
            </Put>
          </FUSBody>
        </FUSMsg>
    """
    root = ET.Element("FUSMsg")
    hdr = ET.SubElement(root, "FUSHdr")
    ET.SubElement(hdr, "ProtoVer").text = "1.0"

    body = ET.SubElement(root, "FUSBody")
    put = ET.SubElement(body, "Put")

    for key, value in fields.items():
        elem = ET.SubElement(put, key)
        data = ET.SubElement(elem, "Data")
        data.text = str(value)

    return ET.tostring(root, encoding="unicode", xml_declaration=True)


def parse_fus_response(xml_text: str) -> dict:
    """
    Parse a FUS XML response into a flat dict of key -> value.
    Extracts all <Key><Data>value</Data></Key> pairs from <Put>.
    Also extracts <Status> from <Results>.
    """
    result = {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        print(f"[!] XML parse error: {e}")
        return result

    # Status from Results
    status_elem = root.find(".//FUSBody/Results/Status")
    if status_elem is not None and status_elem.text:
        result["_STATUS"] = status_elem.text

    # All data fields from Put
    put = root.find(".//FUSBody/Put")
    if put is not None:
        for child in put:
            data = child.find("Data")
            if data is not None and data.text:
                result[child.tag] = data.text

    return result


# ---------------------------------------------------------------------------
# FUS session
# ---------------------------------------------------------------------------
class FUSSession:
    """Manages the FUS HTTP session with nonce-based authentication."""

    def __init__(self, base_url: str = FUS_BASE_URL):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
        })
        self.nonce = None  # decrypted nonce bytes
        self.encrypted_nonce = None  # re-encrypted for auth header

    def generate_nonce(self):
        """
        POST to NF_DownloadGenerateNonce.do to get a session nonce.
        The server returns the encrypted nonce in the NONCE response header
        and sets session cookies (JSESSIONID).
        """
        url = self.base_url + NONCE_ENDPOINT
        print(f"[*] Generating nonce: POST {url}")

        resp = self.session.post(url, timeout=30)
        resp.raise_for_status()

        nonce_header = resp.headers.get("NONCE")
        if not nonce_header:
            raise RuntimeError("Server did not return NONCE header")

        self.nonce = decrypt_nonce(nonce_header)
        self.encrypted_nonce = encrypt_nonce(self.nonce)

        # Strip PKCS padding from decrypted nonce for logic_check
        pad_byte = self.nonce[-1]
        if 0 < pad_byte <= 16 and all(b == pad_byte for b in self.nonce[-pad_byte:]):
            self.nonce = self.nonce[:-pad_byte]

        print(f"    Nonce: {len(self.nonce)} bytes")

    def _auth_header(self) -> str:
        """Build the Authorization header value."""
        return (
            f'FUS nonce="{self.encrypted_nonce}", '
            f'signature="", nc="", type="", realm="", newauth="1"'
        )

    def _post_fus(self, endpoint: str, fields: dict) -> dict:
        """POST a FUS XML request with nonce auth and parse the response."""
        url = self.base_url + endpoint
        xml_body = build_fus_xml(fields)

        headers = {
            "Authorization": self._auth_header(),
            "Content-Type": "application/xml",
        }

        resp = self.session.post(url, data=xml_body, headers=headers, timeout=60)
        resp.raise_for_status()

        # Server may refresh the nonce
        new_nonce = resp.headers.get("NONCE")
        if new_nonce:
            self.nonce = decrypt_nonce(new_nonce)
            self.encrypted_nonce = encrypt_nonce(self.nonce)
            pad_byte = self.nonce[-1]
            if 0 < pad_byte <= 16 and all(b == pad_byte for b in self.nonce[-pad_byte:]):
                self.nonce = self.nonce[:-pad_byte]

        return parse_fus_response(resp.text)

    def binary_inform(self, model: str, region: str,
                      fw_version: str = "", binary_nature: int = 1) -> dict:
        """
        POST NF_DownloadBinaryInform.do to get firmware info.

        binary_nature: 1 = latest full firmware, 0 = delta from fw_version
        Returns firmware details including version, path, filename, size, CRC.
        """
        # Build the logic check from the firmware version (or model if no version)
        lc_input = fw_version if fw_version else f"{model}/{region}"
        lc = logic_check(lc_input, self.nonce)

        fields = {
            "ACCESS_MODE": "2",
            "BINARY_NATURE": str(binary_nature),
            "CLIENT_PRODUCT": CLIENT_PRODUCT,
            "DEVICE_FW_VERSION": fw_version,
            "DEVICE_LOCAL_CODE": region,
            "DEVICE_MODEL_NAME": model,
            "LOGIC_CHECK": lc,
        }

        print(f"[*] Binary inform: POST {BINARY_INFORM_ENDPOINT}")
        print(f"    Model: {model}, Region: {region}")
        if fw_version:
            print(f"    Current version: {fw_version}")

        return self._post_fus(BINARY_INFORM_ENDPOINT, fields)

    def binary_init(self, filename: str) -> dict:
        """
        POST NF_DownloadBinaryInitForMass.do to initialize a download session.
        Must be called before downloading the binary.
        """
        lc = logic_check(filename, self.nonce)

        fields = {
            "BINARY_FILE_NAME": filename,
            "LOGIC_CHECK": lc,
        }

        print(f"[*] Binary init: POST {BINARY_INIT_ENDPOINT}")
        return self._post_fus(BINARY_INIT_ENDPOINT, fields)


# ---------------------------------------------------------------------------
# Version check (simple XML — no auth required)
# ---------------------------------------------------------------------------
def check_version_xml(model: str, region: str) -> str | None:
    """
    Fetch the latest firmware version from the version.xml endpoint.
    This is a simple GET that doesn't require FUS nonce auth.

    Returns the version string (PDA/CSC/PHONE/DATA) or None.
    """
    url = f"{FUS_BASE_URL}/firmware/{region}/{model}/version.xml"
    print(f"[*] Checking version: GET {url}")

    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=30)
        if resp.status_code == 404:
            print(f"    Not found (invalid model or region?)")
            return None
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        return None

    try:
        root = ET.fromstring(resp.text)
    except ET.ParseError:
        print(f"[!] Failed to parse version XML")
        print(f"    Raw: {resp.text[:500]}")
        return None

    latest = root.findtext(".//firmware/version/latest")
    if latest:
        return latest.strip()

    # Some models use a different XML structure
    upgrade = root.findtext(".//firmware/version/upgrade/value")
    if upgrade:
        return upgrade.strip()

    print(f"[!] No version found in XML response")
    print(f"    Raw: {resp.text[:500]}")
    return None


# ---------------------------------------------------------------------------
# Download with progress and resume
# ---------------------------------------------------------------------------
def download_firmware(session: FUSSession, path: str, filename: str,
                      output_dir: str, expected_size: int = 0,
                      expected_crc: str = ""):
    """Download the encrypted firmware binary with progress and resume."""
    url = f"{FUS_BASE_URL}/firmware/{path}{filename}"
    output_path = os.path.join(output_dir, filename)

    print(f"[*] Downloading: {url}")
    print(f"    Output: {output_path}")

    # Support resume
    downloaded = 0
    mode = "wb"
    headers = {
        "User-Agent": USER_AGENT,
        "Authorization": session._auth_header(),
    }

    if os.path.exists(output_path):
        downloaded = os.path.getsize(output_path)
        if downloaded > 0 and (expected_size == 0 or downloaded < expected_size):
            print(f"    Resuming from byte {downloaded}")
            headers["Range"] = f"bytes={downloaded}-"
            mode = "ab"
        elif expected_size > 0 and downloaded >= expected_size:
            print(f"    File already complete ({downloaded} bytes)")
            return output_path

    resp = session.session.get(url, headers=headers, stream=True, timeout=60)

    if resp.status_code == 416:
        print(f"    File already complete")
        return output_path

    if resp.status_code not in (200, 206):
        # Try CDN fallback
        cdn_url = f"{CDN_BASE_URL}/firmware/{path}{filename}"
        print(f"    HTTP {resp.status_code}, trying CDN: {cdn_url}")
        resp = session.session.get(cdn_url, headers=headers, stream=True, timeout=60)

    if resp.status_code not in (200, 206):
        print(f"[!] Download failed: HTTP {resp.status_code}")
        return None

    total = expected_size or int(resp.headers.get("content-length", 0)) + downloaded

    md5_ctx = hashlib.md5()

    # Hash existing data if resuming
    if downloaded > 0 and mode == "ab":
        print(f"    Hashing existing {downloaded} bytes...")
        with open(output_path, "rb") as ef:
            while True:
                chunk = ef.read(102400)
                if not chunk:
                    break
                md5_ctx.update(chunk)

    with open(output_path, mode) as f:
        last_pct = -1
        for chunk in resp.iter_content(chunk_size=102400):
            if not chunk:
                continue
            f.write(chunk)
            md5_ctx.update(chunk)
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

    got_md5 = md5_ctx.hexdigest()
    if expected_crc:
        ok = "OK" if got_md5.lower() == expected_crc.lower() else "MISMATCH"
        print(f"    MD5: {got_md5} [{ok}]")
    else:
        print(f"    MD5: {got_md5}")

    return output_path


# ---------------------------------------------------------------------------
# Firmware decryption
# ---------------------------------------------------------------------------
def decrypt_firmware(input_path: str, output_path: str, key: bytes):
    """
    Decrypt a Samsung .enc2 or .enc4 firmware file.

    The file is AES-128-ECB encrypted. The last block may have PKCS#7
    padding or trailing zeros from the encryption padding.
    """
    if not HAS_CRYPTO:
        print("[!] pycryptodomex required for decryption: pip install pycryptodomex")
        return False

    input_size = os.path.getsize(input_path)
    print(f"[*] Decrypting: {input_path}")
    print(f"    Size: {input_size} bytes ({input_size / 1024 / 1024:.1f} MB)")
    print(f"    Output: {output_path}")
    print(f"    Key: {key.hex()}")

    md5_ctx = hashlib.md5()
    decrypted = 0

    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        while True:
            chunk = fin.read(102400)  # Must be multiple of 16
            if not chunk:
                break
            # Handle last partial block
            if len(chunk) % 16 != 0:
                pad = 16 - (len(chunk) % 16)
                chunk += bytes(pad)
            plain = aes_ecb_decrypt(chunk, key)
            fout.write(plain)
            md5_ctx.update(plain)
            decrypted += len(plain)

            if input_size > 0:
                pct = int(decrypted * 100 / input_size)
                if pct % 10 == 0:
                    print(f"\r    Decrypting... {pct}%", end="", flush=True)

    print(f"\r    Decryption complete: {decrypted} bytes")
    print(f"    Output MD5: {md5_ctx.hexdigest()}")
    return True


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------
def cmd_check(args):
    """Check for the latest firmware version."""
    model = args.model.upper()
    region = args.region.upper()

    print(f"[*] Samsung firmware check")
    print(f"    Model:  {model}")
    print(f"    Region: {region}")
    print()

    # Quick check via version.xml
    version = check_version_xml(model, region)
    if version:
        parts = version.split("/")
        print(f"\n[+] Latest firmware version:")
        print(f"    Full:  {version}")
        if len(parts) >= 4:
            print(f"    PDA:   {parts[0]}")
            print(f"    CSC:   {parts[1]}")
            print(f"    PHONE: {parts[2]}")
            print(f"    DATA:  {parts[3]}")
    else:
        print(f"\n[-] Could not determine latest version via version.xml")
        print(f"    Try the download command which uses the full FUS protocol")

    # Detailed info via FUS binary-inform
    if args.detailed or not version:
        print(f"\n[*] Querying FUS for detailed firmware info...")
        try:
            fus = FUSSession()
            fus.generate_nonce()
            info = fus.binary_inform(model, region,
                                     fw_version=args.version or "",
                                     binary_nature=1)

            status = info.get("_STATUS", "")
            if status != "200":
                print(f"[!] FUS returned status {status}")
                if info:
                    for k, v in sorted(info.items()):
                        if not k.startswith("_"):
                            print(f"    {k}: {v}")
                return

            print(f"\n[+] FUS firmware info:")
            display_keys = [
                ("LATEST_FW_VERSION", "Version"),
                ("BINARY_NAME", "Filename"),
                ("BINARY_BYTE_SIZE", "Size"),
                ("BINARY_CRC", "CRC (MD5)"),
                ("CURRENT_OS_VERSION", "Android"),
                ("MODEL_PATH", "Path"),
                ("DESCRIPTION", "Description"),
            ]
            for key, label in display_keys:
                val = info.get(key)
                if val:
                    if key == "BINARY_BYTE_SIZE":
                        val = f"{val} ({int(val) / 1024 / 1024:.1f} MB)"
                    print(f"    {label}: {val}")

            # Print any extra fields not in display list
            shown = {k for k, _ in display_keys} | {"_STATUS"}
            for k, v in sorted(info.items()):
                if k not in shown and v:
                    print(f"    {k}: {v}")

        except Exception as e:
            print(f"[!] FUS query failed: {e}")


def cmd_download(args):
    """Download firmware via the FUS protocol."""
    model = args.model.upper()
    region = args.region.upper()
    output_dir = args.output

    os.makedirs(output_dir, exist_ok=True)

    print(f"[*] Samsung firmware download")
    print(f"    Model:  {model}")
    print(f"    Region: {region}")
    print(f"    Output: {output_dir}")
    print()

    # Step 1: Generate nonce
    fus = FUSSession()
    fus.generate_nonce()

    # Step 2: Binary inform — get firmware details
    info = fus.binary_inform(model, region,
                             fw_version=args.version or "",
                             binary_nature=1)

    status = info.get("_STATUS", "")
    if status != "200":
        print(f"[!] FUS returned status {status}")
        for k, v in sorted(info.items()):
            if not k.startswith("_"):
                print(f"    {k}: {v}")
        return

    filename = info.get("BINARY_NAME", "")
    model_path = info.get("MODEL_PATH", "")
    version = info.get("LATEST_FW_VERSION", "")
    size = int(info.get("BINARY_BYTE_SIZE", "0"))
    crc = info.get("BINARY_CRC", "")

    if not filename or not model_path:
        print("[!] No firmware binary available")
        print(f"    Response: {info}")
        return

    print(f"\n[+] Firmware available:")
    print(f"    Version:  {version}")
    print(f"    Filename: {filename}")
    print(f"    Size:     {size} bytes ({size / 1024 / 1024:.1f} MB)")
    print(f"    Path:     {model_path}")
    if crc:
        print(f"    CRC:      {crc}")
    print()

    # Step 3: Binary init — prepare download session
    init_resp = fus.binary_init(filename)
    init_status = init_resp.get("_STATUS", "")
    if init_status != "200":
        print(f"[!] Binary init returned status {init_status}")
        # Non-fatal — some servers skip this step

    # Step 4: Download
    enc_path = download_firmware(
        session=fus,
        path=model_path,
        filename=filename,
        output_dir=output_dir,
        expected_size=size,
        expected_crc=crc,
    )

    if not enc_path:
        return

    # Step 5: Decrypt if requested
    if args.decrypt:
        dec_filename = filename
        for suffix in (".enc4", ".enc2"):
            if dec_filename.lower().endswith(suffix):
                dec_filename = dec_filename[:-len(suffix)]
                break
        dec_path = os.path.join(output_dir, dec_filename)

        if filename.lower().endswith(".enc4"):
            key = get_v4_key(version, model, region, fus.nonce)
        elif filename.lower().endswith(".enc2"):
            key = get_v2_key(version, model, region)
        else:
            print(f"[!] Unknown encryption format: {filename}")
            print(f"    Cannot determine decryption key")
            return

        print()
        decrypt_firmware(enc_path, dec_path, key)
    elif filename.lower().endswith((".enc2", ".enc4")):
        print(f"\n[*] File is encrypted. Run with --decrypt to decrypt, or:")
        print(f"    python3 {sys.argv[0]} decrypt {enc_path} "
              f"--version '{version}' --model {model} --region {region}")


def cmd_decrypt(args):
    """Decrypt a previously downloaded .enc2/.enc4 file."""
    if not os.path.exists(args.file):
        print(f"[!] File not found: {args.file}")
        return

    model = args.model.upper()
    region = args.region.upper()
    version = args.version

    output = args.output
    if not output:
        output = args.file
        for suffix in (".enc4", ".enc2"):
            if output.lower().endswith(suffix):
                output = output[:-len(suffix)]
                break
        if output == args.file:
            output = args.file + ".dec"

    if args.file.lower().endswith(".enc4"):
        # v4 key normally needs the session nonce, but we can approximate
        # using a simple derivation when decrypting offline
        print("[*] Using v4 key derivation (offline mode)")
        raw = f"{version}:{region}:{model}"
        key = hashlib.md5(raw.encode()).digest()
    elif args.file.lower().endswith(".enc2"):
        key = get_v2_key(version, model, region)
    else:
        print("[!] Unknown file extension — trying v2 key derivation")
        key = get_v2_key(version, model, region)

    decrypt_firmware(args.file, output, key)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Samsung Firmware Downloader — FUS protocol client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s check --model SM-S926B --region EUX\n"
            "  %(prog)s check --model SM-A556B --region XEF --detailed\n"
            "  %(prog)s download --model SM-S926B --region EUX --decrypt\n"
            "  %(prog)s download --model SM-G991B --region BTU -o firmware/\n"
            "  %(prog)s decrypt SM-S926B_fw.zip.enc4 --version PDA/CSC/PH/DATA"
            " --model SM-S926B --region EUX\n"
            "\n"
            "Common region codes:\n"
            "  EUX  European open      BTU  UK open (British)\n"
            "  XEF  France open        DBT  Germany open\n"
            "  ITV  Italy open         PHE  Spain open\n"
            "  XSA  Australia open     INS  India open\n"
            "  XAA  US unlocked        TMB  T-Mobile US\n"
            "  SPR  Sprint US          VZW  Verizon US\n"
            "  ATT  AT&T US            USC  US Cellular\n"
        ),
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # -- check --
    p_check = sub.add_parser("check", help="Check latest firmware version")
    p_check.add_argument("--model", required=True, help="Device model (e.g. SM-S926B)")
    p_check.add_argument("--region", required=True, help="Region/CSC code (e.g. EUX)")
    p_check.add_argument("--version", default="", help="Current firmware version (for delta check)")
    p_check.add_argument("--detailed", action="store_true",
                         help="Also query FUS for detailed binary info")

    # -- download --
    p_dl = sub.add_parser("download", help="Download firmware")
    p_dl.add_argument("--model", required=True, help="Device model (e.g. SM-S926B)")
    p_dl.add_argument("--region", required=True, help="Region/CSC code (e.g. EUX)")
    p_dl.add_argument("--version", default="", help="Specific firmware version to download")
    p_dl.add_argument("--decrypt", action="store_true",
                       help="Decrypt after download")
    p_dl.add_argument("-o", "--output", default=".", help="Output directory (default: .)")

    # -- decrypt --
    p_dec = sub.add_parser("decrypt", help="Decrypt a .enc2/.enc4 firmware file")
    p_dec.add_argument("file", help="Encrypted firmware file")
    p_dec.add_argument("--version", required=True,
                       help="Firmware version string (PDA/CSC/PHONE/DATA)")
    p_dec.add_argument("--model", required=True, help="Device model (e.g. SM-S926B)")
    p_dec.add_argument("--region", required=True, help="Region/CSC code (e.g. EUX)")
    p_dec.add_argument("-o", "--output", default="", help="Output file path")

    args = parser.parse_args()

    if args.command == "check":
        cmd_check(args)
    elif args.command == "download":
        cmd_download(args)
    elif args.command == "decrypt":
        cmd_decrypt(args)


if __name__ == "__main__":
    main()
