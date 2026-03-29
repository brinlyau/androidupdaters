#!/usr/bin/env python3
"""
Android OTA Update Checker & Downloader

Reconstructed from reverse-engineering GmsCore 25.10.36 checkin protocol.
Sends an AndroidCheckinRequest protobuf to Google's checkin endpoint,
parses the response for OTA update URLs, and downloads the payload.

Works with any device using Google's OTA infrastructure. Device properties
can be read from a connected device via ADB or specified manually.

Usage:
    python3 fp6_ota_checker.py --adb [--download]
    python3 fp6_ota_checker.py [--download] [--state state.json]
"""

import argparse
import gzip
import hashlib
import io
import json
import os
import struct
import subprocess
import sys
import time
import urllib.request
import urllib.error

# ---------------------------------------------------------------------------
# Minimal protobuf wire-format encoder/decoder (no external deps)
# ---------------------------------------------------------------------------

WIRE_VARINT = 0
WIRE_FIXED64 = 1
WIRE_LEN = 2
WIRE_FIXED32 = 5


def _encode_varint(value):
    if value < 0:
        value += 1 << 64
    out = bytearray()
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value & 0x7F)
    return bytes(out)


def _decode_varint(data, pos):
    result = 0
    shift = 0
    while True:
        b = data[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def _encode_tag(field_number, wire_type):
    return _encode_varint((field_number << 3) | wire_type)


def pb_varint(field, value):
    """Encode a varint field (int32, int64, bool)."""
    return _encode_tag(field, WIRE_VARINT) + _encode_varint(value)


def pb_string(field, value):
    """Encode a length-delimited string field."""
    if isinstance(value, str):
        value = value.encode("utf-8")
    return _encode_tag(field, WIRE_LEN) + _encode_varint(len(value)) + value


def pb_bytes(field, value):
    """Encode a length-delimited bytes field."""
    return _encode_tag(field, WIRE_LEN) + _encode_varint(len(value)) + value


def pb_message(field, msg_bytes):
    """Encode an embedded message field."""
    return _encode_tag(field, WIRE_LEN) + _encode_varint(len(msg_bytes)) + msg_bytes


def pb_fixed64(field, value):
    """Encode a fixed64 field."""
    return _encode_tag(field, WIRE_FIXED64) + struct.pack("<Q", value)


def pb_decode(data):
    """Decode a protobuf message into {field_number: [(wire_type, value), ...]}."""
    fields = {}
    pos = 0
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_number = tag >> 3
        wire_type = tag & 0x07
        if wire_type == WIRE_VARINT:
            value, pos = _decode_varint(data, pos)
        elif wire_type == WIRE_FIXED64:
            value = struct.unpack_from("<Q", data, pos)[0]
            pos += 8
        elif wire_type == WIRE_LEN:
            length, pos = _decode_varint(data, pos)
            value = data[pos : pos + length]
            pos += length
        elif wire_type == WIRE_FIXED32:
            value = struct.unpack_from("<I", data, pos)[0]
            pos += 4
        else:
            raise ValueError(f"Unknown wire type {wire_type} at pos {pos}")
        fields.setdefault(field_number, []).append((wire_type, value))
    return fields


# ---------------------------------------------------------------------------
# ADB device property reader
# ---------------------------------------------------------------------------


def adb_shell(cmd, serial=None):
    """Run an adb shell command and return stripped stdout."""
    adb_cmd = ["adb"]
    if serial:
        adb_cmd += ["-s", serial]
    adb_cmd += ["shell", cmd]
    try:
        result = subprocess.run(adb_cmd, capture_output=True, text=True, timeout=10)
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        raise RuntimeError(f"ADB command failed: {e}")


def adb_getprop(prop, serial=None):
    """Get a single system property via adb."""
    return adb_shell(f"getprop {prop}", serial)


def get_props_from_adb(serial=None):
    """Read all required device properties from a connected device via ADB."""
    print("[*] Reading device properties via ADB...")

    # Verify device is connected
    try:
        check_cmd = ["adb"]
        if serial:
            check_cmd += ["-s", serial]
        check_cmd += ["get-state"]
        result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)
        if result.stdout.strip() != "device":
            raise RuntimeError(f"ADB device not ready (state: {result.stdout.strip()})")
    except FileNotFoundError:
        raise RuntimeError("adb not found in PATH. Install Android platform-tools.")

    # Read core build properties
    props = {
        "fingerprint": adb_getprop("ro.build.fingerprint", serial),
        "hardware": adb_getprop("ro.hardware", serial),
        "brand": adb_getprop("ro.product.brand", serial),
        "device": adb_getprop("ro.product.device", serial),
        "model": adb_getprop("ro.product.model", serial),
        "manufacturer": adb_getprop("ro.product.manufacturer", serial),
        "product": adb_getprop("ro.product.name", serial),
        "board": adb_getprop("ro.product.board", serial),
        "platform": adb_getprop("ro.board.platform", serial),
        "sdk_version": int(adb_getprop("ro.build.version.sdk", serial) or "0"),
        "build_id": adb_getprop("ro.build.display.id", serial),
        "incremental": adb_getprop("ro.build.version.incremental", serial),
        "security_patch": adb_getprop("ro.build.version.security_patch", serial),
        "build_date": adb_getprop("ro.build.date", serial),
        "build_timestamp": int(adb_getprop("ro.build.date.utc", serial) or "0"),
        "release": adb_getprop("ro.build.version.release", serial),
        "client_id_base": adb_getprop("ro.com.google.clientidbase", serial),
        "gms_version": adb_getprop("ro.com.google.gmsversion", serial),
    }

    # Read partition fingerprints
    partitions = {}
    partition_names = ["system", "vendor", "product", "system_ext", "odm"]
    for part in partition_names:
        fp = adb_getprop(f"ro.{part}.build.fingerprint", serial)
        if not fp:
            fp = props["fingerprint"]  # fallback to main fingerprint
        device = adb_getprop(f"ro.product.{part}.device", serial)
        if not device:
            device = props["device"]
        date_utc = adb_getprop(f"ro.{part}.build.date.utc", serial)
        if not date_utc:
            date_utc = str(props["build_timestamp"])
        partitions[part] = {
            "fingerprint": fp,
            "device": device,
            "build_date_utc": date_utc,
        }
    props["partitions"] = partitions

    # Validate we got meaningful data
    if not props["fingerprint"]:
        raise RuntimeError("Failed to read build fingerprint - is the device connected?")

    print(f"[+] Device: {props['brand']} {props['model']} ({props['device']})")
    print(f"[+] Fingerprint: {props['fingerprint']}")
    print(f"[+] SDK: {props['sdk_version']}, Security patch: {props['security_patch']}")

    return props


# ---------------------------------------------------------------------------
# Fallback: Fairphone 6 hardcoded properties
# ---------------------------------------------------------------------------

FP6_PROPS = {
    "fingerprint": "Fairphone/FP6/FP6:15/FP6.QREL.15.178.0/VS22:user/release-keys",
    "hardware": "qcom",
    "brand": "Fairphone",
    "device": "FP6",
    "model": "Fairphone 6",
    "manufacturer": "Fairphone",
    "product": "FP6",
    "board": "fps",
    "platform": "volcano",
    "sdk_version": 35,
    "build_id": "FP6.QREL.15.178.0",
    "incremental": "VS22",
    "security_patch": "2026-02-05",
    "build_date": "Wed Feb  4 14:51:37 CST 2026",
    "build_timestamp": 1770187897,
    "release": "15",
    "client_id_base": "android-fairphone",
    "gms_version": "15_202510",
    "partitions": {
        "system": {
            "fingerprint": "Fairphone/FP6/FP6:15/FP6.QREL.15.178.0/VS22:user/release-keys",
            "device": "FP6",
            "build_date_utc": "1770187897",
        },
        "vendor": {
            "fingerprint": "Fairphone/FP6/FP6:15/FP6.QREL.15.178.0/VS22:user/release-keys",
            "device": "FP6",
            "build_date_utc": "1770189114",
        },
        "product": {
            "fingerprint": "Fairphone/FP6/FP6:15/FP6.QREL.15.178.0/VS22:user/release-keys",
            "device": "FP6",
            "build_date_utc": "1770187897",
        },
        "system_ext": {
            "fingerprint": "Fairphone/FP6/FP6:15/FP6.QREL.15.178.0/VS22:user/release-keys",
            "device": "qssi_64",
            "build_date_utc": "1770187897",
        },
        "odm": {
            "fingerprint": "Fairphone/FP6/FP6:15/FP6.QREL.15.178.0/VS22:user/release-keys",
            "device": "FP6",
            "build_date_utc": "1770189114",
        },
    },
}


# ---------------------------------------------------------------------------
# Protobuf message builders (field numbers from reverse-engineered proto)
# ---------------------------------------------------------------------------


def build_partition_fingerprint(name, info):
    """Build a PartitionFingerprint message (apap)."""
    msg = b""
    msg += pb_string(1, name)  # partition_name
    msg += pb_string(2, info["device"])  # device_name
    msg += pb_string(3, info["fingerprint"])  # fingerprint
    msg += pb_string(4, info["build_date_utc"])  # build_date_utc
    return msg


def build_android_build_proto(props):
    """Build an AndroidBuildProto message (apaq).

    Field mapping from gjeh descriptor in apaq.java:
      1=fingerprint, 2=radio, 3=bootloader, 4=hardware, 5=brand,
      6=client_id, 7=timestamp, 8=sdk_version(int), 9=device,
      10=gms_version_code(int), 11=model, 12=manufacturer, 13=product,
      14=ota_installed(bool), 17=security_patch, 18=partition_fingerprints
    """
    msg = b""
    msg += pb_string(1, props["fingerprint"])  # Build.FINGERPRINT
    # field 2 = radio (omit, runtime only)
    # field 3 = bootloader (omit, runtime only)
    msg += pb_string(4, props["hardware"])  # Build.HARDWARE
    msg += pb_string(5, props["brand"])  # Build.BRAND
    msg += pb_string(6, props["client_id_base"])  # client_id
    msg += pb_varint(7, props["build_timestamp"])  # Build.TIME / 1000
    msg += pb_varint(8, props["sdk_version"])  # Build.VERSION.SDK_INT
    msg += pb_string(9, props["device"])  # Build.DEVICE
    msg += pb_varint(10, 251036035)  # GmsCore package version code
    msg += pb_string(11, props["model"])  # Build.MODEL
    msg += pb_string(12, props["manufacturer"])  # Build.MANUFACTURER
    msg += pb_string(13, props["product"])  # Build.PRODUCT
    msg += pb_varint(14, 0)  # ota_installed (bool)
    msg += pb_string(17, props["security_patch"])  # Build.VERSION.SECURITY_PATCH
    # field 18 = partition fingerprints (repeated message)
    for name, info in props["partitions"].items():
        pf = build_partition_fingerprint(name, info)
        msg += pb_message(18, pf)
    return msg


def build_checkin_reason(reason_code=1, retry_count=1, source_package="unspecified"):
    """Build a CheckinReason message (apav)."""
    msg = b""
    msg += pb_varint(1, reason_code)  # reason (0-indexed: 0=periodic)
    msg += pb_varint(2, retry_count)  # retry_count
    msg += pb_string(3, source_package)  # source_package
    msg += pb_string(4, "")  # source_class
    msg += pb_varint(5, 0)  # forced (bool)
    return msg


def build_android_checkin_proto(props, last_checkin_ms=0):
    """Build an AndroidCheckinProto message (apas)."""
    msg = b""
    build = build_android_build_proto(props)
    msg += pb_message(1, build)  # build
    msg += pb_varint(2, last_checkin_ms)  # last_checkin_ms
    # field 6 = cell_operator (omit)
    # field 7 = sim_operator (omit)
    # field 8 = roaming (omit)
    reason = build_checkin_reason(reason_code=0, retry_count=1)
    msg += pb_message(12, reason)  # reason
    return msg


def build_checkin_request(
    props, android_id=0, security_token=0, locale="en-US", timezone="UTC",
    fetch_system_updates=True, last_checkin_ms=0,
):
    """Build an AndroidCheckinRequest message (apad)."""
    msg = b""
    # field 1 = imei (string, omit for privacy)
    msg += pb_varint(2, android_id)  # android_id
    msg += pb_string(3, "")  # digest
    msg += pb_string(6, locale)  # locale
    checkin = build_android_checkin_proto(props, last_checkin_ms)
    msg += pb_message(4, checkin)  # checkin (field 4, not 8)
    # field 9 = account_cookie (repeated, omit)
    # field 10 = esn (omit)
    # field 11 = mac_addr (repeated, omit)
    msg += pb_string(12, timezone)  # timezone (field 12)
    if security_token:
        msg += pb_fixed64(13, security_token)  # security_token (fixed64)
    msg += pb_varint(14, 3)  # version = 3 (protocol version)
    # field 15 = requested_group (omit)
    # field 16 = serial_number (omit)
    # field 18 = user_profile (omit)
    # field 19 = ota_certs (repeated, omit for now)
    msg += pb_varint(29, 1 if fetch_system_updates else 0)  # fetch_system_updates
    msg += pb_varint(30, 0)  # euicc_provisioned
    return msg


# ---------------------------------------------------------------------------
# Checkin HTTP request
# ---------------------------------------------------------------------------

CHECKIN_URL = "https://android.googleapis.com/checkin"
USER_AGENT = "CheckinService-251036000/2.0"


def do_checkin(request_bytes):
    """Send a checkin request and return the raw response protobuf bytes."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(request_bytes)
    body = buf.getvalue()

    req = urllib.request.Request(
        CHECKIN_URL,
        data=body,
        headers={
            "Content-Type": "application/x-protobuffer",
            "Content-Encoding": "gzip",
            "Accept-Encoding": "gzip",
            "User-Agent": USER_AGENT,
        },
        method="POST",
    )

    print(f"[*] Sending checkin request to {CHECKIN_URL} ({len(body)} bytes compressed)")

    try:
        resp = urllib.request.urlopen(req, timeout=120)
    except urllib.error.HTTPError as e:
        checkin_error = e.headers.get("checkin-error", "")
        error_body = e.read()
        print(f"[!] HTTP {e.code}: {e.reason}")
        if checkin_error:
            print(f"[!] checkin-error header: {checkin_error}")
        if error_body:
            try:
                print(f"[!] Response body: {error_body.decode('utf-8', errors='replace')[:500]}")
            except Exception:
                print(f"[!] Response body: {error_body[:500]}")
        raise

    status = resp.status
    content_type = resp.headers.get("Content-Type", "")
    content_encoding = resp.headers.get("Content-Encoding", "")

    print(f"[*] Response: HTTP {status}, Content-Type: {content_type}")

    raw = resp.read()
    if "gzip" in content_encoding:
        raw = gzip.decompress(raw)

    if status != 200:
        raise RuntimeError(f"Checkin failed with HTTP {status}")
    if not content_type.startswith("application/x-protobuffer"):
        raise RuntimeError(f"Bad Content-Type: {content_type}")

    return raw


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------


def parse_checkin_response(data):
    """Parse AndroidCheckinResponse and extract relevant fields."""
    fields = pb_decode(data)
    result = {}

    # field 1 = stats_ok (bool varint)
    if 1 in fields:
        result["stats_ok"] = fields[1][0][1] != 0

    # field 3 = time_msec (int64)
    if 3 in fields:
        result["time_msec"] = fields[3][0][1]

    # field 7 = android_id (fixed64)
    if 7 in fields:
        result["android_id"] = fields[7][0][1]

    # field 8 = security_token (fixed64)
    if 8 in fields:
        result["security_token"] = fields[8][0][1]

    # field 9 = version_info (string)
    if 9 in fields:
        val = fields[9][0][1]
        result["version_info"] = val.decode("utf-8", errors="replace") if isinstance(val, bytes) else str(val)

    # field 12 = device_data_version_info (string)
    if 12 in fields:
        val = fields[12][0][1]
        result["device_data_version_info"] = val.decode("utf-8", errors="replace") if isinstance(val, bytes) else str(val)

    # field 5 = setting (repeated GservicesSetting)
    gservices = {}
    if 5 in fields:
        for _, setting_bytes in fields[5]:
            sf = pb_decode(setting_bytes)
            name = sf.get(1, [(None, b"")])[0][1].decode("utf-8", errors="replace")
            value = sf.get(2, [(None, b"")])[0][1].decode("utf-8", errors="replace")
            gservices[name] = value
    result["gservices"] = gservices

    # field 6 = intent/extra (repeated message with key-value pairs)
    intents = {}
    if 6 in fields:
        for wt, intent_bytes in fields[6]:
            if wt == WIRE_LEN:
                intf = pb_decode(intent_bytes)
                key = intf.get(1, [(None, b"")])[0][1]
                value = intf.get(2, [(None, b"")])[0][1]
                if isinstance(key, bytes):
                    key = key.decode("utf-8", errors="replace")
                if isinstance(value, bytes):
                    value = value.decode("utf-8", errors="replace")
                if key:
                    intents[key] = value
    result["intents"] = intents

    return result


# ---------------------------------------------------------------------------
# State persistence (android_id + security_token)
# ---------------------------------------------------------------------------

DEFAULT_STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "checkin_state.json")


def load_state(path):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {"android_id": 0, "security_token": 0, "last_checkin_ms": 0}


def save_state(path, state):
    with open(path, "w") as f:
        json.dump(state, f, indent=2)
    print(f"[*] State saved to {path}")


# ---------------------------------------------------------------------------
# OTA download
# ---------------------------------------------------------------------------


def download_ota(url, output_dir="."):
    """Download an OTA package with resume support."""
    filename = url.split("/")[-1].split("?")[0]
    if not filename or filename == "":
        filename = "ota_update.zip"
    output_path = os.path.join(output_dir, filename)

    existing_size = 0
    if os.path.exists(output_path):
        existing_size = os.path.getsize(output_path)

    headers = {"User-Agent": USER_AGENT}
    if existing_size > 0:
        headers["Range"] = f"bytes={existing_size}-"
        print(f"[*] Resuming download from byte {existing_size}")

    req = urllib.request.Request(url, headers=headers)

    try:
        resp = urllib.request.urlopen(req, timeout=300)
    except urllib.error.HTTPError as e:
        if e.code == 416:
            print(f"[*] File already fully downloaded: {output_path}")
            return output_path
        raise

    total = resp.headers.get("Content-Length")
    if total:
        total = int(total) + existing_size

    mode = "ab" if existing_size > 0 and resp.status == 206 else "wb"
    if mode == "wb":
        existing_size = 0

    print(f"[*] Downloading to {output_path}")
    if total:
        print(f"[*] Total size: {total / (1024*1024):.1f} MB")

    sha256 = hashlib.sha256()
    downloaded = existing_size

    # If resuming, hash the existing portion first
    if mode == "ab" and existing_size > 0:
        with open(output_path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha256.update(chunk)

    with open(output_path, mode) as f:
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            f.write(chunk)
            sha256.update(chunk)
            downloaded += len(chunk)
            if total:
                pct = downloaded * 100 / total
                bar = "#" * int(pct // 2) + "-" * (50 - int(pct // 2))
                print(f"\r[{bar}] {pct:.1f}% ({downloaded/(1024*1024):.1f}/{total/(1024*1024):.1f} MB)", end="", flush=True)

    print()
    print(f"[+] Download complete: {output_path}")
    print(f"[+] SHA-256: {sha256.hexdigest()}")
    return output_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Android OTA Update Checker & Downloader")
    parser.add_argument("--adb", action="store_true", help="Read device properties from a connected device via ADB")
    parser.add_argument("--serial", default=None, help="ADB device serial (for multiple devices)")
    parser.add_argument("--download", action="store_true", help="Download the OTA if available")
    parser.add_argument("--output-dir", default=".", help="Directory to save downloaded OTA")
    parser.add_argument("--state", default=DEFAULT_STATE_FILE, help="Path to state file for android_id persistence")
    parser.add_argument("--locale", default="en-US", help="Device locale")
    parser.add_argument("--timezone", default="UTC", help="Device timezone")
    parser.add_argument("--fingerprint", default=None, help="Override build fingerprint")
    parser.add_argument("--security-patch", default=None, help="Override security patch level")
    parser.add_argument("--dump-gservices", action="store_true", help="Dump all GServices settings from response")
    parser.add_argument("--dump-raw", default=None, help="Dump raw response protobuf to file")
    parser.add_argument("--dump-props", action="store_true", help="Dump device properties as JSON and exit")
    args = parser.parse_args()

    if args.adb:
        props = get_props_from_adb(serial=args.serial)
    else:
        props = dict(FP6_PROPS)
        print("[*] Using hardcoded Fairphone 6 properties (use --adb for connected device)")

    if args.fingerprint:
        props["fingerprint"] = args.fingerprint
        for part in props["partitions"]:
            props["partitions"][part]["fingerprint"] = args.fingerprint
    if args.security_patch:
        props["security_patch"] = args.security_patch

    if args.dump_props:
        print(json.dumps(props, indent=2))
        return

    state = load_state(args.state)
    print(f"[*] Loaded state: android_id={state['android_id']}, "
          f"security_token={'(set)' if state['security_token'] else '(none)'}")

    # --- First checkin (registration) if no android_id ---
    if state["android_id"] == 0:
        print("[*] No android_id found, performing initial registration checkin...")
        reg_req = build_checkin_request(
            props,
            android_id=0,
            security_token=0,
            locale=args.locale,
            timezone=args.timezone,
            fetch_system_updates=False,
        )
        reg_resp_raw = do_checkin(reg_req)
        reg_resp = parse_checkin_response(reg_resp_raw)

        if not reg_resp.get("stats_ok"):
            print("[!] Registration checkin rejected by server")
            sys.exit(1)

        state["android_id"] = reg_resp.get("android_id", 0)
        # security_token from response field 8 (fixed64)
        if reg_resp.get("security_token"):
            state["security_token"] = reg_resp["security_token"]
        state["last_checkin_ms"] = reg_resp.get("time_msec", int(time.time() * 1000))

        save_state(args.state, state)
        print(f"[+] Registered: android_id={state['android_id']}")
        print("[*] Waiting 2 seconds before update check...")
        time.sleep(2)

    # --- Main checkin with fetch_system_updates=True ---
    print("[*] Building checkin request with fetch_system_updates=True...")
    print(f"[*] Device: {props['brand']} {props['model']}")
    print(f"[*] Fingerprint: {props['fingerprint']}")
    print(f"[*] Security patch: {props['security_patch']}")
    print(f"[*] SDK: {props['sdk_version']}, Build: {props['build_id']}")

    request = build_checkin_request(
        props,
        android_id=state["android_id"],
        security_token=state["security_token"],
        locale=args.locale,
        timezone=args.timezone,
        fetch_system_updates=True,
        last_checkin_ms=state.get("last_checkin_ms", 0),
    )

    resp_raw = do_checkin(request)

    if args.dump_raw:
        with open(args.dump_raw, "wb") as f:
            f.write(resp_raw)
        print(f"[*] Raw response dumped to {args.dump_raw}")

    resp = parse_checkin_response(resp_raw)

    if not resp.get("stats_ok"):
        print("[!] Checkin rejected by server (stats_ok=false)")
        sys.exit(1)

    # Update state
    if resp.get("android_id"):
        state["android_id"] = resp["android_id"]
    state["last_checkin_ms"] = resp.get("time_msec", int(time.time() * 1000))
    save_state(args.state, state)

    # Print response info
    print(f"\n[+] Checkin successful")
    print(f"    android_id: {resp.get('android_id', 'N/A')}")
    print(f"    time_msec:  {resp.get('time_msec', 'N/A')}")
    if resp.get("version_info"):
        print(f"    version_info: {resp['version_info']}")
    if resp.get("device_data_version_info"):
        print(f"    device_data_version_info: {resp['device_data_version_info']}")

    # Dump GServices if requested
    gs = resp.get("gservices", {})
    if args.dump_gservices and gs:
        print(f"\n[*] GServices settings ({len(gs)} entries):")
        for k in sorted(gs.keys()):
            print(f"    {k} = {gs[k]}")

    # Look for OTA update URL
    update_url = gs.get("update_url", "")
    if not update_url:
        # Also check common key variations
        for key in ["ota_update_url", "system_update_url", "url"]:
            if key in gs and gs[key]:
                update_url = gs[key]
                break

    # Print all update-related gservices
    update_keys = {k: v for k, v in gs.items() if "update" in k.lower() or "ota" in k.lower()}
    if update_keys:
        print(f"\n[*] Update-related GServices settings:")
        for k, v in sorted(update_keys.items()):
            marker = " <<<" if v.startswith("http") else ""
            print(f"    {k} = {v}{marker}")

    if update_url:
        print(f"\n[+] OTA UPDATE AVAILABLE!")
        print(f"    URL: {update_url}")

        if args.download:
            os.makedirs(args.output_dir, exist_ok=True)
            download_ota(update_url, args.output_dir)
        else:
            print(f"\n    Run with --download to download the OTA package")
            print(f"    Or download manually:")
            print(f"    curl -L -o ota_update.zip '{update_url}'")
    else:
        print(f"\n[-] No OTA update URL found in response")
        print(f"    This could mean:")
        print(f"    - Device is already on the latest version")
        print(f"    - Server requires a real device android_id")
        print(f"    - Update is being staged/rolled out gradually")
        print(f"\n    Tip: Try --dump-gservices to see all server settings")


if __name__ == "__main__":
    main()
