#!/usr/bin/env python3
"""
HMD OTA Update Downloader

Supports two update channels extracted from HMD Pulse (Legend) firmware:

1. FOTA (Firmware OTA) — system/firmware updates via FotaClient
   Server: https://backend.hmdfota.com/deviceapi/
   Flow:  check-serviceprovider -> register -> check-for-updates -> download

2. Carrier Profile (CP) OTA — carrier config updates via HMDOTAClient
   Server: https://otaserver.hmdglobal.net/
   Flow:  getcp -> download ZIP

FOTA requires real device identifiers. The check-serviceprovider endpoint
validates the IMEI against HMD's device database (TAC prefix + registration).
Fake/zeroed IMEIs will be rejected.

To get the required values from a real HMD Pulse via adb:

    adb shell getprop ro.boot.serialno
        -> serial_number

    adb shell service call iphonesubinfo 1
        -> IMEI (slot 1)

    adb shell service call iphonesubinfo 4
        -> IMEI (slot 2, dual-SIM)

    adb shell cat /sys/firmware/devicetree/base/serial-number
        -> SoC serial, SHA-256 hashed to produce unique_id

    adb shell getprop ro.build.fingerprint
        -> fingerprint (e.g. HMD/Legend_00EEA/LGD:15/...)

    adb shell getprop ro.build.software.version
        -> software_version (e.g. V2.450)

    adb shell getprop ro.build.version.security_patch
        -> security_patch_level (e.g. 2025-03-05)

Then run:
    python3 hmd_ota_download.py fota --imei <IMEI> --serial <SERIAL>

The CP OTA endpoint works without real device identifiers — it only needs
a valid project name (e.g. "Legend") and MCC/MNC codes.
"""

import argparse
import hashlib
import json
import uuid
import zipfile
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── FOTA (system firmware) ──────────────────────────────────────────────────

FOTA_BASE_URL = "https://backend.hmdfota.com/deviceapi/"

# Device defaults from this ROM
FOTA_DEFAULTS = {
    "fingerprint": "HMD/Legend_00EEA/LGD:15/AP3A.241105.008/00WW_2_450:user/release-keys",
    "software_version": "V2.450",
    "security_patch_level": "2025-03-05",
    "skuid": "",
    "model": "HMD Pulse",
    "serial_number": "UNKNOWN",
    "imei": "000000000000000",
    "imei2": "000000000000000",
    "android_version": 35,
}


def fota_compute_signature(imei: str, imei2: str, serial: str, unique_id: str) -> str:
    """Compute the check-serviceprovider signature.
    signature = SHA-256(imei + imei2 + serial + unique_id + SALT)
    where SALT = "6a347180-31f6-4d55-8ecb-f8c6021c2421" (hardcoded in FotaClient)
    """
    salt = "6a347180-31f6-4d55-8ecb-f8c6021c2421"
    data = imei + imei2 + serial + unique_id + salt
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def fota_check_sp(base_url: str = FOTA_BASE_URL, **device) -> dict:
    """POST check-serviceprovider to verify if this device is served."""
    fingerprint = device.get("fingerprint", FOTA_DEFAULTS["fingerprint"])
    imei = device.get("imei", FOTA_DEFAULTS["imei"])
    imei2 = device.get("imei2", FOTA_DEFAULTS["imei2"])
    serial = device.get("serial_number", FOTA_DEFAULTS["serial_number"])
    unique_id = device.get("unique_id", str(uuid.uuid4()))

    signature = fota_compute_signature(imei, imei2, serial, unique_id)

    payload = {
        "imei": imei,
        "imei2": imei2,
        "serial_number": serial,
        "unique_id": unique_id,
        "fingerprint": fingerprint,
        "signature": signature,
    }
    resp = requests.post(
        base_url + "check-serviceprovider",
        json=payload, verify=False, timeout=90,
    )
    resp.raise_for_status()
    return resp.json()


def fota_register(base_url: str, token: str, **device) -> dict:
    """POST register to get a device_token for subsequent calls."""
    payload = {
        "imei": device.get("imei", FOTA_DEFAULTS["imei"]),
        "imei2": device.get("imei2", FOTA_DEFAULTS["imei2"]),
        "unique_id": device.get("unique_id", str(uuid.uuid4())),
        "serial_number": device.get("serial_number", FOTA_DEFAULTS["serial_number"]),
        "model": device.get("model", FOTA_DEFAULTS["model"]),
        "skuid": device.get("skuid", FOTA_DEFAULTS["skuid"]),
        "fingerprint": device.get("fingerprint", FOTA_DEFAULTS["fingerprint"]),
        "android_version": device.get("android_version", FOTA_DEFAULTS["android_version"]),
        "software_version": device.get("software_version", FOTA_DEFAULTS["software_version"]),
        "security_patch_level": device.get("security_patch_level", FOTA_DEFAULTS["security_patch_level"]),
    }
    resp = requests.post(
        base_url + "register",
        json=payload, verify=False, timeout=90,
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    return resp.json()


def fota_check_update(base_url: str, device_token: str, **device) -> dict:
    """POST check-for-updates to get available firmware update info."""
    payload = {
        "skuid": device.get("skuid", FOTA_DEFAULTS["skuid"]),
        "fingerprint": device.get("fingerprint", FOTA_DEFAULTS["fingerprint"]),
        "software_version": device.get("software_version", FOTA_DEFAULTS["software_version"]),
        "security_patch_level": device.get("security_patch_level", FOTA_DEFAULTS["security_patch_level"]),
    }
    resp = requests.post(
        base_url + "check-for-updates",
        json=payload, verify=False, timeout=90,
        headers={"Authorization": f"Bearer {device_token}"},
    )
    resp.raise_for_status()
    return resp.json()


def cmd_fota(args):
    """Full FOTA flow: check-sp -> register -> check-for-updates -> download."""
    device = {}
    if args.fingerprint:
        device["fingerprint"] = args.fingerprint
    if args.swversion:
        device["software_version"] = args.swversion
    if args.imei:
        device["imei"] = args.imei
    if args.serial:
        device["serial_number"] = args.serial

    base_url = args.server or FOTA_BASE_URL
    unique_id = str(uuid.uuid4())
    device["unique_id"] = unique_id

    # Step 1: check-serviceprovider
    print(f"[*] Step 1: check-serviceprovider @ {base_url}")
    try:
        sp = fota_check_sp(base_url, **device)
    except requests.exceptions.HTTPError as e:
        print(f"[!] HTTP error: {e}")
        print(f"[!] Response: {e.response.text}")
        return
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection error: {e}")
        return

    print(f"  Result: {json.dumps(sp, indent=2)}")

    result = sp.get("result", "")
    if result == "redirect":
        redirect_url = sp.get("backend_url", base_url)
        print(f"[*] Redirected to: {redirect_url}")
        base_url = redirect_url if redirect_url.endswith("/") else redirect_url + "/"
    elif result == "rejected":
        print("[!] Device rejected by service provider check.")
        return
    elif result == "pending":
        print(f"[!] Pending — retry after {sp.get('delay', '?')} seconds.")
        return
    elif result != "ok":
        print(f"[!] Unexpected result: {result}")
        return

    reg_token = sp.get("registration_token", "")

    # Step 2: register
    print(f"\n[*] Step 2: register device")
    try:
        reg = fota_register(base_url, reg_token, **device)
    except requests.exceptions.HTTPError as e:
        print(f"[!] HTTP error: {e}")
        print(f"[!] Response: {e.response.text}")
        return

    print(f"  Result: {json.dumps(reg, indent=2)}")
    device_token = reg.get("device_token", "")
    if not device_token:
        print("[!] No device_token received. Cannot proceed.")
        return

    # Step 3: check-for-updates
    print(f"\n[*] Step 3: check-for-updates")
    try:
        update = fota_check_update(base_url, device_token, **device)
    except requests.exceptions.HTTPError as e:
        print(f"[!] HTTP error: {e}")
        print(f"[!] Response: {e.response.text}")
        return

    print(f"  Result: {json.dumps(update, indent=2)}")

    is_active = update.get("is_active", False)
    ota = update.get("ota")

    if not is_active or not ota:
        print("[*] No firmware update available.")
        return

    dl_url = ota.get("download_url", "")
    version = ota.get("version", "unknown")
    size = ota.get("size_in_bytes", 0)
    spl = ota.get("security-patch-level", "")

    print(f"\n[+] Firmware update available!")
    print(f"    Version: {version}")
    print(f"    Security patch: {spl}")
    print(f"    Size: {size} bytes ({size / 1024 / 1024:.1f} MB)")
    print(f"    URL: {dl_url}")

    if args.download and dl_url:
        out_dir = Path(args.output)
        out_dir.mkdir(parents=True, exist_ok=True)
        filename = f"FOTA_{version.replace(' ', '_')}.zip"
        dest = out_dir / filename
        print(f"\n[*] Downloading to {dest} ...")
        download_file(dl_url, dest)
        print(f"[+] Saved: {dest} ({dest.stat().st_size} bytes)")


# ── Carrier Profile OTA ─────────────────────────────────────────────────────

CP_BASE_URL = "https://otaserver.hmdglobal.net/"
CP_API_KEY = "StDAm4bNPJNEg9QCJcO4"

CP_HEADERS = {
    "Content-Type": "application/json",
    "apiKey": CP_API_KEY,
}

CP_DEFAULTS = {
    "projectname": "Legend",
    "swmodel": "",
    "swsku": "",
    "swversion": "V2.450",
    "chipsetvendor": "ums9230",
    "serialnumber": "UNKNOWN",
    "iccid": "",
    "fcmtoken": "No Token",
    "currentcpversion": "0",
    "ismvnoType": False,
    "mvnotype": "",
    "mvnoData": "",
}

WELL_KNOWN_OPERATORS = {
    "310-260": "T-Mobile US",     "310-410": "AT&T",
    "311-480": "Verizon",         "312-530": "Sprint/T-Mobile",
    "234-10":  "O2 UK",           "234-15":  "Vodafone UK",
    "234-20":  "3 UK",            "234-30":  "EE UK",
    "234-33":  "EE UK",
    "262-01":  "Telekom DE",      "262-02":  "Vodafone DE",
    "262-03":  "O2 DE",
    "208-01":  "Orange FR",       "208-10":  "SFR",
    "208-15":  "Free FR",         "208-20":  "Bouygues FR",
    "404-10":  "AirTel IN",       "404-45":  "AirTel IN",
    "405-854": "Jio IN",          "404-86":  "Vodafone IN",
    "244-05":  "Elisa FI",        "244-91":  "DNA FI",
    "244-12":  "Telia FI",
    "222-01":  "TIM IT",          "222-10":  "Vodafone IT",
    "222-50":  "Iliad IT",        "222-88":  "WindTre IT",
    "214-01":  "Vodafone ES",     "214-03":  "Orange ES",
    "214-04":  "Yoigo ES",        "214-07":  "Movistar ES",
    "204-04":  "Vodafone NL",     "204-08":  "KPN NL",
    "204-16":  "T-Mobile NL",
    "260-01":  "Plus PL",         "260-02":  "T-Mobile PL",
    "260-03":  "Orange PL",       "260-06":  "Play PL",
    "505-01":  "Telstra AU",      "505-02":  "Optus AU",
    "505-03":  "Vodafone AU",
    "724-02":  "TIM BR",          "724-05":  "Claro BR",
    "724-10":  "Vivo BR",         "724-11":  "Vivo BR",
    "240-01":  "Telia SE",        "240-07":  "Comviq SE",
    "240-08":  "Telenor SE",
}


def query_cp(mcc: str, mnc: str, **overrides) -> dict:
    """POST to /poc/hmd/getcp and return the parsed JSON response."""
    payload = {k: overrides.get(k, v) for k, v in CP_DEFAULTS.items()}
    payload["mcc"] = mcc
    payload["mnc"] = mnc

    resp = requests.post(
        CP_BASE_URL + "poc/hmd/getcp",
        json=payload, headers=CP_HEADERS, verify=False, timeout=90,
    )
    resp.raise_for_status()
    return resp.json()


def cmd_cp_check(args):
    """Check for CP updates for a single MCC/MNC."""
    print(f"[*] Querying CP OTA for MCC={args.mcc} MNC={args.mnc} ...")
    overrides = {}
    if args.project:
        overrides["projectname"] = args.project
    if args.swversion:
        overrides["swversion"] = args.swversion
    if args.cpversion:
        overrides["currentcpversion"] = args.cpversion

    try:
        data = query_cp(args.mcc, args.mnc, **overrides)
    except requests.exceptions.HTTPError as e:
        print(f"[!] HTTP error: {e}")
        return
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection error: {e}")
        return

    print(f"[*] Response:")
    print(json.dumps(data, indent=2))

    cp_version = data.get("cpversion")
    dl_url = data.get("url")
    if not cp_version:
        print("[*] No CP update available.")
        return

    print(f"\n[+] CP version: {cp_version}")
    print(f"[+] Download URL: {dl_url}")

    if args.download and dl_url and dl_url != "CP Not Found":
        out_dir = Path(args.output)
        out_dir.mkdir(parents=True, exist_ok=True)
        filename = f"CP_{args.mcc}_{args.mnc}_v{cp_version}.zip"
        dest = out_dir / filename
        print(f"\n[*] Downloading to {dest} ...")
        download_file(dl_url, dest)
        print(f"[+] Saved: {dest} ({dest.stat().st_size} bytes)")
        if args.extract:
            try_extract_zip(dest, out_dir / dest.stem)


def cmd_cp_scan(args):
    """Scan all known operators for CP updates."""
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    overrides = {}
    if args.project:
        overrides["projectname"] = args.project
    if args.swversion:
        overrides["swversion"] = args.swversion

    results = []
    total = len(WELL_KNOWN_OPERATORS)
    print(f"[*] Scanning {total} MCC/MNC codes for CP updates...\n")

    for i, (mccmnc, name) in enumerate(WELL_KNOWN_OPERATORS.items(), 1):
        mcc, mnc = mccmnc.split("-")
        label = f"[{i}/{total}] MCC={mcc} MNC={mnc} ({name})"
        try:
            data = query_cp(mcc, mnc, **overrides)
            cp_version = data.get("cpversion")
            dl_url = data.get("url")
            if cp_version:
                print(f"  {label} -> CP v{cp_version}")
                results.append({
                    "mcc": mcc, "mnc": mnc, "operator": name,
                    "cpversion": cp_version, "url": dl_url,
                    "response": data,
                })
            else:
                print(f"  {label} -> no update")
        except Exception as e:
            print(f"  {label} -> error: {e}")

    print(f"\n[*] Found {len(results)} carrier profile(s) with updates.\n")

    index_path = out_dir / "cp_scan_results.json"
    with open(index_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[+] Results saved to {index_path}")

    if args.download:
        for r in results:
            if not r["url"] or r["url"] == "CP Not Found":
                continue
            safe_name = r["operator"].replace(" ", "_").replace("/", "_")
            filename = f"CP_{r['mcc']}_{r['mnc']}_{safe_name}_v{r['cpversion']}.zip"
            dest = out_dir / filename
            print(f"  [{r['operator']}] downloading {dest.name}")
            try:
                download_file(r["url"], dest)
                if args.extract:
                    try_extract_zip(dest, out_dir / dest.stem)
            except Exception as e:
                print(f"    [!] Failed: {e}")

    if results:
        print("\n[*] Summary:")
        for r in results:
            print(f"  {r['operator']}: MCC={r['mcc']} MNC={r['mnc']} CP v{r['cpversion']}")


# ── Shared helpers ───────────────────────────────────────────────────────────

def download_file(url: str, dest: Path, chunk_size: int = 8192) -> Path:
    """Stream-download a file with progress."""
    resp = requests.get(url, stream=True, verify=False, timeout=90)
    resp.raise_for_status()
    total = int(resp.headers.get("content-length", 0))
    downloaded = 0
    with open(dest, "wb") as f:
        for chunk in resp.iter_content(chunk_size=chunk_size):
            f.write(chunk)
            downloaded += len(chunk)
            if total:
                pct = downloaded * 100 // total
                print(f"\r  Downloading: {downloaded}/{total} bytes ({pct}%)", end="", flush=True)
            else:
                print(f"\r  Downloading: {downloaded} bytes", end="", flush=True)
    print()
    return dest


def try_extract_zip(zip_path: Path, dest_dir: Path):
    """Try to extract a ZIP, silently skip if not a ZIP."""
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(dest_dir)
            print(f"  Extracted {len(zf.namelist())} files to {dest_dir}/")
            for name in zf.namelist():
                print(f"    {name}")
    except zipfile.BadZipFile:
        print(f"  [!] Not a ZIP — kept raw at {zip_path}")


def cmd_download(args):
    """Download from a direct URL."""
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    filename = args.url.split("/")[-1].split("?")[0] or "ota_download.bin"
    dest = out_dir / filename
    print(f"[*] Downloading {args.url}")
    download_file(args.url, dest)
    print(f"[+] Saved: {dest} ({dest.stat().st_size} bytes)")
    if args.extract:
        try_extract_zip(dest, out_dir / dest.stem)


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="HMD OTA Update Downloader (FOTA + Carrier Profile)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
== FOTA (system firmware) ==
  %(prog)s fota                              # Check for firmware updates
  %(prog)s fota --download                   # Check and download
  %(prog)s fota --fingerprint "HMD/..."      # Custom fingerprint
  %(prog)s fota --swversion V2.450           # Specific SW version

== Carrier Profile ==
  %(prog)s cp-check --mcc 310 --mnc 260      # Check single operator
  %(prog)s cp-check --mcc 234 --mnc 15 -d    # Check and download
  %(prog)s cp-scan                            # Scan all known operators
  %(prog)s cp-scan --download --extract       # Scan, download, extract all

== Direct download ==
  %(prog)s download <url>                     # Download any URL
  %(prog)s download <url> --extract           # Download and extract
""",
    )
    parser.add_argument("-o", "--output", default="ota_downloads",
                        help="Output directory (default: ota_downloads)")

    sub = parser.add_subparsers(dest="command", required=True)

    # ── fota ──
    p_fota = sub.add_parser("fota", help="Check/download system firmware updates (FOTA)")
    p_fota.add_argument("-d", "--download", action="store_true",
                        help="Download the update if available")
    p_fota.add_argument("--server", default=None,
                        help=f"Override FOTA server URL (default: {FOTA_BASE_URL})")
    p_fota.add_argument("--fingerprint", default=None,
                        help="Device fingerprint (ro.build.fingerprint)")
    p_fota.add_argument("--swversion", default=None,
                        help=f"Software version (default: {FOTA_DEFAULTS['software_version']})")
    p_fota.add_argument("--imei", default=None, help="IMEI (default: zeros)")
    p_fota.add_argument("--serial", default=None, help="Serial number")
    p_fota.set_defaults(func=cmd_fota)

    # ── cp-check ──
    p_cp = sub.add_parser("cp-check", help="Check carrier profile update for MCC/MNC")
    p_cp.add_argument("--mcc", required=True, help="Mobile Country Code")
    p_cp.add_argument("--mnc", required=True, help="Mobile Network Code")
    p_cp.add_argument("-d", "--download", action="store_true")
    p_cp.add_argument("-x", "--extract", action="store_true")
    p_cp.add_argument("--project", default=None, help="Project name (default: Legend)")
    p_cp.add_argument("--swversion", default=None)
    p_cp.add_argument("--cpversion", default=None)
    p_cp.set_defaults(func=cmd_cp_check)

    # ── cp-scan ──
    p_scan = sub.add_parser("cp-scan", help="Scan all known operators for CP updates")
    p_scan.add_argument("-d", "--download", action="store_true")
    p_scan.add_argument("-x", "--extract", action="store_true")
    p_scan.add_argument("--project", default=None)
    p_scan.add_argument("--swversion", default=None)
    p_scan.set_defaults(func=cmd_cp_scan)

    # ── download ──
    p_dl = sub.add_parser("download", help="Download from a direct URL")
    p_dl.add_argument("url", help="Direct download URL")
    p_dl.add_argument("-x", "--extract", action="store_true")
    p_dl.set_defaults(func=cmd_download)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
