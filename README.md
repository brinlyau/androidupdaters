# Android OTA Updaters

A collection of reverse-engineered Android OTA (Over-The-Air) update clients for various manufacturers. Each script is a standalone tool that replicates the firmware update checking and downloading flow from its respective vendor's update app.

## Scripts

### adups_fota_client.py
OTA client for devices using the **Adups FOTA** platform (e.g. OUKITEL C62). Reverse-engineered from `com.oukitel.update` (FotaApp v5.30). Includes a reimplementation of the app's custom XOR+rotate cipher for request signing.

```
python3 adups_fota_client.py check [--imei IMEI]
python3 adups_fota_client.py check-full [--imei IMEI]
python3 adups_fota_client.py download [--imei IMEI] [-o OUTPUT]
```

### gmscore_ota_checker.py
Generic OTA checker using **Google's protobuf-based checkin protocol**, reverse-engineered from GmsCore 25.10.36. Works with any device on Google's OTA infrastructure. Includes a minimal protobuf wire-format encoder/decoder with no external proto dependencies. Can read device properties from a connected device via ADB.

```
python3 gmscore_ota_checker.py --adb [--download]
python3 gmscore_ota_checker.py [--download] [--state state.json]
python3 gmscore_ota_checker.py --dump-gservices
```

### hmd_ota_download.py
Dual-channel OTA client for **HMD Global** devices (Nokia/HMD Pulse). Supports two update channels:

- **FOTA** — system firmware updates (requires real IMEI and serial number)
- **CP** (Carrier Profile) — carrier configuration updates, with bulk scanning across 70+ known operators

```
python3 hmd_ota_download.py fota --imei <IMEI> --serial <SERIAL>
python3 hmd_ota_download.py cp-scan [--download]
```

### samsung_fw_download.py
Firmware downloader for **Samsung** devices, reverse-engineered from the FUS (Firmware Update Server) protocol used by Smart Switch and Kies. Uses nonce-based session authentication, XML request/response protocol, and AES decryption for .enc2/.enc4 firmware archives. No Samsung account required.

```
python3 samsung_fw_download.py check --model SM-S926B --region EUX
python3 samsung_fw_download.py download --model SM-S926B --region EUX --decrypt
python3 samsung_fw_download.py decrypt file.enc4 --version PDA/CSC/PH/DATA --model SM-S926B --region EUX
```

### moto_fw_download.py
Firmware downloader for **Motorola** devices, replicating the LMSA (Lenovo Software Assistant) flow. Authenticates via Lenovo ID (opens browser for OAuth2 login), detects connected devices over ADB/fastboot, and provides interactive firmware selection.

```
python3 moto_fw_download.py
```

### vivo_ota.py
OTA/COTA client for **Vivo** devices with full end-to-end encryption. Supports multiple crypto backends (DirectAES with hardcoded keys, AdbProxy for device-side encryption, and Passthrough for testing). Includes RSA/ECC signature verification and TLV-encoded protocol wrapping.

- **FOTA** — firmware updates (check, auth, download, verify)
- **COTA** — carrier OTA (channel selection, activation, download, verify, report)

```
python3 vivo_ota.py fota --check
python3 vivo_ota.py cota --channel
```

## Dependencies

All scripts use Python 3 with minimal external dependencies:

- **requests** — used by all scripts
- **pycryptodomex** — used by `vivo_ota.py` and `samsung_fw_download.py`

```
pip install requests pycryptodomex
```

## Notes

- Device parameters are typically hardcoded from extracted `build.prop` values, but several scripts support reading properties from a connected device via ADB.
- Downloads support resumption and integrity verification (MD5, SHA-256, or RSA/ECC signatures depending on the vendor).
- These are research/reverse-engineering tools — they replicate vendor protocols and are not officially supported by any manufacturer.
