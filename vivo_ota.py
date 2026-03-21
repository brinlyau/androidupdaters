"""
Vivo OTA/COTA Client - Protocol-compatible implementation.

Single-file implementation covering:
  - Device/domain configuration
  - Data models for FOTA and COTA responses
  - Crypto backends (DirectAES, AdbProxy, Passthrough)
  - Protocol package wrapping, signature verification
  - Encrypted HTTP transport
  - FOTA client (check -> auth -> download -> verify)
  - COTA client (channel -> activation -> download -> verify -> report)
  - CLI entry point
"""

import argparse
import base64
import hashlib
import json
import logging
import os
import struct
import subprocess
import sys
import time
import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import requests
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS, pkcs1_15
from Crypto.Util.Padding import pad, unpad

__version__ = "1.0.0"
log = logging.getLogger(__name__)


# ==========================================================================
# Configuration
# ==========================================================================

@dataclass
class DeviceConfig:
    """Device identity matching the PD2541F_EX firmware build.prop values."""

    model: str = "V2556"
    release_model: str = "V2556i"
    release_name: str = "Y05"
    internal_model: str = "PD2541F_EX"
    oem_model: str = "PD2541F_EX"
    hardware_version: str = "PD2541F_EXMA"
    oem_name: str = "PD2541F_EX_N_NULL_NULL"
    device_type: str = "phone"
    tier_level: str = "4"
    quick_start_device_id: str = "Y05"
    quick_start_oem_id: str = "0837"

    build_version: str = "PD2541F_EX_A_16.0.8.2.W30"
    software_version: str = "PD2541F_EX_A_16.0.8.2.W30"
    android_version: str = "16"
    sdk_version: str = "36"
    security_patch: str = "2026-01-01"
    incremental: str = "compiler260116221120"
    build_fingerprint: str = "vivo/V2556i/V2556:16/BP2A.250605.031.A3_V000L1/compiler260116221120:user/release-keys"

    country_region: str = "N"
    customize_bbk: str = "N"
    customize_comercial: str = "NULL"
    update_model: str = "PD2541F_EX"
    dyn_type: str = "DYNN"

    imei: str = ""
    serial_number: str = ""
    emmc_id: str = ""

    protocol_version: str = "1.0"

    @property
    def serial_last5(self) -> str:
        return self.serial_number[-5:] if len(self.serial_number) >= 5 else self.serial_number

    @property
    def public_model(self) -> str:
        return self.release_model

    @property
    def hw_fingerprint(self) -> str:
        return self.build_fingerprint


@dataclass
class DomainConfig:
    """Server domains from oem/etc/domains/ configuration files."""

    fota_server: str = "asia-sysupgrade-api.vivoglobal.com"
    fota_data_collection: str = "asia-st-sysupgrade.vivoglobal.com"
    cota_server: str = "asia-cota.vivoglobal.com"
    cota_dsm_server: str = "asia-vem-dsm.vivoglobal.com"
    app_upgrade: str = "asia-exappupgrade.vivoglobal.com"
    app_upgrade_stats: str = "asia-st-exappupgrade.vivoglobal.com"
    seckey_update: str = "asia-vmd.vivoglobal.com"
    domain_sync: str = "domaincfg.vivoglobal.com"

    @property
    def fota_check_url(self) -> str:
        return f"https://{self.fota_server}/vgc/v2/getVgcAndPatch.do?"

    @property
    def fota_auth_url(self) -> str:
        return f"https://{self.fota_server}/auth/getAuthForClient?"

    @property
    def fota_degrade_url(self) -> str:
        return f"https://{self.fota_server}/degrade/updateEffectTime"

    @property
    def fota_trial_url(self) -> str:
        return f"https://{self.fota_server}/upgrade/trial/getTastePk"

    @property
    def fota_redirect_url(self) -> str:
        return f"https://{self.fota_server}/pk/redirPost.do"

    @property
    def fota_agreement_url(self) -> str:
        return f"https://{self.fota_server}/data/agreeLogs.do"

    @property
    def fota_user_advisor_url(self) -> str:
        return f"https://{self.fota_server}/vgc/v2/getUserAdvisorProgram.do?"

    @property
    def cota_base_url(self) -> str:
        return f"https://{self.cota_server}/api/v1/"

    @property
    def cota_activate_query_url(self) -> str:
        return f"{self.cota_base_url}custom/activate/query"

    @property
    def cota_activate_feedback_url(self) -> str:
        return f"{self.cota_base_url}custom/activate/feedback"

    @property
    def cota_restore_feedback_url(self) -> str:
        return f"{self.cota_base_url}custom/restore/feedback"

    @property
    def cota_failover_frequency_url(self) -> str:
        return f"{self.cota_base_url}custom/active/failover/frequency"

    @property
    def cota_token_auth_url(self) -> str:
        return f"{self.cota_base_url}token/auth"

    @property
    def cota_report_url(self) -> str:
        return f"{self.cota_base_url}report"

    @property
    def cota_activate_channel_url(self) -> str:
        return f"https://{self.cota_server}/activate"

    @property
    def cota_rollback_url(self) -> str:
        return f"https://{self.cota_server}/rollback"

    @property
    def vem_oem_sync_url(self) -> str:
        return f"https://{self.cota_dsm_server}/oem/sync"

    @property
    def vem_param_sync_url(self) -> str:
        return f"https://{self.cota_dsm_server}/param/sync"

    @property
    def vem_param_feedback_url(self) -> str:
        return f"https://{self.cota_dsm_server}/param/sync/feedback"

    @property
    def vem_vtrust_check_url(self) -> str:
        return f"https://{self.cota_dsm_server}/device/rouse/check"


# CLIENT_TOKEN values decoded from the APKs
UPDATER_CLIENT_TOKEN = (
    "AAAAdQAAAAAHnRn6AAEAAAAEDmZvckNvbnN0cnVjdG9yD2NvbS5iYmsudXBkYXRlchBT"
    "amhJaWZUVmVwcjhBSmM4BUNsb3NlK3sicHJvdGVjdGlvblRocmVhZE1vZGUiOjAsInNl"
    "Y3VyaXR5TW9kZSI6MH0A"
)
UPDATER_PACKAGE = "com.bbk.updater"
UPDATER_KEY_ID = "SjhIifTVepr8AJc8"

COTA_CLIENT_TOKEN = (
    "AAAAeQAAAAAw7ESdAAEAAAAEDmZvckNvbnN0cnVjdG9yDWNvbS52aXZvLmNvdGEQU0Fy"
    "a0NTSDhZTXZ3QUlyNwlFbmZvcmNpbmcteyJwcm90ZWN0aW9uVGhyZWFkTW9kZSI6MSwi"
    "c2VjdXJpdHlNb2RlIjoxOTl9AA"
)
COTA_PACKAGE = "com.vivo.cota"
COTA_KEY_ID = "SArkCSH8YMvwAIr7"

UPDATER_RSA_PUBKEY = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxBG2Wh3lQ/1+eBOhm063"
    "GkBye1DZ4dpZfWq69k3TZLEV/bi1g0YMCCszp2o7uOTAyDiNPzp1Ydbu7Aeh1IPr"
    "5GfoelW9qys45tIvEZvIqKO+XH9YR144vTQvIEclATwph6QOpo5njeFNJm2Yp56W"
    "uoxukqbWeg2tZlB7CPNJKwPkC8XgNkadJXavlFYty5ZWEjhBoWYxRLOBMPWMdFZG"
    "n4VSA5OJSx7RcCDPzgDwfDSSaoVqPMF143ZGcbzRb+84aU/FLVtOJBmSt5HTw3cJ"
    "Fb9U95usUtvoh6IlzRDgYE9/gHreyp8D9w7ArjHoXWhxX1wv7R5bggiJm5xOXXYs"
    "QwIDAQAB"
)

UPDATER_EC_PUBKEY = (
    "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEB8WI0W0PMDw8rYf6UrM4zkB4OKdjhKcc"
    "p6Q8F0j8xMrsdpMVWaZaLaJhRcq6IgfDjFsVCLFD+Lf4gWr96fMFuWosk7O0o7am"
    "eHssYE5Im7asoPnrnOvunmM0HG5UQpGV"
)

ROLLBACK_VERSION = 6


# ==========================================================================
# Models
# ==========================================================================

@dataclass
class UpdateInfo:
    """FOTA update information from server response (patch field)."""
    ard_ver: str = ""
    version: str = ""
    cross_version: str = ""
    os_ard_cross: str = ""
    download_url: str = ""
    pkg_md5: str = ""
    pkg_sha256: str = ""
    pkg_len: int = 0
    pkg_name: str = ""
    h5_zip: str = ""
    h5_zip_md5: str = ""
    h5_zip_sha256: str = ""
    h5_url: str = ""
    ota_type: str = ""
    gg_bug: int = 0
    log_ver: str = ""
    gg_invite: int = 0
    way: int = 0
    way_setting: str = ""
    check_string: str = ""

    @classmethod
    def from_json(cls, data: dict) -> "UpdateInfo":
        if not data:
            return cls()
        return cls(
            ard_ver=data.get("ardVer", ""),
            version=data.get("version", ""),
            cross_version=data.get("crossVersion", ""),
            os_ard_cross=data.get("osArdCross", ""),
            download_url=data.get("pk", ""),
            pkg_md5=data.get("pkMd5", ""),
            pkg_sha256=data.get("pkSha256", ""),
            pkg_len=int(data.get("pkLen", 0)),
            pkg_name=data.get("pkName", ""),
            h5_zip=data.get("h5Zip", ""),
            h5_zip_md5=data.get("h5ZipMd5", ""),
            h5_zip_sha256=data.get("h5ZipSha256", ""),
            h5_url=data.get("h5Url", ""),
            ota_type=data.get("otaType", ""),
            gg_bug=int(data.get("ggBug", 0)),
            log_ver=data.get("logVer", ""),
            gg_invite=int(data.get("ggInvite", 0)),
            way=int(data.get("way", 0)),
            way_setting=data.get("waySetting", ""),
            check_string=data.get("checkString", ""),
        )


@dataclass
class VgcUpdateInfo:
    """VGC component update information from server response (vgc field)."""
    version: str = ""
    version_show: str = ""
    download_url: str = ""
    pkg_md5: str = ""
    pkg_sha256: str = ""
    pkg_len: int = 0
    h5_link: str = ""

    @classmethod
    def from_json(cls, data: dict) -> "VgcUpdateInfo":
        if not data:
            return cls()
        return cls(
            version=data.get("version", ""),
            version_show=data.get("versionShow", ""),
            download_url=data.get("pk", ""),
            pkg_md5=data.get("pkMd5", ""),
            pkg_sha256=data.get("pkSha256", ""),
            pkg_len=int(data.get("pkLen", 0)),
            h5_link=data.get("h5Link", ""),
        )


@dataclass
class ExtendedInfo:
    """Extended update configuration from server response (ext field)."""
    net_speed_threshold: int = 0
    is_full: int = 0
    t1: int = 38
    t2: int = 46
    t3: int = 53
    manual_install_temp: int = 46
    storage: int = 300
    compilation_time: int = 10
    small_ver_comp_time: int = 0
    big_ver_comp_time: int = 5
    space: int = 100
    banner_pic: str = ""
    text_color: str = ""
    logo_config: str = ""
    bind_charge_day: int = 0
    timestamp: int = 0
    bbklog: int = 0

    @classmethod
    def from_json(cls, data: dict) -> "ExtendedInfo":
        if not data:
            return cls()
        return cls(
            net_speed_threshold=int(data.get("netSpeedThreshold", 0)),
            is_full=int(data.get("isFull", 0)),
            t1=int(data.get("t1", 38)),
            t2=int(data.get("t2", 46)),
            t3=int(data.get("t3", 53)),
            manual_install_temp=int(data.get("manualInstallTemp", data.get("t2", 46))),
            storage=int(data.get("storage", 300)),
            compilation_time=int(data.get("compilationTime", 10)),
            small_ver_comp_time=int(data.get("smallVersionCompilationTime", 0)),
            big_ver_comp_time=int(data.get("bigVersionCompilationTime", 5)),
            space=int(data.get("space", 100)),
            banner_pic=data.get("bannerPic", ""),
            text_color=data.get("textColor", ""),
            logo_config=data.get("logoConfig", ""),
            bind_charge_day=int(data.get("bindChargeDay", 0)),
            timestamp=int(data.get("timeStamp", data.get("timestamp", 0))),
            bbklog=int(data.get("bbklog", 0)),
        )


@dataclass
class UpdateCheckResult:
    """Complete parsed result from FOTA update check."""
    retcode: int = 0
    message: str = ""
    fota: Optional[UpdateInfo] = None
    vgc: Optional[VgcUpdateInfo] = None
    ext: Optional[ExtendedInfo] = None

    @property
    def has_update(self) -> bool:
        return self.retcode == 0

    @property
    def is_newest(self) -> bool:
        return self.retcode in (200, 210, 1210)


@dataclass
class CotaResourceBean:
    """COTA resource package details."""
    project_code: str = ""
    project_name: str = ""
    project_type: int = 0
    carrier_name: str = ""
    download_url: str = ""
    package_ver: str = ""
    package_size: int = 0
    package_sha256: str = ""
    apk_name_list: List[str] = field(default_factory=list)
    activate_log_url: str = ""
    activate_log_html: str = ""
    activate_logo_url: str = ""

    @classmethod
    def from_json(cls, data: dict) -> "CotaResourceBean":
        if not data:
            return cls()
        return cls(
            project_code=data.get("projectCode", ""),
            project_name=data.get("projectName", ""),
            project_type=int(data.get("projectType", 0)),
            carrier_name=data.get("carrierName", ""),
            download_url=data.get("customPackageUrl", data.get("downloadUrl", "")),
            package_ver=data.get("customPackageVer", data.get("packageVer", "")),
            package_size=int(data.get("customPackageSize", data.get("size", 0))),
            package_sha256=data.get("customPackageSha256", data.get("sha256", "")),
            apk_name_list=data.get("apkNameList", []),
            activate_log_url=data.get("activateLogUrl", ""),
            activate_log_html=data.get("activateLogHtml", ""),
            activate_logo_url=data.get("activateLogoUrl", ""),
        )


@dataclass
class CotaConfigBean:
    """COTA behavior configuration from server."""
    force_activate: int = 0
    auto_download: int = 0
    auto_activate: int = 0
    wifi_only: int = 0
    enable_clear_data: int = 0
    need_enable_vtrust: int = 0
    write_rpmb: int = 0
    reboot_instantly: int = 0
    antiflash_level: int = 0
    apk_install_level: int = 0
    need_download_pkg: int = 0
    free_traffic: int = 0
    check_interval_minutes: int = 4320
    activate_notify_level: int = 0
    activate_popout_level: int = 0
    activate_boot_guide_level: int = 0
    request_max_days: int = 0
    custom_prompt_content: int = 0
    dialog_content: Optional[Dict] = None

    @classmethod
    def from_json(cls, data: dict) -> "CotaConfigBean":
        if not data:
            return cls()
        return cls(
            force_activate=int(data.get("forceActivate", 0)),
            auto_download=int(data.get("autoDownload", 0)),
            auto_activate=int(data.get("autoActivate", 0)),
            wifi_only=int(data.get("onlyWifiDownload", data.get("wifiOnly", 0))),
            enable_clear_data=int(data.get("enableClearData", 0)),
            need_enable_vtrust=int(data.get("needEnableVtrust", 0)),
            write_rpmb=int(data.get("writeRpmbZone", data.get("isWriteRpmb", 0))),
            reboot_instantly=int(data.get("activeRestart", data.get("isRebootInstantly", 0))),
            antiflash_level=int(data.get("antiflashlevel", 0)),
            apk_install_level=int(data.get("apkInstallLevel", data.get("activeForceInstall", 0))),
            need_download_pkg=int(data.get("needDownloadPkg", data.get("needDownloadPackage", 0))),
            free_traffic=int(data.get("freeDownload", data.get("isFreeTraffic", 0))),
            check_interval_minutes=int(data.get("checkIntervalMinutes", data.get("checkRate", 4320))),
            activate_notify_level=int(data.get("activateNotifyLevel", 0)),
            activate_popout_level=int(data.get("activatePopoutLevel", 0)),
            activate_boot_guide_level=int(data.get("activateBootGuideLevel", 0)),
            request_max_days=int(data.get("requestMaxDays", 0)),
            custom_prompt_content=int(data.get("customPromptContent", 0)),
            dialog_content=data.get("popoutContentMap"),
        )


@dataclass
class CotaActivationResult:
    """Complete parsed result from COTA activation query."""
    retcode: int = 0
    message: str = ""
    batch_no: int = 0
    resource: Optional[CotaResourceBean] = None
    config: Optional[CotaConfigBean] = None
    token: str = ""
    custom_content_detail: Optional[List] = None

    @property
    def has_activation(self) -> bool:
        return self.retcode == 0 and self.resource is not None


@dataclass
class CotaCustNameBean:
    """Carrier channel identification result."""
    cust_name: str = ""

    @classmethod
    def from_json(cls, data: dict) -> "CotaCustNameBean":
        if not data:
            return cls()
        return cls(cust_name=data.get("vgcCu", data.get("custName", "")))


@dataclass
class VTrustVerifyResult:
    """VTrust device verification response."""
    allow_rouse: bool = False

    @classmethod
    def from_json(cls, data: dict) -> "VTrustVerifyResult":
        if not data:
            return cls()
        return cls(allow_rouse=data.get("isAllowRouse", False))


@dataclass
class OemSyncResult:
    """OEM sync response."""
    domain: str = ""
    is_cota: bool = False
    is_vtrust: bool = False
    oem: str = ""
    imei: str = ""

    @classmethod
    def from_json(cls, data: dict) -> "OemSyncResult":
        if not data:
            return cls()
        return cls(
            domain=data.get("domain", ""),
            is_cota=data.get("isCota", False),
            is_vtrust=data.get("isVtrust", False),
            oem=data.get("oem", ""),
            imei=data.get("imei", ""),
        )


# ==========================================================================
# Crypto - Protocol Package helpers
# ==========================================================================

def parse_client_token(token_b64: str) -> dict:
    """Parse a CLIENT_TOKEN from its Base64 representation."""
    data = base64.b64decode(token_b64 + "==")
    off = 0
    header_len = struct.unpack(">I", data[off:off+4])[0]; off += 4
    _crc = struct.unpack(">Q", data[off:off+8])[0]; off += 8
    version = struct.unpack(">H", data[off:off+2])[0]; off += 2
    cipher_mode = struct.unpack(">I", data[off:off+4])[0]; off += 4

    def read_field():
        nonlocal off
        length = data[off]; off += 1
        val = data[off:off+length].decode("utf-8", errors="replace"); off += length
        return val

    tag = read_field()
    package_name = read_field()
    key_id = read_field()
    security_use = read_field()
    protection_config = read_field()

    return {
        "version": version,
        "cipher_mode": cipher_mode,
        "tag": tag,
        "package_name": package_name,
        "key_id": key_id,
        "security_use": security_use,
        "protection_config": json.loads(protection_config) if protection_config.startswith("{") else protection_config,
    }


def build_protocol_package(pkg_type: int, key_version: int, token: str, payload: bytes) -> bytes:
    """Build a ProtocolPackage wrapping encrypted data."""
    token_bytes = token.encode("utf-8")
    header = struct.pack(">BIH", pkg_type, key_version, len(token_bytes))
    return header + token_bytes + payload


def parse_protocol_package(data: bytes) -> tuple:
    """Parse a ProtocolPackage, return (pkg_type, key_version, token, payload)."""
    off = 0
    pkg_type = data[off]; off += 1
    key_version = struct.unpack(">I", data[off:off+4])[0]; off += 4
    token_len = struct.unpack(">H", data[off:off+2])[0]; off += 2
    token = data[off:off+token_len].decode("utf-8"); off += token_len
    payload = data[off:]
    return pkg_type, key_version, token, payload


# ==========================================================================
# Crypto - Signature verification
# ==========================================================================

def verify_rsa_signature(data: bytes, signature_hex: str) -> bool:
    """Verify SHA256withRSA signature using the hardcoded Updater RSA key."""
    try:
        pubkey_der = base64.b64decode(UPDATER_RSA_PUBKEY)
        key = RSA.import_key(pubkey_der)
        h = SHA256.new(data)
        sig_bytes = bytes.fromhex(signature_hex)
        pkcs1_15.new(key).verify(h, sig_bytes)
        return True
    except (ValueError, TypeError) as e:
        log.warning("RSA signature verification failed: %s", e)
        return False


def verify_ec_signature(data: bytes, signature_hex: str) -> bool:
    """Verify SHA256WithECDSA signature using the hardcoded EC P-384 key."""
    try:
        pubkey_der = base64.b64decode(UPDATER_EC_PUBKEY)
        key = ECC.import_key(pubkey_der)
        h = SHA256.new(data)
        sig_bytes = bytes.fromhex(signature_hex)
        DSS.new(key, "fips-186-3").verify(h, sig_bytes)
        return True
    except (ValueError, TypeError) as e:
        log.warning("EC signature verification failed: %s", e)
        return False


def compute_device_fingerprint(model: str, hw_ver: str, imei: str,
                                emmc_id: str, sw_ver: str, check_string: str) -> str:
    """
    Compute device fingerprint for auth binding.
    SHA256(model + hwVer + SHA256(imei) + SHA256(emmcId) + swVer + checkString)
    """
    imei_hash = hashlib.sha256(imei.encode()).hexdigest()
    emmc_hash = hashlib.sha256(emmc_id.encode()).hexdigest()
    combined = f"{model}{hw_ver}{imei_hash}{emmc_hash}{sw_ver}{check_string}"
    return hashlib.sha256(combined.encode()).hexdigest()


# ==========================================================================
# Crypto - Backends
# ==========================================================================

class CryptoBackend(ABC):
    """Abstract base for encryption/decryption backends."""

    @abstractmethod
    def encrypt_params(self, plaintext: str) -> str: ...

    @abstractmethod
    def decrypt_response(self, ciphertext: str) -> str: ...

    @abstractmethod
    def encrypt_url(self, url: str, mode: int = 1) -> str: ...

    def encrypt_string(self, plaintext: str) -> str:
        return self.encrypt_params(plaintext)

    def decrypt_string(self, ciphertext: str) -> str:
        return self.decrypt_response(ciphertext)


class DirectAESBackend(CryptoBackend):
    """
    Uses the extracted Vivo AES-128-CBC key with ProtocolPackage wrapping.

    Extracted key: 836e75afddae728551ad22b2bae6ca57
    Static IV:     047cd76d65d3b28b4ccc2c0246681aa6
    Token:         jnisgmain_v2@com.bbk.updater
    Key version:   2
    Package type:  5 (PKGTYPE_AES_ENCRYPT)
    """

    VIVO_KEY = bytes.fromhex("836e75afddae728551ad22b2bae6ca57")
    VIVO_IV = bytes.fromhex("047cd76d65d3b28b4ccc2c0246681aa6")
    TOKEN = "jnisgmain_v2@com.bbk.updater"
    KEY_VERSION = 2
    PKG_TYPE_AES = 5

    def __init__(self, key: Optional[bytes] = None, iv: Optional[bytes] = None):
        self.key = key or self.VIVO_KEY
        self.iv = iv or self.VIVO_IV
        if len(self.key) not in (16, 24, 32):
            raise ValueError(f"AES key must be 16/24/32 bytes, got {len(self.key)}")

    def _aes_encrypt(self, plaintext: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return cipher.encrypt(pad(plaintext, AES.block_size))

    def _aes_decrypt(self, ciphertext: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)

    def _wrap_protocol(self, ciphertext: bytes) -> bytes:
        token_bytes = self.TOKEN.encode("utf-8")
        header = b'\x00\x2c\x00\x00\x00\x00'
        header += struct.pack(">I", 0x8926065d)
        header += b'\x00\x01'
        header += bytes([len(token_bytes)])
        header += token_bytes
        header += bytes([0x00, self.KEY_VERSION, self.PKG_TYPE_AES])
        return header + ciphertext

    def _unwrap_protocol(self, data: bytes) -> bytes:
        token_bytes = self.TOKEN.encode("utf-8")
        idx = data.find(token_bytes)
        if idx >= 0:
            ct_start = idx + len(token_bytes) + 3
            return data[ct_start:]
        for tok in [b"jnisgmain_v2@", b"jnisgmain@"]:
            idx = data.find(tok)
            if idx >= 0:
                end = data.find(b'\x00', idx + len(tok))
                if end >= 0:
                    return data[end + 3:]
        return data

    def encrypt_params(self, plaintext: str) -> str:
        ct = self._aes_encrypt(plaintext.encode("utf-8"))
        wrapped = self._wrap_protocol(ct)
        return base64.b64encode(wrapped).decode("ascii")

    def decrypt_response(self, ciphertext: str) -> str:
        decoded = ciphertext
        try:
            b64 = decoded.replace('-', '+').replace('_', '/')
            while len(b64) % 4:
                b64 += '='
            raw = base64.b64decode(b64)
        except Exception:
            try:
                raw = base64.b64decode(decoded)
            except Exception:
                raw = decoded.encode("utf-8")
        ct = self._unwrap_protocol(raw)
        pt = self._aes_decrypt(ct)
        return pt.decode("utf-8")

    def encrypt_url(self, url: str, mode: int = 1) -> str:
        parsed = urllib.parse.urlparse(url)
        if parsed.query:
            encrypted = self.encrypt_params(parsed.query)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?jvq_param={urllib.parse.quote(encrypted)}"
        return url


class AdbProxyBackend(CryptoBackend):
    """
    Forwards encrypt/decrypt operations to an Android device running the
    VivoOtaCryptoProxy app via ADB.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 19847):
        self.host = host
        self.port = port
        self._setup_adb_forward()

    def _setup_adb_forward(self):
        try:
            subprocess.run(
                ["adb", "forward", f"tcp:{self.port}", f"tcp:{self.port}"],
                capture_output=True, timeout=5
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            log.warning("Could not set up ADB forward - ensure device is connected")

    def _rpc(self, method: str, data: str) -> str:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((self.host, self.port))
            request = json.dumps({"method": method, "data": data}).encode("utf-8")
            s.sendall(struct.pack(">I", len(request)) + request)
            resp_len = struct.unpack(">I", s.recv(4))[0]
            resp_data = b""
            while len(resp_data) < resp_len:
                resp_data += s.recv(resp_len - len(resp_data))
            result = json.loads(resp_data.decode("utf-8"))
            if result.get("error"):
                raise RuntimeError(f"Crypto proxy error: {result['error']}")
            return result["data"]

    def encrypt_params(self, plaintext: str) -> str:
        return self._rpc("encrypt_params", plaintext)

    def decrypt_response(self, ciphertext: str) -> str:
        return self._rpc("decrypt_response", ciphertext)

    def encrypt_url(self, url: str, mode: int = 1) -> str:
        return self._rpc("encrypt_url", json.dumps({"url": url, "mode": mode}))


class PassthroughBackend(CryptoBackend):
    """No encryption - passes data through unchanged. For local testing only."""

    def encrypt_params(self, plaintext: str) -> str:
        return base64.b64encode(plaintext.encode("utf-8")).decode("ascii")

    def decrypt_response(self, ciphertext: str) -> str:
        try:
            return base64.b64decode(ciphertext).decode("utf-8")
        except Exception:
            return urllib.parse.unquote(ciphertext)

    def encrypt_url(self, url: str, mode: int = 1) -> str:
        return url


# ==========================================================================
# HTTP Client
# ==========================================================================

class VivoHttpClient:
    """HTTP client implementing the Vivo OTA protocol."""

    def __init__(self, device: DeviceConfig, domains: DomainConfig,
                 crypto: CryptoBackend):
        self.device = device
        self.domains = domains
        self.crypto = crypto
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "text/plain",
            "Connection": "close",
            "User-Agent": "",
        })
        self.session.trust_env = False
        self.timeout = 6.0

    # -- FOTA parameter builders --

    def build_fota_check_params(self, is_manual: bool = True,
                                 is_full: bool = False,
                                 vgc_sw_ver: str = "",
                                 vgc_cu: str = "",
                                 check_trigger: str = "MANUL") -> Dict[str, str]:
        d = self.device
        return {
            "model": d.model,
            "dModel": d.update_model,
            "imei": d.imei,
            "s_n": d.serial_last5,
            "dType": d.device_type,
            "version": d.build_version,
            "public_model": d.public_model,
            "cy": d.country_region,
            "cu": d.customize_bbk,
            "vgcSwVer": vgc_sw_ver,
            "vgcCu": vgc_cu or d.customize_bbk,
            "hasVgc": "1" if vgc_sw_ver else "0",
            "cuFlag": "",
            "elapsedtime": str(int(time.time() * 1000)),
            "st1": "",
            "st2": "",
            "emmcid": d.emmc_id,
            "fullVer": d.build_version,
            "scy": d.country_region,
            "si": "",
            "ne": "",
            "ch": "",
            "hwVer": d.hardware_version,
            "swVer": d.software_version,
            "language": "en",
            "isMan": "1" if is_manual else "0",
            "isFull": "1" if is_full else "0",
            "protocalversion": d.protocol_version,
            "disDownable": "0",
            "checkTrige": check_trigger,
            "isstlifeover": "0",
            "countrycode": d.country_region,
            "alwaysFailedVersion": "",
        }

    def build_fota_auth_params(self, check_string: str,
                                target_version: str) -> Dict[str, str]:
        d = self.device
        return {
            "checkString": check_string,
            "model": d.model,
            "hwVer": d.hardware_version,
            "swVer": d.software_version,
            "version": target_version,
            "imei": d.imei,
            "emmcid": d.emmc_id,
        }

    def build_fota_download_params(self, version: str,
                                    is_manual: bool = True) -> Dict[str, str]:
        return {
            "upversion": version,
            "dlrequest": "1" if is_manual else "0",
            "timestamp": str(int(time.time() * 1000)),
            "trialversion": "0",
        }

    # -- COTA parameter builders --

    def build_cota_channel_params(self) -> Dict[str, str]:
        d = self.device
        return {
            "model": d.model,
            "hardwareVer": d.hardware_version,
            "region": d.country_region,
            "imei": d.imei,
            "deviceType": d.device_type,
            "snp": d.serial_number,
        }

    def build_cota_activation_params(self, map_key: str = "",
                                      vgc_type: str = "",
                                      oem_type: str = "",
                                      token: str = "",
                                      activate_way: int = 0) -> Dict[str, str]:
        d = self.device
        return {
            "version": d.build_version,
            "imei": d.imei,
            "internalModel": d.internal_model,
            "deriveModel": d.model,
            "hardwareVer": d.hardware_version,
            "mapKey": map_key,
            "region": d.country_region,
            "androidVer": d.android_version,
            "systemVer": d.software_version,
            "vgcType": vgc_type,
            "oemType": oem_type,
            "token": token,
            "activateWay": str(activate_way),
            "timestamp": str(int(time.time() * 1000)),
            "deviceType": d.device_type,
            "snp": d.serial_number,
        }

    def build_vtrust_verify_params(self, wakeup_type: int = 1) -> Dict[str, str]:
        d = self.device
        return {
            "imei": d.imei,
            "emmcid": d.emmc_id,
            "sysVer": d.software_version,
            "model": d.model,
            "region": d.country_region,
            "standardInfo": d.customize_bbk,
            "wakeupType": str(wakeup_type),
            "timestamp": str(int(time.time() * 1000)),
        }

    def build_oem_sync_params(self) -> Dict[str, str]:
        d = self.device
        return {
            "imei": d.imei,
            "emmcid": d.emmc_id,
            "model": d.model,
            "region": d.country_region,
            "sysVer": d.software_version,
        }

    # -- HTTP transport --

    def _encode_params(self, params: Dict[str, str]) -> str:
        query = urllib.parse.urlencode(params)
        return self.crypto.encrypt_params(query)

    def _decode_response(self, text: str) -> dict:
        if not text:
            return {}
        try:
            decrypted = self.crypto.decrypt_response(urllib.parse.unquote(text))
            return json.loads(decrypted)
        except Exception:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                log.error("Failed to decode response: %s...", text[:200])
                return {}

    def post_encrypted(self, url: str, params: Dict[str, str]) -> dict:
        encrypted = self._encode_params(params)
        body = f"jvq_param={urllib.parse.quote(encrypted)}"
        log.debug("POST %s", url)
        log.debug("Params: %s", json.dumps(params, indent=2))
        try:
            resp = self.session.post(
                url, data=body, timeout=self.timeout,
                headers={"Content-Type": "text/plain"}
            )
            resp.raise_for_status()
            result = self._decode_response(resp.text)
            log.debug("Response retcode=%s", result.get("retcode"))
            return result
        except requests.RequestException as e:
            log.error("HTTP request failed: %s", e)
            return {"retcode": -1, "message": str(e)}

    def post_form_encrypted(self, url: str, params: Dict[str, str]) -> dict:
        encrypted_params = {}
        for k, v in params.items():
            encrypted_params[k] = self.crypto.encrypt_string(v) if v else v
        log.debug("POST (form) %s", url)
        try:
            resp = self.session.post(
                url, data=encrypted_params, timeout=self.timeout,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            resp.raise_for_status()
            return self._decode_response(resp.text)
        except requests.RequestException as e:
            log.error("HTTP request failed: %s", e)
            return {"retcode": -1, "message": str(e)}

    def post_json(self, url: str, payload: dict) -> dict:
        log.debug("POST (json) %s", url)
        try:
            resp = self.session.post(
                url, json=payload, timeout=self.timeout,
                headers={"Content-Type": "application/json"}
            )
            resp.raise_for_status()
            return self._decode_response(resp.text)
        except requests.RequestException as e:
            log.error("HTTP request failed: %s", e)
            return {"retcode": -1, "message": str(e)}

    def download_file(self, url: str, dest_path: str,
                      progress_cb=None) -> bool:
        log.info("Downloading %s -> %s", url, dest_path)
        try:
            resp = self.session.get(url, stream=True, timeout=30)
            resp.raise_for_status()
            total = int(resp.headers.get("content-length", 0))
            downloaded = 0
            with open(dest_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=65536):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if progress_cb and total:
                        progress_cb(downloaded, total)
            log.info("Download complete: %d bytes", downloaded)
            return True
        except requests.RequestException as e:
            log.error("Download failed: %s", e)
            return False


# ==========================================================================
# FOTA Client
# ==========================================================================

class FotaClient:
    """FOTA update client matching com.bbk.updater behavior."""

    def __init__(self, device: DeviceConfig, domains: DomainConfig,
                 crypto: CryptoBackend):
        self.device = device
        self.domains = domains
        self.crypto = crypto
        self.http = VivoHttpClient(device, domains, crypto)

    def check_update(self, is_manual: bool = True,
                     vgc_sw_ver: str = "",
                     vgc_cu: str = "") -> UpdateCheckResult:
        """
        Check for system updates.
        Returns UpdateCheckResult with retcode:
          0    = new update available
          200  = success (generic)
          210  = already on newest version
          1210 = newest + auth info included
        """
        url = self.domains.fota_check_url
        params = self.http.build_fota_check_params(
            is_manual=is_manual, vgc_sw_ver=vgc_sw_ver, vgc_cu=vgc_cu,
        )
        log.info("Checking for FOTA update (manual=%s)...", is_manual)
        resp = self.http.post_encrypted(url, params)

        result = UpdateCheckResult(
            retcode=resp.get("retcode", -1),
            message=resp.get("message", ""),
        )

        data = resp.get("data", {})
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                data = {}

        if data:
            result.fota = UpdateInfo.from_json(data.get("patch", {}))
            result.vgc = VgcUpdateInfo.from_json(data.get("vgc", {}))
            result.ext = ExtendedInfo.from_json(data.get("ext", {}))

        if result.has_update and result.fota:
            log.info("Update available: %s (type=%s, size=%d)",
                     result.fota.version, result.fota.ota_type, result.fota.pkg_len)
        elif result.is_newest:
            log.info("Already on newest version")
        else:
            log.warning("Check returned retcode=%d: %s", result.retcode, result.message)

        return result

    def get_auth_info(self, check_string: str,
                      target_version: str) -> Optional[str]:
        """Exchange checkString for authInfo token."""
        url = self.domains.fota_auth_url
        params = self.http.build_fota_auth_params(check_string, target_version)
        log.info("Requesting auth token for version %s...", target_version)
        resp = self.http.post_encrypted(url, params)
        if resp.get("retcode") == 200:
            auth_info = resp.get("data", "")
            log.info("Auth token received (%d chars)", len(auth_info))
            return auth_info
        else:
            log.error("Auth request failed: retcode=%s, msg=%s",
                      resp.get("retcode"), resp.get("message"))
            return None

    def resolve_download_url(self, update: UpdateInfo,
                             is_manual: bool = True) -> Optional[str]:
        """Resolve the actual CDN download URL via redirect."""
        if not update.download_url:
            log.error("No download URL in update info")
            return None
        url = self.domains.fota_redirect_url
        params = self.http.build_fota_download_params(
            version=update.version, is_manual=is_manual,
        )
        log.info("Resolving download URL...")
        resp = self.http.post_encrypted(url, params)
        if resp.get("data"):
            download_url = resp["data"]
            log.info("Resolved download URL: %s", download_url[:80])
            return download_url
        else:
            log.warning("Redirect failed, using original URL")
            return update.download_url

    def download_update(self, url: str, dest_dir: str,
                        filename: Optional[str] = None,
                        progress_cb: Optional[Callable] = None) -> Optional[str]:
        """Download the update package."""
        if not filename:
            filename = url.split("/")[-1].split("?")[0] or "update.zip"
        os.makedirs(dest_dir, exist_ok=True)
        dest_path = os.path.join(dest_dir, filename)
        if self.http.download_file(url, dest_path, progress_cb):
            return dest_path
        return None

    def verify_package(self, filepath: str, update: UpdateInfo) -> bool:
        """Verify downloaded package integrity (SHA256 + MD5)."""
        log.info("Verifying package %s...", filepath)
        if update.pkg_sha256:
            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256.update(chunk)
            file_hash = sha256.hexdigest()
            if file_hash.lower() != update.pkg_sha256.lower():
                log.error("SHA256 mismatch: expected %s, got %s",
                          update.pkg_sha256, file_hash)
                return False
            log.info("SHA256 verified OK")
        if update.pkg_md5:
            md5 = hashlib.md5()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    md5.update(chunk)
            file_hash = md5.hexdigest()
            if file_hash.lower() != update.pkg_md5.lower():
                log.error("MD5 mismatch: expected %s, got %s",
                          update.pkg_md5, file_hash)
                return False
            log.info("MD5 verified OK")
        return True

    def full_update_flow(self, dest_dir: str = "/tmp/vivo_ota",
                         progress_cb: Optional[Callable] = None) -> dict:
        """Execute the complete FOTA flow: check -> auth -> resolve -> download -> verify."""
        results = {"success": False}

        check = self.check_update()
        results["check"] = check
        if not check.has_update:
            results["message"] = "No update available"
            return results

        fota = check.fota
        results["version"] = fota.version

        if fota.check_string:
            auth_info = self.get_auth_info(fota.check_string, fota.version)
            results["auth_info"] = auth_info

        download_url = self.resolve_download_url(fota)
        results["download_url"] = download_url
        if not download_url:
            results["message"] = "Could not resolve download URL"
            return results

        filepath = self.download_update(
            download_url, dest_dir,
            filename=fota.pkg_name or None, progress_cb=progress_cb,
        )
        results["filepath"] = filepath
        if not filepath:
            results["message"] = "Download failed"
            return results

        verified = self.verify_package(filepath, fota)
        results["verified"] = verified
        results["success"] = verified
        results["message"] = (
            f"Update {fota.version} downloaded and verified" if verified
            else "Package verification failed"
        )
        return results


# ==========================================================================
# COTA Client
# ==========================================================================

class CotaClient:
    """COTA component update client matching com.vivo.cota behavior."""

    def __init__(self, device: DeviceConfig, domains: DomainConfig,
                 crypto: CryptoBackend):
        self.device = device
        self.domains = domains
        self.crypto = crypto
        self.http = VivoHttpClient(device, domains, crypto)

    def query_custom_channel(self) -> CotaCustNameBean:
        """Query the carrier/custom channel for this device."""
        url = self.domains.cota_activate_channel_url
        params = self.http.build_cota_channel_params()
        log.info("[cota_step1] Querying custom channel...")
        resp = self.http.post_form_encrypted(url, params)
        data = resp.get("data", {})
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                data = {}
        result = CotaCustNameBean.from_json(data)
        log.info("Custom channel: %s", result.cust_name or "(none)")
        return result

    def query_activation(self, map_key: str = "", vgc_type: str = "",
                         oem_type: str = "", token: str = "",
                         activate_way: int = 0) -> CotaActivationResult:
        """Query available activation resources from server."""
        url = self.domains.cota_activate_query_url
        params = self.http.build_cota_activation_params(
            map_key=map_key, vgc_type=vgc_type, oem_type=oem_type,
            token=token, activate_way=activate_way,
        )
        log.info("[cota_step2] Querying activation resources...")
        resp = self.http.post_encrypted(url, params)

        result = CotaActivationResult(
            retcode=resp.get("retcode", -1),
            message=resp.get("message", ""),
        )
        data = resp.get("data", {})
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                data = {}
        if data:
            result.batch_no = int(data.get("batchNo", 0))
            result.resource = CotaResourceBean.from_json(data.get("resource", {}))
            result.config = CotaConfigBean.from_json(data.get("config", {}))
            result.token = data.get("token", "")
            result.custom_content_detail = data.get("customContentDetail")

        if result.has_activation:
            log.info("Activation available: %s (carrier=%s, %d APKs, size=%d)",
                     result.resource.package_ver, result.resource.carrier_name,
                     len(result.resource.apk_name_list), result.resource.package_size)
        else:
            log.info("No activation available (retcode=%d)", result.retcode)
        return result

    def download_resource(self, resource: CotaResourceBean,
                          dest_dir: str = "/tmp/vivo_cota",
                          progress_cb: Optional[Callable] = None) -> Optional[str]:
        """Download the COTA resource package."""
        if not resource.download_url:
            log.error("No download URL in resource")
            return None
        log.info("[cota_step3] Downloading COTA resource...")
        download_url = self.crypto.encrypt_url(resource.download_url, mode=1)
        os.makedirs(dest_dir, exist_ok=True)
        dest_path = os.path.join(dest_dir, "cota_vgc.zip")
        if self.http.download_file(download_url, dest_path, progress_cb):
            return dest_path
        return None

    def verify_resource(self, filepath: str, resource: CotaResourceBean) -> bool:
        """Verify downloaded COTA package integrity."""
        log.info("[cota_step4] Verifying COTA resource...")
        if resource.package_sha256:
            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256.update(chunk)
            file_hash = sha256.hexdigest()
            if file_hash.lower() != resource.package_sha256.lower():
                log.error("SHA256 mismatch: expected %s, got %s",
                          resource.package_sha256, file_hash)
                return False
            log.info("SHA256 verified OK")
        if resource.package_size > 0:
            actual_size = os.path.getsize(filepath)
            if actual_size != resource.package_size:
                log.error("Size mismatch: expected %d, got %d",
                          resource.package_size, actual_size)
                return False
            log.info("Size verified OK")
        return True

    def report_activation(self, batch_no: int, resource: CotaResourceBean,
                          success: bool = True, code: int = 1) -> dict:
        """Report activation result to server."""
        log.info("[cota_step5] Reporting activation result (success=%s)...", success)
        d = self.device
        params = {
            "imei": d.imei,
            "projectCode": resource.project_code,
            "projectType": str(resource.project_type),
            "batchNo": str(batch_no),
            "code": str(code if success else 0),
            "msg": "success" if success else "failed",
            "internalModel": d.internal_model,
            "deriveModel": d.model,
            "hardwareVer": d.hardware_version,
            "region": d.country_region,
            "systemVer": d.software_version,
            "packageVersion": resource.package_ver,
            "deviceType": d.device_type,
            "snp": d.serial_number,
        }
        return self.http.post_encrypted(self.domains.cota_activate_feedback_url, params)

    def report_rollback(self, resource: CotaResourceBean,
                        code: int = 1, msg: str = "success",
                        vtrust_result: int = 0, vtrust_desc: str = "",
                        rollback_way: int = 0, batch_no: int = 0) -> dict:
        """Report rollback result."""
        d = self.device
        params = {
            "imei": d.imei,
            "projectCode": resource.project_code,
            "projectType": str(resource.project_type),
            "appVer": d.build_version,
            "hardwareVer": d.hardware_version,
            "internalModel": d.internal_model,
            "deriveModel": d.model,
            "mapKey": "",
            "region": d.country_region,
            "vgcType": "",
            "androidVer": d.android_version,
            "systemVer": d.software_version,
            "oemType": "",
            "code": str(code),
            "msg": msg,
            "packageVersion": resource.package_ver,
            "enableVtrustResult": str(vtrust_result),
            "enableVtrustDesc": vtrust_desc,
            "deviceType": d.device_type,
            "snp": d.serial_number,
            "rollbackWay": str(rollback_way),
            "batchNo": str(batch_no),
        }
        return self.http.post_encrypted(self.domains.cota_restore_feedback_url, params)

    def verify_vtrust(self, wakeup_type: int = 1) -> VTrustVerifyResult:
        """Verify VTrust device status with server."""
        url = self.domains.vem_vtrust_check_url
        params = self.http.build_vtrust_verify_params(wakeup_type)
        log.info("Verifying VTrust status (wakeup_type=%d)...", wakeup_type)
        resp = self.http.post_json(url, params)
        data = resp.get("data", {})
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                data = {}
        result = VTrustVerifyResult.from_json(data)
        log.info("VTrust allow_rouse=%s", result.allow_rouse)
        return result

    def sync_oem(self) -> OemSyncResult:
        """Sync OEM parameters with server."""
        url = self.domains.vem_oem_sync_url
        params = self.http.build_oem_sync_params()
        log.info("Syncing OEM parameters...")
        resp = self.http.post_json(url, params)
        data = resp.get("data", {})
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                data = {}
        result = OemSyncResult.from_json(data)
        log.info("OEM sync: isCota=%s, isVtrust=%s, oem=%s",
                 result.is_cota, result.is_vtrust, result.oem)
        return result

    def get_failover_frequency(self) -> dict:
        """Get sync/retry frequency configuration from server."""
        d = self.device
        params = {"imei": d.imei, "model": d.model, "region": d.country_region}
        return self.http.post_encrypted(self.domains.cota_failover_frequency_url, params)

    def full_activation_flow(self, map_key: str = "",
                             dest_dir: str = "/tmp/vivo_cota",
                             progress_cb: Optional[Callable] = None) -> dict:
        """Execute the complete 5-step COTA activation flow."""
        results = {"success": False}

        channel = self.query_custom_channel()
        results["channel"] = channel.cust_name

        activation = self.query_activation(map_key=map_key, vgc_type=channel.cust_name)
        results["activation"] = activation
        if not activation.has_activation:
            results["message"] = "No activation available"
            return results

        resource = activation.resource

        filepath = self.download_resource(resource, dest_dir, progress_cb)
        results["filepath"] = filepath
        if not filepath:
            results["message"] = "Download failed"
            return results

        verified = self.verify_resource(filepath, resource)
        results["verified"] = verified
        if not verified:
            results["message"] = "Verification failed"
            return results

        report = self.report_activation(
            batch_no=activation.batch_no, resource=resource, success=True,
        )
        results["report"] = report
        results["success"] = True
        results["message"] = (
            f"COTA activation {resource.package_ver} "
            f"({resource.carrier_name}) downloaded and verified"
        )
        return results


# ==========================================================================
# CLI
# ==========================================================================

def progress_bar(downloaded: int, total: int):
    pct = downloaded * 100 // total
    bar = "#" * (pct // 2) + "-" * (50 - pct // 2)
    print(f"\r  [{bar}] {pct}% ({downloaded}/{total})", end="", flush=True)
    if downloaded >= total:
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Vivo OTA update checker and downloader",
    )
    parser.add_argument("--imei", required=True, help="Device IMEI")
    parser.add_argument("--serial", required=True, help="Device serial number")
    parser.add_argument("--emmc-id", default="", help="eMMC ID (optional but recommended)")
    parser.add_argument("--crypto", choices=["aes", "adb", "passthrough"], default="aes",
                        help="Crypto backend (default: aes)")
    parser.add_argument("--adb-port", type=int, default=19847,
                        help="ADB proxy port (for adb backend)")
    parser.add_argument("--check-only", action="store_true",
                        help="Only check for updates, don't download")
    parser.add_argument("--output-dir", default="/tmp/vivo_ota",
                        help="Download directory (default: /tmp/vivo_ota)")
    parser.add_argument("--full-pkg", action="store_true",
                        help="Request full update package instead of incremental")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    device = DeviceConfig(
        imei=args.imei,
        serial_number=args.serial,
        emmc_id=args.emmc_id,
    )
    domains = DomainConfig()

    if args.crypto == "adb":
        crypto = AdbProxyBackend(port=args.adb_port)
    elif args.crypto == "passthrough":
        crypto = PassthroughBackend()
    else:
        crypto = DirectAESBackend()

    client = FotaClient(device, domains, crypto)

    print(f"Checking for updates for {device.internal_model} ({device.build_version})...")
    check = client.check_update(is_manual=True)

    if check.is_newest:
        print("Already on the newest version.")
        return 0

    if not check.has_update:
        print(f"No update available (retcode={check.retcode}: {check.message})")
        return 1

    fota = check.fota
    print(f"\nUpdate found!")
    print(f"  Version:  {fota.version}")
    print(f"  Type:     {fota.ota_type}")
    print(f"  Size:     {fota.pkg_len / (1024*1024):.1f} MB")
    print(f"  Package:  {fota.pkg_name}")

    if check.ext:
        print(f"  Full pkg: {'yes' if check.ext.is_full else 'incremental'}")

    if args.check_only:
        print(f"\n  Download URL: {fota.download_url}")
        return 0

    if fota.check_string:
        print("\nRequesting auth token...")
        auth_info = client.get_auth_info(fota.check_string, fota.version)
        if auth_info:
            print(f"  Auth token received ({len(auth_info)} chars)")
        else:
            print("  Warning: auth token request failed (download may still work)")

    print("\nResolving download URL...")
    download_url = client.resolve_download_url(fota)
    if not download_url:
        print("Error: could not resolve download URL")
        return 1
    print(f"  URL: {download_url[:100]}...")

    print(f"\nDownloading to {args.output_dir}/...")
    filepath = client.download_update(
        download_url, args.output_dir,
        filename=fota.pkg_name or None, progress_cb=progress_bar,
    )
    if not filepath:
        print("Error: download failed")
        return 1

    print("Verifying package integrity...")
    if client.verify_package(filepath, fota):
        print(f"\nSuccess! Update saved to: {filepath}")
        return 0
    else:
        print("\nError: package verification failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
