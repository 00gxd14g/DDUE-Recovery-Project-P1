from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class NtfsBoot:
    bytes_per_sector: int
    sectors_per_cluster: int
    total_sectors: int
    mft_lcn: int
    mftmirr_lcn: int
    file_record_size: int

    @property
    def cluster_size(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster

    @property
    def volume_size_bytes(self) -> int:
        return self.total_sectors * self.bytes_per_sector


def parse_ntfs_boot_sector(buf: bytes) -> Optional[NtfsBoot]:
    if len(buf) < 512:
        return None
    # OEM ID is "NTFS    " at offset 3 (8 bytes).
    if buf[3:11] != b"NTFS    ":
        return None
    if buf[510:512] != b"\x55\xAA":
        return None
    bps = int(struct.unpack_from("<H", buf, 11)[0])
    spc = int(buf[13])
    total = int(struct.unpack_from("<Q", buf, 40)[0])
    mft_lcn = int(struct.unpack_from("<Q", buf, 48)[0])
    mftmirr_lcn = int(struct.unpack_from("<Q", buf, 56)[0])
    fr_raw = struct.unpack_from("<b", buf, 64)[0]  # signed
    if bps not in (512, 1024, 2048, 4096):
        return None
    if spc == 0:
        return None
    if total <= 0:
        return None
    if fr_raw == 0:
        return None
    if fr_raw > 0:
        file_record_size = fr_raw * (bps * spc)
    else:
        file_record_size = 1 << (-fr_raw)
    if file_record_size < 512 or file_record_size > 8192:
        # Typical is 1024; allow 512..8192
        return None
    cluster_size = bps * spc
    if cluster_size < 512 or cluster_size > 1024 * 1024:
        return None
    # Validate key cluster pointers stay within the volume.
    total_clusters = int(total // spc) if spc > 0 else 0
    if total_clusters <= 0:
        return None
    if mft_lcn <= 0 or mft_lcn >= total_clusters:
        return None
    if mftmirr_lcn <= 0 or mftmirr_lcn >= total_clusters:
        return None
    return NtfsBoot(
        bytes_per_sector=bps,
        sectors_per_cluster=spc,
        total_sectors=total,
        mft_lcn=mft_lcn,
        mftmirr_lcn=mftmirr_lcn,
        file_record_size=file_record_size,
    )


def is_probable_ntfs_boot_sector(buf: bytes) -> bool:
    return parse_ntfs_boot_sector(buf) is not None
