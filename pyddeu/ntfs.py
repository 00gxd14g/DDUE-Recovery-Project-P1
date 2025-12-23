from __future__ import annotations


def parse_runlist(runlist_bytes: bytes) -> list[tuple[int, int]]:
    """
    Decode an NTFS runlist.
    Returns a list of (length_in_clusters, lcn_delta) tuples.
    """
    runs: list[tuple[int, int]] = []
    i = 0
    while i < len(runlist_bytes):
        header = runlist_bytes[i]
        i += 1
        if header == 0:
            break
        len_bytes = header & 0x0F
        off_bytes = (header >> 4) & 0x0F
        if len_bytes == 0 or i + len_bytes + off_bytes > len(runlist_bytes):
            break
        length = int.from_bytes(runlist_bytes[i : i + len_bytes], "little", signed=False)
        i += len_bytes
        offset_delta = int.from_bytes(runlist_bytes[i : i + off_bytes], "little", signed=True)
        i += off_bytes
        runs.append((length, offset_delta))
    return runs

