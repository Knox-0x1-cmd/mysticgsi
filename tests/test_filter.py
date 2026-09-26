import os
import zipfile

import pytest

from tools.extractor import extract_firmware, postprocess

TARGETS = {"system", "vendor", "product"}


def test_member_filter_keeps_only_what_the_pipeline_uses():
    kept = {
        "system.img", "system_a.img", "vendor-sign.img", "product.img.ext4",
        "super.img", "super_1.img", "system.img_sparsechunk.3",
        "system.new.dat.br", "system.transfer.list", "AP_G998B.tar.md5",
        "system_X-FLASH-ALL-C93B.sin", "UPDATE.APP", "fw.kdz",
        "vendor.bin", "super.bin", "super.img.lz4", "system.img.lz4",
    }
    dropped = {"modem.img", "boot.img", "NON-HLOS.bin", "xbl.elf",
               "vendor_boot.img", "system_other.img", "boot.img.lz4"}

    assert {n for n in kept | dropped
            if postprocess.is_wanted(n, TARGETS)} == kept


def test_qfil_archives_are_not_filtered(tmp_path):
    fw = tmp_path / "fw.zip"
    with zipfile.ZipFile(fw, "w") as zf:
        zf.writestr("rawprogram0.xml", """<data>
          <program SECTOR_SIZE_IN_BYTES="512" label="system"
                   filename="piece_1.img" start_sector="0"/></data>""")
        zf.writestr("piece_1.img", b"\x01" * 4096)

    rc = extract_firmware(str(fw), str(tmp_path / "out"),
                          target_partitions=["system"], logger=print)

    assert rc == 0
    assert (tmp_path / "out" / "system.img").read_bytes() == b"\x01" * 4096


def test_partition_dump_bin_files_become_images(tmp_path):
    fw = tmp_path / "dump.zip"
    with zipfile.ZipFile(fw, "w") as zf:
        zf.writestr("system.bin", b"\x02" * 4096)
        zf.writestr("lk.bin", b"\x03" * 4096)

    rc = extract_firmware(str(fw), str(tmp_path / "out"),
                          target_partitions=["system"], logger=lambda m: None)

    assert rc == 0
    assert os.listdir(tmp_path / "out") == ["system.img"]
    assert (tmp_path / "out" / "system.img").read_bytes() == b"\x02" * 4096


def test_lz4_partition_in_zip_reaches_postprocess(tmp_path):
    import lz4.frame

    firmware = tmp_path / "firmware.zip"
    with zipfile.ZipFile(firmware, "w") as archive:
        archive.writestr("system.img.lz4",
                         lz4.frame.compress(b"partition data"))
        archive.writestr("boot.img.lz4",
                         lz4.frame.compress(b"unwanted data"))
    output = tmp_path / "output"

    assert extract_firmware(str(firmware), str(output),
                            target_partitions=["system"]) == 0
    assert (output / "system.img").read_bytes() == b"partition data"
    assert list(output.iterdir()) == [output / "system.img"]


@pytest.mark.parametrize("name", [
    "system.bin", "system.ext4", "system.raw", "SYSTEM_A.BIN",
    "system.img.ext4", "system_a.img.zst",
])
def test_image_extensions_survive_archive_pipeline(tmp_path, name):
    firmware = tmp_path / "firmware.zip"
    with zipfile.ZipFile(firmware, "w") as archive:
        archive.writestr(f"images/{name}", b"partition data")
        archive.writestr("images/boot.bin", b"unwanted data")
    output = tmp_path / "output"

    assert extract_firmware(str(firmware), str(output),
                            target_partitions=["system"]) == 0
    assert (output / "system.img").read_bytes() == b"partition data"
    assert list(output.iterdir()) == [output / "system.img"]
