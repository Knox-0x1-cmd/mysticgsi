import json
import os
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

import cli
from make import RomPorter
from tools.image import signing


@pytest.mark.skipif(not shutil.which("openssl"), reason="needs OpenSSL")
def test_signed_image_has_valid_footer_and_detects_corruption(tmp_path):
    image = tmp_path / "system.img"
    payload = bytes(range(256)) * 4096
    image.write_bytes(payload)

    assert signing.sign_system_image(str(image)) == 0
    with image.open("rb") as stream:
        assert stream.read(len(payload)) == payload
        stream.seek(-64, os.SEEK_END)
        magic, major, minor, original, offset, size = struct.unpack(
            "!4sIIQQQ28x", stream.read(64))
        assert (magic, major, minor, original) == (
            b"AVBf", 1, 0, len(payload))
        assert original < offset < image.stat().st_size - 64
        assert size > 0
    verify = [sys.executable, signing.AVBTOOL, "verify_image",
              "--image", str(image), "--key", signing.TEST_KEY]
    assert subprocess.run(verify, capture_output=True).returncode == 0

    with image.open("r+b") as stream:
        stream.seek(4096)
        stream.write(b"corrupted")
    assert subprocess.run(verify, capture_output=True).returncode != 0


@pytest.mark.skipif(not shutil.which("openssl"), reason="needs OpenSSL")
@pytest.mark.parametrize("key_bits", [None, 2048, 4096])
def test_rebuild_publishes_and_compresses_signed_image(
        tmp_path, monkeypatch, key_bits):
    monkeypatch.chdir(tmp_path)
    system = tmp_path / "tmp/test/images/system"
    system.mkdir(parents=True)
    out = tmp_path / "out/test"
    out.mkdir(parents=True)
    (out / "rebuilt.zip").write_bytes(b"stale archive")
    (out / "output.txt").write_text("Raw Image Size: old\n")
    payload = bytes(range(256)) * 4096
    key_path = signing.TEST_KEY
    args = ["cli.py", "rebuild", "test", "--compress"]
    if key_bits:
        key_path = str(tmp_path / "custom key.pem")
        subprocess.run([
            "openssl", "genpkey", "-algorithm", "RSA",
            "-pkeyopt", f"rsa_keygen_bits:{key_bits}", "-out", key_path,
        ], check=True, capture_output=True)
        args += ["--avb-key", key_path]
    (tmp_path / "tmp/gsilist.json").write_text(json.dumps([{
        "rom_name": "test", "output_name": "rebuilt",
        "output": "Raw Image Size: old\n",
    }]))

    def build_image(**kwargs):
        Path(kwargs["output_image"]).write_bytes(payload)
        return 0

    monkeypatch.setattr("tools.build_system_image", build_image)
    monkeypatch.setattr("tools.check_environment", lambda: None)
    monkeypatch.setattr(sys, "argv", args)
    assert cli.main() == 0
    image = out / "rebuilt.img"
    assert image.stat().st_size > len(payload)
    assert "old" not in (out / "output.txt").read_text()
    with zipfile.ZipFile(out / "rebuilt.zip") as archive:
        assert archive.namelist() == ["system.img"]
        assert archive.read("system.img") == image.read_bytes()
    (out / "system.img").symlink_to(image.name)
    result = subprocess.run([
        sys.executable, signing.AVBTOOL, "verify_image",
        "--image", str(out / "system.img"), "--key", key_path,
    ], capture_output=True)
    assert result.returncode == 0
    if key_bits:
        result = subprocess.run([
            sys.executable, signing.AVBTOOL, "verify_image",
            "--image", str(out / "system.img"), "--key", signing.TEST_KEY,
        ], capture_output=True)
        assert result.returncode != 0
    result = subprocess.run([
        sys.executable, signing.AVBTOOL, "info_image",
        "--image", str(image),
    ], capture_output=True, text=True, check=True)
    assert f"SHA256_RSA{key_bits or 2048}" in result.stdout


@pytest.mark.parametrize("key_kind", [
    "empty", "missing", "malformed", "public", "encrypted", "unsupported",
])
def test_invalid_custom_key_stops_before_build(
        tmp_path, monkeypatch, key_kind):
    from Crypto.PublicKey import RSA

    key_path = tmp_path / "key.pem"
    if key_kind == "malformed":
        key_path.write_bytes(b"-----BEGIN PRIVATE KEY-----\nbroken\n")
    elif key_kind in ("public", "encrypted", "unsupported"):
        key = RSA.generate(1024)
        if key_kind == "public":
            data = key.public_key().export_key()
        elif key_kind == "encrypted":
            data = key.export_key(passphrase="secret")
        else:
            data = key.export_key()
        key_path.write_bytes(data)

    def unexpected_build(*args, **kwargs):
        pytest.fail("invalid key reached the build pipeline")

    monkeypatch.setattr(RomPorter, "build", unexpected_build)
    monkeypatch.setattr(sys, "argv", [
        "cli.py", "build", "test", "firmware.zip",
        "--avb-key", "" if key_kind == "empty" else str(key_path),
    ])
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2


@pytest.mark.parametrize("failed_step", [
    "add_hashtree_footer", "verify_image", "invalid_key",
])
def test_signing_failure_preserves_published_image(
        tmp_path, monkeypatch, failed_step):
    monkeypatch.chdir(tmp_path)
    system = tmp_path / "system"
    system.mkdir()
    out = tmp_path / "out/test"
    out.mkdir(parents=True)
    destination = out / "previous.img"
    destination.write_bytes(b"previous signed image")
    porter = RomPorter("test")
    porter.partition_dirs = {"system": str(system)}
    porter.images_dir = str(tmp_path)
    if failed_step == "invalid_key":
        porter.avb_key = str(tmp_path / "missing.pem")

    def build_image(**kwargs):
        Path(kwargs["output_image"]).write_bytes(b"new filesystem")
        return 0

    def run_signing(command):
        image = Path(command[command.index("--image") + 1])
        image.write_bytes(b"partial signature")
        return 1 if command[2] == failed_step else 0

    monkeypatch.setattr("tools.build_system_image", build_image)
    monkeypatch.setattr(signing.fsops, "run", run_signing)
    assert porter._write_image("previous") is None
    assert destination.read_bytes() == b"previous signed image"
    assert list(out.iterdir()) == [destination]
