import os
import stat
import struct

import lz4.block

from tools.fs import unpack_filesystem
from tools.fs.f2fs import _crc32


BLOCK_SIZE = 4096


def _put32(data, offset, value):
    struct.pack_into('<I', data, offset, value)


def _put64(data, offset, value):
    struct.pack_into('<Q', data, offset, value)


def _make_inode(nid, mode, size, address=0, inline=None):
    node = bytearray(BLOCK_SIZE)
    struct.pack_into('<H', node, 0, mode)
    _put64(node, 16, size)
    if inline is None:
        _put32(node, 360, address)
    else:
        node[3] = 0x02
        node[364:364 + len(inline)] = inline
    _put32(node, 4072, nid)
    _put32(node, 4076, nid)
    return node


def _add_dentry(block, index, name, nid):
    block[index // 8] |= 1 << (index % 8)
    offset = 30 + index * 11
    _put32(block, offset + 4, nid)
    struct.pack_into('<H', block, offset + 8, len(name))
    block[2384 + index * 8:2384 + index * 8 + len(name)] = name


def _image(path):
    image = bytearray(64 * BLOCK_SIZE)
    sb = memoryview(image)[1024:1024 + 3072]
    _put32(sb, 0, 0xF2F52010)
    _put32(sb, 16, 12)
    _put32(sb, 20, 3)
    _put64(sb, 36, 64)
    _put32(sb, 60, 2)
    _put32(sb, 76, 2)
    _put32(sb, 84, 20)
    _put32(sb, 92, 40)
    _put32(sb, 96, 3)

    cp = bytearray(BLOCK_SIZE)
    _put64(cp, 0, 1)
    _put32(cp, 132, 1)
    _put32(cp, 136, 8)
    _put32(cp, 140, 1)
    _put32(cp, 160, 1)
    _put32(cp, 164, 4092)
    cp[192] = 0x80
    _put32(cp, 4092, _crc32(cp[:4092]))
    image[2 * BLOCK_SIZE:3 * BLOCK_SIZE] = cp
    image[9 * BLOCK_SIZE:10 * BLOCK_SIZE] = cp

    summary = bytearray(BLOCK_SIZE)
    struct.pack_into('<H', summary, 3584, 1)
    _put32(summary, 3586, 3)
    _put32(summary, 3595, 40)
    image[3 * BLOCK_SIZE:4 * BLOCK_SIZE] = summary

    nat = bytearray(BLOCK_SIZE)
    _put32(nat, 4 * 9 + 5, 41)
    _put32(nat, 5 * 9 + 5, 42)
    image[28 * BLOCK_SIZE:29 * BLOCK_SIZE] = nat

    root = _make_inode(3, stat.S_IFDIR | 0o755, BLOCK_SIZE, 43)
    file_node = _make_inode(4, stat.S_IFREG | 0o755, 5000, 44)
    link = _make_inode(5, stat.S_IFLNK | 0o777, 5, inline=b'hello')
    for block, node in ((40, root), (41, file_node), (42, link)):
        image[block * BLOCK_SIZE:(block + 1) * BLOCK_SIZE] = node

    directory = bytearray(BLOCK_SIZE)
    _add_dentry(directory, 0, b'hello', 4)
    _add_dentry(directory, 1, b'link', 5)
    image[43 * BLOCK_SIZE:44 * BLOCK_SIZE] = directory
    image[44 * BLOCK_SIZE:45 * BLOCK_SIZE] = b'A' * BLOCK_SIZE
    path.write_bytes(image)


def test_f2fs_extracts_journal_nat_bitmap_sparse_file_and_link(tmp_path):
    image = tmp_path / 'system.img'
    output = tmp_path / 'system'
    _image(image)

    assert unpack_filesystem(str(image), str(output)) == 0
    assert (output / 'hello').read_bytes() == (
        b'A' * BLOCK_SIZE + b'\0' * 904)
    assert stat.S_IMODE((output / 'hello').stat().st_mode) == 0o755
    assert os.readlink(output / 'link') == 'hello'


def test_f2fs_extracts_inline_directory(tmp_path):
    image = tmp_path / 'system.img'
    output = tmp_path / 'system'
    _image(image)
    with image.open('r+b') as stream:
        stream.seek(40 * BLOCK_SIZE)
        root = bytearray(stream.read(BLOCK_SIZE))
        root[3] = 0x05
        _put64(root, 16, 0)
        root[364:364 + 3488] = b'\0' * 3488
        root[364] = 0x03
        for index, name, nid in ((0, b'hello', 4), (1, b'link', 5)):
            offset = 364 + 30 + index * 11
            _put32(root, offset + 4, nid)
            struct.pack_into('<H', root, offset + 8, len(name))
            start = 364 + 2032 + index * 8
            root[start:start + len(name)] = name
        stream.seek(40 * BLOCK_SIZE)
        stream.write(root)

    assert unpack_filesystem(str(image), str(output)) == 0
    assert (output / 'hello').read_bytes().startswith(b'A' * 100)
    assert os.readlink(output / 'link') == 'hello'


def test_f2fs_decompresses_lz4_cluster(tmp_path):
    image = tmp_path / 'system.img'
    output = tmp_path / 'system'
    _image(image)
    with image.open('r+b') as stream:
        stream.seek(41 * BLOCK_SIZE)
        node = bytearray(stream.read(BLOCK_SIZE))
        node[3] = 0x20
        _put32(node, 80, 0x04)
        struct.pack_into('<H', node, 360, 36)
        node[392] = 1
        node[393] = 2
        struct.pack_into('<H', node, 394, 1)
        _put32(node, 396, 0xfffffffe)
        _put32(node, 400, 44)
        stream.seek(41 * BLOCK_SIZE)
        stream.write(node)

        packed = lz4.block.compress(b'A' * (4 * BLOCK_SIZE),
                                    store_size=False)
        block = bytearray(BLOCK_SIZE)
        _put32(block, 0, len(packed))
        _put32(block, 4, _crc32(packed))
        block[24:24 + len(packed)] = packed
        stream.seek(44 * BLOCK_SIZE)
        stream.write(block)

    assert unpack_filesystem(str(image), str(output)) == 0
    assert (output / 'hello').read_bytes() == b'A' * 5000


def test_f2fs_rejects_truncated_image(tmp_path):
    image = tmp_path / 'system.img'
    output = tmp_path / 'system'
    _image(image)
    with image.open('r+b') as stream:
        stream.truncate(45 * BLOCK_SIZE)

    result = unpack_filesystem(str(image), str(output),
                               logger=lambda _: None)
    assert result == -1
    assert not output.exists()


def test_f2fs_rejects_corrupt_checkpoint(tmp_path):
    image = tmp_path / 'system.img'
    output = tmp_path / 'system'
    _image(image)
    with image.open('r+b') as stream:
        stream.seek(2 * BLOCK_SIZE + 132)
        stream.write(b'\xff')

    result = unpack_filesystem(str(image), str(output),
                               logger=lambda _: None)
    assert result == -1
    assert not output.exists()
