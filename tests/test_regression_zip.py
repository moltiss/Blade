"""Regression: malformed UTF-8 filename in a ZIP central directory."""
import struct
import zipfile

import pytest


def test_zip_rejects_invalid_utf8_filename(update_module, tmp_path):
    package = tmp_path / "malformed.zip"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("a.txt", b"test")

    # Mutate only central-directory metadata: set the UTF-8 flag and put an
    # invalid UTF-8 byte in the filename. No archive extraction is performed.
    data = bytearray(package.read_bytes())
    end = data.rindex(b"PK\x05\x06")
    central = struct.unpack_from("<I", data, end + 16)[0]
    assert data[central:central + 4] == b"PK\x01\x02"
    flags = struct.unpack_from("<H", data, central + 8)[0]
    struct.pack_into("<H", data, central + 8, flags | 0x800)
    data[central + 46] = 0x80
    package.write_bytes(data)

    with pytest.raises(update_module.UpdateError):
        update_module.validate_zip_package(package)
