#!/usr/bin/env python3
import sys

try:
    import hashpumpy
except Exception as exc:  # pragma: no cover - runtime dependency
    print(f"Error: hashpumpy is required: {exc}", file=sys.stderr)
    raise SystemExit(1)

KEY_SIZE = 32


def usage() -> None:
    print("Usage: mac_sha256_attack.py <fich> <ext>", file=sys.stderr)


def main() -> int:
    if len(sys.argv) != 3:
        usage()
        return 1

    fich = sys.argv[1]
    ext = sys.argv[2]

    with open(fich, "rb") as f:
        msg = f.read()
    with open(fich + ".mac", "rb") as f:
        tag = f.read()

    msg_str = msg.decode("latin1")
    tag_hex = tag.hex()

    new_tag_hex, new_msg_str = hashpumpy.hashpump(tag_hex, msg_str, ext, KEY_SIZE)
    new_msg = new_msg_str.encode("latin1")
    new_tag = bytes.fromhex(new_tag_hex)

    with open(fich + ".ext", "wb") as f:
        f.write(new_msg)
    with open(fich + ".ext.mac", "wb") as f:
        f.write(new_tag)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
