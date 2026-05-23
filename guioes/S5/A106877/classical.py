import unicodedata


ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHABET_SIZE = len(ALPHABET)


def preproc(text):
    normalized = unicodedata.normalize("NFD", text)
    chars = []
    for char in normalized:
        if unicodedata.category(char) == "Mn":
            continue
        char = char.upper()
        if "A" <= char <= "Z":
            chars.append(char)
    return "".join(chars)


def key_to_shift(char):
    char = preproc(char)
    if len(char) != 1:
        raise ValueError("key must be one letter")
    return ord(char) - ord("A")


def shift_to_key(shift):
    return chr(ord("A") + (shift % ALPHABET_SIZE))


def caesar(text, shift):
    output = []
    for char in preproc(text):
        pos = ord(char) - ord("A")
        output.append(chr(ord("A") + ((pos + shift) % ALPHABET_SIZE)))
    return "".join(output)


def vigenere(text, key, decrypt=False):
    clean_text = preproc(text)
    clean_key = preproc(key)
    if not clean_key:
        raise ValueError("key must not be empty")

    output = []
    for index, char in enumerate(clean_text):
        shift = key_to_shift(clean_key[index % len(clean_key)])
        if decrypt:
            shift = -shift
        output.append(caesar(char, shift))
    return "".join(output)


def xor_bytes(data, key):
    if len(key) < len(data):
        raise ValueError("key is shorter than data")
    return bytes(byte ^ key[index] for index, byte in enumerate(data))
