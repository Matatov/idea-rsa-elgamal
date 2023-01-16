#!/usr/bin/env python
import random


# A Python implementation of the block cipher IDEA

# Copyright (c) 2015 Bo Zhu https://about.bozhu.me
# MIT License


def _mul(x, y):
    assert 0 <= x <= 0xFFFF
    assert 0 <= y <= 0xFFFF

    if x == 0:
        x = 0x10000
    if y == 0:
        y = 0x10000

    r = (x * y) % 0x10001

    if r == 0x10000:
        r = 0

    assert 0 <= r <= 0xFFFF
    return r


def _KA_layer(x1, x2, x3, x4, round_keys):
    assert 0 <= x1 <= 0xFFFF
    assert 0 <= x2 <= 0xFFFF
    assert 0 <= x3 <= 0xFFFF
    assert 0 <= x4 <= 0xFFFF
    z1, z2, z3, z4 = round_keys[0:4]
    assert 0 <= z1 <= 0xFFFF
    assert 0 <= z2 <= 0xFFFF
    assert 0 <= z3 <= 0xFFFF
    assert 0 <= z4 <= 0xFFFF

    y1 = _mul(x1, z1)
    y2 = (x2 + z2) % 0x10000
    y3 = (x3 + z3) % 0x10000
    y4 = _mul(x4, z4)

    return y1, y2, y3, y4


def _MA_layer(y1, y2, y3, y4, round_keys):
    assert 0 <= y1 <= 0xFFFF
    assert 0 <= y2 <= 0xFFFF
    assert 0 <= y3 <= 0xFFFF
    assert 0 <= y4 <= 0xFFFF
    z5, z6 = round_keys[4:6]
    assert 0 <= z5 <= 0xFFFF
    assert 0 <= z6 <= 0xFFFF

    p = y1 ^ y3
    q = y2 ^ y4

    s = _mul(p, z5)
    t = _mul((q + s) % 0x10000, z6)
    u = (s + t) % 0x10000

    x1 = y1 ^ t
    x2 = y2 ^ u
    x3 = y3 ^ t
    x4 = y4 ^ u

    return x1, x2, x3, x4


# mod 2**16
def _inverse_multiply(number):
    if number == 0:
        return 0
    return pow(number, 0xFFFF, 0x10001)


# mod 2**16
def _inverse_additive(number):
    return (-number) & 0xFFFF



class IDEA:
    def __init__(self, key):
        self._keys = None
        self.change_key(key)

    def change_key(self, key):
        assert 0 <= key < (1 << 128)
        modulus = 1 << 128

        sub_keys = []
        for i in range(9 * 6):
            sub_keys.append((key >> (112 - 16 * (i % 8))) % 0x10000)
            if i % 8 == 7:
                key = ((key << 25) | (key >> 103)) % modulus

        keys = []
        for i in range(9):
            round_keys = sub_keys[6 * i: 6 * (i + 1)]
            keys.append(tuple(round_keys))
        self._keys = tuple(keys)

    def split_plaintext_to_hex_blocks(self, plaintext):
        blocks_list = []
        for i in range(0, len(plaintext), 8):
            block = plaintext[i:i + 8].ljust(8, "\0")
            hex_value = int(hex(int.from_bytes(block.encode('utf-8'), 'big')), 16)  # convert block to hex with \0
            blocks_list.append(hex_value)
        return blocks_list

    def encrypt(self, hex_blocks_list, initial_vect, encrypt_0_decrypt_1):
        cipher_blocks = []

        if encrypt_0_decrypt_1 == 0:  # encrypt flag
            keys = self._keys
        else:  # decrypt flag
            keys = self._generate_decrypt_keys()

        for block in hex_blocks_list:
            if encrypt_0_decrypt_1 == 0:  # cbc encryption
                block = block ^ initial_vect

            assert 0 <= block < (1 << 64)
            x1 = (block >> 48) & 0xFFFF
            x2 = (block >> 32) & 0xFFFF
            x3 = (block >> 16) & 0xFFFF
            x4 = block & 0xFFFF

            for i in range(8):
                round_keys = keys[i]

                y1, y2, y3, y4 = _KA_layer(x1, x2, x3, x4, round_keys)
                x1, x2, x3, x4 = _MA_layer(y1, y2, y3, y4, round_keys)

                x2, x3 = x3, x2

            # Note: The words x2 and x3 are not permuted in the last round
            # So here we use x1, x3, x2, x4 as input instead of x1, x2, x3, x4
            # in order to cancel the last permutation x2, x3 = x3, x2
            y1, y2, y3, y4 = _KA_layer(x1, x3, x2, x4, keys[8])

            merged = (y1 << 48) | (y2 << 32) | (y3 << 16) | y4

            if encrypt_0_decrypt_1 == 0:  # cbc encryption
                initial_vect = merged
                cipher_blocks.append(merged)
            else:  # cbc decryption
                merged = merged ^ initial_vect
                initial_vect = block
                cipher_blocks.append(merged)
        return cipher_blocks

    def _generate_decrypt_keys(self):
        decrypt_keys = []
        keys_to_array = [x for xs in self._keys for x in xs]
        for i in range(8):
            step = i * 6
            lower_index = 46 - step

            decrypt_keys.append(_inverse_multiply(keys_to_array[lower_index + 2]))

            tmp1 = 4
            tmp2 = 3
            if i == 0:
                tmp1 = 3
                tmp2 = 4

            decrypt_keys.append(_inverse_additive(keys_to_array[lower_index + tmp1]))
            decrypt_keys.append(_inverse_additive(keys_to_array[lower_index + tmp2]))

            decrypt_keys.append(_inverse_multiply(keys_to_array[lower_index + 5]))
            decrypt_keys.append(keys_to_array[lower_index])
            decrypt_keys.append(keys_to_array[lower_index + 1])

        decrypt_keys.append(_inverse_multiply(keys_to_array[0]))
        decrypt_keys.append(_inverse_additive(keys_to_array[1]))
        decrypt_keys.append(_inverse_additive(keys_to_array[2]))
        decrypt_keys.append(_inverse_multiply(keys_to_array[3]))

        keys_to_tuple = []  # temp array
        for i in range(9):
            round_keys = decrypt_keys[6 * i: 6 * (i + 1)]
            keys_to_tuple.append(tuple(round_keys))

        return tuple(keys_to_tuple)

    def from_hex_to_string(self, decrypted_blocks_hex):
        decrypted_blocks = []
        for block in decrypted_blocks_hex:
            s = bytes.fromhex(hex(block)[2:]).decode('utf-8')
            decrypted_blocks.append(s)
        decrypted_blocks[-1] = decrypted_blocks[-1].rstrip('\x00')

        return ''.join(decrypted_blocks)


def main():
    key = random.getrandbits(128)
    iv = random.getrandbits(64)

    plain = "jubula moya"
    print('\nkey\t\t\t', hex(key))
    print('plaintext\t', plain)

    my_IDEA = IDEA(key)

    hex_blocks_after_split = my_IDEA.split_plaintext_to_hex_blocks(plaintext=plain)
    print("plaintext after split as hex blocks:\t", hex_blocks_after_split)

    encrypted_blocks = my_IDEA.encrypt(hex_blocks_after_split, iv, 0)
    print('encrypted hex blocks:\t\t\t\t\t', encrypted_blocks)

    decrypted_blocks_hex = my_IDEA.encrypt(encrypted_blocks, iv, 1)
    print('decrypted hex blocks:\t\t\t\t\t', decrypted_blocks_hex)


    decrypted_blocks = my_IDEA.from_hex_to_string(decrypted_blocks_hex)
    print(decrypted_blocks)





if __name__ == '__main__':
    main()
