import random
from hashlib import sha256
import idea_cbc
import elgamal

import rsa_encrypt

""" 
    1. Generate a pair of ELGamal keys, public and private  V
    2. Generate a pair of RSA keys, public and private key  V
    3. Initialize the IDEA     
    4. Promt user for message to be encrypted and signed    V
    5. Use RSA public key to encrypt the message using IDEA in CBC mode  
    6. Use the ElGamal private key to sign one the message    V
    7. Send the encrypted keys, message and signed message to recipient V
    8. Decrypt keys and message
    8. Uses the ElGamal public key to verify the message  V
    9. If not valid display Error message   V
    10. Otherwise dispaly the decrypted message

"""
hash_function = sha256()
key_length = 128

# 1. Generate a pair of ELGamal keys, public and private and ElGamal sytems
print(">>> Alice generates ElGamal DS system...")
alice_elgsys = elgamal.generate_system(key_length, hash_function)
bob_elgsys = elgamal.generate_system(key_length, hash_function)
alice_sig_keys = elgamal.generate_keys(alice_elgsys)
bob_sig_keys = elgamal.generate_keys(bob_elgsys)
print(">>> Alice shares with Bob public key...")

# 2. Bob Generates a pair of RSA keys, public and private key
bit_length = 256
q = rsa_encrypt.getRandomPrime(bit_length)
p = rsa_encrypt.getRandomPrime(bit_length)
while p == q:
    q = rsa_encrypt.getRandomPrime(bit_length)
public, private = rsa_encrypt.getKeys(p, q)
print(">>> Bob generates a pair of RSA keys, and send the public one to Alice")


key = random.getrandbits(128)
iv = random.getrandbits(64)
print(">>> Alice generates private IDEA key and IV...")
# Encrypt the key and iv
encrypted_key = rsa_encrypt.encrypt(str(key), public)
encrypted_iv = rsa_encrypt.encrypt(str(iv), public)


# 3. Initialize the IDEA
encryptor_alice = idea_cbc.IDEA(key=key)

# 4. Prompt user for message to be encrypted and signed
print(">>> Alice writes the email...")
message = "\"Hello, Bob! Happy New Year! Learn Data Security and Cryptology!\""
print('The message is - ' + message)


# 5. Use RSA public key to encrypt the message using IDEA in CBC mode
hex_blocks_after_split = encryptor_alice.split_plaintext_to_hex_blocks(plaintext=message)
cipher_text = encryptor_alice.encrypt(hex_blocks_after_split, iv, 0)

cipher_text_as_string = [str(block) for block in cipher_text]

print(">>> Alice encrypts the message...")
print("The cipher is " + ''.join(cipher_text_as_string))

# 6. Use the ElGamal private key to sign the encrypted message
# signatureOnCipher = elgamal.sign(alice_elgsys, ''.join(cipher_text_as_string), alice_sig_keys[0])
signatureOnCipher = elgamal.sign(alice_elgsys, message, alice_sig_keys[0])
print(">>> Alice signs on ciphertext...")
# 7. Send the encrypted message and signed message to recipient
print('>>> Alice sends the encrypted email and the digital signature')
print('>>> Bob receives the encrypted email and the digital signature')

print(">>> Bob decrypts the IDEA key and IV using his private RSA key")
decrypted_key = int(rsa_encrypt.decrypt(encrypted_key, private))
decrypted_iv = int(rsa_encrypt.decrypt(encrypted_iv, private))
decryptor_bob = idea_cbc.IDEA(key=decrypted_key)  # noqa
print(">>> Bob decrypts the message...")
decryptedMessage = decryptor_bob.encrypt(cipher_text, decrypted_iv, 1)
decryptedMessage = decryptor_bob.from_hex_to_string(decryptedMessage)



print('>>> Bob verificates the ciphertext') # noqa
# 8. Recipient uses the ElGamal public key to verify
isVerified = elgamal.verify(alice_elgsys, decryptedMessage, signatureOnCipher, alice_sig_keys[1])
if not isVerified:
    print("ERROR - the message is fake ")
else:
    print("Decrypted message - " + decryptedMessage)

