PROJECT TITLE : Implementation of Advanced Encryption Standard (AES)

Name of student : Asawaree Bhide
MIS ID of student : 111503014

Project Features :
----------------
1) Encryption and decryption of files using AES-128, AES-192 or AES-256
2) Secure password storage using SHA-256 (my implementation)

Project Summary :
---------------
This project is an implementation of the Advanced Encryption Standard - a symmetric encryption algorithm. All three variants of Advanced Encryption Standard - AES-128, AES-192 and AES-256 have been implemented.

AES-128 uses 128-bit keys for encryption, while AES-192 and AES-256 use 192-bit and 256-bit keys respectively.
Users can encrypt any file using any of these three variants. The program asks for a password before encrypting the file and stores this password securely by hashing. For hashing, a cryptographic hash function has been used viz. Secure Hash Algorithm (SHA-256) (implemented by me). This generates a 256-bit hash for passwords of any length.

For encryption using AES-128, the first 128 bits of this hash are used as the key. AES-192 uses the first 192 bits of the hash as key and AES-256 uses all 256 bits as the key. According to the AES variant chosen, a series of substitutions and permutations are performed on the message to be encrypted. The 256-bit hash, along with the encrypted message (cipher) is stored in a file.

During decryption, the program asks for the password again and generates its hash. This hash value is compared with the previously generated hash and if it doesn't match, decryption is not done. If the hash values are equal, the same series of substitutions and permutations are performed on the cipher, but in reverse. The program also asks for the AES variant during decryption. If the user specifies the same variant and the same password used during encryption, the original message is retrieved. If the password is the same and the AES variant is different, decryption is done but the decrypted message will not be the same as original message.








