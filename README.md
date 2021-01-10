# Unity

libcrypto is required for compilation.

Unity is a hybrid cryptosystem for Android that uses modern encryption algorithms RSA 2048/4096 bit and AES-256-CBC.

This is the version for linux.

In addition to simple encryption using a public / private key, the program provides group encryption – this is encryption with the keys of a certain group of participants in accordance with one of three modes:

    1) in the first mode, the file is encrypted for a group of participants and it becomes possible to decrypt the file only by gathering all together. The presence of each member of the group is mandatory;

    2) in the second mode, in order to decrypt the file, you need to bypass all the participants, the order and time for which the bypass will be performed is not important;

    3) in the third mode, in order to decrypt the file, it is enough to meet with any of the group members. One participant is enough for decoding.

If these conditions are not met, the file cannot be decrypted even partially.
