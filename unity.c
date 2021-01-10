#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdint.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include "unity.h"

#define FILE_BUF_SIZE   65536
#define DEF_BUF_SIZE    65536

unsigned char ivAES[16] = {8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8};
unsigned char keyAES[32] = {0};

void printUsage(const char * path)
{
    printf("Use:\n\t%s <options> <infile|text>\n\n"
        "options:\n\n"
        "--type|-t\tgroup - the file will encrypted for a group of participants\n"
        "\t\tall - to decrypt the file, you need to bypass all the participants\n"
        "\t\tany - to decrypt the file, it is enough to meet with any of the group members\n"
        "--keydir|-k\tdirectory with keys\n"
        "--out|-o\toutput file\n"
        "--text|-x\tUse text message instead of file\n\n"
        "Example:\n\n"
        "%s --type group --keydir /path/to/keys --out /path/to/file.ucrypt.jpg /path/to/file.jpg\n\n"
        "%s -t any -k /path/to/keys -o /path/to/file.ucrypt.txt -x \"Hello world\"\n\n\n", path, path, path);
}

int encryptBytesAES(unsigned char * bytesIn, int lengthIn, unsigned char * cipherBytes, const unsigned char * key)
{
	EVP_CIPHER_CTX* ctx;

	int len;
 	int cipherLen;

	if (!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, ivAES))
	{
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

	if (1 != EVP_EncryptUpdate(ctx, cipherBytes, &len, bytesIn, lengthIn))
	{
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    cipherLen = len;

	EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

	if (1 != EVP_EncryptFinal_ex(ctx, cipherBytes + len, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

	cipherLen += len;

	EVP_CIPHER_CTX_free(ctx);

 	return cipherLen;
}

int encryptFileAES(const char * pathFrom, const char * pathTo, const char * header, int hSize)
{
	EVP_CIPHER_CTX* ctx;

	int len;
    int tmp;
    FILE * fFrom;
    FILE * fTo;
    unsigned char buf[FILE_BUF_SIZE + 16];
    unsigned char cipherBuf[FILE_BUF_SIZE + 16];

	if (!(ctx = EVP_CIPHER_CTX_new()))
		return -1;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, keyAES, ivAES))
	{
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (!(fFrom = fopen(pathFrom, "rb")))
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (!(fTo = fopen(pathTo, "wb")))
    {
        EVP_CIPHER_CTX_free(ctx);
        fclose(fFrom);
        return -1;
    }

    if (header)
        fwrite(header, 1, hSize, fTo);

    while (!feof(fFrom))
    {
        size_t n = fread(buf, 1, FILE_BUF_SIZE, fFrom);
        if (1 != EVP_EncryptUpdate(ctx, cipherBuf, &len, buf, n))
        {
            EVP_CIPHER_CTX_free(ctx);
            fclose(fFrom);
            fclose(fTo);
            return -1;
        }

        if (feof(fFrom))
        {
            EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);
            if (1 != EVP_EncryptFinal_ex(ctx, cipherBuf + len, &tmp))
            {
                EVP_CIPHER_CTX_free(ctx);
                fclose(fFrom);
                fclose(fTo);
                return -1;
            }
            len += tmp;
        }

        fwrite(cipherBuf, 1, len, fTo);
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(fFrom);
    fclose(fTo);
 	return 1;
}


int decryptBytesAES(unsigned char * cipherBytes, int cipherLen, unsigned char * bytesOut)
{
	EVP_CIPHER_CTX* ctx;
 	int len;
 	int outBytesLen = 0;

	if (!(ctx = EVP_CIPHER_CTX_new()))
		return -1;

	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, keyAES, ivAES))
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

	EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

	if (1 != EVP_DecryptUpdate(ctx, bytesOut, &len, cipherBytes, cipherLen))
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    outBytesLen = len;

	if (1 != EVP_DecryptFinal_ex(ctx, bytesOut + len, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

	outBytesLen += len;

	EVP_CIPHER_CTX_free(ctx);
 	return outBytesLen;
}

int decryptFileAES(const char * pathFrom, const char * pathTo)
{
	EVP_CIPHER_CTX* ctx;
 	int len;
    int tmp;
 	int plainTextLen = 0;
    FILE * fFrom;
    FILE * fTo;
    unsigned char buf[FILE_BUF_SIZE + 16];
    unsigned char cipherBuf[FILE_BUF_SIZE + 16];

    if (!(ctx = EVP_CIPHER_CTX_new()))
		return -1;

	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, keyAES, ivAES))
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

	EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    if (!(fFrom = fopen(pathFrom, "rb")))
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (!(fTo = fopen(pathTo, "wb")))
    {
        EVP_CIPHER_CTX_free(ctx);
        fclose(fFrom);
        return -1;
    }

    while (!feof(fFrom))
    {
        size_t n = fread(cipherBuf, 1, FILE_BUF_SIZE, fFrom);
        if (1 != EVP_DecryptUpdate(ctx, buf, &len, cipherBuf, n))
        {
            EVP_CIPHER_CTX_free(ctx);
            fclose(fFrom);
            fclose(fTo);
            return -1;
        }

        if (feof(fFrom))
        {
            if (1 != EVP_DecryptFinal_ex(ctx, buf + len, &tmp))
            {
                EVP_CIPHER_CTX_free(ctx);
                fclose(fFrom);
                fclose(fTo);
                return -1;
            }
            len += tmp;
        }

        fwrite(buf, 1, len, fTo);
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(fFrom);
    fclose(fTo);
	return plainTextLen;
}

int base64Decode(char * b64message, unsigned char * outBytes, size_t * outLength)
{
	BIO * bio, * b64;
	bio = BIO_new_mem_buf(b64message, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	*outLength = BIO_read(bio, outBytes, strlen(b64message));
	BIO_free_all(bio);
	return *outLength;
}

int base64Encode(unsigned char * input, int length, char * outB64message)
{
	BIO *bio, *b64;
    int len;
    char * buf;
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, input, length);
	BIO_flush(bio);
	len = BIO_get_mem_data(bio, &buf);
    strcpy(outB64message, buf);
    BIO_free_all(bio);
    return len;
}

RSA * createRSA(const char * key)
{
    RSA * rsa = NULL;
    BIO * keybio;
    keybio = BIO_new_mem_buf(key, -1);
    if (!keybio)
        return 0;
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    BIO_free(keybio);
    return rsa;
}

int RSAEncrypt(unsigned char * input, size_t length, const char * key, unsigned char * output)
{
    RSA * rsa = createRSA(key);
    int encrypt_len = RSA_public_encrypt(length, input, output, rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
    return encrypt_len;
}

unsigned int readFolder(char * keysDir, char ** names, char ** keys)
{
    DIR * dir;
    struct dirent * ent;
    FILE * f;
    char path[PATH_MAX];
    unsigned int participantsCount = 0;
    char buf[FILE_BUF_SIZE];
    int n;

    strcpy(path, keysDir);
    strcat(path, "/");
    n = strlen(path);

    if (!(dir = opendir(keysDir)))
        exit(1);

    while ((ent = readdir(dir)) != NULL)
    {
        char * name;
        char * key;
        char * tmp;

        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
            continue;

        strcpy(&path[n], ent->d_name);

        if ((f = fopen(path, "r")))
        {
            size_t len;
            len = fread(buf, 1, FILE_BUF_SIZE, f);
            name = strstr(buf, "Name: ") + 6;
            tmp = strstr(name, "\r\n");
            key = strstr(name, "Key: ") + 5;
            tmp[0] = '\0';
            buf[len] = '\0';
            names[participantsCount] = strdup(name);
            keys[participantsCount] = malloc(4000);
            strcpy(keys[participantsCount],"-----BEGIN PUBLIC KEY-----\n");
            strcat(keys[participantsCount], strdup(key));
            strcat(keys[participantsCount],"\n-----END PUBLIC KEY-----");

            fclose(f);
            participantsCount++;
        }
    }
    closedir(dir);

    return participantsCount;
}

int encryptGroup(char * textOrPath, char * keysDir, char * outFile, int isText)
{
    char buf[DEF_BUF_SIZE];
    char bufCur[DEF_BUF_SIZE];
    unsigned int n, i;
    unsigned int participantsCount = 0;
    FILE * f;

    char * names[1024] = {0};
    char * keys[1024] = {0};

    participantsCount = readFolder(keysDir, names, keys);
    if (!participantsCount)
        exit(1);

    int rc = RAND_bytes(keyAES, 32);
    if(rc != 1)
        exit(1);

    *(uint16_t *)bufCur = 0;
    memcpy(bufCur + 2, keyAES, 32);
    n = 34; // size bufCur

    for (i = 0; i < participantsCount; i++)
    {
        unsigned char key[32];
        int cipherAESLen, len;
        unsigned char cipherAESBuf[DEF_BUF_SIZE];
        
        int rc = RAND_bytes(key, 32);
        if(rc != 1)
            exit(1);

        cipherAESLen = encryptBytesAES((unsigned char *)bufCur, n, (unsigned char *)cipherAESBuf, key);

        len = RSAEncrypt(key, 32, keys[i], (unsigned char *)buf);
        if (len == -1)
            exit(1);

        *(uint16_t *)(bufCur) = strlen(names[i]);
        strcpy(bufCur + 2, names[i]);
        *(uint16_t *)(bufCur + 2 + strlen(names[i])) = len;
        memcpy(bufCur + 2 + strlen(names[i]) + 2, buf, len);
        *(uint16_t *)(bufCur + 2 + strlen(names[i]) + 2 + len) = cipherAESLen;
        memcpy(bufCur + 2 + strlen(names[i]) + 2 + len + 2, cipherAESBuf, cipherAESLen);
        n = 2 + strlen(names[i]) + 2 + len + 2 + cipherAESLen;
    }

    //end
    *(uint16_t *)(buf) = UNITY_TYPE_GROUP;
    *(uint16_t *)(buf + 2) = participantsCount;
    *(uint16_t *)(buf + 2 + 2) = n + 2 + 2 + 2 + 4; // size head
    *(uint32_t *)(buf + 2 + 2 + 2) = 1 + rand() - 1;
    memcpy(buf + 2 + 2 + 2 + 4, bufCur, n);
    n += 2 + 2 + 2 + 4;

    if (isText)
    {
        int cipherTextLen = encryptBytesAES((unsigned char *)textOrPath, strlen(textOrPath), (unsigned char *)bufCur, keyAES);
        memcpy(&buf[n], bufCur, cipherTextLen);
        if ((f = fopen(outFile, "wb")))
        {
            fwrite(buf, 1, n + cipherTextLen, f);
            fclose(f);
        }
    }
    else
    {
        encryptFileAES(textOrPath, outFile, buf, n);
    }

    for (i = 0; i < participantsCount; i++)
    {
        free(names[i]);
        free(keys[i]);
    }

    return 1;
}

int encryptAll(char * textOrPath, char * keysDir, char * outFile, int isText)
{
    char buf[DEF_BUF_SIZE];
    char bufCur[DEF_BUF_SIZE];
    int count;
    unsigned int n, i, j;
    unsigned int participantsCount = 0;
    FILE * f;

    char * names[1024] = {0};
    char * keys[1024] = {0};

    participantsCount = readFolder(keysDir, names, keys);
    if (!participantsCount)
        exit(1);

    for (count = 0; count < 32; ++count)
        keyAES[count] = 0;

    n = 0;
    for (i = 0; i < participantsCount; i++)
    {
        int len;
        unsigned char key[32];

        int rc = RAND_bytes(key, 32);
        if(rc != 1)
            exit(1);
        
        for (j = 0; j < 32; ++j)
            keyAES[j] = keyAES[j] ^ key[j];

        len = RSAEncrypt(key, 32, keys[i], (unsigned char *)buf);
        if (len == -1)
            exit(1);

        *(uint16_t *)(bufCur + n) = strlen(names[i]);
        strcpy(bufCur + n + 2, names[i]);
        *(uint16_t *)(bufCur + n + 2 + strlen(names[i])) = len;
        memcpy(bufCur + n + 2 + strlen(names[i]) + 2, buf, len);

        n += 2 + strlen(names[i]) + 2 + len;
    }
    *(uint16_t *)(bufCur + n) = 0;
    n += 2;

    //end
    *(uint16_t *)(buf) = UNITY_TYPE_ALL;
    *(uint16_t *)(buf + 2) = participantsCount;
    *(uint16_t *)(buf + 2 + 2) = n + 2 + 2 + 2 + 4; // size head
    *(uint32_t *)(buf + 2 + 2 + 2) = 1 + rand() - 1;
    memcpy(buf + 2 + 2 + 2 + 4, bufCur, n);
    n += 2 + 2 + 2 + 4;

    if (isText)
    {
        int cipherTextLen = encryptBytesAES((unsigned char *)textOrPath, strlen(textOrPath), (unsigned char *)bufCur, keyAES);
        memcpy(&buf[n], bufCur, cipherTextLen);
        if ((f = fopen(outFile, "wb")))
        {
            fwrite(buf, 1, n + cipherTextLen, f);
            fclose(f);
        }
    }
    else
    {
        encryptFileAES(textOrPath, outFile, buf, n);
    }

    for (i = 0; i < participantsCount; i++)
    {
        free(names[i]);
        free(keys[i]);
    }

    return 1;
}

int encryptAny(char * textOrPath, char * keysDir, char * outFile, int isText)
{
    char buf[DEF_BUF_SIZE];
    char bufCur[DEF_BUF_SIZE];
    unsigned int n, i;
    unsigned int participantsCount = 0;
    FILE * f;

    char * names[1024] = {0};
    char * keys[1024] = {0};

    participantsCount = readFolder(keysDir, names, keys);
    if (!participantsCount)
        exit(1);

    int rc = RAND_bytes(keyAES, 32);
    if(rc != 1)
        exit(1);

    n = 0;
    for (i = 0; i < participantsCount; i++)
    {
        int len = RSAEncrypt(keyAES, 32, keys[i], (unsigned char *)buf);
        if (len == -1)
            exit(1);

        *(uint16_t *)(bufCur + n) = strlen(names[i]);
        strcpy(bufCur + n + 2, names[i]);
        *(uint16_t *)(bufCur + n + 2 + strlen(names[i])) = len;
        memcpy(bufCur + n + 2 + strlen(names[i]) + 2, buf, len);

        n += 2 + strlen(names[i]) + 2 + len;
    }
    *(uint16_t *)(bufCur + n) = 0;
    n += 2;

    //end
    *(uint16_t *)(buf) = UNITY_TYPE_ANY;
    *(uint16_t *)(buf + 2) = participantsCount;
    *(uint16_t *)(buf + 2 + 2) = n + 2 + 2 + 2 + 4; // size head
    *(uint32_t *)(buf + 2 + 2 + 2) = 1 + rand() - 1;
    memcpy(buf + 2 + 2 + 2 + 4, bufCur, n);
    n += 2 + 2 + 2 + 4;

    if (isText)
    {
        int cipherTextLen = encryptBytesAES((unsigned char *)textOrPath, strlen(textOrPath), (unsigned char *)bufCur, keyAES);
        memcpy(&buf[n], bufCur, cipherTextLen);
        if ((f = fopen(outFile, "wb")))
        {
            fwrite(buf, 1, n + cipherTextLen, f);
            fclose(f);
        }
    }
    else
    {
        encryptFileAES(textOrPath, outFile, buf, n);
    }

    for (i = 0; i < participantsCount; i++)
    {
        free(names[i]);
        free(keys[i]);
    }

    return 1;
}

int main(int argc, char **argv)
{
    UNITY_TYPE type = UNITY_TYPE_NONE;
    char * keyDir = NULL;
    char * outFile = NULL;
    char * path = NULL;
    char * text = NULL;
    int isText = 0;
    int count = 0;

    if (argc < 6)
    {
        printUsage(argv[0]);
        return 1;
    }

    for (count = 1; count < argc; ++count)
    {
        if (!strcmp(argv[count], "--type") || !strcmp(argv[count], "-t"))
        {
            if (!strcmp(argv[count + 1], "group") || !strcmp(argv[count + 1], "1"))
            {
                type = UNITY_TYPE_GROUP;
            }
            else if (!strcmp(argv[count + 1], "all") || !strcmp(argv[count + 1], "2"))
            {
                type = UNITY_TYPE_ALL;
            }
            else if (!strcmp(argv[count + 1], "any") || !strcmp(argv[count + 1], "3"))
            {
                type = UNITY_TYPE_ANY;
            }
        }
        else if (!strcmp(argv[count], "--keydir") || !strcmp(argv[count], "-k"))
        {
            keyDir = argv[count + 1];
        }
        else if (!strcmp(argv[count], "--out") || !strcmp(argv[count], "-o"))
        {
            outFile = argv[count + 1];
        }
        else if (!strcmp(argv[count], "--text") || !strcmp(argv[count], "-x"))
        {
            isText = 1;
        }
    }

    if (isText)
        text = argv[argc - 1];
    else
        path = argv[argc - 1];

    if (!type || !keyDir || !outFile)
    {
        printUsage(argv[0]);
        return 1;
    }

    srand(time(NULL));

    switch (type)
    {
        case UNITY_TYPE_GROUP:
            if (isText)
                encryptGroup(text, keyDir, outFile, 1);
            else
                encryptGroup(path, keyDir, outFile, 0);
            break;

        case UNITY_TYPE_ALL:
            if (isText)
                encryptAll(text, keyDir, outFile, 1);
            else
                encryptAll(path, keyDir, outFile, 0);
            break;

        case UNITY_TYPE_ANY:
            if (isText)
                encryptAny(text, keyDir, outFile, 1);
            else
                encryptAny(path, keyDir, outFile, 0);
            break;
        
        default:
        case UNITY_TYPE_NONE:
            return 1;
            break;
    }

	return 0;
}
