#include "h264Util.h"
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <time.h>


static long long getSystemTimeMs() {
	long long ms = 0;
	struct timeval time;
	gettimeofday( &time, NULL );
	ms = time.tv_sec *1000;
	ms += time.tv_usec / 1000;
    return ms;
}


static int base64_encode(char* src, int len, char* dst)
{
	BIO *b64, *bio;
	BUF_MEM *bptr = NULL;
	size_t size = 0;
	if(NULL == src || NULL == dst)
		return -1;
	b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem()); 
    bio = BIO_push(b64, bio);
	
	BIO_write(bio, src, len);  
    BIO_flush(bio);
	
	BIO_get_mem_ptr(bio, &bptr);
    memcpy(dst, bptr->data, bptr->length);
    dst[bptr->length - 1] = '\0';
    size = bptr->length;
	
	BIO_free_all(bio);
	return size;
}

static int base64_decode(char* src, int len, char* dst)
{
	BIO *b64, *bio;
    BUF_MEM *bptr = NULL;
    int counts;
    int size = 0;
  
    if (src == NULL || dst == NULL)
        return -1;
  
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  
    bio = BIO_new_mem_buf(src, len);
    bio = BIO_push(b64, bio);
  
    size = BIO_read(bio, dst, len);
    dst[size] = '\0';
  
    BIO_free_all(bio);
    return size;
}

static int aes128_encode(AES_KEY* key, char* src, int len, char* dst)
{
	if(NULL == key || NULL == src || NULL == dst)
		return -1;
	//src,dst必须是16个字节长度
	AES_encrypt(src, dst, key);
	return 0;
}

static int aes128_deccode(AES_KEY* key, char* src, int len, char* dst)
{
	if(NULL == key || NULL == src || NULL == dst)
		return -1;
	//src,dst必须是16个字节长度
	AES_decrypt(src, dst, key);
	return 0;
}

static void test_base64()
{
	char baseEnc[] = {"test base64 encode"};
	char baseDec[] = {"dGVzdCBiYXNlNjQgZGVjb2Rl"};
	char buf[1024] = {0};
	
	if(base64_encode(baseEnc, sizeof(baseEnc), buf) <= 0)
		fprintf(stderr, "%s\n", "base64 encode failed");
	else
		fprintf(stderr, "base64 encode done, data:%s\n", buf);
	if(base64_decode(baseDec, sizeof(baseDec), buf) <= 0)
		fprintf(stderr, "%s\n", "base64 encode failed");
	else
		fprintf(stderr, "base64 decode done, data:%s\n", buf);
}

static void test_aes128()
{
	AES_KEY aes128enckey, aes128deckey;
	char key[] = {"abcdefghijklmnop"};
	char aes128data[] = {"1"};
	char aes128out[17] = {0};
	char aes128decout[17] = {0};
	aes128data[10] = 'k';
	int ret = AES_set_encrypt_key(key, 128, &aes128enckey);
	fprintf(stderr, "set encode key ret=%d\n", ret);
	ret = aes128_encode(&aes128enckey, aes128data, 16, aes128out);
	//fprintf(stderr, "aes128 encode ret=%d, data=%s\n", ret, aes128out);
	ret = AES_set_decrypt_key(key, 128, &aes128deckey);
	ret = aes128_deccode(&aes128deckey, aes128out, 16, aes128decout);
	//fprintf(stderr, "aes128 decode ret=%d, data=%s\n", ret, aes128decout);
	ret = memcmp(aes128data, aes128decout, 16);
	fprintf(stderr, "cmp decode encode ret=%d\n", ret);
}

static void test(int argc, char** argv)
{
	AES_KEY aes;  
    unsigned char key[AES_BLOCK_SIZE];        // AES_BLOCK_SIZE = 16  
    unsigned char iv[AES_BLOCK_SIZE];        // init vector  
    unsigned char* input_string;  
    unsigned char* encrypt_string;  
    unsigned char* decrypt_string;  
    unsigned int len;        // encrypt length (in multiple of AES_BLOCK_SIZE)  
    unsigned int i;  
   
    // check usage  
    if (argc != 2) {  
        fprintf(stderr, "%s <plain text>\n", argv[0]);  
        exit(-1);  
    }  
   
    // set the encryption length  
    len = 0;  
    if ((strlen(argv[1]) + 1) % AES_BLOCK_SIZE == 0) {  
        len = strlen(argv[1]) + 1;  
    } else {  
        len = ((strlen(argv[1]) + 1) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;  
    }  
   
    // set the input string  
    input_string = (unsigned char*)calloc(len, sizeof(unsigned char));  
    if (input_string == NULL) {  
        fprintf(stderr, "Unable to allocate memory for input_string\n");  
        exit(-1);  
    }  
    strncpy((char*)input_string, argv[1], strlen(argv[1]));  
   
    // Generate AES 128-bit key  
    for (i=0; i<16; ++i) {  
        key[i] = 32 + i;  
    }  
   
    // Set encryption key  
    for (i=0; i<AES_BLOCK_SIZE; ++i) {  
        iv[i] = 0;  
    }  
    if (AES_set_encrypt_key(key, 128, &aes) < 0) {  
        fprintf(stderr, "Unable to set encryption key in AES\n");  
        exit(-1);  
    }  
   
    // alloc encrypt_string  
    encrypt_string = (unsigned char*)calloc(len, sizeof(unsigned char));      
    if (encrypt_string == NULL) {  
        fprintf(stderr, "Unable to allocate memory for encrypt_string\n");  
        exit(-1);  
    }  
   
    // encrypt (iv will change)  
    AES_cbc_encrypt(input_string, encrypt_string, len, &aes, iv, AES_ENCRYPT);
	int num = 0;
	//AES_cfb128_encrypt(input_string, encrypt_string, len, &aes, iv, &num, AES_ENCRYPT);
   
    // alloc decrypt_string  
    decrypt_string = (unsigned char*)calloc(len, sizeof(unsigned char));  
    if (decrypt_string == NULL) {  
        fprintf(stderr, "Unable to allocate memory for decrypt_string\n");  
        exit(-1);  
    }  
   
    // Set decryption key  
    for (i=0; i<AES_BLOCK_SIZE; ++i) {  
        iv[i] = 0;  
    }  
    if (AES_set_decrypt_key(key, 128, &aes) < 0) {  
        fprintf(stderr, "Unable to set decryption key in AES\n");  
        exit(-1);  
    }  
   
    // decrypt  
    AES_cbc_encrypt(encrypt_string, decrypt_string, len, &aes, iv, AES_DECRYPT);  
	//AES_cfb128_encrypt(encrypt_string, decrypt_string, len, &aes, iv, &num, AES_DECRYPT); 
   
    // print  
    printf("input_string = %s\n", input_string);  
    printf("encrypted string = ");  
    for (i=0; i<len; ++i) {  
        printf("%x%x", (encrypt_string[i] >> 4) & 0xf,   
                encrypt_string[i] & 0xf);      
    }  
    printf("\n");  
    printf("decrypted string = %s\n", decrypt_string);  
}

int main(int argc, char** argv)
{
	
	test(argc, argv);
	return 0;
	
	int count = 400;
	h264Helper helper;
	long long t_start, t_end;
	if(argc < 2)
	{
		fprintf(stderr, "usage:%s filename\n", argv[0]);
		return 0;
	}
	
	test_base64();
	fprintf(stderr, "\n=====================================================================================================%s\n", "=");
	test_aes128();
	fprintf(stderr, "\n=====================================================================================================%s\n", "=");
	
	char* encodeName = "./encode.h264";
	
	FILE* file = fopen(encodeName, "wb");
	char* buf = malloc(1024*1024);
	int ret = h264HelperInit(&helper, argv[1], 0);
	fprintf(stderr, "open encode file ret=%d\n", ret);
	AES_KEY handle;
	char key[] = {"1234567890123456"};
	ret = AES_set_encrypt_key(key, 128, &handle);
	fprintf(stderr, "encode key=%s, ret=%d\n", key, ret);
	if(ret == 0)
	{
		char ivec[16] = {0};
		while(count-->0)
		{
			ret = getH264Frame(&helper);
			if(ret == 0)
			{
				if (helper.naluType == 5)
				{
					t_start = getSystemTimeMs();
					int num = 0;
					AES_cfb128_encrypt(helper.data+helper.startCodeLen+1, buf, helper.dataLen-helper.startCodeLen-1, &handle, ivec, &num, AES_ENCRYPT);
					//AES_cbc_encrypt(helper.data+helper.startCodeLen+1, buf, helper.dataLen-helper.startCodeLen-1, &handle, ivec, AES_ENCRYPT);
					t_end = getSystemTimeMs();
					int diff = t_end - t_start;
					fprintf(stderr, "got a i frame crypto it num=%d, len=%d, start code len=%d, time=%dms\n", num, helper.dataLen, helper.startCodeLen, diff);
					memcpy(helper.data+helper.startCodeLen+1, buf, helper.dataLen - helper.startCodeLen - 1);
				}
			}
			else
			{
				break;				
			}
			ret = fwrite(helper.data, helper.dataLen, 1, file);
			//fprintf(stderr, "write file ret=%d, dataLen=%d, type=%d\n", ret, helper.dataLen, helper.naluType);
			fflush(file);
		}
	}
	else
	{
		fprintf(stderr, "init h264 helper failed, ret=%d\n", ret);
	}
	h264HelperFree(&helper);
	
	fclose(file);
	file = NULL;
	
	fprintf(stderr, "======================================================================================================start to decode %s", "\n");
	
	
	AES_KEY aes_dec_ctx;
	char key2[] = {"1234567890123456"};
	ret = AES_set_decrypt_key(key2, 128, &aes_dec_ctx);
	fprintf(stderr, "AES_set_decrypt_key key=%s ret=%d\n", key2, ret);
	count = 400;
	ret = h264HelperInit(&helper, encodeName, 0);
	
	if(ret == 0)
	{
		char ivec[16] = {0};
		FILE* dec = fopen("./dec_encode.h264", "wb");
		while(count-->0)
			{
				ret = getH264Frame(&helper);
				if(ret == 0)
				{
					if (helper.naluType == 5)
					{
						int num = 0;
						t_start = getSystemTimeMs();
						AES_cfb128_encrypt(helper.data+helper.startCodeLen+1, buf, helper.dataLen-helper.startCodeLen-1, &aes_dec_ctx, ivec, &num, AES_DECRYPT);
						//AES_cbc_encrypt(helper.data+helper.startCodeLen+1, buf, helper.dataLen-helper.startCodeLen-1, &aes_dec_ctx, ivec, AES_DECRYPT);
						t_end = getSystemTimeMs();
						int diff = t_end - t_start;
						fprintf(stderr, "got a i frame de crypto it num=%d, len=%d, start code len=%d, time=%dms\n", num, helper.dataLen, helper.startCodeLen, diff);
						memcpy(helper.data+helper.startCodeLen+1, buf, helper.dataLen - helper.startCodeLen - 1);
					}
				}
				else
				{
					break;				
				}
				ret = fwrite(helper.data, helper.dataLen, 1, dec);
				//fprintf(stderr, "write file ret=%d, dataLen=%d, type=%d\n", ret, helper.dataLen, helper.naluType);
				fflush(dec);
		}
		fclose(dec);
		file = NULL;
	}else
	{
		fprintf(stderr, "init2 h264 helper failed, ret=%d\n", ret);
	}
	h264HelperFree(&helper);
	
	return 0;
}