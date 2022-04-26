#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;

	char *encrypt = "-e";
	char *decrypt = "-d";
	int enc_dec;
	int fd;

	char inputText[1024] = {0,};
	char encryptedText[1024] = {0,};
	int len = 1024;
	char encrypted_randomkey[2];

	if(argc != 3){
		printf("invalid input.\n");
		return 1;
	}
	if(!strcmp(encrypt, argv[1]))  	   {enc_dec = 0;}
	else if(!strcmp(decrypt, argv[1])) {enc_dec = 1;}
	else {
		printf("Invalid command.\n");
		return 1;
	}
	
	
	if(enc_dec == 0) { //Encrypt
		/* Initialize a context connecting us to the TEE */
		res = TEEC_InitializeContext(NULL, &ctx);

		res = TEEC_OpenSession(&ctx, &sess, &uuid,
				       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

		fd = open(argv[2], O_RDONLY);
		if(fd == -1){
			printf("read fail");
			return 1;
		} else {
			read(fd, inputText, len);
			close(fd);
		}

		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT, //!!!!!!
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = inputText;
		op.params[0].tmpref.size = len;
		memcpy(op.params[0].tmpref.buffer, inputText, len);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op,
					 &err_origin);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
					 &err_origin);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_RANDOMKEY, &op,
					 &err_origin);
		
		memcpy(encryptedText, op.params[0].tmpref.buffer, len);
		encrypted_randomkey[0] = op.params[1].value.a;
		encrypted_randomkey[1] = '\0';
		strcat(encryptedText, encrypted_randomkey);

		if(0 < (fd = creat("./encryptedText.txt", 0644))) {
			write(fd, encryptedText, strlen(encryptedText));
			close(fd);
		} else {
			printf("create fail");
			return 1;
		}
		
		printf("Encryption complete\n");
		TEEC_CloseSession(&sess);

		TEEC_FinalizeContext(&ctx);

		return 0;
	} else { //Decrypt
		/* Initialize a context connecting us to the TEE */
		res = TEEC_InitializeContext(NULL, &ctx);

		res = TEEC_OpenSession(&ctx, &sess, &uuid,
				       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

		fd = open(argv[2], O_RDONLY);
		if(fd == -1){
			printf("read fail");
			return 1;
		} else {
			read(fd, encryptedText, len);
			close(fd);
		}

		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = encryptedText;
		op.params[0].tmpref.size = len;
		memcpy(op.params[0].tmpref.buffer, encryptedText, len);		
		
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_RANDOMKEY, &op,
					 &err_origin);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
					 &err_origin);

		memcpy(inputText, op.params[0].tmpref.buffer, len);

		if(0 < (fd = creat("./decryptedText.txt", 0644))) {
			write(fd, inputText, strlen(inputText));
			close(fd);
		} else {
			printf("write fail");
			return 1;
		}

		printf("Decryption complete\n");
		TEEC_CloseSession(&sess);

		TEEC_FinalizeContext(&ctx);
	}
	return 0;
}
