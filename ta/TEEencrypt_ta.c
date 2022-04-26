#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <TEEencrypt_ta.h>

#include <stdio.h>
#include <string.h>

unsigned int random_key;
int root_key = 3;

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Hello World!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}

static TEE_Result create_randomKey(uint32_t param_types,
	TEE_Param params[4])
{
	IMSG("================================^^^===============");
	do{
		TEE_GenerateRandom(&random_key, sizeof(random_key));
		random_key = random_key % 26;
	} while(random_key == 0);
	
	IMSG("New RandomKey : %d\n", random_key);

	return TEE_SUCCESS;
}

static TEE_Result enc_randomKey(uint32_t param_types,
	TEE_Param params[4])
{
	IMSG("================================^^^===============");
	DMSG("!Encrypt Key\n");
	if(random_key>='a' && random_key <='z'){
		random_key -= 'a';
		random_key += root_key;
		random_key = random_key % 26;
		random_key += 'a';
	} else if (random_key >= 'A' && random_key <= 'Z') {
		random_key -= 'A';
		random_key += root_key;
		random_key = random_key % 26;
		random_key += 'A';
	}

	params[1].value.a = (uint32_t)random_key;

	return TEE_SUCCESS;
}

static TEE_Result dec_randomKey(uint32_t param_types,
	TEE_Param params[4])
{
	
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	char encrypted [1024]={0,};	
	IMSG("================================^^^===============");
	DMSG("!Decrypt Key\n");
	memcpy(encrypted, in, in_len);
	random_key = encrypted[in_len-1];


	if(random_key>='a' && random_key <='z'){
		random_key -= 'a';
		random_key -= root_key;
		random_key += 26;
		random_key = random_key % 26;
		random_key += 'a';
	} else if (random_key >= 'A' && random_key <= 'Z') {
		random_key -= 'A';
		random_key -= root_key;
		random_key += 26;
		random_key = random_key % 26;
		random_key += 'A';
	}
	IMSG("Decrypted Key : %d\n", random_key);

	return TEE_SUCCESS;
}


static TEE_Result enc_value(uint32_t param_types,
	TEE_Param params[4])
{
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	char encrypted [1024] = {0,};
	DMSG("================================^^^===============");
	DMSG("InputText to encrypt : %s", in);
	memcpy(encrypted, in, in_len);

	for(int i=0; i<in_len;i++) {
		if(encrypted[i]>='a' && encrypted[i]<='z') {
			encrypted[i] -= 'a';
			encrypted[i] += random_key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'a';
		} else if(encrypted[i]>='A' && encrypted[i]<='Z') {
			encrypted[i] -= 'A';
			encrypted[i] += random_key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'A';
		}
	}
	memcpy(in, encrypted, in_len);
	DMSG("CaeserText : %s", encrypted);
	
	return TEE_SUCCESS;

}

static TEE_Result dec_value(uint32_t param_types,
	TEE_Param params[4])
{
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	char decrypted [1024]={0,};
	IMSG("================================^^^===============");
	DMSG ("Caesertext to decrypt :  %s", in);
	memcpy(decrypted, in, in_len);

	for(int i=0; i<in_len-1;i++){
		if(decrypted[i]>='a' && decrypted[i] <='z'){
			decrypted[i] -= 'a';
			decrypted[i] -= random_key;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'a';
		} else if (decrypted[i] >= 'A' && decrypted[i] <= 'Z') {
			decrypted[i] -= 'A';
			decrypted[i] -= random_key;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'A';
		}
	}
	decrypted[in_len-1] = '\0';
	DMSG ("Plaintext :  %s", decrypted);
	memcpy(in, decrypted, in_len);

	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_TEEencrypt_CMD_ENC_VALUE:
		return enc_value(param_types, params);
	case TA_TEEencrypt_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	case TA_TEEencrypt_CMD_RANDOMKEY_GET:
		return create_randomKey(param_types, params);
	case TA_TEEencrypt_CMD_ENC_RANDOMKEY:
		return enc_randomKey(param_types, params);
	case TA_TEEencrypt_CMD_DEC_RANDOMKEY:
		return dec_randomKey(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
