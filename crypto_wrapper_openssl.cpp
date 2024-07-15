#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "crypto_wrapper.h"

#ifdef OPENSSL
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

#include <openssl/err.h>

#ifdef WIN
#pragma comment (lib, "libcrypto.lib")
#pragma comment (lib, "openssl.lib")
#endif // #ifdef WIN

static constexpr size_t PEM_BUFFER_SIZE_BYTES = 10000;
static constexpr size_t HASH_SIZE_BYTES = 32; //To be define by the participants
static constexpr size_t IV_SIZE_BYTES = 12; //To be define by the participants
static constexpr size_t GMAC_SIZE_BYTES = 16; //To be define by the participants 


bool CryptoWrapper::hmac_SHA256(IN const BYTE* key, size_t keySizeBytes, IN const BYTE* message, IN size_t messageSizeBytes, OUT BYTE* macBuffer, IN size_t macBufferSizeBytes)
{
	EVP_MD_CTX* ctx = NULL;
	EVP_PKEY* pkey = NULL;
	int rc;

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
	{
		printf("EVP_MD_CTX_new failed on HMAC\n");
		goto err;
	}

	pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, keySizeBytes);
	if (pkey == NULL) {
		printf("EVP_PKEY_new_raw_private_key failed on HMAC\n");
		goto err;
	}

	rc = EVP_DigestSignInit(ctx, NULL, EVP_get_digestbyname("SHA256"), NULL, pkey);

	if (rc == 0) {
		printf("EVP_DigestSignInit failed on HMAC\n");
		goto err;
	}

	rc = EVP_DigestSignUpdate(ctx, message, messageSizeBytes);

	if (rc == 0) {
		printf("EVP_DigestSignUpdate for message failed on HMAC\n");
		goto err;
	}

	rc = EVP_DigestSignFinal(ctx, macBuffer, &macBufferSizeBytes);

	if (rc == 0) {
		printf("EVP_DigestSignFinal failed on HMAC\n");
		goto err;
	}

	return true;

err:
	printf("Error 0x%lx\n", ERR_get_error());
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return false;
}

bool CryptoWrapper::deriveKey_HKDF_SHA256(IN const BYTE* salt, IN size_t saltSizeBytes,
	IN const BYTE* secretMaterial, IN size_t secretMaterialSizeBytes,
	IN const BYTE* context, IN size_t contextSizeBytes,
	OUT BYTE* outputBuffer, IN size_t outputBufferSizeBytes)
{
	bool ret = false;
	EVP_PKEY_CTX* pctx = NULL;

	int res;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (pctx == NULL)
	{
		printf("failed to get HKDF context\n");
		goto err;
	}

	res = EVP_PKEY_derive_init(pctx);

	if (res <= 0) {
		printf("failed to initialize derive\n");
		if (res == -2)
			printf("operation is not supported by the public key algorithm (while initializing derive)\n");
		goto err;
	}

	res = EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());

	if (res <= 0) {
		printf("failed to set HKDF MD derive\n");
		if (res == -2)
			printf("operation is not supported by the public key algorithm (while setting HKDF MD)\n");
		goto err;
	}

	res = EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltSizeBytes);

	if (res <= 0) {
		printf("failed to set HKDF salt derive\n");
		if (res == -2)
			printf("operation is not supported by the public key algorithm (while setting HKDF salt)\n");
		goto err;
	}

	res = EVP_PKEY_CTX_set1_hkdf_key(pctx, secretMaterial, secretMaterialSizeBytes);

	if (res <= 0) {
		printf("failed to set HKDF secret/key derive\n");
		if (res == -2)
			printf("operation is not supported by the public key algorithm (while setting HKDF secret/key)\n");
		goto err;
	}

	res = EVP_PKEY_CTX_add1_hkdf_info(pctx, context, contextSizeBytes);

	if (res <= 0) {
		printf("failed to add HKDF info derive\n");
		if (res == -2)
			printf("operation is not supported by the public key algorithm (while adding HKDF info)\n");
		goto err;
	}

	res = EVP_PKEY_derive(pctx, outputBuffer, &outputBufferSizeBytes);

	if (res <= 0) {
		printf("failed at HKDF derive\n");
		if (res == -2)
			printf("operation is not supported by the public key algorithm (while HKDF derive)\n");
		goto err;
	}

	ret = true;

err:
	EVP_PKEY_CTX_free(pctx);

	return ret;


}

size_t CryptoWrapper::getCiphertextSizeAES_GCM256(IN size_t plaintextSizeBytes)
{
	return plaintextSizeBytes + IV_SIZE_BYTES + GMAC_SIZE_BYTES;
}

size_t CryptoWrapper::getPlaintextSizeAES_GCM256(IN size_t ciphertextSizeBytes)
{
	return (ciphertextSizeBytes > IV_SIZE_BYTES + GMAC_SIZE_BYTES ? ciphertextSizeBytes - IV_SIZE_BYTES - GMAC_SIZE_BYTES : 0);
}

bool CryptoWrapper::encryptAES_GCM256(IN const BYTE* key, IN size_t keySizeBytes,
	IN const BYTE* plaintext, IN size_t plaintextSizeBytes,
	IN const BYTE* aad, IN size_t aadSizeBytes,
	OUT BYTE* ciphertextBuffer, IN size_t ciphertextBufferSizeBytes, OUT size_t* pCiphertextSizeBytes)
{
	BYTE iv[IV_SIZE_BYTES];
	BYTE mac[GMAC_SIZE_BYTES];
	size_t ciphertextSizeBytes = getCiphertextSizeAES_GCM256(plaintextSizeBytes);

	if ((plaintext == NULL || plaintextSizeBytes == 0) && (aad == NULL || aadSizeBytes == 0))
	{
		return false;
	}

	if (ciphertextBuffer == NULL || ciphertextBufferSizeBytes == 0)
	{
		if (pCiphertextSizeBytes != NULL)
		{
			*pCiphertextSizeBytes = ciphertextSizeBytes;
			return true;
		}
		else
		{
			return false;
		}
	}

	if (ciphertextBufferSizeBytes < ciphertextSizeBytes)
	{
		return false;
	}

	EVP_CIPHER_CTX* ctctx = EVP_CIPHER_CTX_new();
	int len;
	int ctlen;
	bool ret = false;

	if (ctctx == NULL) {
		printf("Error in creating a CIPHER context at encryption\n");
		goto end;
	}

	if (!EVP_EncryptInit_ex(ctctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		printf("Error in initializing encryption with CIPHER\n");
		goto end;
	}

	if (!EVP_CIPHER_CTX_ctrl(ctctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE_BYTES, NULL))
	{
		printf("Error in setting IV length at encryption \n");
		goto end;
	}

	if (!EVP_EncryptInit_ex(ctctx, NULL, NULL, key, iv)) {
		printf("Error in initializing encryption with key and IV at encryption\n");
		goto end;
	}

	if (!EVP_EncryptUpdate(ctctx, NULL, &len, aad, aadSizeBytes)) {
		printf("Error in updating AAD (Additional Authenticated Data) at encryption\n");
		goto end;
	}

	if (!EVP_EncryptUpdate(ctctx, ciphertextBuffer, &len, plaintext, plaintextSizeBytes)) {
		printf("Error in updating cipherText at encryption\n");
		goto end;
	}

	ctlen = len;

	if (!EVP_EncryptFinal_ex(ctctx, ciphertextBuffer + len, &len)) {
		printf("Error in finalizing encryption\n");
		goto end;
	}

	ctlen += len;

	if (!EVP_CIPHER_CTX_ctrl(ctctx, EVP_CTRL_GCM_GET_TAG, GMAC_SIZE_BYTES, mac)) {
		printf("Error in setiing mac tag\n");
		goto end;
	}

	memcpy(ciphertextBuffer + ctlen, mac, GMAC_SIZE_BYTES);

	if (pCiphertextSizeBytes != NULL)
		*pCiphertextSizeBytes = ciphertextSizeBytes;

	//printf("At Encryption - ciphertextSizeBytes [CIPHERTEXT + IV + MAC_LEN]: %zu, ctlen [CIPHERTEXT ONLY]: %d\n", ciphertextSizeBytes, ctlen);

	ret = true;

end:
	EVP_CIPHER_CTX_free(ctctx);
	return ret;
}

bool CryptoWrapper::decryptAES_GCM256(IN const BYTE* key, IN size_t keySizeBytes,
	IN const BYTE* ciphertext, IN size_t ciphertextSizeBytes,
	IN const BYTE* aad, IN size_t aadSizeBytes,
	OUT BYTE* plaintextBuffer, IN size_t plaintextBufferSizeBytes, OUT size_t* pPlaintextSizeBytes)
{
	if (ciphertext == NULL || ciphertextSizeBytes < (IV_SIZE_BYTES + GMAC_SIZE_BYTES))
	{
		return false;
	}

	size_t plaintextSizeBytes = getPlaintextSizeAES_GCM256(ciphertextSizeBytes);

	if (plaintextBuffer == NULL || plaintextBufferSizeBytes == 0)
	{
		if (pPlaintextSizeBytes != NULL)
		{
			*pPlaintextSizeBytes = plaintextSizeBytes;
			return true;
		}
		else
		{
			return false;
		}
	}

	if (plaintextBufferSizeBytes < plaintextSizeBytes)
	{
		return false;
	}

	BYTE iv[IV_SIZE_BYTES];
	BYTE mac[GMAC_SIZE_BYTES];

	// Extracting the MAC from ciphertext
	memcpy(mac, ciphertext + ciphertextSizeBytes - GMAC_SIZE_BYTES, GMAC_SIZE_BYTES);

	EVP_CIPHER_CTX* ptctx = EVP_CIPHER_CTX_new();
	int len;
	int ptlen;
	bool ret = false;

	if (!ptctx) {
		printf("Error in creating a CIPHER context at decryption\n");
		goto end;
	}

	if (!EVP_DecryptInit_ex(ptctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		printf("Error in initializing decryption with CIPHER\n");
		goto end;
	}

	if (!EVP_CIPHER_CTX_ctrl(ptctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE_BYTES, NULL)) {
		printf("Error in setting IV length at decryption\n");
		goto end;
	}

	if (!EVP_DecryptInit_ex(ptctx, NULL, NULL, key, iv)) {
		printf("Error in initializing encryption with key and IV at decryption\n");
		goto end;
	}

	if (!EVP_DecryptUpdate(ptctx, NULL, &len, aad, aadSizeBytes)) {
		printf("Error in updating AAD (Additional Authenticated Data) at decryption\n");
		goto end;
	}

	if (!EVP_DecryptUpdate(ptctx, plaintextBuffer, &len, ciphertext, ciphertextSizeBytes)) {
		printf("Error in updating plaintext at decryption");
		goto end;
	}
	ptlen = len;

	if (!EVP_CIPHER_CTX_ctrl(ptctx, EVP_CTRL_GCM_SET_TAG, GMAC_SIZE_BYTES, mac)) {
		printf("Error in setting the expected mac value at decryption\n");
		goto end;
	}

	if (!EVP_DecryptFinal_ex(ptctx, plaintextBuffer + len, &len))
		ptlen += len;
	else {
		printf("Error in finalizing at decryption\n");
		goto end;
	}

	//printf("At Decryption - plaintextSizeBytes [PLAINTEXT ONLY]: %zu, ptlen [PLAINTEXT + IV + MAC_LEN]: %d\n", plaintextSizeBytes, ptlen);

	if (pPlaintextSizeBytes != NULL)
		*pPlaintextSizeBytes = plaintextSizeBytes;

	ret = true;

end:
	EVP_CIPHER_CTX_free(ptctx);
	return ret;
}
bool CryptoWrapper::readRSAKeyFromFile(IN const char* keyFilename, IN const char* filePassword, OUT KeypairContext** pKeyContext)
{
	BIO* bio = NULL;
	EVP_PKEY* pkey = NULL;
	EVP_PKEY_CTX* ctx = NULL;
	bool ret = false;

	bio = BIO_new_file(keyFilename, "rb");
	if (bio == NULL) {
		printf("Error in reading file at readRSAKeyFromFile\n");
		goto end;
	}

	pkey = PEM_read_bio_PrivateKey_ex(bio, &pkey, NULL, (void*)filePassword, NULL, NULL);
	assert(pkey != NULL);
	if (pkey == NULL) {
		printf("Error in reading pkey from bio at readRSAKeyFromFile\n");
		goto end;
	}

	//printf("pkey type name %s\n",EVP_PKEY_get0_type_name(pkey));

	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (ctx == NULL) {
		printf("Error in creating context from private key at readRSAKeyFromFile\n");
		goto end;
	}

	*pKeyContext = ctx;

	ret = true;

end:
	// EVP_PKEY_CTX_free(ctx);  should not clear this context because it is required for that pKeyContext
	EVP_PKEY_free(pkey);
	BIO_free(bio);
	return ret;
}


bool CryptoWrapper::signMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* privateKeyContext, OUT BYTE* signatureBuffer, IN size_t signatureBufferSizeBytes)
{

	if (!message || !messageSizeBytes || !privateKeyContext)
		return false;

	*signatureBuffer = NULL;

	EVP_MD_CTX* md_ctx = NULL;
	const EVP_MD* md;
	EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(privateKeyContext);
	bool ret = false;
	int rc;

	assert(pkey != NULL);
	if (pkey == NULL) {
		printf("Error in getting pkey from privateKeyContext at signMessageRsa3072Pss\n");
		goto end;
	}

	md_ctx = EVP_MD_CTX_create();
	assert(md_ctx != NULL);
	if (md_ctx == NULL) {
		printf("Error in creating md context at signMessageRsa3072Pss\n");
		goto end;
	}

	md = EVP_get_digestbyname("SHA384");
	assert(md != NULL);
	if (md == NULL) {
		printf("Error in getting md by name at signMessageRsa3072Pss\n");
		goto end;
	}

	rc = EVP_DigestInit_ex(md_ctx, md, NULL);
	assert(rc == 1);
	if (rc != 1) {
		printf("Error in initiating digest at signMessageRsa3072Pss\n");
		goto end;
	}

	rc = EVP_DigestSignInit(md_ctx, NULL, md, NULL, pkey);
	assert(rc == 1);
	if (rc != 1) {
		printf("Error in initiating digest sign at signMessageRsa3072Pss\n");
		goto end;
	}

	rc = EVP_DigestSignUpdate(md_ctx, message, messageSizeBytes);
	assert(rc == 1);
	if (rc != 1) {
		printf("Error in updating digest sign at signMessageRsa3072Pss\n");
		goto end;
	}

	rc = EVP_DigestSignFinal(md_ctx, signatureBuffer, &signatureBufferSizeBytes);  // not updating signatureBufferSizeBytes
	assert(rc == 1);
	if (rc != 1) {
		printf("Error in finalizing digest sign at signMessageRsa3072Pss\n");
		goto end;
	}

	ret = true;

end:
	EVP_MD_CTX_destroy(md_ctx);
	return ret;

}


bool CryptoWrapper::verifyMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* publicKeyContext, IN const BYTE* signature, IN size_t signatureSizeBytes, OUT bool* result)
{
	if (!message || !messageSizeBytes || !publicKeyContext || !signature || !signatureSizeBytes)
		return false;

	EVP_MD_CTX* md_ctx = NULL;
	const EVP_MD* md;
	EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(publicKeyContext);
	bool ret = false;
	int rc;

	assert(pkey != NULL);
	if (pkey == NULL) {
		printf("Error in getting pkey from publicKeyContext at verifyMessageRsa3072Pss\n");
		goto end;
	}

	md_ctx = EVP_MD_CTX_create();
	assert(md_ctx != NULL);
	if (md_ctx == NULL) {
		printf("Error in creating md context at verifyMessageRsa3072Pss\n");
		goto end;
	}

	md = EVP_get_digestbyname("SHA384");
	assert(md != NULL);
	if (md == NULL) {
		printf("Error in getting md by name at verifyMessageRsa3072Pss\n");
		goto end;
	}

	rc = EVP_DigestInit_ex(md_ctx, md, NULL);
	assert(rc == 1);
	if (rc != 1) {
		printf("Error in initiating digest at verifyMessageRsa3072Pss\n");
		goto end;
	}

	rc = EVP_DigestVerifyInit(md_ctx, NULL, md, NULL, pkey);
	assert(rc == 1);
	if (rc != 1) {
		printf("Error in initiating digest verify at verifyMessageRsa3072Pss\n");
		goto end;
	}

	rc = EVP_DigestVerifyUpdate(md_ctx, message, messageSizeBytes);
	assert(rc == 1);
	if (rc != 1) {
		printf("Error in updating digest verify at verifyMessageRsa3072Pss\n");
		goto end;
	}

	rc = EVP_DigestVerifyFinal(md_ctx, signature, signatureSizeBytes);
	//assert(rc == 1); this stops verification when the message tampered.
	if (rc != 1) {
		printf("Error in finalizing digest verify at verifyMessageRsa3072Pss\n");
		goto end;
	}

	ret = true;

end:
	EVP_MD_CTX_destroy(md_ctx);
	*result = ret;
	return ret;
}



void CryptoWrapper::cleanKeyContext(INOUT KeypairContext** pKeyContext)
{
	if (*pKeyContext != NULL)
	{
		EVP_PKEY_CTX_free(*pKeyContext);
		*pKeyContext = NULL;
	}
}

// for me it is not useful when it is keyContext but it is useful if key is used instead of keyPairContext
bool CryptoWrapper::writePublicKeyToPemBuffer(IN KeypairContext* keyContext, OUT BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	bool ret = false;
	EVP_PKEY* key = NULL;
	BIGNUM* pubKey = NULL;
	int rc;

	if (keyContext == NULL || publicKeyPemBuffer == NULL) {
		printf("Invalid input parameters to writePublicKeyToPemBuffer\n");
		goto err;
	}

	key = EVP_PKEY_CTX_get0_pkey(keyContext);
	if (key == NULL) {
		printf("Error in getting key from context at writePublicKeyToPemBuffer\n");
		goto err;
	}

	if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PUB_KEY, &pubKey) != 1) {
		unsigned long errCode = ERR_get_error();
		printf("Lib : %s\n", ERR_lib_error_string(errCode));
		printf("Reason : %s\n", ERR_reason_error_string(errCode));
		goto err;
	}

	rc = BN_bn2bin(pubKey, publicKeyPemBuffer);
	if (rc <= 0) {
		printf("Error in converting BN to buffer at writePublicKeyToPemBuffer\n");
		goto err;
	}

	ret = true;

err:
	BN_free(pubKey);
	EVP_PKEY_free(key);
	// EVP_PKEY_CTX_free(keyContext); Don't know why but cleaning this context affects the creation of derivation context at getDhSharedSecret. may be it deletes the key too
	return ret;
}

bool CryptoWrapper::loadPublicKeyFromPemBuffer(INOUT KeypairContext* context, IN const BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{

err:
	return false;
}

// There is no need to regenerate it at creatingPeerPublicKey but we only have public key which is not enough to create a peerKey at creatingPeerPublicKey, it will be useful if the creatingPeerPublicKey accepts the current user context with which we can get p and g values easily without generating it once again. 
bool generateDhParameters(BIGNUM** p, BIGNUM** g) {
	unsigned char generator = 2;
	*p = BN_get_rfc3526_prime_3072(NULL);
	if (*p == NULL)
		return false;

	*g = BN_bin2bn(&generator, 1, NULL);
	if (*g == NULL)
		return false;

	return true;
}

bool CryptoWrapper::startDh(OUT DhContext** pDhContext, OUT BYTE* publicKeyBuffer, IN size_t publicKeyBufferSizeBytes)
{
	bool ret = false;
	BIGNUM* p = NULL;
	BIGNUM* g = NULL;

	int rc = 0;
	OSSL_PARAM_BLD* bld = NULL;
	OSSL_PARAM* params = NULL;
	EVP_PKEY* paramKey = NULL;
	EVP_PKEY_CTX* paramKeyCtx = NULL;
	EVP_PKEY* keyPair = NULL;
	EVP_PKEY_CTX* keyGenCtx = NULL;
	EVP_PKEY_CTX* keyPairCtx = NULL;

	if (!generateDhParameters(&p, &g)) {
		printf("Error in generating DH parameters at startDh\n");
		goto err;
	}

	//..
	bld = OSSL_PARAM_BLD_new();
	if (bld == NULL) {
		printf("Error in creating a param bld at startDh\n");
		goto err;
	}

	rc = OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p);
	if (rc == 0) {
		printf("Error in pushing p to params bld at startDh\n");
		goto err;
	}

	rc = OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g);
	if (rc == 0) {
		printf("Error in pushing g to params bld at startDh\n");
		goto err;
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (params == NULL) {
		printf("Error in converting params bld to params at startDh\n");
		goto err;
	}

	paramKeyCtx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
	if (paramKeyCtx == NULL) {
		printf("Error in creating context from name at startDh\n");
		goto err;
	}

	rc = EVP_PKEY_fromdata_init(paramKeyCtx);
	if (rc <= 0) {
		printf("Error in initializing paramKey from data at startDh\n");
		goto err;
	}

	rc = EVP_PKEY_fromdata(paramKeyCtx, &paramKey, EVP_PKEY_KEY_PARAMETERS, params);
	if (rc <= 0) {
		printf("Error in getting paramKey from data at startDh\n");
		goto err;
	}

	// printf("pkey type is - %s\n", EVP_PKEY_get0_type_name(paramKey));

	keyGenCtx = EVP_PKEY_CTX_new_from_pkey(NULL, paramKey, NULL);
	if (keyGenCtx == NULL) {
		printf("Error in creating key generation context with paramKey at startDh\n");
		goto err;
	}

	rc = EVP_PKEY_keygen_init(keyGenCtx);
	if (rc <= 0) {
		printf("Error in initiating key generation with keyGenContext at startDh\n");
		goto err;
	}

	rc = EVP_PKEY_generate(keyGenCtx, &keyPair);
	if (rc <= 0) {
		printf("Error in generating key with keyGenContext at startDh\n");
		goto err;
	}

	keyPairCtx = EVP_PKEY_CTX_new_from_pkey(NULL, keyPair, NULL);
	if (keyPairCtx == NULL) {
		printf("Error in creating key pair context with keyPair at startDh\n");
		goto err;
	}

	if (!writePublicKeyToPemBuffer(keyPairCtx, publicKeyBuffer, publicKeyBufferSizeBytes)) {
		printf("Error in writting public key to public key buffer at startDh\n");
		goto err;
	}

	*pDhContext = keyPair;

	ret = true;

err:
	BN_free(p);
	BN_free(g);
	OSSL_PARAM_BLD_free(bld);
	OSSL_PARAM_free(params);
	EVP_PKEY_free(paramKey);
	EVP_PKEY_CTX_free(paramKeyCtx);
	EVP_PKEY_CTX_free(keyGenCtx);
	//EVP_PKEY_CTX_free(keyPairCtx);

	return ret;
}

bool CreatePeerPublicKey(const BYTE* peerPublicKey, size_t peerPublicKeySizeBytes, EVP_PKEY** genPeerPublicKey)
{
	bool ret = false;
	BIGNUM* pubKey = NULL;
	BIGNUM* p = NULL;
	BIGNUM* g = NULL;
	OSSL_PARAM* params = NULL;
	OSSL_PARAM_BLD* bld = NULL;
	EVP_PKEY_CTX* peerKeyCtx = NULL;
	EVP_PKEY* peerKey = NULL;
	int rc;

	if (!generateDhParameters(&p, &g)) {
		printf("Error in generating DH parameters at CreatePeerPublicKey\n");
		goto err;
	}

	pubKey = BN_bin2bn(peerPublicKey, peerPublicKeySizeBytes, NULL);
	if (pubKey == NULL) {
		printf("Error in converting buffer to BN at CreatePeerPublicKey\n");
		goto err;
	}

	bld = OSSL_PARAM_BLD_new();
	if (bld == NULL) {
		printf("Error in creating a param bld at CreatePeerPublicKey\n");
		goto err;
	}

	rc = OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p);
	if (rc <= 0) {
		printf("Error in pushing p to params bld at CreatePeerPublicKey\n");
		goto err;
	}

	rc = OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g);
	if (rc <= 0) {
		printf("Error in pushing g to params bld at CreatePeerPublicKey\n");
		goto err;
	}

	rc = OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, pubKey);
	if (rc <= 0) {
		printf("Error in pushing pubKey to params bld at CreatePeerPublicKey\n");
		goto err;
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (params == NULL) {
		printf("Error in converting params bld to params at CreatePeerPublicKey\n");
		goto err;
	}

	peerKeyCtx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
	if (peerKeyCtx == NULL) {
		printf("Error in creating context from name at CreatePeerPublicKey\n");
		goto err;
	}

	rc = EVP_PKEY_fromdata_init(peerKeyCtx);
	if (rc <= 0) {
		printf("Error in initializing peerKey from data at CreatePeerPublicKey\n");
		goto err;
	}

	rc = EVP_PKEY_fromdata(peerKeyCtx, &peerKey, EVP_PKEY_PUBLIC_KEY, params);
	if (rc <= 0) {
		printf("Error in getting peerKey from data at CreatePeerPublicKey\n");
		goto err;
	}

	*genPeerPublicKey = peerKey;

	ret = true;

err:
	BN_free(pubKey);
	BN_free(p);
	BN_free(g);
	OSSL_PARAM_BLD_free(bld);
	OSSL_PARAM_free(params);
	EVP_PKEY_CTX_free(peerKeyCtx);
	return ret;
}

bool CryptoWrapper::getDhSharedSecret(INOUT DhContext* dhContext, IN const BYTE* peerPublicKey, IN size_t peerPublicKeySizeBytes, OUT BYTE* sharedSecretBuffer, IN size_t sharedSecretBufferSizeBytes)
{
	bool ret = false;
	EVP_PKEY* genPeerPublicKey = NULL;
	EVP_PKEY_CTX* derivationCtx = NULL;
	int rc = 0;

	if (dhContext == NULL || peerPublicKey == NULL || sharedSecretBuffer == NULL) {
		printf("Error: Null input at getDhSharedSecret\n");
		goto err;
	}

	if (!CreatePeerPublicKey(peerPublicKey, peerPublicKeySizeBytes, &genPeerPublicKey)) {
		printf("Error: Failed to create peer public key at getDhSharedSecret\n");
		goto err;
	}

	derivationCtx = EVP_PKEY_CTX_new(dhContext, NULL);
	if (derivationCtx == NULL) {
		printf("Error: Creating derivation context with dhContext at getDhSharedSecret\n");
		goto err;
	}

	rc = EVP_PKEY_derive_init(derivationCtx);
	if (rc != 1) {
		printf("Error: Initiating derivation context at getDhSharedSecret\n");
		goto err;
	}

	rc = EVP_PKEY_derive_set_peer(derivationCtx, genPeerPublicKey);
	if (rc != 1) {
		printf("Error: Setting peer at getDhSharedSecret\n");
		goto err;
	}

	rc = EVP_PKEY_derive(derivationCtx, sharedSecretBuffer, &sharedSecretBufferSizeBytes);
	if (rc != 1) {
		printf("Error: Deriving shared secret at getDhSharedSecret\n");
		goto err;
	}

	printf("Debug: Shared secret derived successfully at getDhSharedSecret\n");
	ret = true;

err:
	EVP_PKEY_CTX_free(derivationCtx);
	EVP_PKEY_free(genPeerPublicKey);
	return ret;
}

void CryptoWrapper::cleanDhContext(INOUT DhContext** pDhContext)
{
	if (*pDhContext != NULL)
	{
		EVP_PKEY_free(*pDhContext);
		*pDhContext = NULL;
		printf("Debug: DH context cleaned up successfully at cleanDhContext\n");
	}
	else {
		printf("Debug: DH context was already NULL at cleanDhContext\n");
	}
}


X509* loadCertificate(const BYTE* certBuffer, size_t certSizeBytes)
{
	int ret = 0;
	BIO* bio = NULL;
	X509* cert = NULL;

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
	{
		printf("BIO_new() fail \n");
		goto err;
	}

	ret = BIO_write(bio, (const void*)certBuffer, (int)certSizeBytes);
	if (ret <= 0)
	{
		printf("BIO_write() fail \n");
		goto err;
	}

	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (cert == NULL)
	{
		printf("PEM_read_bio_X509() fail \n");
		goto err;
	}

err:
	BIO_free(bio);

	return cert;
}

bool CryptoWrapper::checkCertificate(const BYTE* cACcertBuffer, size_t cACertSizeBytes, const BYTE* certBuffer, size_t certSizeBytes, const char* expectedCN)
{
	int ret = 0;
	X509* userCert = NULL;
	X509* caCert = NULL;
	X509_STORE* trustStore = NULL;
	X509_STORE_CTX* storeCtx = NULL;
	int rc = 0;

	// Load the CA certificate
	caCert = loadCertificate(cACcertBuffer, cACertSizeBytes);
	if (caCert == NULL)
	{
		printf("Failed to load CA certificate\n");
		goto cleanup;
	}

	// Load the user certificate
	userCert = loadCertificate(certBuffer, certSizeBytes);
	if (userCert == NULL)
	{
		printf("Failed to load user certificate\n");
		goto cleanup;
	}

	// Create a new X509 store
	trustStore = X509_STORE_new();
	if (trustStore == NULL)
	{
		printf("Failed to create X509 store\n");
		goto cleanup;
	}

	// Add the CA certificate to the store
	if (X509_STORE_add_cert(trustStore, caCert) != 1)
	{
		printf("Failed to add CA certificate to store\n");
		goto cleanup;
	}

	// Create a new store context
	storeCtx = X509_STORE_CTX_new();
	if (storeCtx == NULL)
	{
		printf("Failed to create X509 store context\n");
		goto cleanup;
	}

	// Initialize the store context
	if (X509_STORE_CTX_init(storeCtx, trustStore, userCert, NULL) != 1)
	{
		printf("Failed to initialize store context\n");
		goto cleanup;
	}

	// Verify the certificate
	rc = X509_verify_cert(storeCtx);
	if (rc != 1)
	{
		printf("Certificate verification failed: %s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(storeCtx)));
		goto cleanup;
	}

	// Check the expected common name (CN)
	rc = X509_check_host(userCert, expectedCN, strlen(expectedCN), X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS, NULL);
	if (rc != 1)
	{
		printf("Certificate CN check failed\n");
		goto cleanup;
	}

	// If all checks passed, set the return value to true
	ret = 1;

cleanup:
	if (caCert)
		X509_free(caCert);
	if (userCert)
		X509_free(userCert);
	if (trustStore)
		X509_STORE_free(trustStore);
	if (storeCtx)
		X509_STORE_CTX_free(storeCtx);

	return ret;
}




bool CryptoWrapper::getPublicKeyFromCertificate(IN const BYTE* certBuffer, IN size_t certSizeBytes, OUT KeypairContext** pPublicKeyContext)
{
	bool ret = false;
	X509* x509 = NULL;
	EVP_PKEY* pkey = NULL;
	EVP_PKEY_CTX* ctx = NULL;

	x509 = loadCertificate(certBuffer, certSizeBytes);
	if (x509 == NULL) {
		printf("Error in creating x509 from bio at getPublicKeyFromCertificate\n");
		goto err;
	}

	pkey = X509_get_pubkey(x509);
	if (pkey == NULL) {
		printf("Error in getting pkey from x509 at getPublicKeyFromCertificate\n");
		goto err;
	}

	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (ctx == NULL) {
		printf("Error in creating ctx from pkey at getPublicKeyFromCertificate\n");
		goto err;
	}
	*pPublicKeyContext = ctx;

	ret = true;

err:
	X509_free(x509);
	EVP_PKEY_free(pkey);
	// EVP_PKEY_CTX_free(ctx);
	return ret;
}

#endif // #ifdef OPENSSL