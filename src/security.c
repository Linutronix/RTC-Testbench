// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2023 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <errno.h>

#include "security.h"

/*
 * Code inspired by https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
 * and https://github.com/openssl/openssl/discussions/22161
 *
 * Notes for the algorithms used: The IV size is 12 bytes. The tag len is always 16 bytes. And Input
 * equals Output length. Furthermore, PROFINET supports Authentification Only. In that case
 * plaintext respectively ciphertext is NULL.
 */

struct security_context *security_init(enum security_algorithm algorithm, const unsigned char *key)
{
	struct security_context *context;

	context = calloc(1, sizeof(*context));
	if (!context)
		return NULL;

	context->algorithm = algorithm;

	context->cipher = EVP_CIPHER_fetch(NULL, security_algorithm_to_string(algorithm), NULL);
	if (!context->cipher)
		goto err_cipher;

	context->ctx = EVP_CIPHER_CTX_new();
	if (!context->ctx)
		goto err_ctx;

	/* Set key and cipher */
	if (1 != EVP_EncryptInit_ex2(context->ctx, context->cipher, key, NULL, NULL))
		goto err_init;

	return context;

err_init:
	EVP_CIPHER_CTX_free(context->ctx);
err_ctx:
	EVP_CIPHER_free(context->cipher);
err_cipher:
	free(context);

	return NULL;
}

void security_exit(struct security_context *context)
{
	if (!context)
		return;

	EVP_CIPHER_free(context->cipher);
	EVP_CIPHER_CTX_free(context->ctx);
	free(context);
}

int security_encrypt(struct security_context *context, const unsigned char *plaintext,
		     size_t plaintext_length, const unsigned char *associated_data,
		     size_t associated_data_length, const unsigned char *iv,
		     unsigned char *ciphertext, unsigned char *tag)
{
	int ret = -EINVAL, len;

	/* Set IV */
	if (1 != EVP_EncryptInit_ex2(context->ctx, NULL, NULL, iv, NULL))
		goto out;

	/* Provide associatedData data. */
	if (1 !=
	    EVP_EncryptUpdate(context->ctx, NULL, &len, associated_data, associated_data_length))
		goto out;

	/* Provide the message to be encrypted, and obtain the encrypted output. */
	if (plaintext) {
		if (1 !=
		    EVP_EncryptUpdate(context->ctx, ciphertext, &len, plaintext, plaintext_length))
			goto out;
	}

	if (1 != EVP_EncryptFinal_ex(context->ctx, plaintext ? ciphertext + len : NULL, &len))
		goto out;

	if (1 != EVP_CIPHER_CTX_ctrl(context->ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
		goto out;

	ret = 0;

out:
	return ret;
}

int security_decrypt(struct security_context *context, const unsigned char *ciphertext,
		     size_t ciphertext_length, const unsigned char *associated_data,
		     size_t associated_data_length, unsigned char *tag, const unsigned char *iv,
		     unsigned char *plaintext)
{
	int ret = -EINVAL, len;

	/* Set IV */
	if (1 != EVP_DecryptInit_ex2(context->ctx, NULL, NULL, iv, NULL))
		goto out;

	/* Provide associatedData data. */
	if (!EVP_DecryptUpdate(context->ctx, NULL, &len, associated_data, associated_data_length))
		goto out;

	/* Provide the message to be decrypted, and obtain the plaintext output. */
	if (ciphertext) {
		if (!EVP_DecryptUpdate(context->ctx, plaintext, &len, ciphertext,
				       ciphertext_length))
			goto out;
	}

	if (!EVP_CIPHER_CTX_ctrl(context->ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
		goto out;

	ret = EVP_DecryptFinal_ex(context->ctx, ciphertext ? plaintext + len : NULL, &len);

	ret = ret > 0 ? 0 : -EPERM;

out:
	return ret;
}
