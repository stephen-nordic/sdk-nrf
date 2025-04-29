/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/logging/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>

#ifdef CONFIG_BUILD_WITH_TFM
#include <tfm_ns_interface.h>
#endif

#define APP_SUCCESS		(0)
#define APP_ERROR		(-1)
#define APP_SUCCESS_MESSAGE "Example finished successfully!"
#define APP_ERROR_MESSAGE "Example exited with error!"

#define PRINT_HEX(p_label, p_text, len)\
	({\
		LOG_INF("---- %s (len: %u): ----", p_label, len);\
		LOG_HEXDUMP_INF(p_text, len, "Content:");\
		LOG_INF("---- %s end  ----", p_label);\
	})

LOG_MODULE_REGISTER(ecdsa, LOG_LEVEL_DBG);

/* ====================================================================== */
/*				Global variables/defines for the ECDSA example			  */

#define NRF_CRYPTO_EXAMPLE_ECDSA_TEXT_SIZE (11)

#define NRF_CRYPTO_EXAMPLE_ECDSA_PUBLIC_KEY_SIZE (49)
#define NRF_CRYPTO_EXAMPLE_ECDSA_SIGNATURE_SIZE (48)
#define NRF_CRYPTO_EXAMPLE_ECDSA_HASH_SIZE (48)

/* Below text is used as plaintext for signing/verification */
static uint8_t m_plain_text[NRF_CRYPTO_EXAMPLE_ECDSA_TEXT_SIZE] = {
	0x21, 0xea, 0x09, 0xc5, 0x56, 0x2d, 0x72, 0xa1, 0xa9, 0xb1, 0x51
};

static uint8_t m_pub_key[NRF_CRYPTO_EXAMPLE_ECDSA_PUBLIC_KEY_SIZE];

static uint8_t m_signature[NRF_CRYPTO_EXAMPLE_ECDSA_SIGNATURE_SIZE];
static uint8_t m_hash[NRF_CRYPTO_EXAMPLE_ECDSA_HASH_SIZE];

static psa_key_id_t keypair_id;
static psa_key_id_t pub_key_id;
/* ====================================================================== */

/*  Test vector: (ECDSA sign hash)
	CURVE: secp192r1
	d: 588b588cfb9de12d1f00e02af57c3bf6587652295ecfc52b
	digest: 2659e9d03330de6ca10046cfcca39e76dcc0450483597db9f9a67db8886b0e5f4f67522c2a36c9b81c71c21efd7edb48
	hash: SHA384
	msg: 21ea09c5562d72a1a9b151
	r: 36a75091be370af9ad1adea1b71581094980742737bef55d
	s: 4dbc50dc413fa8e387be7adf1b70378e0c88041b89bc00a4
*/

static uint8_t d[] = {
	0x58, 0x8b, 0x58, 0x8c, 0xfb, 0x9d, 0xe1, 0x2d,
	0x1f, 0x00, 0xe0, 0x2a, 0xf5, 0x7c, 0x3b, 0xf6,
	0x58, 0x76, 0x52, 0x29, 0x5e, 0xcf, 0xc5, 0x2b
};

static uint8_t ref_hash[] = {
	0x26, 0x59, 0xe9, 0xd0, 0x33, 0x30, 0xde, 0x6c,
	0xa1, 0x00, 0x46, 0xcf, 0xcc, 0xa3, 0x9e, 0x76,
	0xdc, 0xc0, 0x45, 0x04, 0x83, 0x59, 0x7d, 0xb9,
	0xf9, 0xa6, 0x7d, 0xb8, 0x88, 0x6b, 0x0e, 0x5f,
	0x4f, 0x67, 0x52, 0x2c, 0x2a, 0x36, 0xc9, 0xb8,
	0x1c, 0x71, 0xc2, 0x1e, 0xfd, 0x7e, 0xdb, 0x48
};

static uint8_t signature[] = {
	0x36, 0xa7, 0x50, 0x91, 0xbe, 0x37, 0x0a, 0xf9,
	0xad, 0x1a, 0xde, 0xa1, 0xb7, 0x15, 0x81, 0x09,
	0x49, 0x80, 0x74, 0x27, 0x37, 0xbe, 0xf5, 0x5d,
	0x4d, 0xbc, 0x50, 0xdc, 0x41, 0x3f, 0xa8, 0xe3,
	0x87, 0xbe, 0x7a, 0xdf, 0x1b, 0x70, 0x37, 0x8e,
	0x0c, 0x88, 0x04, 0x1b, 0x89, 0xbc, 0x00, 0xa4
};

int crypto_init(void)
{
	psa_status_t status;

	/* Initialize PSA Crypto */
	status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_crypto_init failed! (Error: %d)", status);
		return APP_ERROR;
	}

	return APP_SUCCESS;
}

int crypto_finish(void)
{
	psa_status_t status;

	/* Destroy the key handle */
	status = psa_destroy_key(keypair_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_destroy_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	status = psa_destroy_key(pub_key_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_destroy_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	return APP_SUCCESS;
}

int import_ecdsa_keypair(void)
{
	psa_status_t status;
	size_t olen;

	/* Configure the key attributes */
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	/* Configure the key attributes */
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_SIGN_HASH);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_384));
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&key_attributes, 192);

	/* Generate a random keypair. The keypair is not exposed to the application,
	 * we can use it to sign hashes.
	 */
	status = psa_import_key(&key_attributes, d, sizeof(d), &keypair_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_generate_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	/* Export the public key */
	status = psa_export_public_key(keypair_id, m_pub_key, sizeof(m_pub_key), &olen);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_export_public_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	/* Reset key attributes and free any allocated resources. */
	psa_reset_key_attributes(&key_attributes);

	return APP_SUCCESS;
}

int import_ecdsa_pub_key(void)
{
	/* Configure the key attributes */
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status;

	/* Configure the key attributes */
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_384));
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&key_attributes, 192);

	status = psa_import_key(&key_attributes, m_pub_key, sizeof(m_pub_key), &pub_key_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_import_key for pubkey failed! (Error: %d)", status);
		return APP_ERROR;
	}

	/* Reset key attributes and free any allocated resources. */
	psa_reset_key_attributes(&key_attributes);

	return APP_SUCCESS;
}

int sign_message(void)
{
	uint32_t output_len;
	psa_status_t status;

	LOG_INF("Signing a message using ECDSA...");

	/* Compute the SHA384 hash*/
	status = psa_hash_compute(PSA_ALG_SHA_384,
				  m_plain_text,
				  sizeof(m_plain_text),
				  m_hash,
				  sizeof(m_hash),
				  &output_len);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_hash_compute failed! (Error: %d)", status);
		return APP_ERROR;
	}

	/* Check that hash matches test vector */
	if (memcmp(m_hash, ref_hash, sizeof(m_hash))) {
		LOG_INF("Hash mismatch!");
		return APP_ERROR;
	}

	/* Sign the hash */
	status = psa_sign_hash(keypair_id,
			       PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_384),
			       m_hash,
			       sizeof(m_hash),
			       m_signature,
			       sizeof(m_signature),
			       &output_len);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_sign_hash failed! (Error: %d)", status);
		return APP_ERROR;
	}

	/* Check that signature matches test vector */
	if (memcmp(m_signature, signature, sizeof(m_signature))) {
		LOG_INF("Signature mismatch!");
		return APP_ERROR;
	}

	LOG_INF("Message signed successfully!");
	PRINT_HEX("Plaintext", m_plain_text, sizeof(m_plain_text));
	PRINT_HEX("SHA384 hash", m_hash, sizeof(m_hash));
	PRINT_HEX("Signature", m_signature, sizeof(m_signature));

	return APP_SUCCESS;
}

int verify_message(void)
{
	psa_status_t status;

	LOG_INF("Verifying ECDSA signature...");

	/* Verify the signature of the hash */
	status = psa_verify_hash(pub_key_id,
				 PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_384),
				 m_hash,
				 sizeof(m_hash),
				 m_signature,
				 sizeof(m_signature));
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_verify_hash failed! (Error: %d)", status);
		return APP_ERROR;
	}

	LOG_INF("Signature verification was successful!");

	return APP_SUCCESS;
}

int main(void)
{
	int status;

	LOG_INF("Starting ECDSA example...");

	status = crypto_init();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	status = import_ecdsa_keypair();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	status = import_ecdsa_pub_key();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	status = sign_message();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	status = verify_message();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	status = crypto_finish();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	LOG_INF(APP_SUCCESS_MESSAGE);

	return APP_SUCCESS;
}
