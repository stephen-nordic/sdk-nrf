/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
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

#include <cracen_psa.h>

#ifdef CONFIG_BUILD_WITH_TFM
#include <tfm_ns_interface.h>
#endif

#define APP_SUCCESS	    (0)
#define APP_ERROR	    (-1)
#define APP_SUCCESS_MESSAGE "Example finished successfully!"
#define APP_ERROR_MESSAGE   "Example exited with error!"

#define PRINT_HEX(p_label, p_text, len)                                                            \
	({                                                                                         \
		LOG_INF("---- %s (len: %u): ----", p_label, len);                                  \
		LOG_HEXDUMP_INF(p_text, len, "Content:");                                          \
		LOG_INF("---- %s end  ----", p_label);                                             \
	})

LOG_MODULE_REGISTER(eddsa, LOG_LEVEL_DBG);

/* Global variables/defines for the EDDSA example */

#define NRF_CRYPTO_EXAMPLE_EDDSA_TEXT_SIZE (1)

#define NRF_CRYPTO_EXAMPLE_EDDSA_PUBLIC_KEY_SIZE (32)
#define NRF_CRYPTO_EXAMPLE_EDDSA_SIGNATURE_SIZE	 (64)

static uint8_t m_pub_key[NRF_CRYPTO_EXAMPLE_EDDSA_PUBLIC_KEY_SIZE];
static size_t m_pub_key_len;

static uint8_t m_signature[NRF_CRYPTO_EXAMPLE_EDDSA_SIGNATURE_SIZE];
static size_t m_signature_len;

static psa_key_id_t m_key_pair_id =
	PSA_KEY_HANDLE_FROM_CRACEN_KMU_SLOT(CRACEN_KMU_KEY_USAGE_SCHEME_RAW, 75);
static psa_key_id_t m_pub_key_id =
	PSA_KEY_HANDLE_FROM_CRACEN_KMU_SLOT(CRACEN_KMU_KEY_USAGE_SCHEME_RAW, 77);

/* Test Vector */
/* Private Key */
static const uint8_t ed25519_privkey[32] = {0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
					    0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
					    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
					    0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb};

/* Public Key */
static const uint8_t ed25519_pubkey[32] = {0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a,
					   0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
					   0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
					   0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c};

static uint8_t m_plain_text[NRF_CRYPTO_EXAMPLE_EDDSA_TEXT_SIZE] = {0x72};

uint8_t test_vector_signature[NRF_CRYPTO_EXAMPLE_EDDSA_SIGNATURE_SIZE] = {
	/* R */
	0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25,
	0x40, 0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f, 0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb,
	0x69, 0xda,

	/* S */
	0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e, 0x45, 0x8f, 0x36, 0x13, 0xd0, 0xf1, 0x1d,
	0x8c, 0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee, 0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb,
	0x0c, 0x00};

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
	status = psa_destroy_key(m_key_pair_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_destroy_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	status = psa_destroy_key(m_pub_key_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_destroy_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	return APP_SUCCESS;
}

int import_eddsa_keypair(void)
{
	psa_status_t status;

	LOG_INF("Importing EDDSA keypair...");

	/* Configure the key attributes */
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	/* Configure the key attributes */
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_SIGN_MESSAGE |
							 PSA_KEY_USAGE_SIGN_HASH |
							 PSA_KEY_USAGE_EXPORT);
	psa_set_key_lifetime(&key_attributes,
			     PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
				     PSA_KEY_PERSISTENCE_DEFAULT, PSA_KEY_LOCATION_CRACEN_KMU));
	psa_set_key_algorithm(&key_attributes, PSA_ALG_PURE_EDDSA);
	psa_set_key_type(&key_attributes,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
	psa_set_key_bits(&key_attributes, 255);
	psa_set_key_id(&key_attributes, m_key_pair_id);

	/* Import keypair */
	status = psa_import_key(&key_attributes, ed25519_privkey, sizeof(ed25519_privkey),
				&m_key_pair_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_import_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	/* Export the public key */
	status = psa_export_public_key(m_key_pair_id, m_pub_key, sizeof(m_pub_key), &m_pub_key_len);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_export_public_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	// Compare against test vector
	if (!(memcmp(m_pub_key, ed25519_pubkey, NRF_CRYPTO_EXAMPLE_EDDSA_PUBLIC_KEY_SIZE) == 0)) {
		LOG_INF("Pubkey not equal to test vector!");
		return APP_ERROR;
	}
	LOG_INF("Pubkey matched test vector");

	PRINT_HEX("Public-key", m_pub_key, m_pub_key_len);

	/* Reset key attributes and free any allocated resources. */
	psa_reset_key_attributes(&key_attributes);

	return APP_SUCCESS;
}

int import_eddsa_pub_key(void)
{
	/* Configure the key attributes */
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status;

	/* Configure the key attributes */
	psa_set_key_usage_flags(&key_attributes,
				PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_lifetime(&key_attributes,
			     PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
				     PSA_KEY_PERSISTENCE_DEFAULT, PSA_KEY_LOCATION_CRACEN_KMU));
	psa_set_key_algorithm(&key_attributes, PSA_ALG_PURE_EDDSA);
	psa_set_key_type(&key_attributes,
			 PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS));
	psa_set_key_bits(&key_attributes, 255);
	psa_set_key_id(&key_attributes, m_pub_key_id);

	status = psa_import_key(&key_attributes, ed25519_pubkey,
				NRF_CRYPTO_EXAMPLE_EDDSA_PUBLIC_KEY_SIZE, &m_pub_key_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_import_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	/* Reset key attributes and free any allocated resources. */
	psa_reset_key_attributes(&key_attributes);

	return APP_SUCCESS;
}

int sign_message(void)
{
	psa_status_t status;

	LOG_INF("Signing a message using EDDSA...");

	/* Sign the message */
	status = psa_sign_message(m_key_pair_id, PSA_ALG_PURE_EDDSA, m_plain_text,
				  sizeof(m_plain_text), m_signature, sizeof(m_signature),
				  &m_signature_len);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_sign_message failed! (Error: %d)", status);
		return APP_ERROR;
	}

	/* Compare against test vector */
	if (!(memcmp(m_signature, test_vector_signature, NRF_CRYPTO_EXAMPLE_EDDSA_SIGNATURE_SIZE) ==
	      0)) {
		LOG_INF("Generated signature not equal to test vector!");
		return APP_ERROR;
	}
	LOG_INF("Generated signature matched test vector");

	LOG_INF("Message signed successfully!");
	PRINT_HEX("Plaintext", m_plain_text, sizeof(m_plain_text));
	PRINT_HEX("Signature", m_signature, sizeof(m_signature));

	return APP_SUCCESS;
}

int verify_message(void)
{
	psa_status_t status;

	LOG_INF("Verifying EDDSA signature...");

	/* Verify the signature of the message */
	status = psa_verify_message(m_pub_key_id, PSA_ALG_PURE_EDDSA, m_plain_text,
				    sizeof(m_plain_text), m_signature, m_signature_len);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_verify_message failed! (Error: %d)", status);
		return APP_ERROR;
	}

	LOG_INF("Signature verification was successful!");

	return APP_SUCCESS;
}

int main(void)
{
	int status;

	LOG_INF("Starting EDDSA example...");

	status = crypto_init();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	/*
	status = import_eddsa_keypair();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	status = import_eddsa_pub_key();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}
	*/

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

	/*
	status = crypto_finish();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}
	*/

	LOG_INF(APP_SUCCESS_MESSAGE);

	return APP_SUCCESS;
}
