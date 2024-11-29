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
// #include <psa/crypto.h>
// #include <psa/crypto_extra.h>

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

#define NRF_CRYPTO_EXAMPLE_ECDSA_TEXT_SIZE (50)
#define NRF_CRYPTO_EXAMPLE_ECDSA_SIGNATURE_SIZE (96)
#define NRF_CRYPTO_EXAMPLE_ECDSA_HASH_SIZE (32)

/* Below text is used as plaintext for signing/verification */
static uint8_t m_plain_text[NRF_CRYPTO_EXAMPLE_ECDSA_TEXT_SIZE] = {
	"Example string to demonstrate basic usage of ECDSA"
};

// static uint8_t m_priv_key[48] = {
//     0x00, 0x9b, 0xf1, 0x50, 0x1f, 0xd7, 0xb7, 0xdd, 
//     0x4a, 0x4c, 0xfe, 0x01, 0x87, 0x58, 0x2c, 0xa2, 
//     0x96, 0xed, 0x31, 0xe7, 0xfb, 0x15, 0xe8, 0x5b, 
//     0xed, 0x0d, 0x2c, 0x95, 0xba, 0xb2, 0x67, 0xd1, 
//     0x62, 0x7f, 0x58, 0x17, 0xde, 0x28, 0x6e, 0xe5, 
//     0x06, 0x32, 0x71, 0x26, 0x18, 0x18, 0x25, 0x52
// };

static uint8_t m_pub_key[] = {
    0x04, 0xdf, 0x9b, 0x25, 0x6d, 0x12, 0xbf, 0x94, 
    0xcd, 0x58, 0xea, 0x44, 0xb3, 0x6c, 0x64, 0xaf, 
    0xbb, 0xf1, 0x98, 0x0a, 0x98, 0xc4, 0x7b, 0xc0, 
    0x14, 0x3f, 0x11, 0xa2, 0xed, 0x9e, 0x98, 0x76, 
    0x66, 0x67, 0xf7, 0x49, 0xef, 0xc5, 0xaf, 0x76, 
    0x7c, 0x99, 0xdd, 0x9e, 0xb5, 0xb1, 0xa9, 0x96, 
    0x91, 0x94, 0x53, 0xa0, 0xe0, 0x01, 0x5b, 0x8d, 
    0x94, 0x3d, 0xf7, 0xa2, 0xba, 0x26, 0xd8, 0xdf, 
    0xaf, 0xce, 0x07, 0xb6, 0x74, 0xd9, 0x0c, 0x6b, 
    0x6f, 0xee, 0xd0, 0x74, 0xe0, 0xab, 0xfd, 0x7e, 
    0xef, 0x3d, 0x49, 0x62, 0x56, 0xc1, 0xc4, 0x12, 
    0x46, 0x29, 0xc2, 0xeb, 0xb3, 0xe4, 0xcd, 0xe6, 
    0x11
};

static const uint8_t SIGNATURE_REF[] = {
    0x5a, 0x67, 0x73, 0xac, 0xa7, 0xc2, 0xef, 0x57, 
    0x8f, 0x68, 0x4f, 0x60, 0xbb, 0x0b, 0x94, 0x1b, 
    0xa8, 0x86, 0xe5, 0x69, 0x3b, 0xb6, 0x00, 0x54, 
    0x17, 0x4c, 0x44, 0x41, 0x78, 0xbc, 0xd6, 0x4a, 
    0xb0, 0x94, 0xdb, 0x5a, 0x37, 0x7a, 0x8b, 0x08, 
    0x88, 0xc4, 0xb9, 0xf9, 0xfe, 0x71, 0x2d, 0x8a, 
    0x58, 0xbb, 0x5d, 0x24, 0x40, 0x37, 0xce, 0xf7, 
    0xd0, 0x3d, 0xc7, 0x28, 0xe8, 0xa7, 0x6a, 0x1b, 
    0xba, 0x0e, 0xdb, 0x1d, 0x2c, 0xa9, 0xa7, 0xf1, 
    0x92, 0xde, 0xcf, 0x0e, 0x2f, 0x01, 0x5f, 0xec, 
    0xba, 0x81, 0x97, 0x3c, 0x2d, 0x05, 0xbb, 0x9c, 
    0x34, 0xb8, 0xf7, 0xe3, 0xc9, 0xa9, 0x5d, 0x2c
};

// static uint8_t m_signature[NRF_CRYPTO_EXAMPLE_ECDSA_SIGNATURE_SIZE];
static uint8_t m_hash[NRF_CRYPTO_EXAMPLE_ECDSA_HASH_SIZE];


/* ====================================================================== */

/*
// static psa_key_id_t keypair_id;
static psa_key_id_t pub_key_id;

int crypto_init(void)
{
	psa_status_t status;

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

	// status = psa_destroy_key(keypair_id);
	// if (status != PSA_SUCCESS) {
	// 	LOG_INF("psa_destroy_key failed! (Error: %d)", status);
	// 	return APP_ERROR;
	// }

	status = psa_destroy_key(pub_key_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_destroy_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	return APP_SUCCESS;
}

int import_ecdsa_pub_key(void)
{
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status;


	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&key_attributes, 384);

	status = psa_import_key(&key_attributes, m_pub_key, sizeof(m_pub_key), &pub_key_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_import_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	psa_reset_key_attributes(&key_attributes);

	return APP_SUCCESS;
}

int hash_message(void)
{
	size_t output_len;
	psa_status_t status;


	psa_hash_operation_t operation = psa_hash_operation_init();
	status = psa_hash_setup(&operation, PSA_ALG_SHA_256);

	if (status != PSA_SUCCESS) {
		LOG_INF("psa_hash_setup failed! (Error: %d)", status);
		return APP_ERROR;
	}

	status = psa_hash_update(&operation, m_plain_text, sizeof(m_plain_text));
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_hash_update failed! (Error: %d)", status);
		return APP_ERROR;
	}

	status = psa_hash_finish(&operation, m_hash, sizeof(m_hash), &output_len);

	if (status != PSA_SUCCESS) {
		LOG_INF("psa_hash_finish failed! (Error: %d)", status);
		return APP_ERROR;
	}

	return APP_SUCCESS;
}

int verify_message(void)
{
	psa_status_t status;

	status = hash_message();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	status = psa_verify_hash(pub_key_id,
				 PSA_ALG_ECDSA(PSA_ALG_SHA_256),
				 m_hash,
				 sizeof(m_hash),
				 SIGNATURE_REF,
				 sizeof(SIGNATURE_REF));
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_verify_hash failed! (Error: %d)", status);
		return APP_ERROR;
	}

	LOG_INF("Signature verification was successful!");

	return APP_SUCCESS;
}

*/

// int import_ecdsa_keypair(void)
// {
// 	psa_status_t status;
// 	size_t olen;

// 	LOG_INF("Generating random ECDSA keypair...");

// 	/* Configure the key attributes */
// 	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

// 	/* Configure the key attributes */
// 	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_SIGN_HASH);
// 	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
// 	psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
// 	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
// 	psa_set_key_bits(&key_attributes, 384);

// 	/* Generate a random keypair. The keypair is not exposed to the application,
// 	 * we can use it to sign hashes.
// 	 */
// 	status = psa_import_key(&key_attributes, m_priv_key, sizeof(m_priv_key), &keypair_id);
// 	if (status != PSA_SUCCESS) {
// 		LOG_INF("psa_generate_key failed! (Error: %d)", status);
// 		return APP_ERROR;
// 	}

// 	uint8_t public_key[97];

// 	/* Export the public key */
// 	status = psa_export_public_key(keypair_id, public_key, sizeof(public_key), &olen);
// 	if (status != PSA_SUCCESS) {
// 		LOG_INF("psa_export_public_key failed! (Error: %d)", status);
// 		return APP_ERROR;
// 	}

// 	/* Compare length of exported pubkey */
// 	if (olen != sizeof(m_pub_key)) {
// 		LOG_INF("Public key length mismatch!");
// 		return APP_ERROR;
// 	}

// 	if (memcmp(m_pub_key, public_key, olen) != 0) {
// 		LOG_INF("Public key mismatch!");
// 		return APP_ERROR;
// 	}

// 	/* Reset key attributes and free any allocated resources. */
// 	psa_reset_key_attributes(&key_attributes);

// 	return APP_SUCCESS;
// }


// int sign_message(void)
// {
// 	uint32_t output_len;
// 	psa_status_t status;

// 	LOG_INF("Signing a message using ECDSA...");

// 	/* Hash the message */
//     status = hash_message();
// 	if (status != APP_SUCCESS) {
// 		LOG_INF(APP_ERROR_MESSAGE);
// 		return APP_ERROR;
// 	}

// 	/* Sign the hash */
// 	status = psa_sign_hash(keypair_id,
// 			       PSA_ALG_ECDSA(PSA_ALG_SHA_256),
// 			       m_hash,
// 			       sizeof(m_hash),
// 			       m_signature,
// 			       sizeof(m_signature),
// 			       &output_len);
// 	if (status != PSA_SUCCESS) {
// 		LOG_INF("psa_sign_hash failed! (Error: %d)", status);
// 		return APP_ERROR;
// 	}

// 	LOG_INF("Message signed successfully!");
// 	PRINT_HEX("Plaintext", m_plain_text, sizeof(m_plain_text));
// 	PRINT_HEX("SHA256 hash", m_hash, sizeof(m_hash));
// 	PRINT_HEX("Signature", m_signature, sizeof(m_signature));

// 	return APP_SUCCESS;
// }



int main(void)
{
	int status;

	LOG_INF("Starting ECDSA example...");

	// status = crypto_init();
	// if (status != APP_SUCCESS) {
	// 	LOG_INF(APP_ERROR_MESSAGE);
	// 	return APP_ERROR;
	// }

	// status = import_ecdsa_keypair();
	// if (status != APP_SUCCESS) {
	// 	LOG_INF(APP_ERROR_MESSAGE);
	// 	return APP_ERROR;
	// }

	// status = import_ecdsa_pub_key();
	// if (status != APP_SUCCESS) {
	// 	LOG_INF(APP_ERROR_MESSAGE);
	// 	return APP_ERROR;
	// }

	// status = sign_message();
	// if (status != APP_SUCCESS) {
	// 	LOG_INF(APP_ERROR_MESSAGE);
	// 	return APP_ERROR;
	// }

	// status = verify_message();
	// if (status != APP_SUCCESS) {
	// 	LOG_INF(APP_ERROR_MESSAGE);
	// 	return APP_ERROR;
	// }

	// status = crypto_finish();
	// if (status != APP_SUCCESS) {
	// 	LOG_INF(APP_ERROR_MESSAGE);
	// 	return APP_ERROR;
	// }

	LOG_INF(APP_SUCCESS_MESSAGE);

	return APP_SUCCESS;
}
