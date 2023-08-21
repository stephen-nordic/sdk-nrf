/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stddef.h>

#include <mbedtls/ecp.h>
#include "common_test.h"

/**@brief ECDSA test vectors can be found on NIST web pages.
 *
 * https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Component-Testing
 */


#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)

ITEM_REGISTER(
	test_vector_ecdsa_sign_data,
	test_vector_ecdsa_sign_t test_vector_ecdsa_sign_secp256k1_SHA256_1) = {
	.curve_type = MBEDTLS_ECP_DP_SECP256K1,
	.expected_sign_err_code = 0,
	.expected_verify_err_code = 0,
	.p_test_vector_name = TV_NAME("secp256k1 valid SHA256 1"),
	.p_input =
		"4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a",
	.p_qx = "779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcd",
	.p_qy = "e94b724a555b6d017bb7607c3e3281daf5b1699d6ef4124975c9237b917d426f",
	.p_x = "ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f"
};

#endif

