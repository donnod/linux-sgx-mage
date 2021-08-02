/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#ifndef _SGX_MAGE_H_
#define _SGX_MAGE_H_

#ifdef __cplusplus
extern "C" {
#endif

#define SGX_MAGE_SEC_NAME ".sgx_mage"
#define SGX_MAGE_SEC_SIZE 4096
// must be a multiple of 4096 (page size)

typedef struct _sgx_mage_entry_t
{
    uint64_t size;              // number of blocks updated
    uint64_t offset;            // offset of sgx_mage section
    uint8_t digest[32];         // sha-256 internal state
} sgx_mage_entry_t;

typedef struct _sgx_mage_t
{
    uint64_t size;
    sgx_mage_entry_t entries[];
} sgx_mage_t;

uint64_t sgx_mage_get_size();

sgx_status_t sgx_mage_derive_measurement(uint64_t mage_idx, sgx_measurement_t *mr);

uint8_t* get_sgx_mage_sec_buf_addr();

#ifdef __cplusplus
}
#endif

#endif
