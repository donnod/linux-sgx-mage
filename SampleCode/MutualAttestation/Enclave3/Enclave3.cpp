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


// Enclave3.cpp : Defines the exported functions for the DLL application
#include "sgx_eid.h"
#include "Enclave3_t.h"

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "sgx_utils.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_mage.h"

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    e3_ocall_print_string(buf);
}

sgx_status_t print_measurement()
{
    sgx_status_t ret = SGX_SUCCESS;
    sgx_target_info_t target_info = {};
    sgx_report_t report;
    sgx_report_data_t report_data = {{0}};
    ret = sgx_create_report(&target_info, &report_data, &report);
    if (ret != SGX_SUCCESS) printf("ERROR get report %x\n", ret);
    else {
        for(int i = 0; i < 32; i++) printf("%02x", report.body.mr_enclave.m[i]);
        printf("\n");
    }
    return ret;
}

uint32_t e3_ecall_main()
{
    uint32_t ret = 0;

    printf("Enclave measurement:\n");
    print_measurement();
    
    uint64_t mage_size = sgx_mage_get_size();
    printf("MAGE has %lu entries:\n", mage_size);
    sgx_measurement_t mr;
    for (uint64_t i = 0; i < mage_size; i++) {
        printf("Entry %d:\n", i);
        if (SGX_SUCCESS != sgx_mage_derive_measurement(i, &mr)) {
            printf("failed to generate mage measurement\n");
            continue;
        }
        for (uint64_t j = 0; j < sizeof(mr.m); j++)
            printf("%02x", mr.m[j]);
        printf("\n");
    }

    return ret;
}