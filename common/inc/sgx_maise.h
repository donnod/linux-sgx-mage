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


#ifndef _SGX_MAISE_H_
#define _SGX_MAISE_H_

// #include "metadata.h"
// #include "uncopyable.h"
// #include "loader.h"
// #include "binparser.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SGX_MAISE_SEC_NAME ".sgx_maise"
#define SGX_MAISE_SEC_SIZE 4096


typedef struct _sgx_maise_entry_t
{
    uint64_t size;              // number of blocks updated
    uint64_t offset;            // offset of sgx_maise section
    uint8_t digest[32];         // sha-256 internal state
} sgx_maise_entry_t;

typedef struct _sgx_maise_t
{
    uint64_t size;
    sgx_maise_entry_t entries[];
} sgx_maise_t;

// class CMaise:
// {
// public:
//     CMaise(metadata_t *metadata, BinParser *parser);
//     ~CMaise();
//     bool build_metadata(const xml_parameter_t *parameter);

//     bool get_time(uint32_t *date);
//     bool modify_metadata(const xml_parameter_t *parameter);
//     bool check_xml_parameter(const xml_parameter_t *parameter);
//     bool fill_enclave_css(const xml_parameter_t *parameter);
//     void *alloc_buffer_from_metadata(uint32_t size);
//     bool get_xsave_size(uint64_t xfrm, uint32_t *xsave_size);
//     bool build_layout_table();
//     bool build_patch_table();
//     bool update_layout_entries();
//     bool build_layout_entries();
//     bool build_patch_entries(std::vector<patch_entry_t> &patches);

//     layout_entry_t *get_entry_by_id(uint16_t id, bool do_assert);
//     bool build_tcs_template(tcs_t *tcs);
//     bool build_gd_template(uint8_t *data, uint32_t *data_size);

//     uint64_t calculate_sections_size();
//     uint64_t calculate_enclave_size(uint64_t size);
//     void* get_rawdata_by_rva(uint64_t rva);
// private:
//     metadata_t *m_metadata;
//     BinParser *m_parser;
//     create_param_t m_create_param;
//     std::vector <layout_t> m_layouts;
//     uint64_t m_rva;
//     uint32_t m_gd_size;
//     uint8_t *m_gd_template;
// };

#ifdef __cplusplus
}
#endif

#endif
