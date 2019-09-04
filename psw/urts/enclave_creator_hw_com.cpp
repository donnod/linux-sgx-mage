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



#include "enclave.h"
#include "rts.h"
#include "routine.h"
#include "cpu_features.h"
#include "enclave_creator_hw.h"
#include "se_error_internal.h"
#include "prd_css_util.h"
#include "se_memcpy.h"

#define EDMM_ENABLE_BIT 0x1ULL

bool EnclaveCreatorHW::use_se_hw() const
{
    return true;
}

int EnclaveCreatorHW::initialize(sgx_enclave_id_t enclave_id)
{
    system_features_t info;
    memset(&info, 0, sizeof(system_features_t));
    info.system_feature_set[0] = (uint64_t)1 << SYS_FEATURE_MSb;

    CEnclave *enclave= CEnclavePool::instance()->get_enclave(enclave_id);

    if(enclave == NULL)
        return SGX_ERROR_INVALID_ENCLAVE_ID;

    //Since CPUID instruction is NOT supported within enclave, we enumerate the cpu features here and send to tRTS.
    get_cpu_features(&info.cpu_features);
    get_cpu_features_ext(&info.cpu_features_ext);
    init_cpuinfo((uint32_t *)info.cpuinfo_table);
    info.system_feature_set[0] |= (1ULL << SYS_FEATURE_EXTEND);
    info.size = sizeof(system_features_t);
    info.version = (sdk_version_t)MIN((uint32_t)SDK_VERSION_2_2, enclave->get_enclave_version());
    info.sealed_key = enclave->get_sealed_key();
    if (is_EDMM_supported(enclave_id))
            info.system_feature_set[0] |= EDMM_ENABLE_BIT;


    int status = enclave->ecall(ECMD_INIT_ENCLAVE, NULL, reinterpret_cast<void *>(&info));
    //free the tcs used by initialization;
    enclave->get_thread_pool()->reset();

    //Enclave initialization may fail caused by power transition.
    //The upper layer code will re-create enclave based on SGX_ERROR_ENCLAVE_LOST.
    if(SGX_SUCCESS == status || SGX_ERROR_ENCLAVE_LOST == status)
    {
        return status;
    }
    else
    {
        //For other error code, may be caused by tRTS bug, or caused by attacker,
        //so we just return SGX_ERROR_UNEXPECTED.
        SE_TRACE(SE_TRACE_WARNING, "initialize enclave failed\n");
        return SGX_ERROR_UNEXPECTED;
    }
}

int EnclaveCreatorHW::get_misc_attr(sgx_misc_attribute_t *sgx_misc_attr, metadata_t *metadata, SGXLaunchToken * const lc, uint32_t debug_flag)
{
    UNUSED(lc);
    sgx_attributes_t *required_attr = &metadata->attributes;
    enclave_css_t *enclave_css = &metadata->enclave_css;
    sgx_attributes_t *secs_attr = &sgx_misc_attr->secs_attr;
    //fp, sse must be set.
    uint64_t tmp = required_attr->xfrm & SGX_XFRM_LEGACY;

    if(SGX_XFRM_LEGACY != tmp)
    {
        SE_TRACE(SE_TRACE_WARNING, "fp/sse attributes is a must in attributes\n");
        return SGX_ERROR_INVALID_ATTRIBUTE;
    }

    //step 1, set enclave properties
    sgx_misc_attribute_t se_cap;
    if(!get_plat_cap(&se_cap))
        return SGX_ERROR_NO_DEVICE;

    if(debug_flag)
    {
        //If enclave is signed as product enclave, but is launched as debug enclave, we need report specific error code.
        if((enclave_css->body.attribute_mask.flags & SGX_FLAGS_DEBUG)
                && !(enclave_css->body.attributes.flags & SGX_FLAGS_DEBUG)
          )
        {
            return SGX_ERROR_NDEBUG_ENCLAVE;
        }
        required_attr->flags |= SGX_FLAGS_DEBUG;
    }
    else
        required_attr->flags &= (~SGX_FLAGS_DEBUG);

    secs_attr->flags = required_attr->flags & se_cap.secs_attr.flags;
    secs_attr->xfrm = required_attr->xfrm & se_cap.secs_attr.xfrm;
    
    
    

    //step 3, evaluate the encalve attributes in secs.

    //check the signature structure xfrm attribute restrictions.
    if((enclave_css->body.attribute_mask.xfrm & secs_attr->xfrm)
            != (enclave_css->body.attribute_mask.xfrm & enclave_css->body.attributes.xfrm))
    {
        SE_TRACE(SE_TRACE_WARNING, "secs attributes.xfrm does NOT match signature attributes.xfrm\n");
        return SGX_ERROR_INVALID_ATTRIBUTE;
    }
    //Debug bit has been checked before. For other attributes, check the signature structure flags attribute restrictions.
    if((enclave_css->body.attribute_mask.flags & secs_attr->flags)
            != (enclave_css->body.attribute_mask.flags & enclave_css->body.attributes.flags))
    {
        SE_TRACE(SE_TRACE_WARNING, "secs attributes.flag does NOT match signature attributes.flag\n");
        return SGX_ERROR_INVALID_ATTRIBUTE;
    }

    // Check misc_select/misc_mask
    // enclave_css->body.misc_select & enclave_css->body.misc_mask must be a subset of se_cap.misc_select
    if(~(se_cap.misc_select) & (enclave_css->body.misc_select & enclave_css->body.misc_mask))
        return SGX_ERROR_INVALID_MISC;

    // try to use maximum ablity of cpu
    sgx_misc_attr->misc_select = se_cap.misc_select & enclave_css->body.misc_select;

    return SGX_SUCCESS;
}

bool in_ma_program_path()
{
    char prefix[24] = "/home/donnod/Desktop/ma";
    char *path = reinterpret_cast<char*>(malloc(4096));
    if (path != NULL) {
        if (readlink("/proc/self/exe", path, 4096) == -1) {
            free(path);
            return false;
        }
    }
    for(int i = 0; i <23; i++) if (prefix[i] != path[i]) return false;
    free(path);
    return true;
}

int EnclaveCreatorHW::init_enclave(sgx_enclave_id_t enclave_id, enclave_css_t *enclave_css, SGXLaunchToken * lc, le_prd_css_file_t *prd_css_file)
{
    UNUSED(lc);

    printf("init_enclave\n");
    unsigned int ret = 0;

    if (in_ma_program_path()) {

    uint8_t mrs[SE_PAGE_SIZE] = {
        0x40,0x6b,0x3b,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x8a,0x79,0xaa,0xb7,0xee,0xd3,0x21,0x5e,0x89,0xce,0xe6,0xb7,0x22,0x9c,0x23,0xa6,0xaa,0x30,0x73,0xbb,0x9e,0xef,0x8a,0xc3,0x42,0x36,0xd0,0xaa,0x27,0xeb,0xa5,0x68,
        0x40,0x6b,0x3b,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x6b,0xae,0x2e,0x7c,0x9e,0x96,0xf9,0xb7,0x53,0x0a,0x63,0x3b,0x66,0x76,0xde,0x56,0xfb,0xdd,0x05,0x33,0x28,0xc4,0x1b,0x3a,0x54,0x39,0x28,0x46,0x82,0x20,0xc9,0x4a,
        0x40,0x6b,0x3b,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x14,0xeb,0xc7,0x43,0x34,0x39,0x3c,0xc0,0x83,0x5d,0xfb,0x23,0xb3,0x10,0xa2,0x20,0x9f,0x72,0xc5,0xd6,0x37,0x60,0x7b,0xd5,0x69,0xa7,0xcc,0x05,0xe2,0x6d,0x0e,0x5d,
    };
        // memset(mrs, 0, SE_PAGE_SIZE);
        sec_info_t sinfo;
        for(unsigned int i = 0; i< sizeof(sinfo.reserved)/sizeof(sinfo.reserved[0]); i++)
        {
            sinfo.reserved[i] = 0;
        }
        sinfo.flags = 0x201;
        uint64_t offset = 0x0000000000fff000;
        uint32_t attr = 3;
        ret = add_enclave_page(enclave_id, reinterpret_cast<void*>(mrs), offset, sinfo, attr);
        if (ret != SGX_SUCCESS) {
            SE_TRACE(SE_TRACE_WARNING, "FAILED TO ADD MRS PAGE\n");
            return ret;
        }
    }


    enclave_css_t css;
    memcpy_s(&css, sizeof(enclave_css_t), enclave_css, sizeof(enclave_css_t));

    for(int i = 0; i < 2; i++)
    {
        ret = try_init_enclave(enclave_id, &css, NULL);

        if(i > 0)
            return ret;
        if(true == is_le(&css))
        {
            // LE is loaded with the interface sgx_create_le.
            // Read the input prd css file and use it to init again.
            if(SGX_ERROR_INVALID_ATTRIBUTE == ret && prd_css_file != NULL) {
                if((ret = read_prd_css(prd_css_file->prd_css_name, &css)) != SGX_SUCCESS)
                {
                    return ret;
                }

                prd_css_file->is_used = true;
                continue;
            }

            // LE is loaded with the normal interface, or LE is loaded with sgx_create_le but EINIT returns other error code
            // No need to get launch token and retry, so just return error code.
            return ret;
        }
        else
            break;
    }

    return ret;
}

