
#include "string.h"
#include "sgx_tcrypto.h"
#include "sgx_mage.h"

#define DATA_BLOCK_SIZE 64
#define SIZE_NAMED_VALUE 8
#define SE_PAGE_SIZE 0x1000

#define HANDLE_SIZE_OFFSET 152
#define HANDLE_HASH_OFFSET 168
#define SHA256_DIGEST_SIZE 32

const uint8_t __attribute__((section(SGX_MAGE_SEC_NAME))) sgx_mage_sec_buf[SGX_MAGE_SEC_SIZE] __attribute__((aligned (SE_PAGE_SIZE))) = {};

uint64_t sgx_mage_get_size()
{
    sgx_mage_t* mage_hdr = (sgx_mage_t*)sgx_mage_sec_buf;
    if (mage_hdr->size * sizeof(sgx_mage_entry_t) + sizeof(sgx_mage_t) > SGX_MAGE_SEC_SIZE) {
        return 0;
    }
    return mage_hdr->size;
}

sgx_status_t sgx_mage_derive_measurement(uint64_t mage_idx, sgx_measurement_t *mr)
{
    sgx_status_t ret = SGX_SUCCESS;

    sgx_mage_t* mage_hdr = (sgx_mage_t*)sgx_mage_sec_buf;
    if (mage_hdr->size * sizeof(sgx_mage_entry_t) + sizeof(sgx_mage_t) > SGX_MAGE_SEC_SIZE || mage_hdr->size <= mage_idx || mr == NULL) {
        return SGX_ERROR_UNEXPECTED;
    }

    sgx_mage_entry_t *mage = mage_hdr->entries + mage_idx;

    sgx_sha_state_handle_t sha_handle = NULL;
    if(sgx_sha256_init(&sha_handle) != SGX_SUCCESS)
    {
        return SGX_ERROR_UNEXPECTED;
    }

    memcpy(reinterpret_cast<uint8_t*>(sha_handle) + HANDLE_HASH_OFFSET, mage->digest, SHA256_DIGEST_SIZE);
    memcpy(reinterpret_cast<uint8_t*>(sha_handle) + HANDLE_SIZE_OFFSET, &mage->size, sizeof(mage->size));

    uint64_t page_offset = mage->offset;
    uint8_t* source = reinterpret_cast<uint8_t*>(reinterpret_cast<uint64_t>(sgx_mage_sec_buf));
    uint8_t* mage_sec_end_addr = source + SGX_MAGE_SEC_SIZE;

    while (source < mage_sec_end_addr) {
        uint8_t eadd_val[SIZE_NAMED_VALUE] = "EADD\0\0\0";
        uint8_t sinfo[64] = {0x01, 0x02};

        uint8_t data_block[DATA_BLOCK_SIZE];
        size_t db_offset = 0;
        memset(data_block, 0, DATA_BLOCK_SIZE);
        memcpy(data_block, eadd_val, SIZE_NAMED_VALUE);
        db_offset += SIZE_NAMED_VALUE;
        memcpy(data_block+db_offset, &page_offset, sizeof(page_offset));
        db_offset += sizeof(page_offset);
        memcpy(data_block+db_offset, &sinfo, sizeof(data_block)-db_offset);

        if(sgx_sha256_update(data_block, DATA_BLOCK_SIZE, sha_handle) != SGX_SUCCESS)
        {
            ret = SGX_ERROR_UNEXPECTED;
            goto CLEANUP;
        }

        uint8_t eextend_val[SIZE_NAMED_VALUE] = "EEXTEND";

        #define EEXTEND_TIME  4
        for(int i = 0; i < SE_PAGE_SIZE; i += (DATA_BLOCK_SIZE * EEXTEND_TIME))
        {
            db_offset = 0;
            memset(data_block, 0, DATA_BLOCK_SIZE);
            memcpy(data_block, eextend_val, SIZE_NAMED_VALUE);
            db_offset += SIZE_NAMED_VALUE;
            memcpy(data_block+db_offset, &page_offset, sizeof(page_offset));
            
            if(sgx_sha256_update(data_block, DATA_BLOCK_SIZE, sha_handle) != SGX_SUCCESS)
            {
                ret = SGX_ERROR_UNEXPECTED;
                goto CLEANUP;
            }

            for(int j = 0; j < EEXTEND_TIME; j++)
            {
                memcpy(data_block, source, DATA_BLOCK_SIZE);

                if(sgx_sha256_update(data_block, DATA_BLOCK_SIZE, sha_handle) != SGX_SUCCESS)
                {
                    ret = SGX_ERROR_UNEXPECTED;
                    goto CLEANUP;
                }

                source += DATA_BLOCK_SIZE;
                page_offset += DATA_BLOCK_SIZE;
            }
        }
    }

    if(sgx_sha256_get_hash(sha_handle, &mr->m) != SGX_SUCCESS)
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto CLEANUP;
    }

CLEANUP:
    sgx_sha256_close(sha_handle);
    return ret;
}

uint8_t* get_sgx_mage_sec_buf_addr()
{
    return reinterpret_cast<uint8_t*>(reinterpret_cast<uint64_t>(sgx_mage_sec_buf));
}