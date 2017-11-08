#include "trts_emodpr.h"

#include "sgx_trts.h" // for sgx_ocalloc, sgx_is_outside_enclave
#include "arch.h"
#include "sgx_edger8r.h" // for sgx_ocall etc.
#include "internal/rts.h"

/* sgx_ocfree() just restores the original outside stack pointer. */
#define OCALLOC(val, type, len) do {    \
    void* __tmp = sgx_ocalloc(len); \
    if (__tmp == NULL) {    \
        sgx_ocfree();   \
        return SGX_ERROR_UNEXPECTED;\
    }           \
    (val) = (type)__tmp;    \
} while (0)

typedef struct ms_change_permissions_ocall_t {
    size_t ms_addr;
    size_t ms_size;
    uint64_t ms_pte_perms;
    uint64_t ms_epcm_perms;
} ms_change_permissions_ocall_t;

sgx_status_t SGXAPI change_permissions_ocall(size_t addr, size_t size, uint64_t pte_perms, uint64_t epcm_perms)
{
#ifdef SE_SIM
    (void)addr;
    (void)size;
    (void)pte_perms;
    (void)epcm_perms;
    return SGX_SUCCESS;
#else
    sgx_status_t status = SGX_SUCCESS;

    ms_change_permissions_ocall_t* ms;
    OCALLOC(ms, ms_change_permissions_ocall_t*, sizeof(*ms));

    ms->ms_addr = addr;
    ms->ms_size = size;
    ms->ms_pte_perms = pte_perms;
    ms->ms_epcm_perms = epcm_perms;
    status = sgx_ocall(EDMM_MODPR, ms);


    sgx_ocfree();
    return status;
#endif
}
