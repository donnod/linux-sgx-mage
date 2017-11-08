#include "trts_trim.h"
#include "sgx_trts.h" // for sgx_ocalloc, sgx_is_outside_enclave
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

typedef struct ms_trim_range_ocall_t {
    size_t ms_fromaddr;
    size_t ms_toaddr;
} ms_trim_range_ocall_t;

typedef struct ms_trim_range_commit_ocall_t {
    size_t ms_addr;
} ms_trim_range_commit_ocall_t;

sgx_status_t SGXAPI trim_range_ocall(size_t fromaddr, size_t toaddr)
{
    sgx_status_t status = SGX_SUCCESS;

    ms_trim_range_ocall_t* ms;
    OCALLOC(ms, ms_trim_range_ocall_t*, sizeof(*ms));

    ms->ms_fromaddr = fromaddr;
    ms->ms_toaddr = toaddr;
    status = sgx_ocall(EDMM_TRIM, ms);


    sgx_ocfree();
    return status;
}

sgx_status_t SGXAPI trim_range_commit_ocall(size_t addr)
{
    sgx_status_t status = SGX_SUCCESS;

    ms_trim_range_commit_ocall_t* ms;
    OCALLOC(ms, ms_trim_range_commit_ocall_t*, sizeof(*ms));

    ms->ms_addr = addr;
    status = sgx_ocall(EDMM_TRIM_COMMIT, ms);


    sgx_ocfree();
    return status;
}

