#ifndef MPROTECT_T_H__
#define MPROTECT_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_trts.h"


#include <stdlib.h> // for size_t

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t SGXAPI change_permissions_ocall(size_t addr, size_t size, uint64_t pte_perms, uint64_t epcm_perms);

sgx_status_t change_protection(void *enclave_base);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
