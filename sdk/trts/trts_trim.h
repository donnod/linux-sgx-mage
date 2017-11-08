#ifndef TRIM_RANGE_T_H__
#define TRIM_RANGE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" // for sgx_ocall etc.


#include <stdlib.h> // for size_t

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t SGXAPI trim_range_ocall(size_t fromaddr, size_t toaddr);
sgx_status_t SGXAPI trim_range_commit_ocall(size_t addr);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
