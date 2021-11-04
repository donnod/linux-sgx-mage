# MAGE: Mutual Attestation for a Group of Enclaves without Trusted Third Parties

MAGE is an extension of Intel SGX SDK ([v2.6](https://github.com/intel/linux-sgx/tree/sgx_2.6)) to support mutual attestation for a group of enclaves without trusted third parties.

The extension includes:
### MAGE Library ([sdk/mage](sdk/mage)):
- Reserve a read-only data section, named `.sgx_mage`, to store auxiliary information for mutual attestation.
- Provide APIs for deriving trusted enclaves' measurements from `.sgx_mage`.

### Modified Enclave Loader ([psw/urts/loader](psw/urts/loader.cpp), [psw/urts/parser](psw/urts/parser)):
- Change the order of loading EPC pages, so that the EPC pages in `.sgx_mage` section are loaded after all other EPC pages.

### Modified Signing Tool ([sdk/sign_tool/SignTool](sdk/sign_tool/SignTool)):
- Extract auxiliary information from enclaves.
- Insert auxiliary information into the `.sgx_mage` section of enclaves.

Build Instructions
------------
Follow the original build instructions to build the SDK [linux-sgx_2.6](https://github.com/intel/linux-sgx/tree/sgx_2.6).

Sample Code
------------
Sample Code for three enclaves to mutually derive measurements is provided in [SampleCode/MutualAttestation](SampleCode/MutualAttestation).

Integration with Open-Sourced SGX Application
------------
[OPERA-MAGE: Open Remote Attestation for Intel's Secure Enclaves (MAGE version)](https://github.com/donnod/opera-mage)

Artifact Evaluation
------------
This repo is an prototype implementation of the following paper:

[USENIX Security’22] *MAGE: Mutual Attestation for a Group of Enclaves without Trusted Third Parties* by Guoxing Chen and Yinqian Zhang

The code and instructions for reproducing the results presented in the paper can be found in [sec22ae](https://github.com/donnod/sec22ae).