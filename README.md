MAGE: Mutual Attestation for a Group of Enclaves without Trusted Third Parties

================================================

MAGE is an extension of Intel SGX SDK to support mutual attestation for a group of enclaves without trusted third parties.

The extension includes:
### MAGE Library ([sdk/mage](sdk/mage)):
- Reserve a read-only data section, named `.sgx_mage`, to store auxiliary information for mutual attestation.
- Provide APIs for deriving trusted enclaves' measurements from `.sgx_mage`.

### Modified Enclave Loader ([loader](psw/urts/loader.cpp), [parser](psw/urts/parser):
- Change the order of loading EPC pages, so that the EPC pages in .sgx_mage section are loaded after all other EPC pages.

### Modified Signing Tool ([SignTool](sdk/sign_tool/SignTool)):
- Extract auxiliary information from enclaves.
- Insert auxiliary information into the .sgx_mage section of enclaves.

Build Instructions
------------
Follow the original build instructions to build the SDK [linux-sgx](https://github.com/01org/linux-sgx).

Sample Code
------------
Sample Code for three enclaves to mutually derive measurements is provided in [SampleCode/MutualAttestation](SampleCode/MutualAttestation).