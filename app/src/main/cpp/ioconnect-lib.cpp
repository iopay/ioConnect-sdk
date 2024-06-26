#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "include/DeviceConnect_Core.h"
#include <jni.h>
#include <android/log.h>

#define LOG_TAG "IOConnect Tag"

extern "C"
JNIEXPORT void JNICALL
Java_io_iotex_ndktest_IOConnect_00024Companion_main(JNIEnv *env, jobject thiz) {
    psa_status_t status = psa_crypto_init();
    if (PSA_SUCCESS != status)
        return;

    //************************ STEP. 1 ******************************//

    unsigned int mySignKeyID, myKeyAgreementKeyID;

    mySignKeyID = 1;

//    JWK *mySignJWK = iotex_jwk_generate(JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_P256,
//                                        IOTEX_JWK_LIFETIME_PERSISTENT,
//                                        PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT,
//                                        PSA_ALG_ECDSA(PSA_ALG_SHA_256),
//                                        &mySignKeyID);
//    if (NULL == mySignJWK) {
//        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Failed to Generate a our own Sign JWK\n");
//        return;
//    }

    JWK *myKAJWK = iotex_jwk_generate(JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_P256,
                                      IOTEX_JWK_LIFETIME_VOLATILE,
                                      PSA_KEY_USAGE_DERIVE,
                                      PSA_ALG_ECDH,
                                      &myKeyAgreementKeyID);
    if (NULL == myKAJWK) {
        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Failed to Generate a our own KeyAgreement JWK\n");
        return;
    }

    //************************ STEP. 2 ******************************//
    // Based on the JWK generated in Step 1,
    // generate the corresponding DID and use the "io" method

//    char *mySignDID = iotex_did_generate("io", mySignJWK);
//    if (mySignDID)
//        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "My Sign DID : \t\t\t%s\n", mySignDID);
//    else
//        return;

    char *myKADID = iotex_did_generate("io", myKAJWK);
    if (myKADID)
        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "My Key Agreement DID : \t\t%s\n", myKADID);
    else
        return;

    char *myKAKID = iotex_jwk_generate_kid("io", myKAJWK);
    if (NULL == myKAKID)
        return;

    iotex_registry_item_register(myKAKID, myKAJWK);

    //************************ STEP. 3 ******************************//
    // In order to simulate C/S communication,
    // we generate the JWK of the peer's key exchange and the corresponding DID.

    unsigned int peerSignKeyID, peerKeyAgreementKeyID;

    JWK *peerSignJWK = iotex_jwk_generate(JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_P256,
                                          IOTEX_JWK_LIFETIME_VOLATILE,
                                          PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT,
                                          PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                          &peerSignKeyID);
    if (NULL == peerSignJWK) {
        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Failed to Generate a peer Sign JWK\n");
        return;
    }

    JWK *peerKAJWK = iotex_jwk_generate(JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_P256,
                                        IOTEX_JWK_LIFETIME_VOLATILE,
                                        PSA_KEY_USAGE_DERIVE,
                                        PSA_ALG_ECDH,
                                        &peerKeyAgreementKeyID);
    if (NULL == peerKAJWK) {
        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Failed to Generate a peer KeyAgreement JWK\n");
        return;
    }

    char *peerSignDID = iotex_did_generate("io", peerSignJWK);
    if (peerSignDID)
        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Peer DID : \t\t\t%s\n", peerSignDID);
    else
        return;

    char *peerKADID = iotex_did_generate("io", peerKAJWK);
    if (peerKADID)
        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Peer Key Agreement DID : \t%s\n", peerKADID);
    else
        return;

    char *peerSignKID = iotex_jwk_generate_kid("io", peerSignJWK);
    if (NULL == peerSignKID)
        return;

    char *peerKAKID = iotex_jwk_generate_kid("io", peerKAJWK);
    if (NULL == peerKAKID)
        return;

    iotex_registry_item_register(peerKAKID, peerKAJWK);

    //************************ STEP. 4 ******************************//
    // In order to simulate C/S communication,
    // generate a DIDDoc for the peer.

    did_status_t did_status;

    DIDDoc* peerDIDDoc = iotex_diddoc_new();
    if (NULL == peerDIDDoc) {
        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Failed to new a peerDIDDoc\n");
        return;
    }

    did_status = iotex_diddoc_property_set(peerDIDDoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTEXT, NULL,
                                           (void *) "https://www.w3.org/ns/did/v1");
    did_status = iotex_diddoc_property_set(peerDIDDoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_CONTEXT, NULL,
                                           (void *) "https://w3id.org/security#keyAgreementMethod");
    did_status = iotex_diddoc_property_set(peerDIDDoc, IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ID, NULL, peerSignDID);
    if (DID_SUCCESS != did_status) {
        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "iotex_diddoc_property_set [%d] ret %d\n", IOTEX_DIDDOC_BUILD_PROPERTY_TYPE_ID, did_status);
        return;
    }

    // 4.1 Make a verification method [type : authentication]
    DIDDoc_VerificationMethod* vm_authentication = iotex_diddoc_verification_method_new(peerDIDDoc, VM_PURPOSE_AUTHENTICATION, VM_TYPE_DIDURL);
    if (NULL == vm_authentication) {
        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Failed to iotex_diddoc_verification_method_new()\n");
    }

    did_status = iotex_diddoc_verification_method_set(vm_authentication, VM_TYPE_DIDURL, peerSignKID);
    if (DID_SUCCESS != did_status) {
        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "iotex_diddoc_verification_method_set ret %d\n", did_status);
        return;
    }

    VerificationMethod_Map vm_map_1 = iotex_diddoc_verification_method_map_new();
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_ID, peerSignKID);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_TYPE,
                                                          (void *) "JsonWebKey2020");
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_CON, peerSignDID);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_1, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_JWK, _did_jwk_json_generate(peerSignJWK));

    // 4.2 Make a verification method [type : key agreement]
    DIDDoc_VerificationMethod* vm_agreement = iotex_diddoc_verification_method_new(peerDIDDoc, VM_PURPOSE_KEY_AGREEMENT, VM_TYPE_DIDURL);
    if (NULL == vm_agreement) {
        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Failed to iotex_diddoc_verification_method_new()\n");
    }

    did_status = iotex_diddoc_verification_method_set(vm_agreement, VM_TYPE_DIDURL, peerKAKID);
    if (DID_SUCCESS != did_status) {
        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "iotex_diddoc_verification_method_set ret %d\n", did_status);
        return;
    }

    VerificationMethod_Map vm_map_2 = iotex_diddoc_verification_method_map_new();
    did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_ID, peerKAKID);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_TYPE,
                                                          (void *) "JsonWebKey2020");
    did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_CON, peerSignDID);
    did_status = iotex_diddoc_verification_method_map_set(vm_map_2, IOTEX_DIDDOC_BUILD_VM_MAP_TYPE_JWK, _did_jwk_json_generate(peerKAJWK));

    DIDDoc_VerificationMethod* vm_vm = iotex_diddoc_verification_method_new(peerDIDDoc, VM_PURPOSE_VERIFICATION_METHOD, VM_TYPE_MAP);
    did_status = iotex_diddoc_verification_method_set(vm_vm, VM_TYPE_MAP, vm_map_1);
    did_status = iotex_diddoc_verification_method_set(vm_vm, VM_TYPE_MAP, vm_map_2);

    char *peerDIDDoc_Serialize = iotex_diddoc_serialize(peerDIDDoc, true);
    if (peerDIDDoc_Serialize)
        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "DIDdoc : \n%s\n", peerDIDDoc_Serialize);

    iotex_diddoc_destroy(peerDIDDoc);

    // 4.3 Parse a DIDDoc
    DIDDoc *parsed_diddoc = iotex_diddoc_parse(peerDIDDoc_Serialize);

    if (parsed_diddoc)
        iotex_diddoc_destroy(parsed_diddoc);
}