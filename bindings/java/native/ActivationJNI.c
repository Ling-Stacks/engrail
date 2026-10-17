/*
 * MIT License
 *
 * Copyright (c) 2026 ActivationSystem Contributors
 *
 * JNI glue between Activation.java and the pure-C ABI. Only this
 * file knows about JNI; the crypto stays in libactivation's C core.
 */

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "activation/license.h"
#include "activation/fingerprint.h"
#include "activation/state.h"
#include "activation/sm2.h"

/* helpers */

static void hex_encode(const uint8_t *b, size_t n, char *out)
{
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = hx[b[i] >> 4];
        out[2 * i + 1] = hx[b[i] & 15];
    }
    out[2 * n] = '\0';
}

/* NewStringUTF requires modified-UTF-8; hex strings are plain ASCII. */
static jstring hex_jstring(JNIEnv *env, const uint8_t *b, size_t n)
{
    char buf[2 * 64 + 1]; /* max: 64 bytes */
    hex_encode(b, n > 64 ? 64 : n, buf);
    return (*env)->NewStringUTF(env, buf);
}

/* Activation natives */

JNIEXPORT void JNICALL
Java_Activation_nMachineCode(JNIEnv *env, jclass cls, jbyteArray jpub,
                             jbyteArray jds, jint product, jbyteArray jout)
{
    (void)cls;
    uint8_t pubkey[32], dsalt[32], mc[16];
    (*env)->GetByteArrayRegion(env, jpub, 0, 32, (jbyte *)pubkey);
    (*env)->GetByteArrayRegion(env, jds, 0, 32, (jbyte *)dsalt);

    act_fingerprint(pubkey, dsalt, (uint32_t)product, NULL, 0, mc);

    char str[ACT_MACHINE_CODE_STR_SIZE];
    act_fp_to_string(mc, str);
    (*env)->SetByteArrayRegion(env, jout, 0, (jsize)strlen(str),
                               (const jbyte *)str);
}

JNIEXPORT jint JNICALL
Java_Activation_nVerifyCode(JNIEnv *env, jclass cls, jbyteArray jcode,
                            jbyteArray jpub, jint product, jbyteArray jmc,
                            jobject jinfo)
{
    (void)cls;
    jsize code_len = (*env)->GetArrayLength(env, jcode);
    char *code = (char *)malloc((size_t)code_len + 1);
    (*env)->GetByteArrayRegion(env, jcode, 0, code_len, (jbyte *)code);
    code[code_len] = '\0';

    uint8_t pubkey[32], mc[16];
    (*env)->GetByteArrayRegion(env, jpub, 0, 32, (jbyte *)pubkey);
    (*env)->GetByteArrayRegion(env, jmc, 0, 16, (jbyte *)mc);

    act_license_info info;
    const act_status st = act_license_verify(code, pubkey, (uint32_t)product,
                                             mc, (int64_t)time(NULL), &info);
    free(code);
    if (st != ACT_OK || jinfo == NULL) {
        return st;
    }

    /* reflect fields into LicenseInfo */
    jclass ic = (*env)->GetObjectClass(env, jinfo);
    jfieldID f;
    f = (*env)->GetFieldID(env, ic, "productId", "I");
    (*env)->SetIntField(env, jinfo, f, (jint)info.product_id);
    f = (*env)->GetFieldID(env, ic, "machineCode", "Ljava/lang/String;");
    (*env)->SetObjectField(env, jinfo, f, hex_jstring(env, info.machine_code, 16));
    f = (*env)->GetFieldID(env, ic, "expiryDays", "I");
    (*env)->SetIntField(env, jinfo, f, (jint)info.expiry_days);
    f = (*env)->GetFieldID(env, ic, "perpetual", "Z");
    (*env)->SetBooleanField(env, jinfo, f, (jboolean)info.perpetual);
    f = (*env)->GetFieldID(env, ic, "trial", "Z");
    (*env)->SetBooleanField(env, jinfo, f, (jboolean)info.trial);
    f = (*env)->GetFieldID(env, ic, "serial", "Ljava/lang/String;");
    (*env)->SetObjectField(env, jinfo, f, hex_jstring(env, info.serial, 8));
    f = (*env)->GetFieldID(env, ic, "features", "I");
    (*env)->SetIntField(env, jinfo, f, (jint)info.features);
    return st;
}

JNIEXPORT jint JNICALL
Java_Activation_nActivate(JNIEnv *env, jclass cls, jbyteArray jcode,
                          jbyteArray jpub, jint product, jbyteArray jmc,
                          jbyteArray jpath)
{
    (void)cls;
    jsize code_len = (*env)->GetArrayLength(env, jcode);
    char *code = (char *)malloc((size_t)code_len + 1);
    (*env)->GetByteArrayRegion(env, jcode, 0, code_len, (jbyte *)code);
    code[code_len] = '\0';

    jsize path_len = (*env)->GetArrayLength(env, jpath);
    char *path = (char *)malloc((size_t)path_len + 1);
    (*env)->GetByteArrayRegion(env, jpath, 0, path_len, (jbyte *)path);
    path[path_len] = '\0';

    uint8_t pubkey[32], mc[16];
    (*env)->GetByteArrayRegion(env, jpub, 0, 32, (jbyte *)pubkey);
    (*env)->GetByteArrayRegion(env, jmc, 0, 16, (jbyte *)mc);

    act_status st = act_license_verify(code, pubkey, (uint32_t)product, mc,
                                       (int64_t)time(NULL), NULL);
    if (st == ACT_OK) {
        uint8_t payload[ACT_PAYLOAD_SIZE], sig[ACT_SIG_SIZE];
        if (act_license_decode(code, payload, sig) == ACT_OK) {
            st = act_state_save(path, payload, sig);
        } else {
            st = ACT_ERR_FORMAT;
        }
    }
    free(code);
    free(path);
    return st;
}

JNIEXPORT jint JNICALL
Java_Activation_nVerifySaved(JNIEnv *env, jclass cls, jbyteArray jpath,
                             jbyteArray jpub, jint product, jbyteArray jmc)
{
    (void)cls;
    jsize path_len = (*env)->GetArrayLength(env, jpath);
    char *path = (char *)malloc((size_t)path_len + 1);
    (*env)->GetByteArrayRegion(env, jpath, 0, path_len, (jbyte *)path);
    path[path_len] = '\0';

    uint8_t pubkey[32], mc[16];
    (*env)->GetByteArrayRegion(env, jpub, 0, 32, (jbyte *)pubkey);
    (*env)->GetByteArrayRegion(env, jmc, 0, 16, (jbyte *)mc);

    const act_status st = act_state_check(path, pubkey, (uint32_t)product, mc,
                                          (int64_t)time(NULL), NULL);
    free(path);
    return st;
}

/* SM2 natives */

JNIEXPORT void JNICALL
Java_Activation_nSm2Keypair(JNIEnv *env, jclass cls, jbyteArray jpub,
                            jbyteArray jpriv)
{
    (void)cls;
    uint8_t pub[64], priv[32];
    act_sm2_keypair(NULL, pub, priv);
    (*env)->SetByteArrayRegion(env, jpub, 0, 64, (const jbyte *)pub);
    (*env)->SetByteArrayRegion(env, jpriv, 0, 32, (const jbyte *)priv);
}

JNIEXPORT jint JNICALL
Java_Activation_nSm2Sign(JNIEnv *env, jclass cls, jbyteArray jsig,
                         jbyteArray jmsg, jbyteArray jpriv)
{
    (void)cls;
    jsize mlen = (*env)->GetArrayLength(env, jmsg);
    uint8_t *msg = (uint8_t *)(*env)->GetByteArrayElements(env, jmsg, NULL);
    uint8_t priv[32], sig[64];
    (*env)->GetByteArrayRegion(env, jpriv, 0, 32, (jbyte *)priv);

    const act_status st = act_sm2_sign(sig, msg, (size_t)mlen, priv, NULL);
    (*env)->ReleaseByteArrayElements(env, jmsg, (jbyte *)msg, JNI_ABORT);

    if (st == ACT_OK) {
        (*env)->SetByteArrayRegion(env, jsig, 0, 64, (const jbyte *)sig);
    }
    return st;
}

JNIEXPORT jint JNICALL
Java_Activation_nSm2Verify(JNIEnv *env, jclass cls, jbyteArray jsig,
                           jbyteArray jmsg, jbyteArray jpub)
{
    (void)cls;
    jsize mlen = (*env)->GetArrayLength(env, jmsg);
    uint8_t *msg = (uint8_t *)(*env)->GetByteArrayElements(env, jmsg, NULL);
    uint8_t sig[64], pub[64];
    (*env)->GetByteArrayRegion(env, jsig, 0, 64, (jbyte *)sig);
    (*env)->GetByteArrayRegion(env, jpub, 0, 64, (jbyte *)pub);

    const act_status st = act_sm2_verify(sig, msg, (size_t)mlen, pub, NULL);
    (*env)->ReleaseByteArrayElements(env, jmsg, (jbyte *)msg, JNI_ABORT);
    return st;
}

JNIEXPORT jint JNICALL
Java_Activation_nSm2Encrypt(JNIEnv *env, jclass cls, jbyteArray jpub,
                            jbyteArray jmsg, jbyteArray jout, jlongArray jlen)
{
    (void)cls;
    jsize mlen = (*env)->GetArrayLength(env, jmsg);
    uint8_t *msg = (uint8_t *)(*env)->GetByteArrayElements(env, jmsg, NULL);
    uint8_t pub[64];
    (*env)->GetByteArrayRegion(env, jpub, 0, 64, (jbyte *)pub);

    uint8_t *out = (uint8_t *)(*env)->GetByteArrayElements(env, jout, NULL);
    jsize out_cap = (*env)->GetArrayLength(env, jout);

    size_t out_len = 0;
    const act_status st = act_sm2_encrypt(pub, msg, (size_t)mlen, out,
                                          (size_t)out_cap, &out_len);
    (*env)->ReleaseByteArrayElements(env, jmsg, (jbyte *)msg, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, jout, (jbyte *)out, 0);

    jlong jl = (jlong)out_len;
    (*env)->SetByteArrayRegion(env, jlen, 0, 0, NULL); /* no-op keep alive */
    (*env)->SetLongArrayRegion(env, jlen, 0, 1, &jl);
    return st;
}

JNIEXPORT jint JNICALL
Java_Activation_nSm2Decrypt(JNIEnv *env, jclass cls, jbyteArray jin,
                            jbyteArray jpriv, jbyteArray jout,
                            jlongArray jlen)
{
    (void)cls;
    jsize ilen = (*env)->GetArrayLength(env, jin);
    uint8_t *in = (uint8_t *)(*env)->GetByteArrayElements(env, jin, NULL);
    uint8_t priv[32];
    (*env)->GetByteArrayRegion(env, jpriv, 0, 32, (jbyte *)priv);

    uint8_t *out = (uint8_t *)(*env)->GetByteArrayElements(env, jout, NULL);
    jsize out_cap = (*env)->GetArrayLength(env, jout);

    size_t out_len = 0;
    const act_status st = act_sm2_decrypt(in, (size_t)ilen, priv, out,
                                          (size_t)out_cap, &out_len);
    (*env)->ReleaseByteArrayElements(env, jin, (jbyte *)in, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, jout, (jbyte *)out, 0);

    jlong jl = (jlong)out_len;
    (*env)->SetLongArrayRegion(env, jlen, 0, 1, &jl);
    return st;
}
