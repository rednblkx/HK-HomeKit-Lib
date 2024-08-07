/*
  Code highly inspired by https://github.com/kormax/apple-home-key-reader/blob/main/util/iso18013.py
 */

#include <ISO18013SecureContext.h>

const std::vector<uint8_t> READER_CONTEXT = {'S', 'K', 'R', 'e', 'a', 'd', 'e', 'r'};
const std::vector<uint8_t> ENDPOINT_CONTEXT = {'S', 'K', 'D', 'e', 'v', 'i', 'c', 'e'};

const std::vector<uint8_t> READER_MODE = {0x00, 0x00, 0x00, 0x00};
const std::vector<uint8_t> ENDPOINT_MODE = {0x00, 0x00, 0x00, 0x01};

ISO18013SecureContext::ISO18013SecureContext(const std::vector<uint8_t> &sharedSecret, const std::vector<uint8_t> &salt, size_t keyLength)
{
    LOG(V, "Shared Secret: %s", hk_utils::bufToHexString(sharedSecret.data(), sharedSecret.size()).c_str());
    LOG(V, "Salt: %s", hk_utils::bufToHexString(salt.data(), salt.size()).c_str());
    LOG(V, "Key Length: %d", keyLength);
    this->readerCounter = 1;
    this->endpointCounter = 1;
    this->keyLength = keyLength;
    uint8_t outReader[keyLength];
    uint8_t outEndpoint[keyLength];
    int ret1 = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt.data(), salt.size(), sharedSecret.data(), sharedSecret.size(),
                            READER_CONTEXT.data(), READER_CONTEXT.size(),
                            outReader, keyLength);
    int ret2 = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt.data(), salt.size(), sharedSecret.data(), sharedSecret.size(),
                            ENDPOINT_CONTEXT.data(), ENDPOINT_CONTEXT.size(),
                            outEndpoint, keyLength);

    LOG(V, "READER Key: %s", hk_utils::bufToHexString(outReader, keyLength).c_str());
    LOG(V, "ENDPOINT Key: %s", hk_utils::bufToHexString(outEndpoint, keyLength).c_str());
    if(!ret1){
        this->readerKey.insert(this->readerKey.begin(), outReader, outReader + keyLength);
    } else {
        LOG(E, "Cannot derive READER Key - %s", mbedtls_high_level_strerr(ret1));
    }
    if(!ret2){
        this->endpointKey.insert(this->endpointKey.begin(), outEndpoint, outEndpoint + keyLength);
    } else {
        LOG(E, "Cannot derive Endpoint Key - %s", mbedtls_high_level_strerr(ret2));
    }
}

std::vector<uint8_t> ISO18013SecureContext::getReaderIV() const
{
    std::vector<uint8_t> iv(4, 0);
    iv.insert(iv.end(), READER_MODE.begin(), READER_MODE.end());
    uint8_t counter[4] = {0x0, 0x0, 0x0, (uint8_t)this->readerCounter};
    iv.insert(iv.end(), counter, counter + sizeof(counter));
    return iv;
}

std::vector<uint8_t> ISO18013SecureContext::getEndpointIV() const
{
    std::vector<uint8_t> iv(4, 0);
    iv.insert(iv.end(), ENDPOINT_MODE.begin(), ENDPOINT_MODE.end());
    uint8_t counter[4] = { 0x0, 0x0, 0x0, (uint8_t)this->endpointCounter};
    iv.insert(iv.end(), counter, counter + sizeof(counter));
    return iv;
}

std::vector<uint8_t> ISO18013SecureContext::encryptMessageToEndpoint(const std::vector<uint8_t> &message)
{
    if (readerKey.size() == 0 || endpointKey.size() == 0)
    {
        return std::vector<unsigned char>();
    }
    uint8_t ciphertext[message.size() + 16];
    std::vector<uint8_t> iv = getReaderIV();
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    int setKey = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, this->readerKey.data(), this->keyLength * 8);

    if (setKey != 0)
    {
        LOG(E, "Cannot set key - %s", mbedtls_high_level_strerr(setKey));
        return std::vector<unsigned char>();
    }

    int enc = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, message.size(),
                                        iv.data(), iv.size(), NULL, 0,
                                        message.data(), ciphertext,
                                        16, ciphertext + message.size());

    mbedtls_gcm_free(&ctx);

    if (enc != 0)
    {
        LOG(E, "Cannot encrypt - %s", mbedtls_high_level_strerr(enc));
        return std::vector<unsigned char>();
    }

    LOG(D, "CIPHERTEXT LEN: %d DATA: %s", sizeof(ciphertext), hk_utils::bufToHexString(ciphertext, sizeof(ciphertext)).c_str());
    CborEncoder cipher;
    uint8_t cipherBuf[sizeof(ciphertext) + 16];
    cbor_encoder_init(&cipher, cipherBuf, sizeof(ciphertext) + 16, 0);
    CborEncoder cipherMap;
    cbor_encoder_create_map(&cipher, &cipherMap, 1);
    cbor_encode_text_stringz(&cipherMap, "data");
    cbor_encode_byte_string(&cipherMap, ciphertext, sizeof(ciphertext));
    cbor_encoder_close_container(&cipher, &cipherMap);
    readerCounter++;

    LOG(D, "CBOR LEN: %d DATA: %s", sizeof(cipherBuf), hk_utils::bufToHexString(cipherBuf, sizeof(cipherBuf)).c_str());

    return std::vector<uint8_t>{cipherBuf, cipherBuf + sizeof(cipherBuf)};
}

std::vector<uint8_t> ISO18013SecureContext::decryptMessageFromEndpoint(const std::vector<uint8_t> &message)
{
    if (readerKey.size() == 0 || endpointKey.size() == 0)
    {
        return std::vector<unsigned char>();
    }
    json j = json::from_cbor(message);

    LOG(I, "ENC MSG: %s", j.dump().c_str());
    json data = j.at("data");
    if (!data.is_binary()) return std::vector<uint8_t>();
    auto& cborCiphertext = data.get_binary();
    if (data.size() == 0) {
        return std::vector<unsigned char>();
    }
    std::vector<uint8_t> plaintext(cborCiphertext.size() - 16);

    std::vector<uint8_t> iv = getEndpointIV();

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    int setKey = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, endpointKey.data(), keyLength * 8);
    if (setKey != 0)
    {
        char err[64];
        mbedtls_strerror(setKey, err, 64);
        LOG(E, "Cannot set key - %s - %d", err, setKey);
        return std::vector<unsigned char>();
    }
    int dec = mbedtls_gcm_auth_decrypt(&ctx, cborCiphertext.size() - 16,
                                       iv.data(), iv.size(), nullptr, 0,
                                       cborCiphertext.data() + cborCiphertext.size() - 16, 16,
                                       cborCiphertext.data(),
                                       plaintext.data());

    mbedtls_gcm_free(&ctx);

    if (dec != 0)
    {
        char err[64];
        mbedtls_strerror(setKey, err, 64);
        LOG(E, "Cannot decrypt - %s", err);
        return std::vector<unsigned char>();
    }

    endpointCounter++;

    LOG(D, "PLAINTEXT LEN: %d DATA: %s", plaintext.size(), hk_utils::bufToHexString(plaintext.data(), plaintext.size()).c_str());

    return plaintext;
}