/*
  Code highly inspired by https://github.com/kormax/apple-home-key-reader/blob/main/util/iso18013.py
 */

#include <ISO18013SecureContext.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/gcm.h>
#include <mbedtls/error.h>
#include <logging.h>
#include <cbor.h>
#include <vector>
#include <array>

const std::array<uint8_t, 8> READER_CONTEXT = {'S', 'K', 'R', 'e', 'a', 'd', 'e', 'r'};
const std::array<uint8_t, 8> ENDPOINT_CONTEXT = {'S', 'K', 'D', 'e', 'v', 'i', 'c', 'e'};

const std::array<uint8_t, 4> READER_MODE = {0x00, 0x00, 0x00, 0x00};
const std::array<uint8_t, 4> ENDPOINT_MODE = {0x00, 0x00, 0x00, 0x01};

ISO18013SecureContext::ISO18013SecureContext(const std::vector<uint8_t> &sharedSecret, const std::vector<uint8_t> &salt, size_t keyLength)
{
    LOG(V, "Shared Secret: %s", red_log::bufToHexString(sharedSecret.data(), sharedSecret.size()).c_str());
    LOG(V, "Salt: %s", red_log::bufToHexString(salt.data(), salt.size()).c_str());
    LOG(V, "Key Length: %d", keyLength);
    this->readerCounter = 1;
    this->endpointCounter = 1;
    this->keyLength = keyLength;
    std::vector<uint8_t> outReader(keyLength);
    std::vector<uint8_t> outEndpoint(keyLength);
    int ret1 = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt.data(), salt.size(), sharedSecret.data(), sharedSecret.size(),
                            READER_CONTEXT.data(), READER_CONTEXT.size(),
                            outReader.data(), keyLength);
    int ret2 = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt.data(), salt.size(), sharedSecret.data(), sharedSecret.size(),
                            ENDPOINT_CONTEXT.data(), ENDPOINT_CONTEXT.size(),
                            outEndpoint.data(), keyLength);

    LOG(V, "READER Key: %s", red_log::bufToHexString(outReader.data(), keyLength).c_str());
    LOG(V, "ENDPOINT Key: %s", red_log::bufToHexString(outEndpoint.data(), keyLength).c_str());
    if(!ret1){
        this->readerKey.insert(this->readerKey.begin(), outReader.begin(), outReader.end());
    } else {
        LOG(E, "Cannot derive READER Key - %d", ret1);
    }
    if(!ret2){
        this->endpointKey.insert(this->endpointKey.begin(), outEndpoint.begin(), outEndpoint.end());
    } else {
        LOG(E, "Cannot derive Endpoint Key - %d", ret2);
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
    std::vector<uint8_t> ciphertext(message.size() + 16);
    std::vector<uint8_t> iv = getReaderIV();
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    int setKey = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, this->readerKey.data(), this->keyLength * 8);

    if (setKey != 0)
    {
        LOG(E, "Cannot set key - %d", setKey);
        return std::vector<unsigned char>();
    }

    int enc = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, message.size(),
                                        iv.data(), iv.size(), NULL, 0,
                                        message.data(), ciphertext.data(),
                                        16, ciphertext.data() + message.size());

    mbedtls_gcm_free(&ctx);

    if (enc != 0)
    {
        LOG(E, "Cannot encrypt - %d", enc);
        return std::vector<unsigned char>();
    }

    LOG(D, "CIPHERTEXT LEN: %d DATA: %s", sizeof(ciphertext), red_log::bufToHexString(ciphertext.data(), ciphertext.size()).c_str());
    CborEncoder cipher;
    std::vector<uint8_t> cipherBuf(ciphertext.size() + 16);
    cbor_encoder_init(&cipher, cipherBuf.data(), ciphertext.size() + 16, 0);
    CborEncoder cipherMap;
    cbor_encoder_create_map(&cipher, &cipherMap, 1);
    cbor_encode_text_stringz(&cipherMap, "data");
    cbor_encode_byte_string(&cipherMap, ciphertext.data(), ciphertext.size());
    cbor_encoder_close_container(&cipher, &cipherMap);
    readerCounter++;

    LOG(D, "CBOR LEN: %d DATA: %s", sizeof(cipherBuf), red_log::bufToHexString(cipherBuf.data(), cipherBuf.size()).c_str());

    return cipherBuf;
}

std::vector<uint8_t> ISO18013SecureContext::decryptMessageFromEndpoint(const std::vector<uint8_t> &message)
{
    if (readerKey.size() == 0 || endpointKey.size() == 0)
    {
        return std::vector<unsigned char>();
    }

    std::vector<uint8_t> cborCiphertext;

    CborParser parser;
    CborValue root_map, data_value;
    CborError err;

    // Initialize the parser and check that the root element is a map.
    err = cbor_parser_init(message.data(), message.size(), 0, &parser, &root_map);
    if (err != CborNoError || !cbor_value_is_map(&root_map)) {
        return std::vector<uint8_t>();
    }

    // Find the value associated with the key "data".
    err = cbor_value_map_find_value(&root_map, "data", &data_value);
    if (err != CborNoError) {
        // This indicates the key "data" was not found or a parsing error occurred.
        return std::vector<uint8_t>();
    }

    // Check that the value found is a byte string.
    if (!cbor_value_is_byte_string(&data_value)) {
        return std::vector<uint8_t>();
    }

    // Get the length of the byte string.
    size_t len;
    err = cbor_value_get_string_length(&data_value, &len);

    // Return if there was an error or if the byte string is empty.
    if (err != CborNoError || len == 0) {
        return std::vector<uint8_t>();
    }

    // Resize the output vector and copy the byte string data into it.
    cborCiphertext.resize(len);
    err = cbor_value_copy_byte_string(&data_value, cborCiphertext.data(), &len, nullptr);
    if (err != CborNoError) {
        // If the copy fails, return an empty vector.
        return std::vector<uint8_t>();
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

    LOG(D, "PLAINTEXT LEN: %d DATA: %s", plaintext.size(), red_log::bufToHexString(plaintext.data(), plaintext.size()).c_str());

    return plaintext;
}
