#include "hkFastAuth.h"
#include "fmt/ranges.h"
#include "logging.h"
#include <mbedtls/hkdf.h>
#include <vector>

#include "TLV8.hpp"
#include "CommonCryptoUtils.h"

/**
 * The function `Auth0_keying_material` generates keying material using the HKDF algorithm based on
 * various input parameters.
 *
 * @param context The `context` parameter is a pointer to a character array that represents the context
 * for the keying material generation. It is used as input to the HKDF (HMAC-based Key Derivation
 * Function) algorithm.
 * @param ePubX ePub_X is a pointer to a uint8_t array that represents the public key of the entity
 * being authenticated. It has a length of 32 bytes.
 * @param keyingMaterial The `keyingMaterial` parameter is a pointer to a buffer where the input keying material to be used with HKDF is stored.
 * It should have a size of at least 32 bytes.
 * @param out The `out` parameter is a pointer to the buffer where the output keying material will be
 * stored. The size of the buffer is specified by the `outLen` parameter.
 * @param outLen The parameter `outLen` represents the length of the output buffer `out`. It specifies
 * the maximum number of bytes that can be written to the `out` buffer.
 */
void HKFastAuth::Auth0_keying_material(const char *context, const std::vector<uint8_t> &ePubX, const std::vector<uint8_t> &keyingMaterial, uint8_t *out, size_t outLen)
{
  uint8_t constant = 0x5E;
  uint8_t version_tlv[4] = {0x5c, 0x02, version[0], version[1]};
  uint8_t supported_vers[6] = {0x5c, 0x04, 0x02, 0x0, 0x01, 0x0};
  std::vector<uint8_t> dataMaterial;
  dataMaterial.reserve(32 + strlen(context) + readerIdentifier.size() + 32 + 1 + sizeof(supported_vers) + sizeof(version_tlv) + readerEphX.size() + 16 + 2 + endpointEphX.size());
  dataMaterial.insert(dataMaterial.end(), std::make_move_iterator(reader_key_X.begin()), std::make_move_iterator(reader_key_X.end()));
  dataMaterial.insert(dataMaterial.end(), (uint8_t *)context, (uint8_t*)context + strlen(context));
  dataMaterial.insert(dataMaterial.end(), std::make_move_iterator(readerIdentifier.begin()), std::make_move_iterator(readerIdentifier.end()));
  if (type == kHomeKey) {
    dataMaterial.insert(dataMaterial.end(), std::make_move_iterator(ePubX.begin()), std::make_move_iterator(ePubX.end()));
  }
  dataMaterial.push_back(constant);
  if (type == kHomeKey) {
    dataMaterial.insert(dataMaterial.end(), supported_vers, supported_vers + sizeof(supported_vers));
  }
  dataMaterial.insert(dataMaterial.end(), version_tlv, version_tlv + sizeof(version_tlv));
  dataMaterial.insert(dataMaterial.end(), std::make_move_iterator(readerEphX.begin()), std::make_move_iterator(readerEphX.end()));
  dataMaterial.insert(dataMaterial.end(), std::make_move_iterator(transactionIdentifier.begin()), std::make_move_iterator(transactionIdentifier.end()));
  dataMaterial.push_back(flags[0]);
  dataMaterial.push_back(flags[1]);
  if (type == kAliro) {
    dataMaterial.push_back(0xA5);
    dataMaterial.push_back(static_cast<uint8_t>(aliroFCI.size()));
    dataMaterial.insert(dataMaterial.end(), aliroFCI.begin(), aliroFCI.end());
    dataMaterial.insert(dataMaterial.end(), ePubX.begin(), ePubX.end());
  }
  if (type == kHomeKey) {
    dataMaterial.insert(dataMaterial.end(), std::make_move_iterator(endpointEphX.begin()), std::make_move_iterator(endpointEphX.end()));
  }
  LOG(D, "Auth0 HKDF Material: %s", fmt::format("{:02X}", fmt::join(dataMaterial, "")).c_str());
  int ret = 0;
  if (type == kHomeKey) {
    ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, keyingMaterial.data(),
                       keyingMaterial.size(), dataMaterial.data(), dataMaterial.size(), out, outLen);
  } else if (type == kAliro) {
    ret = mbedtls_hkdf(
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
      dataMaterial.data(), dataMaterial.size(),
      keyingMaterial.data(), keyingMaterial.size(),
      endpointEphX.data(), endpointEphX.size(),
      out, outLen
    );
  }
  LOG(V, "HKDF Status: %d", ret);
}

/**
 * The function `find_endpoint_by_cryptogram` searches for an endpoint in a list of issuers based on a
 * given cryptogram.
 *
 * @param cryptogram The parameter "cryptogram" is a vector of uint8_t, which represents the cryptogram received in the Auth0 response.
 *
 * @return a pointer to an object of type `hkEndpoint_t`.
 */
std::tuple<hkIssuer_t *, hkEndpoint_t *> HKFastAuth::find_endpoint_by_cryptogram(std::vector<uint8_t> &cryptogram)
{
  hkEndpoint_t *foundEndpoint = nullptr;
  hkIssuer_t *foundIssuer = nullptr;
  for (auto &&issuer : issuers)
  {
    LOG(V, "Issuer: %s, Endpoints: %d", fmt::format("{:02X}", fmt::join(issuer.issuer_id, "")).c_str(), issuer.endpoints.size());
    for (auto &&endpoint : issuer.endpoints)
    {
      if(endpoint.endpoint_prst_k.size() == 0) continue;
      LOG(V, "Endpoint: %s, Persistent Key: %s", fmt::format("{:02X}", fmt::join(endpoint.endpoint_id, "")).c_str(), fmt::format("{:02X}", fmt::join(endpoint.endpoint_prst_k, "")).c_str());
      std::vector<uint8_t> hkdf(type == kHomeKey ? 58 : 160);
      Auth0_keying_material("VolatileFast", endpoint.endpoint_pk_x, endpoint.endpoint_prst_k, hkdf.data(), hkdf.size());
      LOG(V, "HKDF Derived Key: %s", fmt::format("{:02X}", fmt::join(hkdf, "")).c_str());
      if (type == kAliro) {
        std::array<uint8_t,32> sk{};
        std::copy_n(hkdf.data(), 32, sk.data());
        LOG(D, "SK: %s", fmt::format("{:02X}", fmt::join(sk, "")).c_str());
        auto plaintext = CommonCryptoUtils::decryptAesGcm(cryptogram, sk, {0,0,0,0,0,0,0,0,0,0,0,0});
        LOG(D, "Decrypted Cryptogram: %s", fmt::format("{:02X}", fmt::join(plaintext, "")).c_str());
        TLV8 decryptedTlv;
        decryptedTlv.parse(plaintext.data(), plaintext.size());
        auto identifier = decryptedTlv.find(0x5E);
        auto issued_at = decryptedTlv.find(0x91);
        auto expires_at = decryptedTlv.find(0x92);
        if (identifier->value.empty() || issued_at->value.empty() || expires_at->value.empty()) {
          LOG(E, "Could not validate endpoint!");
          continue;
        }
        LOG(D,  "Identifier: %s", fmt::format("{:02X}", fmt::join(identifier->value, "")).c_str());
        LOG(D,  "issued_at: %s", fmt::format("{:02X}", fmt::join(issued_at->value, "")).c_str());
        LOG(D,  "expires_at: %s", fmt::format("{:02X}", fmt::join(expires_at->value, "")).c_str());
        foundIssuer = &issuer;
        foundEndpoint = &endpoint;
        break;
      }
      if (type == kHomeKey) {
        if (!memcmp(hkdf.data(), cryptogram.data(), 16))
        {
          LOG(D, "Endpoint %s matches cryptogram", fmt::format("{:02X}", fmt::join(endpoint.endpoint_id, "")).c_str());
          foundIssuer = &issuer;
          foundEndpoint = &endpoint;
          break;
        }
      }
    }
    if (foundEndpoint != nullptr)
    {
      break;
    }
  }
  return std::make_tuple(foundIssuer, foundEndpoint);
}

/**
 * The function `attest` in the `HKFastAuth` class performs authentication using FAST Flow and returns
 * the issuer, endpoint, and key flow type based on the encrypted message provided.
 * 
 * @param encryptedMessage The `attest` function takes a vector of uint8_t named `encryptedMessage` as
 * input. This function processes the encrypted message to authenticate an endpoint using the FAST
 * flow. If the endpoint is successfully authenticated, it returns a tuple containing the issuer
 * pointer, endpoint pointer, and the KeyFlow type
 * 
 * @return A tuple containing a pointer to the issuer, a pointer to the endpoint, and the KeyFlow type
 * is being returned. The function first checks if the endpoint is authenticated via FAST Flow, and if
 * so, it logs the authentication and returns the tuple with the FAST flow type. If the authentication
 * fails, it logs the failure and returns the tuple with the STANDARD flow type.
 */
std::tuple<hkIssuer_t *, hkEndpoint_t *, KeyFlow> HKFastAuth::attest(std::vector<uint8_t> &encryptedMessage)
{
  auto foundData = find_endpoint_by_cryptogram(encryptedMessage);
  if (std::get<1>(foundData) != nullptr)
  {
    LOG(D, "Endpoint %s Authenticated via FAST Flow", fmt::format("{:02X}", fmt::join(std::get<1>(foundData)->endpoint_id, "")).c_str());
    return std::make_tuple(std::get<0>(foundData), std::get<1>(foundData), kFlowFAST);
  }
  LOG(W, "FAST Flow failed! Moving to STANDARD Flow!");
  return std::make_tuple(nullptr, nullptr, kFlowNext);
}

HKFastAuth::HKFastAuth(DigitalKeyType type, std::vector<uint8_t> &reader_pk_x, std::vector<hkIssuer_t> &issuers,
  std::vector<uint8_t> &readerEphX, std::vector<uint8_t> &endpointEphPubKey, std::vector<uint8_t> &endpointEphX,
  std::vector<uint8_t> &transactionIdentifier, std::vector<uint8_t> &readerIdentifier, std::vector<uint8_t> &aliroFci,
  std::array<uint8_t, 2> &version, std::array<uint8_t, 2> &flags): type(type), reader_key_X(reader_pk_x), issuers(issuers),
                                                                   readerEphX(readerEphX), endpointEphPubKey(endpointEphPubKey),
                                                                   endpointEphX(endpointEphX),
                                                                   transactionIdentifier(transactionIdentifier),
                                                                   readerIdentifier(readerIdentifier),
                                                                   aliroFCI(aliroFci),
                                                                   version(version),
                                                                   flags(flags) {
  /* esp_log_level_set(TAG, ESP_LOG_VERBOSE); */
}
