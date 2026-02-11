#include "hkStdAuth.h"
#include "CommonCryptoUtils.h"
#include "DigitalKeySecureContext.h"
#include "HomeKey.h"
#include "fmt/ranges.h"
#include "x963kdf.h"
#include "logging.h"
#include "simple_tlv.hpp"
#include <iterator>
#include <memory>
#include <mbedtls/hkdf.h>
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <TLV8.hpp>
#include <mbedtls/ecdsa.h>
#include <tuple>
#include <vector>

constexpr char ALIRO_CTX_PERSISTENT_ASTR[] = "Persistent**";
constexpr char HK_CTX_PERSISTENT_ASTR[] = "Persistent";
constexpr char ALIRO_CTX_VOLATILE_ASTR[] = "Volatile****";
constexpr char HK_CTX_VOLATILE_ASTR[] = "Volatile";

/**
 * The function `Auth1_keying_material` generates keying material using various input data and the HKDF
 * algorithm.
 *
 * @param keyingMaterial A pointer to the buffer where the generated keying material will be stored.
 * @param context The "context" parameter is a string that represents the context or additional
 * information for the authentication process. It is used as input to generate the keying material.
 * @param out The `out` parameter is a pointer to a buffer where the generated keying material will be
 * stored. The size of this buffer is specified by the `outLen` parameter.
 * @param outLen The parameter `outLen` represents the length of the output buffer `out` where the
 * generated keying material will be stored.
 */
template<typename Container>
void HKStdAuth::Auth1_keying_material(std::array<uint8_t,32> &keyingMaterial, std::string_view context, Container &out)
{
  uint8_t flags[2] = {0x01, 0x01};
  uint8_t supported_vers[6] = {0x5c, 0x04, 0x02, 0x0, 0x01, 0x0};
  std::vector<uint8_t> dataMaterial;
  dataMaterial.reserve(readerEphX.size() + endpointEphX.size() + transactionIdentifier.size() + 1 + sizeof(flags) + context.size() + version.size() + sizeof(supported_vers));
  if (type == kHomeKey) {
    dataMaterial.insert(dataMaterial.end(), std::make_move_iterator(readerEphX.begin()), std::make_move_iterator(readerEphX.end()));
    dataMaterial.insert(dataMaterial.end(), std::make_move_iterator(endpointEphX.begin()), std::make_move_iterator(endpointEphX.end()));
    dataMaterial.insert(dataMaterial.end(), std::make_move_iterator(transactionIdentifier.begin()), std::make_move_iterator(transactionIdentifier.end()));
    dataMaterial.push_back(0x5E);
    dataMaterial.push_back(flags[0]);
    dataMaterial.push_back(flags[1]);
    dataMaterial.insert(dataMaterial.end(), (uint8_t*)context.begin(), (uint8_t*)context.end());
    dataMaterial.push_back(0x5C);
    dataMaterial.push_back(static_cast<uint8_t>(version.size()));
    dataMaterial.insert(dataMaterial.end(), version.begin(), version.end());
    dataMaterial.insert(dataMaterial.end(), supported_vers, supported_vers + sizeof(supported_vers));
    LOG(D, "DATA Material Length: %d, Data: %s", dataMaterial.size(), fmt::format("{:02X}", fmt::join(dataMaterial, "")).c_str());
    mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, keyingMaterial.data(), 32, dataMaterial.data(), dataMaterial.size(), out.data(), out.size());
  }
  if (type == kAliro) {
    LOG(D,"readerPublicKeyX (%zu bytes): %s", readerPkX.size(),
        fmt::format("{:02X}", fmt::join(readerPkX, "")).c_str());
    dataMaterial.insert(dataMaterial.end(), readerPkX.begin(), readerPkX.end());

    LOG(D,"context: %s", context.data());
    dataMaterial.insert(dataMaterial.end(), (uint8_t*)context.begin(), (uint8_t*)context.end());

    LOG(D,"readerIdentifier (%zu bytes): %s", readerIdentifier.size(),
        fmt::format("{:02X}", fmt::join(readerIdentifier, "")).c_str());
    dataMaterial.insert(dataMaterial.end(), readerIdentifier.begin(), readerIdentifier.end());

    LOG(D,"transport_type: 0x%02X", 0x5E);
    dataMaterial.push_back(0x5E);  // TRANSPORT_TYPE_NFC = 0x5E

    LOG(D,"protocol_version TLV: 5C %02X %02X%02X", version.size(),
        version[0], version[1]);
    dataMaterial.push_back(0x5C);
    dataMaterial.push_back(version.size());
    dataMaterial.insert(dataMaterial.end(), version.begin(), version.end());

    LOG(D,"readerEphX (%zu bytes): %s", readerEphX.size(),
        fmt::format("{:02X}", fmt::join(readerEphX, "")).c_str());
    dataMaterial.insert(dataMaterial.end(), readerEphX.begin(), readerEphX.end());

    LOG(D,"transactionIdentifier (%zu bytes): %s", transactionIdentifier.size(),
        fmt::format("{:02X}", fmt::join(transactionIdentifier, "")).c_str());
    dataMaterial.insert(dataMaterial.end(), transactionIdentifier.begin(), transactionIdentifier.end());

    LOG(D,"transaction_flags: 0x01, transaction_code: 0x01");
    dataMaterial.push_back(0x01);  // FAST flow
    dataMaterial.push_back(0x01);  // UNLOCK, V1

    LOG(D,"fciProprietaryTemplate (%zu bytes): %s", aliroFCI.size(),
        fmt::format("{:02X}", fmt::join(aliroFCI, "")).c_str());
    dataMaterial.push_back(0xA5);
    dataMaterial.push_back(static_cast<uint8_t>(aliroFCI.size()));
    dataMaterial.insert(dataMaterial.end(), aliroFCI.begin(), aliroFCI.end());

    if (context == ALIRO_CTX_PERSISTENT_ASTR) {
        LOG(D,"ep_pk (%zu bytes): %s", epPkX->size(), fmt::format("{:02X}", fmt::join(*epPkX, "")).c_str());
        dataMaterial.insert(dataMaterial.end(), epPkX->begin(), epPkX->end());
    }
    LOG(D,"HKDF Salt (%zu bytes): %s", dataMaterial.size(), fmt::format("{:02X}", fmt::join(dataMaterial, "")).c_str());
    mbedtls_hkdf(
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
      dataMaterial.data(), dataMaterial.size(),
      keyingMaterial.data(), 32,
      endpointEphX.data(), endpointEphX.size(),
      out.data(), out.size()
    );
  }
}

HKStdAuth::HKStdAuth(DigitalKeyType type, const std::function<bool(std::vector<uint8_t> &, std::vector<uint8_t> &, bool)> &nfc,
                     std::vector<uint8_t> &reader_private_key, std::vector<uint8_t> &readerEphPrivKey,
                     std::vector<hkIssuer_t> &issuers,
                     std::vector<uint8_t> &readerEphX, std::vector<uint8_t> &endpointEphPubKey,
                     std::vector<uint8_t> &endpointEphX,
                     std::vector<uint8_t> &transactionIdentifier, std::vector<uint8_t> &readerIdentifier,
                     std::vector<uint8_t> &aliroFci,
                     std::array<uint8_t, 2> &version,
                     std::vector<uint8_t> &readerPkX) : type(type), reader_private_key(reader_private_key),
                                                        readerEphPrivKey(readerEphPrivKey), issuers(issuers),
                                                        readerEphX(readerEphX), endpointEphPubKey(endpointEphPubKey),
                                                        endpointEphX(endpointEphX),
                                                        transactionIdentifier(transactionIdentifier),
                                                        readerIdentifier(readerIdentifier), aliroFCI(aliroFci),
                                                        version(version),
                                                        readerPkX(readerPkX),
                                                        nfc(nfc) {
  /* esp_log_level_set(TAG, ESP_LOG_VERBOSE); */
}

/**
 * Performs authentication using the STANDARD flow.
 * 
 * @return a tuple containing the following elements:
 * 1. A pointer to the issuer object (`hkIssuer_t*`)
 * 2. A pointer to the endpoint object (`hkEndpoint_t*`)
 * 3. An object of type `DigitalKeySecureContext`
 * 4. A vector of `uint8_t` elements
 * 5. An enum value of type `KeyFlow`
 */
std::tuple<hkIssuer_t *, hkEndpoint_t *, std::unique_ptr<DigitalKeySecureContext>, std::array<uint8_t,32>, KeyFlow> HKStdAuth::attest()
{
  // int readerContext = 1096652137;
  std::array<uint8_t,4> readerCtx{0x41, 0x5d, 0x95, 0x69};
  // int deviceContext = 1317567308;
  std::array<uint8_t,4> deviceCtx{0x4e, 0x88, 0x7b, 0x4c};

  std::vector<uint8_t> stdTlv;
  stdTlv.reserve(16 + endpointEphX.size() + readerEphX.size() + 30);
#if __cplusplus >= 202002L
  std::ranges::copy(simple_tlv(0x4D, readerIdentifier), std::back_inserter(stdTlv));
  std::ranges::copy(simple_tlv(0x86, endpointEphX), std::back_inserter(stdTlv));
  std::ranges::copy(simple_tlv(0x87, readerEphX), std::back_inserter(stdTlv));
  std::ranges::copy(simple_tlv(0x4C, transactionIdentifier), std::back_inserter(stdTlv));
  std::ranges::copy(simple_tlv(0x93, readerCtx), std::back_inserter(stdTlv));
#else
  auto tlv1 = simple_tlv(0x4D, readerIdentifier);
  std::copy(tlv1.begin(), tlv1.end(), std::back_inserter(stdTlv));
  auto tlv2 = simple_tlv(0x86, endpointEphX);
  std::copy(tlv2.begin(), tlv2.end(), std::back_inserter(stdTlv));
  auto tlv3 = simple_tlv(0x87, readerEphX);
  std::copy(tlv3.begin(), tlv3.end(), std::back_inserter(stdTlv));
  auto tlv4 = simple_tlv(0x4C, transactionIdentifier);
  std::copy(tlv4.begin(), tlv4.end(), std::back_inserter(stdTlv));
  auto tlv5 = simple_tlv(0x93, readerCtx);
  std::copy(tlv5.begin(), tlv5.end(), std::back_inserter(stdTlv));
#endif

  std::vector<uint8_t> sigPoint = CommonCryptoUtils::signSharedInfo(stdTlv.data(), stdTlv.size(), reader_private_key.data(), reader_private_key.size());
  std::vector<uint8_t> sigTlv = simple_tlv(0x9E, sigPoint);
  std::vector<uint8_t> apdu{0x80, 0x81, 0x0, 0x0};
  if (type == kHomeKey) {
    apdu.push_back(sigTlv.size());
    apdu.resize(apdu.size() + sigTlv.size());
    std::move(sigTlv.begin(), sigTlv.end(), apdu.begin() + 5);
  }
  if (type == kAliro) {
    apdu.push_back(sigTlv.size() + 3);
    apdu.push_back(0x41);
    apdu.push_back(0x01);
    apdu.push_back(0x01);
    apdu.resize(apdu.size() + sigTlv.size());
    std::move(sigTlv.begin(), sigTlv.end(), apdu.begin() + 8);
  }
  std::vector<uint8_t> response;
  LOG(D, "Auth1 APDU Length: %d, DATA: %s", apdu.size(), fmt::format("{:02X}", fmt::join(apdu, "")).c_str());
  nfc(apdu, response, false);
  LOG(D, "Auth1 Response Length: %d, DATA: %s", response.size(), fmt::format("{:02X}", fmt::join(response, "")).c_str());
  std::array<uint8_t,32> persistentKey{};
  std::vector<uint8_t> volatileKey(48);
  if (type == kAliro){ volatileKey.resize(160); }
  uint8_t sharedKey[32];

  CommonCryptoUtils::get_shared_key(readerEphPrivKey, endpointEphPubKey, sharedKey, sizeof(sharedKey));
  LOG(D, "Shared Key: %s", fmt::format("{:02X}", fmt::join(sharedKey, "")).c_str());

  X963KDF kdf(MBEDTLS_MD_SHA256, 32, transactionIdentifier.data(), 16);

  std::array<uint8_t,32> derivedKey{};
  std::array<uint8_t,32> skDevice{};
  std::array<uint8_t,32> skReader{};
  kdf.derive(sharedKey, sizeof(sharedKey), derivedKey.data());
  LOG(D, "X963KDF Derived Key: %s", fmt::format("{:02X}", fmt::join(derivedKey, "")).c_str());
  if (type == kHomeKey) {
    Auth1_keying_material(derivedKey, HK_CTX_PERSISTENT_ASTR, persistentKey);
    Auth1_keying_material(derivedKey, HK_CTX_VOLATILE_ASTR, volatileKey);
  }
  if (type == kAliro) {
    Auth1_keying_material(derivedKey, ALIRO_CTX_VOLATILE_ASTR, volatileKey);
    std::memcpy(skReader.data(), volatileKey.data(), 32);
    std::memcpy(skDevice.data(), volatileKey.data() + 32, 32);

    // std::memcpy(step_up_material.data(), volatileKey.data() + 64, 32);
    // std::memcpy(ble_material.data(), volatileKey.data(), 32);
    // std::memcpy(ur_sk.data(), volatileKey.data() + 0x80, 32);
    // std::vector<uint8_t> saltInput(32, 0);
    // mbedtls_hkdf(
    //     mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
    //     saltInput.data(), saltInput.size(),
    //     step_up_material.data(), step_up_material.size(),
    //     reinterpret_cast<const unsigned char *>("SKReader"), 8,
    //     step_up_sk_reader.data(), step_up_sk_reader.size()
    //     );
    // mbedtls_hkdf(
    //     mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
    //     saltInput.data(), saltInput.size(),
    //     step_up_material.data(), step_up_material.size(),
    //     reinterpret_cast<const unsigned char *>("SKDevice"), 8,
    //     step_up_sk_device.data(), step_up_sk_device.size());
    // mbedtls_hkdf(
    //     mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
    //     saltInput.data(), saltInput.size(),
    //     ble_material.data(),ble_material.size(),
    //     reinterpret_cast<const unsigned char *>("BleSKReader"), 8,
    //     ble_sk_reader.data(), ble_sk_reader.size()
    //     );
    // mbedtls_hkdf(
    //     mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
    //     saltInput.data(), saltInput.size(),
    //     ble_material.data(),ble_material.size(),
    //     reinterpret_cast<const unsigned char *>("BleSKDevice"), 8,
    //     ble_sk_device.data(), ble_sk_device.size());

    LOG(D,"Exchange SK Reader (32 bytes): %s",
        fmt::format("{:02X}", fmt::join(skReader, "")).c_str());
    LOG(D,"Exchange SK Device (32 bytes): %s",
        fmt::format("{:02X}", fmt::join(skDevice, "")).c_str());
  }
  LOG(D, "Persistent Key: %s", fmt::format("{:02X}", fmt::join(persistentKey, "")).c_str());
  LOG(D, "Volatile Key: %s", fmt::format("{:02X}", fmt::join(volatileKey, "")).c_str());
  std::unique_ptr<DigitalKeySecureContext> context;
  if (type == kHomeKey) {
    context = std::make_unique<DigitalKeySecureContext>(volatileKey);
  }
  if (type == kAliro) {
    context = std::make_unique<DigitalKeySecureContext>(&skReader, &skDevice);
  }
  hkEndpoint_t *foundEndpoint = nullptr;
  hkIssuer_t *foundIssuer = nullptr;
  if (response.size() > 2 && response[response.size() - 2] == 0x90)
  {
    auto response_result = context->decrypt_response(response.data(), response.size() - 2);
    LOG(D, "Decrypted Length: %d, Data: %s", response_result.size(), fmt::format("{:02X}", fmt::join(response_result, "")).c_str());
    if (!response_result.empty())
    {
      TLV8 decryptedTlv;
      decryptedTlv.parse(response_result.data(), response_result.size());
      std::vector<uint8_t> signature = decryptedTlv.find(0x9E)->value;
      if (type == kHomeKey) {
        std::vector<uint8_t> device_identifier = decryptedTlv.find(0x4E)->value;
        LOG(D, "Device Identifier: %s", fmt::format("{:02X}", fmt::join(device_identifier, "")).c_str());
        LOG(D, "Signature: %s", fmt::format("{:02X}", fmt::join(signature, "")).c_str());
        if (device_identifier.empty())
        {
          LOG(E, "TLV DATA INVALID!");
          return std::make_tuple(foundIssuer, foundEndpoint, std::move(context), persistentKey, kFlowFailed);
        }
        for (auto &&issuer : issuers)
        {
          for (auto &&endpoint : issuer.endpoints)
          {
            if (std::equal(endpoint.endpoint_id.begin(), endpoint.endpoint_id.end(), device_identifier.begin()))
            {
              LOG(D, "STD_AUTH: Found Matching Endpoint, ID: %s", fmt::format("{:02X}", fmt::join(endpoint.endpoint_id, "")).c_str());
              foundEndpoint = &endpoint;
              foundIssuer = &issuer;
              epPkX = &endpoint.endpoint_pk_x;
            }
          }
        }
      }
      if (type == kAliro) {
        std::vector<uint8_t> devicePk = decryptedTlv.find(0x5A)->value;
        for (auto &issuer: issuers) {
          for (auto &endpoint: issuer.endpoints) {
            if (memcmp(devicePk.data(), endpoint.endpoint_pk.data(), 65) == 0) {
              foundIssuer = &issuer;
              foundEndpoint = &endpoint;
              LOG(I, "Found matching endpoint with public key: %s",
                  fmt::format("{:02X}", fmt::join(devicePk, "")).c_str());
              epPkX = &endpoint.endpoint_pk_x;
              break;
            }
          }
          if (foundEndpoint != nullptr) {
            break;
          }
        }
      }
      if (foundEndpoint != nullptr)
      {
        std::vector<uint8_t> verification_hash_input_material;
        verification_hash_input_material.reserve(readerIdentifier.size() + endpointEphX.size() + readerEphX.size() + 30);

#if __cplusplus >= 202002L
        std::ranges::copy(simple_tlv(0x4D, readerIdentifier), std::back_inserter(verification_hash_input_material));
        std::ranges::copy(simple_tlv(0x86, endpointEphX), std::back_inserter(verification_hash_input_material));
        std::ranges::copy(simple_tlv(0x87, readerEphX), std::back_inserter(verification_hash_input_material));
        std::ranges::copy(simple_tlv(0x4C, transactionIdentifier), std::back_inserter(verification_hash_input_material));
        std::ranges::copy(simple_tlv(0x93, deviceCtx), std::back_inserter(verification_hash_input_material));
#else
        auto vtlv1 = simple_tlv(0x4D, readerIdentifier);
        std::copy(vtlv1.begin(), vtlv1.end(), std::back_inserter(verification_hash_input_material));
        auto vtlv2 = simple_tlv(0x86, endpointEphX);
        std::copy(vtlv2.begin(), vtlv2.end(), std::back_inserter(verification_hash_input_material));
        auto vtlv3 = simple_tlv(0x87, readerEphX);
        std::copy(vtlv3.begin(), vtlv3.end(), std::back_inserter(verification_hash_input_material));
        auto vtlv4 = simple_tlv(0x4C, transactionIdentifier);
        std::copy(vtlv4.begin(), vtlv4.end(), std::back_inserter(verification_hash_input_material));
        auto vtlv5 = simple_tlv(0x93, deviceCtx);
        std::copy(vtlv5.begin(), vtlv5.end(), std::back_inserter(verification_hash_input_material));
#endif

        mbedtls_ecp_keypair keypair;
        mbedtls_ecp_keypair_init(&keypair);

        uint8_t hash[32];

        mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), verification_hash_input_material.data(), verification_hash_input_material.size(), hash);

        LOG(D, "verification_hash_input_material: %s", fmt::format("{:02X}", fmt::join(hash, "")).c_str());
        mbedtls_mpi r;
        mbedtls_mpi s;

        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);
        mbedtls_ecp_group_load(&keypair.private_grp, MBEDTLS_ECP_DP_SECP256R1);
        int pubImport = mbedtls_ecp_point_read_binary(&keypair.private_grp, &keypair.private_Q, foundEndpoint->endpoint_pk.data(), foundEndpoint->endpoint_pk.size());
        LOG(V, "public key import result: %d", pubImport);

        mbedtls_mpi_read_binary(&r, signature.data(), signature.size() / 2);
        mbedtls_mpi_read_binary(&s, signature.data() + (signature.size() / 2), signature.size() / 2);

        int result = mbedtls_ecdsa_verify(&keypair.private_grp, hash, 32, &keypair.private_Q, &r, &s);

        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);

        mbedtls_ecp_keypair_free(&keypair);

        LOG(V, "signature verification result: %d", result);

        if (result == 0)
        {
          if (type == kAliro) {
            Auth1_keying_material(derivedKey, ALIRO_CTX_PERSISTENT_ASTR, persistentKey);
          }
          return std::make_tuple(foundIssuer, foundEndpoint, std::move(context), persistentKey, kFlowSTANDARD);
        }
        LOG(W, "Signature failed verification! Will attempt EXCHANGE flow(last resort)!");
        return std::make_tuple(foundIssuer, foundEndpoint, std::move(context), persistentKey, kFlowNext);
      }
      LOG(W, "Endpoint data missing! Will attempt EXCHANGE flow(last resort)!");
      return std::make_tuple(foundIssuer, foundEndpoint, std::move(context), persistentKey, kFlowNext);
    }
    else
    {
      LOG(E, "Invalid Response! STANDARD Flow failed!");
      return std::make_tuple(foundIssuer, foundEndpoint, std::move(context), persistentKey, kFlowFailed);
    }
  }
  LOG(E, "Response Status not 0x90, something went wrong!");
  return std::make_tuple(foundIssuer, foundEndpoint, std::move(context), persistentKey, kFlowFailed);
}
