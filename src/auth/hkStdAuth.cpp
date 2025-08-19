#include "hkStdAuth.h"
#include "CommonCryptoUtils.h"
#include "x963kdf.h"
#include "logging.h"
#include "simple_tlv.h"
#include <mbedtls/hkdf.h>
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <TLV8.hpp>
#include <mbedtls/ecdsa.h>
#include <vector>

/**
 * The function `Auth1_keys_generator` generates persistent and volatile keys using a shared key and
 * X963KDF algorithm.
 *
 * @param persistentKey The `persistentKey` parameter is a pointer to a buffer where the generated
 * persistent key will be stored. It should have a size of at least 32 bytes.
 * @param volatileKey The `volatileKey` parameter is a pointer to a buffer that will store the volatile
 * key. It is expected to be an array of `uint8_t` with a size of 48 bytes.
 */
void HKStdAuth::Auth1_keys_generator(uint8_t *persistentKey, uint8_t *volatileKey)
{
  uint8_t sharedKey[32];

  CommonCryptoUtils::get_shared_key(readerEphPrivKey, endpointEphPubKey, sharedKey, sizeof(sharedKey));
  LOG(D, "Shared Key: %s", red_log::bufToHexString(sharedKey, 32).c_str());

  X963KDF kdf(MBEDTLS_MD_SHA256, 32, transactionIdentifier.data(), 16);

  // Derive the key using X963KDF
  uint8_t derivedKey[32];
  kdf.derive(sharedKey, sizeof(sharedKey), derivedKey);
  LOG(D, "X963KDF Derived Key: %s", red_log::bufToHexString(derivedKey, 32).c_str());
  Auth1_keying_material(derivedKey, "Persistent", persistentKey, 32);
  Auth1_keying_material(derivedKey, "Volatile", volatileKey, 48);
  LOG(D, "Persistent Key: %s", red_log::bufToHexString(persistentKey, 32).c_str());
  LOG(D, "Volatile Key: %s", red_log::bufToHexString(volatileKey, 48).c_str());
}

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
void HKStdAuth::Auth1_keying_material(uint8_t *keyingMaterial, const char *context, uint8_t *out, size_t outLen)
{
  uint8_t interface = 0x5E;
  uint8_t flags[2] = {0x01, 0x01};
  uint8_t prot_ver[4] = {0x5c, 0x02, 0x02, 0x0};
  uint8_t supported_vers[6] = {0x5c, 0x04, 0x02, 0x0, 0x01, 0x0};
  std::vector<uint8_t> dataMaterial;
  dataMaterial.reserve(readerEphX.size() + endpointEphX.size() + transactionIdentifier.size() + 1 + sizeof(flags) + strlen(context) + sizeof(prot_ver) + sizeof(supported_vers));
  dataMaterial.insert(dataMaterial.end(), std::make_move_iterator(readerEphX.begin()), std::make_move_iterator(readerEphX.end()));
  dataMaterial.insert(dataMaterial.end(), std::make_move_iterator(endpointEphX.begin()), std::make_move_iterator(endpointEphX.end()));
  dataMaterial.insert(dataMaterial.end(), std::make_move_iterator(transactionIdentifier.begin()), std::make_move_iterator(transactionIdentifier.end()));
  dataMaterial.push_back(interface);
  dataMaterial.push_back(flags[0]);
  dataMaterial.push_back(flags[1]);
  dataMaterial.insert(dataMaterial.end(), (uint8_t*)context, (uint8_t*)context + strlen(context));
  dataMaterial.insert(dataMaterial.end(), prot_ver, prot_ver + sizeof(prot_ver));
  dataMaterial.insert(dataMaterial.end(), supported_vers, supported_vers + sizeof(supported_vers));
  LOG(D, "DATA Material Length: %d, Data: %s", sizeof(dataMaterial), red_log::bufToHexString(dataMaterial.data(), dataMaterial.size()).c_str());
  mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, keyingMaterial, 32, dataMaterial.data(), dataMaterial.size(), out, outLen);
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
std::tuple<hkIssuer_t *, hkEndpoint_t *, DigitalKeySecureContext, std::vector<uint8_t>, KeyFlow> HKStdAuth::attest()
{
  // int readerContext = 1096652137;
  uint8_t readerCtx[4]{0x41, 0x5d, 0x95, 0x69};
  // int deviceContext = 1317567308;
  uint8_t deviceCtx[4]{0x4e, 0x88, 0x7b, 0x4c};

  std::vector<uint8_t> stdTlv(16 + endpointEphX.size() + readerEphX.size() + 30);
  size_t len = 0;
  simple_tlv(0x4D, readerIdentifier.data(), 16, stdTlv.data(), &len);
  simple_tlv(0x86, endpointEphX.data(), endpointEphX.size(), stdTlv.data() + len, &len);
  simple_tlv(0x87, readerEphX.data(), readerEphX.size(), stdTlv.data() + len, &len);
  simple_tlv(0x4C, transactionIdentifier.data(), 16, stdTlv.data() + len, &len);
  simple_tlv(0x93, readerCtx, 4, stdTlv.data() + len, &len);
  std::vector<uint8_t> sigPoint = CommonCryptoUtils::signSharedInfo(stdTlv.data(), len, reader_private_key.data(), reader_private_key.size());
  std::vector<uint8_t> sigTlv = simple_tlv(0x9E, sigPoint.data(), sigPoint.size());
  std::vector<uint8_t> apdu{0x80, 0x81, 0x0, 0x0, (uint8_t)sigTlv.size()};
  apdu.resize(apdu.size() + sigTlv.size());
  std::move(sigTlv.begin(), sigTlv.end(), apdu.begin() + 5);
  std::vector<uint8_t> response;
  LOG(D, "Auth1 APDU Length: %d, DATA: %s", apdu.size(), red_log::bufToHexString(apdu.data(), apdu.size()).c_str());
  nfc(apdu, response, false);
  LOG(D, "Auth1 Response Length: %d, DATA: %s", response.size(), red_log::bufToHexString(response.data(), response.size()).c_str());
  std::vector<uint8_t> persistentKey(32);
  uint8_t volatileKey[48];
  Auth1_keys_generator(persistentKey.data(), volatileKey);
  DigitalKeySecureContext context = DigitalKeySecureContext(volatileKey);
  hkEndpoint_t *foundEndpoint = nullptr;
  hkIssuer_t *foundIssuer = nullptr;
  if (response.size() > 2 && response[response.size() - 2] == 0x90)
  {
    auto response_result = context.decrypt_response(response.data(), response.size() - 2);
    LOG(D, "Decrypted Length: %d, Data: %s", response_result.size(), red_log::bufToHexString(response_result.data(), response_result.size()).c_str());
    if (response_result.size() > 0)
    {
      TLV8 decryptedTlv;
      decryptedTlv.parse(response_result.data(), response_result.size());
      tlv_it devId = decryptedTlv.find(0x4E);
      tlv_it sig = decryptedTlv.find(0x9E);
      std::vector<uint8_t> device_identifier = devId->value;
      std::vector<uint8_t> signature = sig->value;
      LOG(D, "Device Identifier: %s", red_log::bufToHexString(device_identifier.data(), device_identifier.size()).c_str());
      LOG(D, "Signature: %s", red_log::bufToHexString(signature.data(), signature.size()).c_str());
      if (device_identifier.size() == 0)
      {
        LOG(E, "TLV DATA INVALID!");
        return std::make_tuple(foundIssuer, foundEndpoint, context, persistentKey, kFlowFailed);
      }
      for (auto &&issuer : issuers)
      {
        for (auto &&endpoint : issuer.endpoints)
        {
          if (std::equal(endpoint.endpoint_id.begin(), endpoint.endpoint_id.end(), device_identifier.begin()))
          {
            LOG(D, "STD_AUTH: Found Matching Endpoint, ID: %s", red_log::bufToHexString(endpoint.endpoint_id.data(), endpoint.endpoint_id.size()).c_str());
            foundEndpoint = &endpoint;
            foundIssuer = &issuer;
          }
        }
      }
      if (foundEndpoint != nullptr)
      {
        std::vector<uint8_t> verification_hash_input_material(readerIdentifier.size() + endpointEphX.size() + readerEphX.size() + 30);
        size_t olen = 0;

        simple_tlv(0x4D, readerIdentifier.data(), readerIdentifier.size(), verification_hash_input_material.data(), &olen);
        simple_tlv(0x86, endpointEphX.data(), endpointEphX.size(), verification_hash_input_material.data() + olen, &olen);
        simple_tlv(0x87, readerEphX.data(), readerEphX.size(), verification_hash_input_material.data() + olen, &olen);
        simple_tlv(0x4C, transactionIdentifier.data(), 16, verification_hash_input_material.data() + olen, &olen);
        simple_tlv(0x93, deviceCtx, 4, verification_hash_input_material.data() + olen, &olen);
        mbedtls_ecp_keypair keypair;
        mbedtls_ecp_keypair_init(&keypair);

        uint8_t hash[32];

        mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), verification_hash_input_material.data(), olen, hash);

        LOG(D, "verification_hash_input_material: %s", red_log::bufToHexString(hash, 32).c_str());
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
          return std::make_tuple(foundIssuer, foundEndpoint, context, persistentKey, kFlowSTANDARD);
        }
        else if (device_identifier.size() > 0)
        {
          LOG(W, "Signature failed verification! Will attempt EXCHANGE flow(last resort)!");
          return std::make_tuple(foundIssuer, foundEndpoint, context, persistentKey, kFlowNext);
        }
      }
      LOG(W, "Endpoint data missing! Will attempt EXCHANGE flow(last resort)!");
      return std::make_tuple(foundIssuer, foundEndpoint, context, persistentKey, kFlowNext);
    }
    else
    {
      LOG(E, "Invalid Response! STANDARD Flow failed!");
      return std::make_tuple(foundIssuer, foundEndpoint, context, persistentKey, kFlowFailed);
    }
  }
  LOG(E, "Response Status not 0x90, something went wrong!");
  return std::make_tuple(foundIssuer, foundEndpoint, context, persistentKey, kFlowFailed);
}
