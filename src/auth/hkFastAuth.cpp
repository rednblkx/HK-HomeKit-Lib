#include <hkFastAuth.h>

/**
 * The function `Auth0_keying_material` generates keying material using the HKDF algorithm based on
 * various input parameters.
 *
 * @param context The `context` parameter is a pointer to a character array that represents the context
 * for the keying material generation. It is used as input to the HKDF (HMAC-based Key Derivation
 * Function) algorithm.
 * @param ePub_X ePub_X is a pointer to a uint8_t array that represents the public key of the entity
 * being authenticated. It has a length of 32 bytes.
 * @param keyingMaterial The `keyingMaterial` parameter is a pointer to a buffer where the input keying material to be used with HKDF is stored.
 * It should have a size of at least 32 bytes.
 * @param out The `out` parameter is a pointer to the buffer where the output keying material will be
 * stored. The size of the buffer is specified by the `outLen` parameter.
 * @param outLen The parameter `outLen` represents the length of the output buffer `out`. It specifies
 * the maximum number of bytes that can be written to the `out` buffer.
 */
void HKFastAuth::Auth0_keying_material(const char *context, const std::vector<uint8_t> &ePub_X, const std::vector<uint8_t> &keyingMaterial, uint8_t *out, size_t outLen)
{
  uint8_t interface = 0x5E;
  uint8_t flags[2] = {0x01, 0x01};
  uint8_t prot_ver[4] = {0x5c, 0x02, 0x02, 0x0};
  uint8_t supported_vers[6] = {0x5c, 0x04, 0x02, 0x0, 0x01, 0x0};
  uint8_t dataMaterial[32 + strlen(context) + readerIdentifier.size() + 32 + 1 + sizeof(supported_vers) + sizeof(prot_ver) + readerEphX.size() + 16 + 2 + endpointEphX.size()];
  size_t olen = 0;
  hk_utils::pack(reader_key_X.data(), 32, dataMaterial, &olen);
  hk_utils::pack((uint8_t *)context, strlen(context), dataMaterial, &olen);
  hk_utils::pack(readerIdentifier.data(), readerIdentifier.size(), dataMaterial, &olen);
  hk_utils::pack(ePub_X.data(), 32, dataMaterial, &olen);
  hk_utils::pack(&interface, 1, dataMaterial, &olen);
  hk_utils::pack(supported_vers, sizeof(supported_vers), dataMaterial, &olen);
  hk_utils::pack(prot_ver, sizeof(prot_ver), dataMaterial, &olen);
  hk_utils::pack(readerEphX.data(), readerEphX.size(), dataMaterial, &olen);
  hk_utils::pack(transactionIdentifier.data(), 16, dataMaterial, &olen);
  hk_utils::pack(flags, 2, dataMaterial, &olen);
  hk_utils::pack(endpointEphX.data(), endpointEphX.size(), dataMaterial, &olen);
  LOG(D, "Auth0 HKDF Material: %s", hk_utils::bufToHexString(dataMaterial, sizeof(dataMaterial)).c_str());
  int ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, keyingMaterial.data(), keyingMaterial.size(), dataMaterial, sizeof(dataMaterial), out, outLen);
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
    LOG(V, "Issuer: %s, Endpoints: %d", hk_utils::bufToHexString(issuer.issuer_id.data(), issuer.issuer_id.size()).c_str(), issuer.endpoints.size());
    for (auto &&endpoint : issuer.endpoints)
    {
      if(endpoint.endpoint_prst_k.size() == 0) continue;
      LOG(V, "Endpoint: %s, Persistent Key: %s", hk_utils::bufToHexString(endpoint.endpoint_id.data(), endpoint.endpoint_id.size()).c_str(), hk_utils::bufToHexString(endpoint.endpoint_prst_k.data(), endpoint.endpoint_prst_k.size()).c_str());
      std::vector<uint8_t> hkdf(58);
      Auth0_keying_material("VolatileFast", endpoint.endpoint_pk_x, endpoint.endpoint_prst_k, hkdf.data(), hkdf.size());
      LOG(V, "HKDF Derived Key: %s", hk_utils::bufToHexString(hkdf.data(), hkdf.size()).c_str());
      if (!memcmp(hkdf.data(), cryptogram.data(), 16))
      {
        LOG(D, "Endpoint %s matches cryptogram", hk_utils::bufToHexString(endpoint.endpoint_id.data(), endpoint.endpoint_id.size()).c_str());
        foundIssuer = &issuer;
        foundEndpoint = &endpoint;
        break;
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
    LOG(D, "Endpoint %s Authenticated via FAST Flow", hk_utils::bufToHexString(std::get<1>(foundData)->endpoint_id.data(), std::get<1>(foundData)->endpoint_id.size()).c_str());
    return std::make_tuple(std::get<0>(foundData), std::get<1>(foundData), kFlowFAST);
  }
  LOG(W, "FAST Flow failed!");
  return std::make_tuple(std::get<0>(foundData), std::get<1>(foundData), kFlowSTANDARD);
}