#pragma once
#include "HomeKey.h"
#include "DigitalKeySecureContext.h"
#include "hkAuthParams.h"
#include <functional>
#include <memory>
#include <string_view>
#include <vector>

class HKStdAuth
{
private:
  const char *TAG = "HKStdAuth";
  HKAuthParams &params;
  std::vector<uint8_t> *epPkX;
  template <typename Container>
  void Auth1_keying_material(std::array<uint8_t,32> &keyingMaterial, std::string_view context, Container &out);

public:
  HKStdAuth(HKAuthParams &params);
  std::tuple<hkIssuer_t *, hkEndpoint_t *, std::unique_ptr<DigitalKeySecureContext>, std::array<uint8_t,32>, KeyFlow> attest();
};
