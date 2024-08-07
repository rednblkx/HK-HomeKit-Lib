#include <tuple>
#include "HomeKey.h"
#include <hk-utils.h>
#include <nvs.h>
#include <CommonCryptoUtils.h>
#include <BerTlv.h>
#include <esp_log.h>
#include "TLV8.h"

using namespace CommonCryptoUtils;
using namespace hk_utils;

class HK_HomeKit
{
  private:
    const char* TAG = "HK_HomeKit";
    std::vector<uint8_t> &tlvData;
    readerData_t& readerData;
    nvs_handle& nvsHandle;
    const char* nvsKey = "READERDATA";
    bool save_to_nvs();
    std::tuple<std::vector<uint8_t>, int> provision_device_cred(std::vector<uint8_t> buf);
    int set_reader_key(std::vector<uint8_t> buf);
  public:
    HK_HomeKit(readerData_t& readerData, nvs_handle& nvsHandle, const char* nvsKey, std::vector<uint8_t> &tlvData);
    std::vector<uint8_t> processResult();
};