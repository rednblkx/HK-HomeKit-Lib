#include <tuple>
#include <HomeKey.h>
#include <utils.h>
#include <nvs.h>
#include <CommonCryptoUtils.h>
#include <BerTlv.h>

using namespace CommonCryptoUtils;
using namespace utils;

class HK_HomeKit
{
  private:
    const char* TAG = "HK_HomeKit";
    homeKeyReader::readerData_t& readerData;
    nvs_handle& nvsHandle;
    const char* nvsKey = "READERDATA";
    bool save_to_nvs();
    std::tuple<uint8_t*, int> provision_device_cred(std::vector<uint8_t> buf);
    int set_reader_key(std::vector<uint8_t> buf);
  public:
    HK_HomeKit(homeKeyReader::readerData_t& readerData, nvs_handle& nvsHandle, const char* nvsKey);
    std::vector<uint8_t> processResult(std::vector<uint8_t> tlvData);
};