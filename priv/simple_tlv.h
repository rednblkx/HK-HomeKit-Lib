#pragma once
#include <cstdint>
#include <span>
#include <vector>
std::vector<uint8_t> simple_tlv(uint8_t tag, std::span<const uint8_t> value);
