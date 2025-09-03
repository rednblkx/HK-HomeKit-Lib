#include "simple_tlv.h"
#include <algorithm>
#include <span>

/**
 * @brief Creates a simple Tag-Length-Value (TLV) byte vector.
 *
 * This function adheres to a simple TLV format where the length field is one byte
 * for values under 128 bytes, and two bytes for values of 128 bytes or more.
 *
 * @param tag The tag identifier (T).
 * @param value A span of constant bytes representing the value (V).
 * @return A std::vector<uint8_t> containing the full TLV structure.
 */
std::vector<uint8_t> simple_tlv(uint8_t tag, std::span<const uint8_t> value) {
    std::vector<uint8_t> tlv_data;
    const auto value_length = value.size();
    
    // The length field is extended if the value length is 128 or more.
    const bool is_extended_length = (value_length >= 128);

    //    Total Length = Tag (1) + Length field (1 or 2) + Value
    const size_t total_length = sizeof(tag) + (is_extended_length ? 2 : 1) + value_length;
    tlv_data.reserve(total_length);

    tlv_data.push_back(tag);

    if (is_extended_length) {
        // Use a two-byte length encoding: 0x81 followed by the actual length.
        // This assumes the length fits within a single byte (0-255).
        tlv_data.push_back(0x81); // 0b10000001: Indicates one subsequent length byte.
        tlv_data.push_back(static_cast<uint8_t>(value_length));
    } else {
        // Use a single-byte length for lengths 0-127.
        tlv_data.push_back(static_cast<uint8_t>(value_length));
    }

    std::ranges::move(value, std::back_inserter(tlv_data));

    return tlv_data;
}
