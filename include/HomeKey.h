#pragma once
#include "nlohmann/json.hpp"

using json = nlohmann::json;

typedef enum
{
  kReader_Operation = 0x01,
  kReader_Device_Credential_Request = 0x04,
  kReader_Device_Credential_Response = 0x05,
  kReader_Reader_Key_Request = 0x06,
  kReader_Reader_Key_Response = 0x07,
} Reader_Tags;

typedef enum
{
  kReader_Operation_Read = 0x01,
  kReader_Operation_Write = 0x02,
  kReader_Operation_Remove = 0x03,
} Reader_Operation;

typedef enum
{
  kReader_Req_Key_Type = 0x01,
  kReader_Req_Reader_Private_Key = 0x02,
  kReader_Req_Identifier = 0x03,
  kReader_Req_Key_Identifier = 0x04, // This is only relevant for "remove" operation
  kRequest_Reader_Key_Request = 0x06
} Reader_Key_Request;

typedef enum
{
  kReader_Res_Key_Identifier = 0x01,
  kReader_Res_Status = 0x02,
  kReader_Res_Reader_Key_Response = 0x07
} Reader_Key_Response;

typedef enum
{
  kDevice_Req_Key_Type = 0x01,
  kDevice_Req_Public_Key = 0x02,
  kDevice_Req_Issuer_Key_Identifier = 0x03,
  kDevice_Req_Key_State = 0x04,
  kDevice_Req_Key_Identifier = 0x05 // This is only relevant for "remove" operation
} Device_Credential_Request;

typedef enum
{
  kDevice_Res_Key_Identifier = 0x01,
  kDevice_Res_Issuer_Key_Identifier = 0x02,
  kDevice_Res_Status = 0x03,
  kDevice_Credential_Response = 0x05
} Device_Credential_Response;

typedef enum
{
  kEndpoint_Public_Key = 0x86,
  kAuth0_Cryptogram = 0x9D,
  kAuth0Status = 0x90
} AUTH0_RESPONSE;

typedef enum
{
  kNDEF_MESSAGE = 0x53,
  kEnv1Status = 0x90
} ENVELOPE_RESPONSE;

typedef enum
{
  kCmdFlowFailed = 0x0,
  kCmdFlowSuccess = 0x01,
  kCmdFlowAttestation = 0x40
} CommandFlowStatus;

typedef enum
{
  kTransactionSTANDARD = 0x0,
  kTransactionFAST = 0x01
} KeyTransactionFlags;

typedef enum
{
  kFlowFAST = 0x00,
  kFlowSTANDARD = 0x01,
  kFlowATTESTATION = 0x02,
  kFlowFailed = -1
} KeyFlow;
typedef enum
{
  SUCCESS = 0,
  OUT_OF_RESOURCES = 1,
  DUPLICATE = 2,
  DOES_NOT_EXIST = 3,
  NOT_SUPPORTED = 4
} OPERATION_STATUS;

// struct hkEnrollment_t
// {
//   std::time_t unixTime = 0;
//   std::vector<uint8_t> payload;
// };
// struct hkEnrollments_t
// {
//   hkEnrollment_t hap;
//   hkEnrollment_t attestation;
// };

struct hkEndpoint_t
{
  std::vector<uint8_t> endpoint_id;
  uint32_t last_used_at = 0;
  int counter = 0;
  int key_type = 0;
  std::vector<uint8_t> endpoint_pk;
  std::vector<uint8_t> endpoint_pk_x;
  std::vector<uint8_t> endpoint_prst_k;
  // hkEnrollments_t enrollments;
};

inline void to_json(json &j, const hkEndpoint_t &p)
{
  j = json{{"endpointId", p.endpoint_id}, {"last_used_at", p.last_used_at}, {"counter", p.counter}, {"key_type", p.key_type}, {"publicKey", p.endpoint_pk}, {"endpoint_key_x", p.endpoint_pk_x}, {"persistent_key", p.endpoint_prst_k}};
}

inline void from_json(const json &j, hkEndpoint_t &p)
{
  j.at("endpointId").get_to(p.endpoint_id);
  j.at("publicKey").get_to(p.endpoint_pk);
  j.at("endpoint_key_x").get_to(p.endpoint_pk_x);
  j.at("persistent_key").get_to(p.endpoint_prst_k);
  j.at("last_used_at").get_to(p.last_used_at);
  j.at("counter").get_to(p.counter);
  j.at("key_type").get_to(p.key_type);
}

// JSONCONS_ALL_MEMBER_TRAITS(hkEndpoint_t, endpoint_id, last_used_at, counter, key_type, endpoint_pk, endpoint_pk_x, endpoint_prst_k)
// namespace jsoncons { template <class ChT > struct json_traits_macro_names<ChT,hkEndpoint_t > { static inline const char* endpointId_str(char) {return "endpointId";} static inline const wchar_t* endpointId_str(wchar_t) {return L"endpointId";} static inline const char* last_used_at_str(char) {return "last_used_at";} static inline const wchar_t* last_used_at_str(wchar_t) {return L"last_used_at";} static inline const char* counter_str(char) {return "counter";} static inline const wchar_t* counter_str(wchar_t) {return L"counter";} static inline const char* key_type_str(char) {return "key_type";} static inline const wchar_t* key_type_str(wchar_t) {return L"key_type";} static inline const char* publicKey_str(char) {return "publicKey";} static inline const wchar_t* publicKey_str(wchar_t) {return L"publicKey";} static inline const char* endpoint_key_x_str(char) {return "endpoint_key_x";} static inline const wchar_t* endpoint_key_x_str(wchar_t) {return L"endpoint_key_x";} static inline const char* persistent_key_str(char) {return "persistent_key";} static inline const wchar_t* persistent_key_str(wchar_t) {return L"persistent_key";} }; template<typename Json > struct json_type_traits<Json, hkEndpoint_t > { using value_type = hkEndpoint_t ; using allocator_type = typename Json::allocator_type; using char_type = typename Json::char_type; using string_view_type = typename Json::string_view_type; constexpr static size_t num_params = 7; constexpr static size_t num_mandatory_params1 = 7; constexpr static size_t num_mandatory_params2 = 7; static bool is(const Json& ajson) noexcept { if (!ajson.is_object()) return false; if ((num_params-7) < num_mandatory_params1 && !ajson.contains(json_traits_macro_names<char_type,value_type>::endpointId_str(char_type{}))) return false; if ((num_params-6) < num_mandatory_params1 && !ajson.contains(json_traits_macro_names<char_type,value_type>::last_used_at_str(char_type{}))) return false; if ((num_params-5) < num_mandatory_params1 && !ajson.contains(json_traits_macro_names<char_type,value_type>::counter_str(char_type{}))) return false; if ((num_params-4) < num_mandatory_params1 && !ajson.contains(json_traits_macro_names<char_type,value_type>::key_type_str(char_type{}))) return false; if ((num_params-3) < num_mandatory_params1 && !ajson.contains(json_traits_macro_names<char_type,value_type>::publicKey_str(char_type{}))) return false; if ((num_params-2) < num_mandatory_params1 && !ajson.contains(json_traits_macro_names<char_type,value_type>::endpoint_key_x_str(char_type{}))) return false; if ((num_params-1) < num_mandatory_params1 && !ajson.contains(json_traits_macro_names<char_type,value_type>::persistent_key_str(char_type{}))) return false; return true; } static value_type as(const Json& ajson) { if (!is(ajson)) throw conv_error(conv_errc::conversion_failed, "Not a " "hkEndpoint_t"); value_type aval{}; json_traits_helper<Json>::set_udt_member(ajson,json_traits_macro_names<char_type,value_type>::endpointId_str(char_type{}),aval.endpoint_id); json_traits_helper<Json>::set_udt_member(ajson,json_traits_macro_names<char_type,value_type>::last_used_at_str(char_type{}),aval.last_used_at); json_traits_helper<Json>::set_udt_member(ajson,json_traits_macro_names<char_type,value_type>::counter_str(char_type{}),aval.counter); json_traits_helper<Json>::set_udt_member(ajson,json_traits_macro_names<char_type,value_type>::key_type_str(char_type{}),aval.key_type); json_traits_helper<Json>::set_udt_member(ajson,json_traits_macro_names<char_type,value_type>::publicKey_str(char_type{}),aval.endpoint_pk); json_traits_helper<Json>::set_udt_member(ajson,json_traits_macro_names<char_type,value_type>::endpoint_key_x_str(char_type{}),aval.endpoint_pk_x); json_traits_helper<Json>::set_udt_member(ajson,json_traits_macro_names<char_type,value_type>::persistent_key_str(char_type{}),aval.endpoint_prst_k); return aval; } static Json to_json(const value_type& aval, allocator_type alloc=allocator_type()) { Json ajson(json_object_arg, semantic_tag::none, alloc); ajson.try_emplace(json_traits_macro_names<char_type,value_type>::endpointId_str(char_type{}), Json(byte_string_arg, aval.endpoint_id)); ajson.try_emplace(json_traits_macro_names<char_type,value_type>::last_used_at_str(char_type{}), aval.last_used_at); ajson.try_emplace(json_traits_macro_names<char_type,value_type>::counter_str(char_type{}), aval.counter); ajson.try_emplace(json_traits_macro_names<char_type,value_type>::key_type_str(char_type{}), aval.key_type); ajson.try_emplace(json_traits_macro_names<char_type,value_type>::publicKey_str(char_type{}), Json(byte_string_arg, aval.endpoint_pk)); ajson.try_emplace(json_traits_macro_names<char_type,value_type>::endpoint_key_x_str(char_type{}), Json(byte_string_arg, aval.endpoint_pk_x)); ajson.try_emplace(json_traits_macro_names<char_type,value_type>::persistent_key_str(char_type{}), Json(byte_string_arg, aval.endpoint_prst_k)); return ajson; } }; } namespace jsoncons { template <> struct is_json_type_traits_declared<hkEndpoint_t> : public std::true_type {}; }

struct hkIssuer_t
{
  std::vector<uint8_t> issuer_id;
  std::vector<uint8_t> issuer_pk;
  std::vector<uint8_t> issuer_pk_x;
  std::vector<hkEndpoint_t> endpoints;
};
inline void to_json(json &j, const hkIssuer_t &p)
{
  j = json{{"issuerId", p.issuer_id}, {"publicKey", p.issuer_pk}, {"issuer_key_x", p.issuer_pk_x}, {"endpoints", p.endpoints}};
}

inline void from_json(const json &j, hkIssuer_t &p)
{
  j.at("issuerId").get_to(p.issuer_id);
  j.at("publicKey").get_to(p.issuer_pk);
  j.at("issuer_key_x").get_to(p.issuer_pk_x);
  j.at("endpoints").get_to(p.endpoints);
}
// JSONCONS_ALL_MEMBER_TRAITS(hkIssuer_t, issuer_id, issuer_pk, issuer_pk_x, endpoints)
// namespace jsoncons { template <class ChT > struct json_traits_macro_names<ChT, hkIssuer_t > { static inline const char* issuerId_str(char) { return "issuerId"; } static inline const wchar_t* issuerId_str(wchar_t) { return L"issuerId"; } static inline const char* publicKey_str(char) { return "publicKey"; } static inline const wchar_t* publicKey_str(wchar_t) { return L"publicKey"; } static inline const char* issuer_key_x_str(char) { return "issuer_key_x"; } static inline const wchar_t* issuer_key_x_str(wchar_t) { return L"issuer_key_x"; } static inline const char* endpoints_str(char) { return "endpoints"; } static inline const wchar_t* endpoints_str(wchar_t) { return L"endpoints"; } }; template<typename Json > struct json_type_traits<Json, hkIssuer_t > { using value_type = hkIssuer_t; using allocator_type = typename Json::allocator_type; using char_type = typename Json::char_type; using string_view_type = typename Json::string_view_type; constexpr static size_t num_params = 4; constexpr static size_t num_mandatory_params1 = 4; constexpr static size_t num_mandatory_params2 = 4; static bool is(const Json& ajson) noexcept { if (!ajson.is_object()) return false; if ((num_params - 4) < num_mandatory_params1 && !ajson.contains(json_traits_macro_names<char_type, value_type>::issuerId_str(char_type{}))) return false; if ((num_params - 3) < num_mandatory_params1 && !ajson.contains(json_traits_macro_names<char_type, value_type>::publicKey_str(char_type{}))) return false; if ((num_params - 2) < num_mandatory_params1 && !ajson.contains(json_traits_macro_names<char_type, value_type>::issuer_key_x_str(char_type{}))) return false; if ((num_params - 1) < num_mandatory_params1 && !ajson.contains(json_traits_macro_names<char_type, value_type>::endpoints_str(char_type{}))) return false; return true; } static value_type as(const Json& ajson) { if (!is(ajson)) throw conv_error(conv_errc::conversion_failed, "Not a " "hkIssuer_t"); value_type aval{}; json_traits_helper<Json>::set_udt_member(ajson, json_traits_macro_names<char_type, value_type>::issuerId_str(char_type{}), aval.issuer_id); json_traits_helper<Json>::set_udt_member(ajson, json_traits_macro_names<char_type, value_type>::publicKey_str(char_type{}), aval.issuer_pk); json_traits_helper<Json>::set_udt_member(ajson, json_traits_macro_names<char_type, value_type>::issuer_key_x_str(char_type{}), aval.issuer_pk_x); json_traits_helper<Json>::set_udt_member(ajson, json_traits_macro_names<char_type, value_type>::endpoints_str(char_type{}), aval.endpoints); return aval; } static Json to_json(const value_type& aval, allocator_type alloc = allocator_type()) { Json ajson(json_object_arg, semantic_tag::none, alloc); ajson.try_emplace(json_traits_macro_names<char_type, value_type>::issuerId_str(char_type{}), Json(byte_string_arg, aval.issuer_id)); ajson.try_emplace(json_traits_macro_names<char_type, value_type>::publicKey_str(char_type{}), Json(byte_string_arg, aval.issuer_pk)); ajson.try_emplace(json_traits_macro_names<char_type, value_type>::issuer_key_x_str(char_type{}), Json(byte_string_arg, aval.issuer_pk_x)); ajson.try_emplace(json_traits_macro_names<char_type, value_type>::endpoints_str(char_type{}), aval.endpoints); return ajson; } }; } namespace jsoncons { template <> struct is_json_type_traits_declared<hkIssuer_t> : public std::true_type {}; }

struct readerData_t
{
  readerData_t() : reader_sk(32), reader_pk(65), reader_pk_x(32), reader_gid(0), reader_id(0), issuers(0) {}
  std::vector<uint8_t> reader_sk;
  std::vector<uint8_t> reader_pk;
  std::vector<uint8_t> reader_pk_x;
  std::vector<uint8_t> reader_gid;
  std::vector<uint8_t> reader_id;
  std::vector<hkIssuer_t> issuers;
};

inline void to_json(json &j, const readerData_t &p)
{
  j = json{{"reader_private_key", p.reader_sk}, {"reader_public_key", p.reader_pk}, {"reader_key_x", p.reader_pk_x}, {"unique_identifier", p.reader_id}, {"group_identifier", p.reader_gid}, {"issuers", p.issuers}};
}

inline void from_json(const json &j, readerData_t &p)
{
  j.at("reader_private_key").get_to(p.reader_sk);
  j.at("reader_public_key").get_to(p.reader_pk);
  j.at("reader_key_x").get_to(p.reader_pk_x);
  j.at("unique_identifier").get_to(p.reader_id);
  j.at("group_identifier").get_to(p.reader_gid);
  j.at("issuers").get_to(p.issuers);
}