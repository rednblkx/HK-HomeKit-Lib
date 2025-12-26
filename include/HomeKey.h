#pragma once

#include <cstdint>
#include <vector>

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
  kFlowNext = 0xFF,
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
  uint8_t counter = 0;
  uint8_t key_type = 0;
  std::vector<uint8_t> endpoint_pk;
  std::vector<uint8_t> endpoint_pk_x;
  std::vector<uint8_t> endpoint_prst_k;
  // hkEnrollments_t enrollments;
};

struct hkIssuer_t
{
  std::vector<uint8_t> issuer_id;
  std::vector<uint8_t> issuer_pk;
  std::vector<uint8_t> issuer_pk_x;
  std::vector<hkEndpoint_t> endpoints;
};

struct readerData_t
{
  readerData_t() : reader_sk(0), reader_pk(0), reader_pk_x(0), reader_gid(0), reader_id(0), issuers(0) {}
  std::vector<uint8_t> reader_sk;
  std::vector<uint8_t> reader_pk;
  std::vector<uint8_t> reader_pk_x;
  std::vector<uint8_t> reader_gid;
  std::vector<uint8_t> reader_id;
  std::vector<hkIssuer_t> issuers;
};

