/* packet-enc.c
 *
 * Copyright (c) 2003 Markus Friedl.  All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/aftypes.h>
#include <wsutil/pint.h>
#include <epan/crc16-tvb.h>
#include <epan/crc32-tvb.h>
#include <epan/proto_data.h>
#include <epan/expert.h>

#include "proto.h"

void proto_register_crccheck(void);
void proto_reg_handoff_crccheck(void);



 /* header fields */
static int hf_crccheck_checksum_CRC16_ccitt = -1;
static int hf_crccheck_checksum_CRC16_ccitt_status = -1;
// static expert_field ei_crccheck_checksum_CRC16_ccitt_bad = EI_INIT;

// 16:
static int hf_crccheck_checksum_CRC16_x25_ccitt = -1;
static int hf_crccheck_checksum_CRC16_x25_ccitt_status = -1;
// static expert_field ei_crccheck_checksum_CRC16_x25_ccitt_bad = EI_INIT;

// 32:
static int  hf_crccheck_checksum_CRC32_ccitt = -1;
static int  hf_crccheck_checksum_CRC32_ccitt_status = -1;

static dissector_handle_t crccheck_handle;


static int proto_crccheck = -1;

// tree
static gint ett_crccheck = -1;

//prefs
static gboolean global_crccheck_littleendian = FALSE;
static guint pref_crccheck_offset_from_end = 0;



static int
dissect_crccheck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    auto ENCODING_TYPE;
    if (global_crccheck_littleendian)
    {
        ENCODING_TYPE= ENC_LITTLE_ENDIAN;
    }
    else
    {
        ENCODING_TYPE= ENC_BIG_ENDIAN;
    }

    proto_item *crc_ti = proto_tree_add_item(tree, proto_crccheck, tvb, 0, -1,ENC_NA);
    proto_tree *crc_tree = proto_item_add_subtree(crc_ti, ett_crccheck);

    
    // 16
    guint crc_start_byte_16 = tvb_reported_length(tvb) - pref_crccheck_offset_from_end - 2;
    int crcVal_crc16_ccitt = crc16_ccitt_tvb(tvb, crc_start_byte_16);
    int crcVal_crc16_x25_ccitt = crc16_x25_ccitt_tvb(tvb, crc_start_byte_16);

    proto_tree_add_checksum(crc_tree, tvb, crc_start_byte_16, hf_crccheck_checksum_CRC16_ccitt, hf_crccheck_checksum_CRC16_ccitt_status, NULL, pinfo, crcVal_crc16_ccitt, ENCODING_TYPE, PROTO_CHECKSUM_VERIFY);
    proto_tree_add_checksum(crc_tree, tvb, crc_start_byte_16, hf_crccheck_checksum_CRC16_x25_ccitt, hf_crccheck_checksum_CRC16_x25_ccitt_status, NULL, pinfo, crcVal_crc16_x25_ccitt, ENCODING_TYPE, PROTO_CHECKSUM_VERIFY);

    //32
    guint crc_start_byte_32 = tvb_reported_length(tvb) - pref_crccheck_offset_from_end - 4;
    int crcVal_crc32_ccitt =  crc32_ccitt_tvb(tvb, crc_start_byte_32);

    proto_tree_add_checksum(crc_tree, tvb, crc_start_byte_32, hf_crccheck_checksum_CRC32_ccitt, hf_crccheck_checksum_CRC32_ccitt_status, NULL, pinfo, crcVal_crc32_ccitt, ENCODING_TYPE, PROTO_CHECKSUM_VERIFY);



    return tvb_captured_length(tvb);
}

void
proto_register_crccheck(void)
{
    static hf_register_info hf[] =
    {
     // 16 
    { &hf_crccheck_checksum_CRC16_ccitt,                   { "CRC16_ccitt",                       "crccheck.checksum_CRC16_ccitt",                    FT_UINT16,          BASE_HEX,           NULL,                               0x0, "Details at: http://www.wireshark.org/docs/wsug_html_chunked/ChAdvChecksums.html", HFILL }},

    { &hf_crccheck_checksum_CRC16_ccitt_status,            { "CRC16_ccitt Status",                "crccheck.checksum.status_CRC16_ccitt",             FT_UINT8,           BASE_NONE,          VALS(proto_checksum_vals),         0x0,     NULL,    HFILL } },


    { &hf_crccheck_checksum_CRC16_x25_ccitt,               { "CRC16_ccitt_x25",                   "crccheck.checksum_CRC16_ccitt_x25",                FT_UINT16,          BASE_HEX,           NULL,                               0x0, "Details at: http://www.wireshark.org/docs/wsug_html_chunked/ChAdvChecksums.html", HFILL }},

    { &hf_crccheck_checksum_CRC16_x25_ccitt_status,        { "CRC16_ccitt_x25 Status",            "crccheck.checksum.status_CRC16_ccitt_x25",         FT_UINT8,           BASE_NONE,          VALS(proto_checksum_vals),         0x0,     NULL,    HFILL } },

    // 32:
    { &hf_crccheck_checksum_CRC32_ccitt,                   { "CRC32_ccitt",                       "crccheck.checksum_CRC32_ccitt",                    FT_UINT32,          BASE_HEX,           NULL,                               0x0, "Details at: http://www.wireshark.org/docs/wsug_html_chunked/ChAdvChecksums.html", HFILL }},

    { &hf_crccheck_checksum_CRC32_ccitt_status,            { "CRC32_ccitt Status",                "crccheck.checksum.status_CRC32_ccitt",             FT_UINT8,           BASE_NONE,          VALS(proto_checksum_vals),         0x0,     NULL,    HFILL } },
    

    };

  static gint *ett[] =
  {
      &ett_crccheck,
  };

 // static ei_register_info ei[] =
 // {
         // { &ei_crccheck_checksum_CRC16_ccitt_bad,     { "crccheck.warning.expert", PI_CHECKSUM, PI_WARN, "Bad CRC", EXPFILL }},
         // { &ei_crccheck_checksum_CRC16_x25_ccitt_bad, { "crccheck.warning.expert", PI_CHECKSUM, PI_WARN, "Bad CRC", EXPFILL }},

  //};

  proto_crccheck = proto_register_protocol("CRCCHECK","CRCCheck", "crccheck");

  register_dissector("crccheck", dissect_crccheck, proto_crccheck); // for dlt_user

  // prefs
  module_t *crccheck_module;

  crccheck_module = prefs_register_protocol(proto_crccheck, NULL);

  prefs_register_bool_preference(crccheck_module, "use_littleendian",
      "Use LittleEndian",
      "Use LittleEndian for Compare CRC",
      &global_crccheck_littleendian);

  prefs_register_uint_preference(crccheck_module, "crc_offset_from_end",
      "CRC Offset From Last Byte",
      "CRC Offset From Last Byte",
      10, &pref_crccheck_offset_from_end);


  proto_register_field_array(proto_crccheck, hf, array_length(hf));//register fields
  proto_register_subtree_array(ett, array_length(ett));// register subtrees

}

void
proto_reg_handoff_crccheck(void)
{
  crccheck_handle  = create_dissector_handle(dissect_crccheck, proto_crccheck);
  dissector_add_for_decode_as("udp.port", crccheck_handle);
  dissector_add_for_decode_as("tcp.port", crccheck_handle);

}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
