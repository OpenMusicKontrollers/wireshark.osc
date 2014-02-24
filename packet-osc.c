/* packet-osc.c
 * Routines for "Open Sound Control" packet dissection
 * Copyright 2014, Hanspeter Portner <dev@open-music-kontrollers.ch>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * Specification 1.0 (http://http://opensoundcontrol.org/spec-1_0)
 * - based on default argument types: i,f,s,b
 * - including widely used extension types: T,F,N,I,h,d,t,S,c,r,m
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/conversation.h>

/* Open Sound Control (OSC) argument types enumeration */
typedef enum _OSC_Type {
    OSC_INT32   = 'i',
    OSC_FLOAT   = 'f',
    OSC_STRING  = 's',
    OSC_BLOB    = 'b',

    OSC_TRUE    = 'T',
    OSC_FALSE   = 'F',
    OSC_NIL     = 'N',
    OSC_BANG    = 'I',

    OSC_INT64   = 'h',
    OSC_DOUBLE  = 'd',
    OSC_TIMETAG = 't',

    OSC_SYMBOL  = 'S',
    OSC_CHAR    = 'c',
    OSC_RGBA    = 'r',
    OSC_MIDI    = 'm'
} OSC_Type;

/* characters not allowed in OSC path string */
static const char invalid_path_chars [] = {
    ' ', '#', '*', ',', '?', '[', ']', '{', '}',
    '\0'
};

/* allowed characters in OSC format string */
static const char valid_format_chars [] = {
    OSC_INT32, OSC_FLOAT, OSC_STRING, OSC_BLOB,
    OSC_TRUE, OSC_FALSE, OSC_NIL, OSC_BANG,
    OSC_INT64, OSC_DOUBLE, OSC_TIMETAG,
    OSC_SYMBOL, OSC_CHAR, OSC_MIDI,
    '\0'
};

/* Standard MIDI Message Type */
typedef enum _MIDI_Status {
    MIDI_MSG_INVALID          = 0x00,
    MIDI_MSG_NOTE_OFF         = 0x80,
    MIDI_MSG_NOTE_ON          = 0x90,
    MIDI_MSG_NOTE_PRESSURE    = 0xA0,
    MIDI_MSG_CONTROLLER       = 0xB0,
    MIDI_MSG_PGM_CHANGE       = 0xC0,
    MIDI_MSG_CHANNEL_PRESSURE = 0xD0,
    MIDI_MSG_BENDER           = 0xE0,
    MIDI_MSG_SYSTEM_EXCLUSIVE = 0xF0,
    MIDI_MSG_MTC_QUARTER      = 0xF1,
    MIDI_MSG_SONG_POS         = 0xF2,
    MIDI_MSG_SONG_SELECT      = 0xF3,
    MIDI_MSG_TUNE_REQUEST     = 0xF6,
    MIDI_MSG_CLOCK            = 0xF8,
    MIDI_MSG_START            = 0xFA,
    MIDI_MSG_CONTINUE         = 0xFB,
    MIDI_MSG_STOP             = 0xFC,
    MIDI_MSG_ACTIVE_SENSE     = 0xFE,
    MIDI_MSG_RESET            = 0xFF 
} MIDI_Status;

/* Standard MIDI Controller Numbers */
typedef enum _MIDI_Control {
    MIDI_CTL_MSB_BANK             = 0x00,
    MIDI_CTL_MSB_MODWHEEL         = 0x01,
    MIDI_CTL_MSB_BREATH           = 0x02,
    MIDI_CTL_MSB_FOOT             = 0x04,
    MIDI_CTL_MSB_PORTAMENTO_TIME  = 0x05,
    MIDI_CTL_MSB_DATA_ENTRY       = 0x06,
    MIDI_CTL_MSB_MAIN_VOLUME      = 0x07,
    MIDI_CTL_MSB_BALANCE          = 0x08,
    MIDI_CTL_MSB_PAN              = 0x0A,
    MIDI_CTL_MSB_EXPRESSION       = 0x0B,
    MIDI_CTL_MSB_EFFECT1          = 0x0C,
    MIDI_CTL_MSB_EFFECT2          = 0x0D,
    MIDI_CTL_MSB_GENERAL_PURPOSE1 = 0x10,
    MIDI_CTL_MSB_GENERAL_PURPOSE2 = 0x11,
    MIDI_CTL_MSB_GENERAL_PURPOSE3 = 0x12,
    MIDI_CTL_MSB_GENERAL_PURPOSE4 = 0x13,
    MIDI_CTL_LSB_BANK             = 0x20,
    MIDI_CTL_LSB_MODWHEEL         = 0x21,
    MIDI_CTL_LSB_BREATH           = 0x22,
    MIDI_CTL_LSB_FOOT             = 0x24,
    MIDI_CTL_LSB_PORTAMENTO_TIME  = 0x25,
    MIDI_CTL_LSB_DATA_ENTRY       = 0x26,
    MIDI_CTL_LSB_MAIN_VOLUME      = 0x27,
    MIDI_CTL_LSB_BALANCE          = 0x28,
    MIDI_CTL_LSB_PAN              = 0x2A,
    MIDI_CTL_LSB_EXPRESSION       = 0x2B,
    MIDI_CTL_LSB_EFFECT1          = 0x2C,
    MIDI_CTL_LSB_EFFECT2          = 0x2D,
    MIDI_CTL_LSB_GENERAL_PURPOSE1 = 0x30,
    MIDI_CTL_LSB_GENERAL_PURPOSE2 = 0x31,
    MIDI_CTL_LSB_GENERAL_PURPOSE3 = 0x32,
    MIDI_CTL_LSB_GENERAL_PURPOSE4 = 0x33,
    MIDI_CTL_SUSTAIN              = 0x40,
    MIDI_CTL_PORTAMENTO           = 0x41,
    MIDI_CTL_SOSTENUTO            = 0x42,
    MIDI_CTL_SOFT_PEDAL           = 0x43,
    MIDI_CTL_LEGATO_FOOTSWITCH    = 0x44,
    MIDI_CTL_HOLD2                = 0x45,
    MIDI_CTL_SC1_SOUND_VARIATION  = 0x46,
    MIDI_CTL_SC2_TIMBRE           = 0x47,
    MIDI_CTL_SC3_RELEASE_TIME     = 0x48,
    MIDI_CTL_SC4_ATTACK_TIME      = 0x49,
    MIDI_CTL_SC5_BRIGHTNESS       = 0x4A,
    MIDI_CTL_SC6                  = 0x4B,
    MIDI_CTL_SC7                  = 0x4C,
    MIDI_CTL_SC8                  = 0x4D,
    MIDI_CTL_SC9                  = 0x4E,
    MIDI_CTL_SC10                 = 0x4F,
    MIDI_CTL_GENERAL_PURPOSE5     = 0x50,
    MIDI_CTL_GENERAL_PURPOSE6     = 0x51,
    MIDI_CTL_GENERAL_PURPOSE7     = 0x52,
    MIDI_CTL_GENERAL_PURPOSE8     = 0x53,
    MIDI_CTL_PORTAMENTO_CONTROL   = 0x54,
    MIDI_CTL_E1_REVERB_DEPTH      = 0x5B,
    MIDI_CTL_E2_TREMOLO_DEPTH     = 0x5C,
    MIDI_CTL_E3_CHORUS_DEPTH      = 0x5D,
    MIDI_CTL_E4_DETUNE_DEPTH      = 0x5E,
    MIDI_CTL_E5_PHASER_DEPTH      = 0x5F,
    MIDI_CTL_DATA_INCREMENT       = 0x60,
    MIDI_CTL_DATA_DECREMENT       = 0x61,
    MIDI_CTL_NRPN_LSB             = 0x62,
    MIDI_CTL_NRPN_MSB             = 0x63,
    MIDI_CTL_RPN_LSB              = 0x64,
    MIDI_CTL_RPN_MSB              = 0x65,
    MIDI_CTL_ALL_SOUNDS_OFF       = 0x78,
    MIDI_CTL_RESET_CONTROLLERS    = 0x79,
    MIDI_CTL_LOCAL_CONTROL_SWITCH = 0x7A,
    MIDI_CTL_ALL_NOTES_OFF        = 0x7B,
    MIDI_CTL_OMNI_OFF             = 0x7C,
    MIDI_CTL_OMNI_ON              = 0x7D,
    MIDI_CTL_MONO1                = 0x7E,
    MIDI_CTL_MONO2                = 0x7F 
} MIDI_Control;

typedef struct _MIDI_Status_Dict {
    MIDI_Status status;
    const char *id;
} MIDI_Status_Dict;

typedef struct _MIDI_Control_Dict {
    MIDI_Control control;
    const char *id;
} MIDI_Control_Dict;

static const MIDI_Status_Dict midi_status_dict [] = {
    {MIDI_MSG_INVALID          , "Invalid Message"},
    {MIDI_MSG_NOTE_OFF         , "Note Off"},
    {MIDI_MSG_NOTE_ON          , "Note On"},
    {MIDI_MSG_NOTE_PRESSURE    , "Note Pressure"},
    {MIDI_MSG_CONTROLLER       , "Controller"},
    {MIDI_MSG_PGM_CHANGE       , "Program Change"},
    {MIDI_MSG_CHANNEL_PRESSURE , "Channel Pressure"},
    {MIDI_MSG_BENDER           , "Pitch Bender"},
    {MIDI_MSG_SYSTEM_EXCLUSIVE , "System Exclusive Begin"},
    {MIDI_MSG_MTC_QUARTER      , "MTC Quarter Frame"},
    {MIDI_MSG_SONG_POS         , "Song Position"},
    {MIDI_MSG_SONG_SELECT      , "Song Select"},
    {MIDI_MSG_TUNE_REQUEST     , "Tune Request"},
    {MIDI_MSG_CLOCK            , "Clock"},
    {MIDI_MSG_START            , "Start"},
    {MIDI_MSG_CONTINUE         , "Continue"},
    {MIDI_MSG_STOP             , "Stop"},
    {MIDI_MSG_ACTIVE_SENSE     , "Active Sensing"},
    {MIDI_MSG_RESET            , "Reset"},
    {0, NULL}
};

static const MIDI_Control_Dict midi_control_dict [] = {
    {MIDI_CTL_MSB_BANK             , "Bank Selection"},
    {MIDI_CTL_MSB_MODWHEEL         , "Modulation"},
    {MIDI_CTL_MSB_BREATH           , "Breath"},
    {MIDI_CTL_MSB_FOOT             , "Foot"},
    {MIDI_CTL_MSB_PORTAMENTO_TIME  , "Portamento Time"},
    {MIDI_CTL_MSB_DATA_ENTRY       , "Data Entry"},
    {MIDI_CTL_MSB_MAIN_VOLUME      , "Main Volume"},
    {MIDI_CTL_MSB_BALANCE          , "Balance"},
    {MIDI_CTL_MSB_PAN              , "Panpot"},
    {MIDI_CTL_MSB_EXPRESSION       , "Expression"},
    {MIDI_CTL_MSB_EFFECT1          , "Effect1"},
    {MIDI_CTL_MSB_EFFECT2          , "Effect2"},
    {MIDI_CTL_MSB_GENERAL_PURPOSE1 , "General Purpose 1"},
    {MIDI_CTL_MSB_GENERAL_PURPOSE2 , "General Purpose 2"},
    {MIDI_CTL_MSB_GENERAL_PURPOSE3 , "General Purpose 3"},
    {MIDI_CTL_MSB_GENERAL_PURPOSE4 , "General Purpose 4"},
    {MIDI_CTL_LSB_BANK             , "Bank Selection"},
    {MIDI_CTL_LSB_MODWHEEL         , "Modulation"},
    {MIDI_CTL_LSB_BREATH           , "Breath"},
    {MIDI_CTL_LSB_FOOT             , "Foot"},
    {MIDI_CTL_LSB_PORTAMENTO_TIME  , "Portamento Time"},
    {MIDI_CTL_LSB_DATA_ENTRY       , "Data Entry"},
    {MIDI_CTL_LSB_MAIN_VOLUME      , "Main Volume"},
    {MIDI_CTL_LSB_BALANCE          , "Balance"},
    {MIDI_CTL_LSB_PAN              , "Panpot"},
    {MIDI_CTL_LSB_EXPRESSION       , "Expression"},
    {MIDI_CTL_LSB_EFFECT1          , "Effect1"},
    {MIDI_CTL_LSB_EFFECT2          , "Effect2"},
    {MIDI_CTL_LSB_GENERAL_PURPOSE1 , "General Purpose 1"},
    {MIDI_CTL_LSB_GENERAL_PURPOSE2 , "General Purpose 2"},
    {MIDI_CTL_LSB_GENERAL_PURPOSE3 , "General Purpose 3"},
    {MIDI_CTL_LSB_GENERAL_PURPOSE4 , "General Purpose 4"},
    {MIDI_CTL_SUSTAIN              , "Sustain Pedal"},
    {MIDI_CTL_PORTAMENTO           , "Portamento"},
    {MIDI_CTL_SOSTENUTO            , "Sostenuto"},
    {MIDI_CTL_SOFT_PEDAL           , "Soft Pedal"},
    {MIDI_CTL_LEGATO_FOOTSWITCH    , "Legato Foot Switch"},
    {MIDI_CTL_HOLD2                , "Hold2"},
    {MIDI_CTL_SC1_SOUND_VARIATION  , "SC1 Sound Variation"},
    {MIDI_CTL_SC2_TIMBRE           , "SC2 Timbre"},
    {MIDI_CTL_SC3_RELEASE_TIME     , "SC3 Release Time"},
    {MIDI_CTL_SC4_ATTACK_TIME      , "SC4 Attack Time"},
    {MIDI_CTL_SC5_BRIGHTNESS       , "SC5 Brightness"},
    {MIDI_CTL_SC6                  , "SC6"},
    {MIDI_CTL_SC7                  , "SC7"},
    {MIDI_CTL_SC8                  , "SC8"},
    {MIDI_CTL_SC9                  , "SC9"},
    {MIDI_CTL_SC10                 , "SC10"},
    {MIDI_CTL_GENERAL_PURPOSE5     , "General Purpose 5"},
    {MIDI_CTL_GENERAL_PURPOSE6     , "General Purpose 6"},
    {MIDI_CTL_GENERAL_PURPOSE7     , "General Purpose 7"},
    {MIDI_CTL_GENERAL_PURPOSE8     , "General Purpose 8"},
    {MIDI_CTL_PORTAMENTO_CONTROL   , "Portamento Control"},
    {MIDI_CTL_E1_REVERB_DEPTH      , "E1 Reverb Depth"},
    {MIDI_CTL_E2_TREMOLO_DEPTH     , "E2 Tremolo Depth"},
    {MIDI_CTL_E3_CHORUS_DEPTH      , "E3 Chorus Depth"},
    {MIDI_CTL_E4_DETUNE_DEPTH      , "E4 Detune Depth"},
    {MIDI_CTL_E5_PHASER_DEPTH      , "E5 Phaser Depth"},
    {MIDI_CTL_DATA_INCREMENT       , "Data Increment"},
    {MIDI_CTL_DATA_DECREMENT       , "Data Decrement"},
    {MIDI_CTL_NRPN_LSB             , "Non-registered Parameter Number"},
    {MIDI_CTL_NRPN_MSB             , "Non-registered Parameter Number"},
    {MIDI_CTL_RPN_LSB              , "Registered Parameter Number"},
    {MIDI_CTL_RPN_MSB              , "Registered Parameter Number"},
    {MIDI_CTL_ALL_SOUNDS_OFF       , "All Sounds Off"},
    {MIDI_CTL_RESET_CONTROLLERS    , "Reset Controllers"},
    {MIDI_CTL_LOCAL_CONTROL_SWITCH , "Local Control Switch"},
    {MIDI_CTL_ALL_NOTES_OFF        , "All Notes Off"},
    {MIDI_CTL_OMNI_OFF             , "Omni Off"},
    {MIDI_CTL_OMNI_ON              , "Omni On"},
    {MIDI_CTL_MONO1                , "Mono1"},
    {MIDI_CTL_MONO2                , "Mono2"},
    {0, NULL}
};

static const char *immediate_str = "Immediate";
static const char *bundle_str = "#bundle";

/* Initialize the protocol and registered fields */
static dissector_handle_t osc_handle = NULL;

static int proto_osc = -1;

static int hf_osc_bundle_type = -1;
static int hf_osc_message_type = -1;
static int hf_osc_message_header_type = -1;
static int hf_osc_message_blob_type = -1;
static int hf_osc_message_midi_type = -1;
static int hf_osc_message_rgba_type = -1;

static int hf_osc_bundle_timetag_type = -1;
static int hf_osc_bundle_element_size_type = -1;

static int hf_osc_message_path_type = -1;
static int hf_osc_message_format_type = -1;

static int hf_osc_message_int32_type = -1;
static int hf_osc_message_float_type = -1;
static int hf_osc_message_string_type = -1;
static int hf_osc_message_blob_size_type = -1;
static int hf_osc_message_blob_data_type = -1;

static int hf_osc_message_true_type = -1;
static int hf_osc_message_false_type = -1;
static int hf_osc_message_nil_type = -1;
static int hf_osc_message_bang_type = -1;

static int hf_osc_message_int64_type = -1;
static int hf_osc_message_double_type = -1;
static int hf_osc_message_timetag_type = -1;

static int hf_osc_message_symbol_type = -1;
static int hf_osc_message_char_type = -1;

static int hf_osc_message_rgba_red_type = -1;
static int hf_osc_message_rgba_green_type = -1;
static int hf_osc_message_rgba_blue_type = -1;
static int hf_osc_message_rgba_alpha_type = -1;

static int hf_osc_message_midi_channel_type = -1;
static int hf_osc_message_midi_status_type = -1;
static int hf_osc_message_midi_data1_type = -1;
static int hf_osc_message_midi_data2_type = -1;

/* Initialize the subtree pointers */
static int ett_osc_packet = -1;
static int ett_osc_bundle = -1;
static int ett_osc_message = -1;
static int ett_osc_message_header = -1;
static int ett_osc_blob = -1;
static int ett_osc_rgba = -1;
static int ett_osc_midi = -1;

/* check for valid path string */
static int
is_valid_path(const char *path)
{
    const char *ptr;
    if(path[0] != '/')
        return 0;
    for(ptr=invalid_path_chars; *ptr!='\0'; ptr++)
        if(strchr(path+1, *ptr) != NULL)
            return 0;
    return 1;
}

/* check for valid format string */
static int
is_valid_format(const char *format)
{
    const char *ptr;
    if(format[0] != ',')
        return 0;
    for(ptr=format+1; *ptr!='\0'; ptr++)
        if(strchr(valid_format_chars, *ptr) == NULL)
            return 0;
    return 1;
}

/* Dissect OSC message */
static int
dissect_osc_message(tvbuff_t *tvb, proto_item *ti, proto_tree *osc_tree, gint offset, gint len)
{
    proto_tree *message_tree = NULL;
    proto_tree *header_tree = NULL;
    gint slen;
    gint rem;
    gint end = offset + len;
    const gchar *path = NULL;
    gint path_len;
    gint path_offset;
    const gchar *format = NULL;
    gint format_offset;
    gint format_len;
    const gchar *ptr = NULL;

    /* peek/read path */
    path_offset = offset;
    path = tvb_get_const_stringz(tvb, path_offset, &path_len);
    if( (rem = path_len%4) ) path_len += 4-rem;

    if(!is_valid_path(path))
        return -1;

    /* peek/read fmt */
    format_offset = path_offset + path_len;
    format = tvb_get_const_stringz(tvb, format_offset, &format_len);
    if( (rem = format_len%4) ) format_len += 4-rem;

    if(!is_valid_format(format))
        return -1;

    /* create message */
    ti = proto_tree_add_none_format(osc_tree, hf_osc_message_type, tvb, offset, len, "Message: %s %s", path, format);
    message_tree = proto_item_add_subtree(ti, ett_osc_message);

    /* append header */
    ti = proto_tree_add_item(message_tree, hf_osc_message_header_type, tvb, offset, path_len+format_len, ENC_BIG_ENDIAN);
    header_tree = proto_item_add_subtree(ti, ett_osc_message_header);

    /* append path */
    proto_tree_add_item(header_tree, hf_osc_message_path_type, tvb, path_offset, path_len, ENC_ASCII);

    /* append format */
    proto_tree_add_item(header_tree, hf_osc_message_format_type, tvb, format_offset, format_len, ENC_ASCII);

    offset += path_len + format_len;

    /* ::parse argument:: */
    ptr = format + 1; /* skip ',' */
    while( (*ptr != '\0') && (offset < end) )
    {
        switch(*ptr)
        {
            case OSC_INT32:
                proto_tree_add_item(message_tree, hf_osc_message_int32_type, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                break;
            case OSC_FLOAT:
                proto_tree_add_item(message_tree, hf_osc_message_float_type, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                break;
            case OSC_STRING:
                slen = tvb_strsize(tvb, offset);
                if( (rem = slen%4) ) slen += 4-rem;
                proto_tree_add_item(message_tree, hf_osc_message_string_type, tvb, offset, slen, ENC_ASCII);
                offset += slen;
                break;
            case OSC_BLOB:
            {
                proto_item *bi = NULL;
                proto_tree *blob_tree = NULL;

                gint32 blen = tvb_get_ntohl(tvb, offset);
                slen = blen;
                if( (rem = slen%4) ) slen += 4-rem;
                
                bi = proto_tree_add_none_format(message_tree, hf_osc_message_blob_type, tvb, offset, 4+slen, "Blob   : %i bytes", blen);
                blob_tree = proto_item_add_subtree(bi, ett_osc_blob);

                proto_tree_add_int_format_value(blob_tree, hf_osc_message_blob_size_type, tvb, offset, 4, blen, "%i bytes", blen);
                offset += 4;

                /* check for zero length blob */
                if(blen == 0)
                    break;

                proto_tree_add_item(blob_tree, hf_osc_message_blob_data_type, tvb, offset, slen, ENC_BIG_ENDIAN);
                offset += slen;
                break;
            }

            case OSC_TRUE:
                proto_tree_add_item(message_tree, hf_osc_message_true_type, tvb, offset, 0, ENC_BIG_ENDIAN);
                break;
            case OSC_FALSE:
                proto_tree_add_item(message_tree, hf_osc_message_false_type, tvb, offset, 0, ENC_BIG_ENDIAN);
                break;
            case OSC_NIL:
                proto_tree_add_item(message_tree, hf_osc_message_nil_type, tvb, offset, 0, ENC_BIG_ENDIAN);
                break;
            case OSC_BANG:
                proto_tree_add_item(message_tree, hf_osc_message_bang_type, tvb, offset, 0, ENC_BIG_ENDIAN);
                break;

            case OSC_INT64:
                proto_tree_add_item(message_tree, hf_osc_message_int64_type, tvb, offset, 8, ENC_BIG_ENDIAN);
                offset += 8;
                break;
            case OSC_DOUBLE:
                proto_tree_add_item(message_tree, hf_osc_message_double_type, tvb, offset, 8, ENC_BIG_ENDIAN);
                offset += 8;
                break;
            case OSC_TIMETAG:
            {
                guint32 sec = tvb_get_ntohl(tvb, offset);
                guint32 frac = tvb_get_ntohl(tvb, offset+4);
                nstime_t ns;
                if( (sec == 0UL) && (frac == 1UL) )
                    proto_tree_add_time_format_value(message_tree, hf_osc_message_timetag_type, tvb, offset, 8, &ns, immediate_str);
                else
                    proto_tree_add_item(message_tree, hf_osc_message_timetag_type, tvb, offset, 8, ENC_TIME_NTP | ENC_BIG_ENDIAN);
                offset += 8;
            }
                break;

            case OSC_SYMBOL:
                slen = tvb_strsize(tvb, offset);
                if( (rem = slen%4) ) slen += 4-rem;
                proto_tree_add_item(message_tree, hf_osc_message_symbol_type, tvb, offset, slen, ENC_ASCII);
                offset += slen;
                break;
            case OSC_CHAR:
                offset += 3;
                proto_tree_add_item(message_tree, hf_osc_message_char_type, tvb, offset, 1, ENC_ASCII);
                offset += 1;
                break;
            case OSC_RGBA:
            {
                proto_item *ri = NULL;
                proto_tree *rgba_tree = NULL;

                ri = proto_tree_add_item(message_tree, hf_osc_message_rgba_type, tvb, offset, 4, ENC_BIG_ENDIAN);
                rgba_tree = proto_item_add_subtree(ri, ett_osc_rgba);

                proto_tree_add_item(rgba_tree, hf_osc_message_rgba_red_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(rgba_tree, hf_osc_message_rgba_green_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(rgba_tree, hf_osc_message_rgba_blue_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(rgba_tree, hf_osc_message_rgba_alpha_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                break;
            }
            case OSC_MIDI:
            {
                const MIDI_Status_Dict *sd = NULL;
                const MIDI_Control_Dict *cd = NULL;
                proto_item *mi = NULL;
                proto_tree *midi_tree = NULL;
                guint8 channel;
                guint8 status;
                guint8 data1;
                guint8 data2;
                
                channel = tvb_get_guint8(tvb, offset);
                status = tvb_get_guint8(tvb, offset+1);
                data1 = tvb_get_guint8(tvb, offset+2);
                data2 = tvb_get_guint8(tvb, offset+3);

                for(sd = midi_status_dict; sd->id != NULL; sd++)
                    if(sd->status == status)
                        break;
                        
                if(status == MIDI_MSG_CONTROLLER)
                {
                    for(cd = midi_control_dict; cd->id != NULL; cd++)
                        if(cd->control == data1)
                            break;

                    mi = proto_tree_add_none_format(message_tree, hf_osc_message_midi_type, tvb, offset, 4,
                            "MIDI   : Channel %2i, %s (0x%02X), %s (0x%02X), 0x%02X",
                            channel,
                            sd->id, status,
                            cd->id, data1,
                            data2);
                }
                else
                    mi = proto_tree_add_none_format(message_tree, hf_osc_message_midi_type, tvb, offset, 4,
                            "MIDI   : Channel %2i, %s (0x%02X), 0x%02X, 0x%02X",
                            channel,
                            sd->id, status,
                            data1, data2);
                midi_tree = proto_item_add_subtree(mi, ett_osc_midi);

                proto_tree_add_item(midi_tree, hf_osc_message_midi_channel_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                if(sd && sd->id)
                    proto_tree_add_uint_format_value(midi_tree, hf_osc_message_midi_status_type, tvb, offset, 1, status, "%s (0x%02X)", sd->id, status);
                else
                    proto_tree_add_item(midi_tree, hf_osc_message_midi_status_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                if(cd && cd->id)
                    proto_tree_add_uint_format_value(midi_tree, hf_osc_message_midi_data1_type, tvb, offset, 1, data1, "%s (0x%02X)", cd->id, data1);
                else
                    proto_tree_add_item(midi_tree, hf_osc_message_midi_data1_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                proto_tree_add_item(midi_tree, hf_osc_message_midi_data2_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                break;
            }

            default:
                /* if we get here, there must be a bug in the dissector  */
                DISSECTOR_ASSERT(0);
                break;
        }
        ptr++;
    }

    if(offset != end)
        return -1;
    else
        return 0;
}

/* Dissect OSC bundle */
static int
dissect_osc_bundle(tvbuff_t *tvb, proto_item *ti, proto_tree *osc_tree, gint offset, gint len)
{
    const gchar *str;
    proto_tree *bundle_tree = NULL;
    gint end = offset + len;

    /* check for valid #bundle */
    str = tvb_get_const_stringz(tvb, offset, NULL);
    if(strncmp(str, bundle_str, 8)) /* no OSC bundle */
        return -1;

    /* create bundle */
    ti = proto_tree_add_item(osc_tree, hf_osc_bundle_type, tvb, offset, len, ENC_BIG_ENDIAN);
    bundle_tree = proto_item_add_subtree(ti, ett_osc_bundle);

    offset += 8; /* skip bundle_str */

    /* read timetag */
    guint32 sec = tvb_get_ntohl(tvb, offset);
    guint32 frac = tvb_get_ntohl(tvb, offset+4);
    nstime_t ns;
    if( (sec == 0UL) && (frac == 1UL) )
        proto_tree_add_time_format_value(bundle_tree, hf_osc_bundle_timetag_type, tvb, offset, 8, &ns, immediate_str);
    else
        proto_tree_add_item(bundle_tree, hf_osc_bundle_timetag_type, tvb, offset, 8, ENC_TIME_NTP | ENC_BIG_ENDIAN);
    offset += 8;

    /* ::read size, read block:: */
    while(offset < end)
    {
        /* peek bundle element size */
        gint32 size = tvb_get_ntohl(tvb, offset);

        /* read bundle element size */
        proto_tree_add_int_format_value(bundle_tree, hf_osc_bundle_element_size_type, tvb, offset, 4, size, "%i bytes", size);
        offset += 4;

        /* check for zero size bundle element */
        if(size == 0)
            continue;

        /* peek first bundle element char */
        switch(tvb_get_guint8(tvb, offset))
        {
            case '#': /* this is a bundle */
                if(dissect_osc_bundle(tvb, ti, bundle_tree, offset, size))
                    return -1;
                else
                    break;
            case '/': /* this is a message */
                if(dissect_osc_message(tvb, ti, bundle_tree, offset, size))
                    return -1;
                else
                    break;
            default:
                return -1; /* neither message nor bundle */
        }
        offset += size;
    }

    if(offset != end)
        return -1;
    else
        return 0;
}

/* Dissect OSC packet */
static void
dissect_osc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OSC");
    /* clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    if(tree) /* we are being asked for details */
    {
        gint len;
        proto_item *ti = NULL;
        proto_tree *osc_tree = NULL;

        /* create OSC packet */
        ti = proto_tree_add_item(tree, proto_osc, tvb, 0, -1, ENC_NA);
        osc_tree = proto_item_add_subtree(ti, ett_osc_packet);
        len = proto_item_get_len(ti);

        /* peek first bundle element char */
        switch(tvb_get_guint8(tvb, offset))
        {
            case '#': /* this is a bundle */
                if(dissect_osc_bundle(tvb, ti, osc_tree, offset, len))
                    return;
                else
                    break;
            case '/': /* this is a message */
                if(dissect_osc_message(tvb, ti, osc_tree, offset, len))
                    return;
                else
                    break;
            default: /* neither message nor bundle */
                return;
        }
    }
}

/* OSC heuristics */
static gboolean
dissect_osc_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint offset = 0;
    gint slen;
    gint rem;
    const gchar *str = NULL;
    conversation_t *conversation = NULL;

    /* peek first string */
    str = tvb_get_const_stringz(tvb, offset, &slen);
    if(strncmp(str, bundle_str, 8) != 0) /* no OSC bundle */
    {
        /* check for valid path */
        if(!is_valid_path(str))
            return FALSE;

        /* skip path */
        if( (rem = slen%4) ) slen += 4-rem;
        offset += slen;

        /* peek next string */
        str = tvb_get_const_stringz(tvb, offset, &slen);

        /* check for valid format */
        if(!is_valid_format(str))
            return FALSE;
    }

    /* if we get here, then it's an Open Sound Control packet (bundle or message) */

    /* specify that dissect_osc is to be called directly from now on for packets for this connection */
    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, osc_handle);

    /* do the dissection */
    dissect_osc(tvb, pinfo, tree);

    return TRUE; /* OSC heuristics was matched */
}

/* Register the protocol with Wireshark */
void
proto_register_osc(void)
{
    static hf_register_info hf[] = {
        { &hf_osc_bundle_type, { "Bundle ", "osc.bundle",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                "Bundle", HFILL } },
        { &hf_osc_bundle_timetag_type, { "Timetag", "osc.bundle.timetag",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC,
                NULL, 0x0,
                "Scheduled bundle execution time", HFILL } },

        { &hf_osc_bundle_element_size_type, { "Size   ", "osc.bundle.element.size",
                FT_INT32, BASE_DEC,
                NULL, 0x0,
                "Bundle element size", HFILL } },

        { &hf_osc_message_type, { "Message", "osc.message",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                "Message", HFILL } },
        { &hf_osc_message_header_type, { "Header ", "osc.message.header",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                "Message header", HFILL } },
        { &hf_osc_message_path_type, { "Path  ", "osc.message.header.path",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                "Message path", HFILL } },
        { &hf_osc_message_format_type, { "Format", "osc.message.header.format",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                "Message format", HFILL } },

        { &hf_osc_message_int32_type, { "Int32  ", "osc.message.int32",
                FT_INT32, BASE_DEC,
                NULL, 0x0,
                "32bit integer value", HFILL } },
        { &hf_osc_message_float_type, { "Float  ", "osc.message.float",
                FT_FLOAT, BASE_NONE,
                NULL, 0x0,
                "Floating point value", HFILL } },
        { &hf_osc_message_string_type, { "String ", "osc.message.string",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                "String value", HFILL } },

        { &hf_osc_message_blob_type, { "Blob   ", "osc.message.blob",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                "Binary blob value", HFILL } },
        { &hf_osc_message_blob_size_type, { "Size", "osc.message.blob.size",
                FT_INT32, BASE_DEC,
                NULL, 0x0,
                "Binary blob size", HFILL } },
        { &hf_osc_message_blob_data_type, { "Data", "osc.message.blob.data",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                "Binary blob data", HFILL } },

        { &hf_osc_message_true_type, { "True   ", "osc.message.true",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                "Boolean true value", HFILL } },
        { &hf_osc_message_false_type, { "False  ", "osc.message.false",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                "Boolean false value", HFILL } },
        { &hf_osc_message_nil_type, { "Nil    ", "osc.message.nil",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                "Nil value", HFILL } },
        { &hf_osc_message_bang_type, { "Bang   ", "osc.message.bang",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                "Infinity, Impulse or Bang value", HFILL } },

        { &hf_osc_message_int64_type, { "Int64  ", "osc.message.int64",
                FT_INT64, BASE_DEC,
                NULL, 0x0,
                "64bit integer value", HFILL } },
        { &hf_osc_message_double_type, { "Double ", "osc.message.double",
                FT_DOUBLE, BASE_NONE,
                NULL, 0x0,
                "Double value", HFILL } },
        { &hf_osc_message_timetag_type, { "Timetag", "osc.message.timetag",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC,
                NULL, 0x0,
                "NTP time value", HFILL } },

        { &hf_osc_message_symbol_type, { "Symbol ", "osc.message.symbol",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                "Symbol value", HFILL } },
        { &hf_osc_message_char_type, { "Char   ", "osc.message.char",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                "Character value", HFILL } },

        { &hf_osc_message_rgba_type, { "RGBA   ", "osc.message.rgba",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                "RGBA color value", HFILL } },
        { &hf_osc_message_rgba_red_type, { "Red  ", "osc.message.rgba.red",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                "Red color component", HFILL } },
        { &hf_osc_message_rgba_green_type, { "Green", "osc.message.rgba.green",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                "Green color component", HFILL } },
        { &hf_osc_message_rgba_blue_type, { "Blue ", "osc.message.rgba.blue",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                "Blue color component", HFILL } },
        { &hf_osc_message_rgba_alpha_type, { "Alpha", "osc.message.rgba.alpha",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                "Alpha transparency component", HFILL } },

        { &hf_osc_message_midi_type, { "MIDI   ", "osc.message.midi",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                "MIDI value", HFILL } },
        { &hf_osc_message_midi_channel_type, { "Channel", "osc.message.midi.channel",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                "MIDI channel", HFILL } },
        { &hf_osc_message_midi_status_type, { "Status ", "osc.message.midi.status",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                "MIDI status message", HFILL } },
        { &hf_osc_message_midi_data1_type, { "Data1  ", "osc.message.midi.data1",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                "MIDI data value 1", HFILL } },
        { &hf_osc_message_midi_data2_type, { "Data2  ", "osc.message.midi.data2",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                "MIDI data value 2", HFILL } }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_osc_packet,
        &ett_osc_bundle,
        &ett_osc_message,
        &ett_osc_message_header,
        &ett_osc_blob,
        &ett_osc_rgba,
        &ett_osc_midi
    };

    proto_osc = proto_register_protocol("Open Sound Control Protocol", "OSC", "osc");

    proto_register_field_array(proto_osc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_osc(void)
{
    osc_handle = create_dissector_handle(dissect_osc, proto_osc);

    /* register as heuristic dissector for TCP and UDP connections */
    heur_dissector_add("tcp", dissect_osc_heur, proto_osc);
    heur_dissector_add("udp", dissect_osc_heur, proto_osc);
}

#define AS_PLUGIN
#ifdef AS_PLUGIN
gchar *version = "0.3.0";

void
plugin_register(void)
{
    proto_register_osc();
}

void
plugin_reg_handoff(void)
{
    proto_reg_handoff_osc();
}
#endif

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
