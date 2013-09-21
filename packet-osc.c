/*
 * Copyright (c) 2013 Hanspeter Portner (dev@open-music-kontrollers.ch)
 * 
 * This software is provided 'as-is', without any express or implied
 * warranty. In no event will the authors be held liable for any damages
 * arising from the use of this software.
 * 
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 * 
 *     1. The origin of this software must not be misrepresented; you must not
 *     claim that you wrote the original software. If you use this software
 *     in a product, an acknowledgment in the product documentation would be
 *     appreciated but is not required.
 * 
 *     2. Altered source versions must be plainly marked as such, and must not be
 *     misrepresented as being the original software.
 * 
 *     3. This notice may not be removed or altered from any source
 *     distribution.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <config.h>
#include <epan/packet.h>
#include <epan/conversation.h>

gchar version [30] = "0.2";

static dissector_handle_t osc_handle = NULL;

static int proto_osc = -1;

static int ett_osc_packet = -1;
static int ett_osc_bundle = -1;
static int ett_osc_bundle_element = -1;
static int ett_osc_message = -1;
static int ett_osc_blob = -1;

static int hf_osc_bundle_type = -1;
static int hf_osc_bundle_element_type = -1;
static int hf_osc_message_type = -1;
static int hf_osc_message_blob_type = -1;

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
static int hf_osc_message_rgba_type = -1;
static int hf_osc_message_midi_type = -1;

static void
dissect_osc_message(tvbuff_t *tvb, proto_item *ti, proto_tree *osc_tree, gint offset, gint len)
{
	proto_tree *message_tree = NULL;

	// create message
	ti = proto_tree_add_item(osc_tree, hf_osc_message_type, tvb, offset, len, ENC_BIG_ENDIAN);
	message_tree = proto_item_add_subtree(ti, ett_osc_message);

	gint end = offset + len;
	gint slen;
	gint rem;

	// peek/read path
	guint8 *path = tvb_get_ephemeral_stringz(tvb, offset, &slen);
	if(rem = slen%4) slen += 4-rem;
	proto_tree_add_item(message_tree, hf_osc_message_path_type, tvb, offset, slen, ENC_ASCII);
	offset += slen;

	// TODO check for valid path

	// peek/read fmt
	guint8 *format = tvb_get_ephemeral_stringz(tvb, offset, &slen);
	if(rem = slen%4) slen += 4-rem;
	proto_tree_add_item(message_tree, hf_osc_message_format_type, tvb, offset, slen, ENC_ASCII);
	offset += slen;

	// TODO check for valid format

	// ::parse argument::
	guint8 *ptr = format+1; // skip ','
	while( (*ptr != '\0') && (offset < end) )
	{
		switch(*ptr)
		{
			case 'i':
				proto_tree_add_item(message_tree, hf_osc_message_int32_type, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				break;
			case 'f':
				proto_tree_add_item(message_tree, hf_osc_message_float_type, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				break;
			case 's':
				{
					guint8 *s = tvb_get_ephemeral_stringz(tvb, offset, &slen);
					if(rem = slen%4) slen += 4-rem;
					proto_tree_add_item(message_tree, hf_osc_message_string_type, tvb, offset, slen, ENC_ASCII);
					offset += slen;
				}
				break;
			case 'b':
			{
				proto_item *bi = NULL;
				proto_tree *blob_tree = NULL;
				bi = proto_tree_add_item(message_tree, hf_osc_message_blob_type, tvb, offset, len, ENC_BIG_ENDIAN);
				blob_tree = proto_item_add_subtree(bi, ett_osc_blob);

				gint32 bloblen = tvb_get_ntohl(tvb, offset);
				proto_tree_add_item(blob_tree, hf_osc_message_blob_size_type, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(blob_tree, hf_osc_message_blob_data_type, tvb, offset, bloblen, ENC_BIG_ENDIAN);
				offset += bloblen;
				break;
			}

			case 'T':
				proto_tree_add_item(message_tree, hf_osc_message_true_type, tvb, offset, 0, ENC_BIG_ENDIAN);
				break;
			case 'F':
				proto_tree_add_item(message_tree, hf_osc_message_false_type, tvb, offset, 0, ENC_BIG_ENDIAN);
				break;
			case 'N':
				proto_tree_add_item(message_tree, hf_osc_message_nil_type, tvb, offset, 0, ENC_BIG_ENDIAN);
				break;
			case 'I':
				proto_tree_add_item(message_tree, hf_osc_message_bang_type, tvb, offset, 0, ENC_BIG_ENDIAN);
				break;

			case 'h':
				proto_tree_add_item(message_tree, hf_osc_message_int64_type, tvb, offset, 8, ENC_BIG_ENDIAN);
				offset += 8;
				break;
			case 'd':
				proto_tree_add_item(message_tree, hf_osc_message_double_type, tvb, offset, 8, ENC_BIG_ENDIAN);
				offset += 8;
				break;
			case 't':
				proto_tree_add_item(message_tree, hf_osc_message_timetag_type, tvb, offset, 8, ENC_BIG_ENDIAN);
				offset += 8;
				break;

			case 'S':
				{
					guint8 *s = tvb_get_ephemeral_stringz(tvb, offset, &slen);
					if(rem = slen%4) slen += 4-rem;
					proto_tree_add_item(message_tree, hf_osc_message_symbol_type, tvb, offset, slen, ENC_ASCII);
					offset += slen;
				}
				break;
			case 'c':
					offset += 3;
					proto_tree_add_item(message_tree, hf_osc_message_char_type, tvb, offset, 1, ENC_ASCII);
					offset += 1;
				break;
			case 'r':
					proto_tree_add_item(message_tree, hf_osc_message_rgba_type, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
				break;
			case 'm':
					proto_tree_add_item(message_tree, hf_osc_message_midi_type, tvb, offset, 4, ENC_ASCII);
					offset += 4;
				break;

			case '[':
				// TODO begin of array
				break;
			case ']':
				// TODO end of array
				break;

			default:
				// TODO we should never get here
				break;
		}
		ptr++;
	}
}

static void
dissect_osc_bundle(tvbuff_t *tvb, proto_item *ti, proto_tree *osc_tree, gint offset, gint len)
{
	proto_tree *bundle_tree = NULL;

	// create bundle
	ti = proto_tree_add_item(osc_tree, hf_osc_bundle_type, tvb, offset, len, ENC_BIG_ENDIAN);
	bundle_tree = proto_item_add_subtree(ti, ett_osc_bundle);

	gint end = offset + len;

	// skip #bundle
	offset += 8;

	// read timetag
	proto_tree_add_item(bundle_tree, hf_osc_bundle_timetag_type, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	// ::read size, read block::
	while(offset < end)
	{
		proto_tree *element_tree = NULL;

		// peek bundle element size
		gint32 size = tvb_get_ntohl(tvb, offset);

		// create bundle element
		ti = proto_tree_add_item(bundle_tree, hf_osc_bundle_element_type, tvb, offset, size+4, ENC_BIG_ENDIAN);
		element_tree = proto_item_add_subtree(ti, ett_osc_bundle_element);

		// read bundle element size
		proto_tree_add_item(element_tree, hf_osc_bundle_element_size_type, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		// peek first bundle element char
		guint8 ch = tvb_get_guint8(tvb, offset);
		switch(ch)
		{
			case '#': // this is a bundle
				dissect_osc_bundle(tvb, ti, element_tree, offset, size);
				break;
			case '/': // this is a message
				dissect_osc_message(tvb, ti, element_tree, offset, size);
				break;
			default:
				// TODO we should never get here
				break;
		}
		offset += size;
	}
}

static void
dissect_osc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint offset = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "OSC");
	// clear out stuff in the info column
	col_clear(pinfo->cinfo,COL_INFO);

	if (tree) // we are being asked for details
	{
		proto_item *ti = NULL;
		proto_tree *osc_tree = NULL;

		// create OSC packet
		ti = proto_tree_add_item(tree, proto_osc, tvb, 0, -1, ENC_NA);
		osc_tree = proto_item_add_subtree(ti, ett_osc_packet);
		int len = proto_item_get_len(ti);

		// peek first bundle element char
		guint8 ch = tvb_get_guint8(tvb, offset);
		switch(ch)
		{
			case '#': // this is a bundle
				dissect_osc_bundle(tvb, ti, osc_tree, offset, len);
				break;
			case '/': // this is a message
				dissect_osc_message(tvb, ti, osc_tree, offset, len);
				break;
		}
	}
}

static gboolean
dissect_osc_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	gint offset = 0;
	gint slen;
	gint rem;
	guint8 *str;

	// peek first string
	str = tvb_get_ephemeral_stringz(tvb, offset, &slen);
	if(strcmp(str, "#bundle") != 0) // no OSC bundle
	{
		// check whether it's a path
		if(str[0] != '/')
			return FALSE; // OSC heuristics was NOT matched

		// TODO check for valid path

		// skip path
		if(rem = slen%4) slen += 4-rem;
		offset += slen;

		// peek next string
		str = tvb_get_ephemeral_stringz(tvb, offset, &slen);

		// check whether it's a format
		if(str[0] != ',')
			return FALSE; // OSC heuristics was NOT matched

		// TODO check for valid arguments
	}

	// if we get here, then it's an Open Sound Control packet (bundle or message)

	// specify that dissect_osc is to be called directly from now on for packets for this connection
	conversation_t *conversation = NULL;
	conversation = find_or_create_conversation(pinfo);
	conversation_set_dissector(conversation, osc_handle);

	// do the dissection
	dissect_osc(tvb, pinfo, tree);

	return TRUE; // OSC heuristics was matched
}

void
plugin_register(void)
{
	static hf_register_info hf[] = {
		{ &hf_osc_bundle_type, { "bundle", "osc.bundle",
			FT_NONE, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_osc_bundle_timetag_type, { "timetag", "osc.bundle.timetag",
			FT_UINT64, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_osc_bundle_element_type, { "element", "osc.bundle.element",
			FT_NONE, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_osc_bundle_element_size_type, { "size", "osc.bundle.element.size",
			FT_INT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_osc_message_type, { "message", "osc.message",
			FT_NONE, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_osc_message_path_type, { "path   ", "osc.message.path",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_osc_message_format_type, { "format ", "osc.message.format",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_osc_message_int32_type, { "int32  ", "osc.message.int32",
			FT_INT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_osc_message_float_type, { "float  ", "osc.message.float",
			FT_FLOAT, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_osc_message_string_type, { "string ", "osc.message.string",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_osc_message_blob_type, { "blob   ", "osc.message.blob",
			FT_NONE, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_osc_message_blob_size_type, { "size", "osc.message.blob.size",
			FT_INT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_osc_message_blob_data_type, { "data", "osc.message.blob.data",
			FT_BYTES, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_osc_message_true_type, { "true   ", "osc.message.true",
			FT_NONE, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_osc_message_false_type, { "false  ", "osc.message.false",
			FT_NONE, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_osc_message_nil_type, { "nil    ", "osc.message.nil",
			FT_NONE, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_osc_message_bang_type, { "bang   ", "osc.message.bang",
			FT_NONE, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_osc_message_int64_type, { "int64  ", "osc.message.int64",
			FT_INT64, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_osc_message_double_type, { "double ", "osc.message.double",
			FT_DOUBLE, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_osc_message_timetag_type, { "timetag", "osc.message.timetag",
			FT_UINT64, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_osc_message_symbol_type, { "symbol ", "osc.message.symbol",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_osc_message_char_type, { "char   ", "osc.message.char",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_osc_message_rgba_type, { "rgba   ", "osc.message.rgba",
			FT_UINT32, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_osc_message_midi_type, { "midi   ", "osc.message.midi",
			FT_BYTES, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
	};
	
	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_osc_packet,
		&ett_osc_bundle,
		&ett_osc_bundle_element,
		&ett_osc_message,
		&ett_osc_blob,
	};

	proto_osc = proto_register_protocol(
		"Open Sound Control Protocol",	// long name
		"OSC",													// short name
		"osc"														// abbreviation
	);
	
	proto_register_field_array(proto_osc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
plugin_reg_handoff(void)
{
	osc_handle = create_dissector_handle(dissect_osc, proto_osc);

	// register as heuristic dissector for TCP and UDP connections
	heur_dissector_add("tcp", dissect_osc_heur, proto_osc);
	heur_dissector_add("udp", dissect_osc_heur, proto_osc);
}
