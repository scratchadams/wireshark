#include "config.h"
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/conversation_filter.h>
#include <epan/conversation_table.h>
#include <epan/follow.h>
#include <epan/to_str.h>
#include <epan/addr_resolv.h>
#include <epan/capture_dissectors.h>
#include <epan/exported_pdu.h>

#define ICMP_PROTO 1

static int proto_muhproto = -1;
static dissector_handle_t muh_handle;

static int muh_follow_tap = -1;
static int exported_pdu_tap = -1;

static int hf_muh_data1 = -1;
static int hf_muh_data2 = -1;
static int hf_muh_data3 = -1;
static int hf_muh_stream = -1;

static gint ett_muhproto = -1;

static guint muh_stream_count = 0;

/*static const value_string pkttypes[] = {
    {1, "Initialise"},
    {2, "Terminate"},
    {3, "Data" },
    {0, NULL}
};*/

typedef struct _e_muhhdr {
    guint8 uh_data1;
    guint8 uh_data2;
    guint8 uh_data3;
    guint32 uh_stream;
    guint16 uh_sport;
    guint16 uh_dport;
    address ip_src;
    address ip_dst;
} e_muhhdr;

typedef struct _muh_flow_t {
    guint32 process_uid;
    guint32 process_pid;
    gchar *username;
    gchar *command;
} muh_flow_t;

struct muhproto_analysis {
    muh_flow_t flow1;
    muh_flow_t flow2;

    muh_flow_t *fwd;
    muh_flow_t *rev;

    guint32 stream;

    nstime_t ts_first;
    nstime_t ts_prev;
};

/*
static gboolean muh_filter_valid(packet_info *pinfo) {
    return proto_is_frame_protocol(pinfo->layers, "muhproto");
}
*/

/*
static gchar* muh_build_filter(packet_info *pinfo) {
    if(pinfo->net_src.type == AT_IPv4 && pinfo->net_dst.type == AT_IPv4) {
        return ws_strdup_printf("(ip.addr eq %s and ip.addr eq %s)",
                    address_to_str(pinfo->pool, &pinfo->net_src),
                    address_to_str(pinfo->pool, &pinfo->net_dst));
   }

   return NULL;
}
*/

static struct muhproto_analysis *
init_muhproto_conversation_data(packet_info *pinfo) {
    
    struct muhproto_analysis *muhprotod;

    muhprotod = wmem_new0(wmem_file_scope(), struct muhproto_analysis);

    muhprotod->stream = muh_stream_count++;
    muhprotod->ts_first = pinfo->abs_ts;
    muhprotod->ts_prev = pinfo->abs_ts;

    return muhprotod;
}

struct muhproto_analysis *
get_muh_conversation_data(conversation_t *conv, packet_info *pinfo) {
    printf("get_muh_conversation_data() triggered\n");
    printf("pinfo->net_src: %s\n", address_to_str(pinfo->pool, &pinfo->net_src));

    struct muhproto_analysis *muhprotod = NULL;

    if (conv == NULL) {
        conv = find_or_create_conversation(pinfo);
        printf("conv was NULL\n");
    }

    muhprotod = conversation_get_proto_data(conv, proto_muhproto);

    if (!muhprotod) {
        printf("conversation created\n");
        muhprotod = init_muhproto_conversation_data(pinfo);
        conversation_add_proto_data(conv, proto_muhproto, muhprotod);
    }

    if (!muhprotod) {
        return NULL;
    }

    muhprotod->fwd = &(muhprotod->flow1);
    muhprotod->rev = &(muhprotod->flow2);

    return muhprotod;
}

static gchar *muhproto_follow_conv_filter(epan_dissect_t *edt _U_, packet_info *pinfo,
    guint *stream, guint *sub_stream _U_) {

    printf("muhproto_follow_conv_filter() triggered\n");

    conversation_t *conv;
    struct muhproto_analysis *muhprotod;

    if((pinfo->net_src.type = AT_IPv4 && pinfo->net_dst.type == AT_IPv4) &&
        (conv = find_conversation_pinfo(pinfo, 0)) != NULL) {

        muhprotod = get_muh_conversation_data(conv, pinfo); 
        if(muhprotod == NULL)
            return NULL;

        *stream = muhprotod->stream;
        return ws_strdup_printf("muhproto.stream eq %u", muhprotod->stream);

    }

    return NULL;

}

static gchar *muhproto_follow_index_filter(guint stream, guint sub_stream _U_) {
    printf("muhproto_follow_index_filter() triggered\n");

    return ws_strdup_printf("muhproto.stream eq %u", stream);
}

static gchar *muhproto_follow_address_filter(address *src_addr, address *dst_addr, int src_port, int dst_port) {
    const gchar *ip_version = src_addr->type == AT_IPv6 ? "v6" : "";

    gchar src_addr_str[WS_INET6_ADDRSTRLEN];
    gchar dst_addr_str[WS_INET6_ADDRSTRLEN];

    address_to_str_buf(src_addr, src_addr_str, sizeof(src_addr_str));
    address_to_str_buf(dst_addr, dst_addr_str, sizeof(dst_addr_str));
    
    printf("muhproto_follow_address_filter() triggered\n");
    
    return ws_strdup_printf("((ip%s.src eq %s and muhproto.srcport eq %d) and "
                     "(ip%s.dst eq %s and muhproto.dstport eq %d))"
                     " or "
                     "((ip%s.src eq %s and muhproto.srcport eq %d) and "
                     "(ip%s.dst eq %s and muhproto.dstport eq %d))",
                     ip_version, src_addr_str, src_port,
                     ip_version, dst_addr_str, dst_port,
                     ip_version, dst_addr_str, dst_port,
                     ip_version, src_addr_str, src_port);
}

/*
static const char* muh_host_get_filter_type(hostlist_talker_t* host, conv_filter_type_e filter) {
    printf("muh_host_get_filter_type() triggered\n");

    if(host && filter)
        return "ip.src";

    return CONV_FILTER_INVALID;
}
*/

//static hostlist_dissector_info_t muh_host_dissector_info = {&muh_host_get_filter_type};

/*static tap_packet_status
muh_hostlist_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip) {

    printf("muh_hostlist_packet() triggered\n");

    conv_hash_t *hash = (conv_hash_t*) pit;
    const e_muhhdr *muhhdr=(const e_muhhdr *)vip;

    add_hostlist_table_data(hash, &muhhdr->ip_src, muhhdr->uh_sport, 
        TRUE, 1, pinfo->fd->pkt_len, &muh_host_dissector_info, ENDPOINT_MUH);
    add_hostlist_table_data(hash, &muhhdr->ip_dst, muhhdr->uh_dport, 
        FALSE, 1, pinfo->fd->pkt_len, &muh_host_dissector_info, ENDPOINT_MUH);

    return TAP_PACKET_REDRAW;
}
*/

/*
static const char* muh_conv_get_filter_type(conv_item_t* conv, conv_filter_type_e filter) {
    printf("muh_conv_get_filter_type() triggered\n");

    if (filter && conv)
        return "ip.src";

    return CONV_FILTER_INVALID;
}
*/
//static ct_dissector_info_t muh_ct_dissector_info = {&muh_conv_get_filter_type};

static int
dissect_muhproto(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    int offset = 1;
    proto_item *item;
    conversation_t *conv = NULL;
    struct muhproto_analysis *muhprotod = NULL;

    e_muhhdr *muhh;

    muhh = wmem_new0(pinfo->pool, e_muhhdr);
    copy_address_shallow(&muhh->ip_src, &pinfo->src);
    copy_address_shallow(&muhh->ip_dst, &pinfo->dst);
    
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MUHPROTO");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_muhproto, tvb, 0, -1, ENC_NA);
    proto_tree *muh_tree = proto_item_add_subtree(ti, ett_muhproto);

    proto_tree_add_item(muh_tree, hf_muh_data1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 3;

    proto_tree_add_item(muh_tree, hf_muh_data2, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(muh_tree, hf_muh_data3, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    
    conv = find_or_create_conversation(pinfo);
    muhprotod = get_muh_conversation_data(conv, pinfo);

    if(muhprotod) {
        item = proto_tree_add_uint(muh_tree, hf_muh_stream, tvb, offset, 0, muhprotod->stream);
        proto_item_set_generated(item);

        printf("added muhproto stream item\n");
        muhh->uh_stream = muhprotod->stream;
    }
    
    tap_queue_packet(muh_follow_tap, pinfo, tvb);

    if(have_tap_listener(muh_follow_tap)) {
        printf("yes we have tap listener\n");
    }

    return tvb_captured_length(tvb);
}

/*
static tap_packet_status
muh_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip) {
    conv_hash_t *hash = (conv_hash_t*) pct;
    const e_muhhdr *muhhdr=(const e_muhhdr *)vip;

    printf("muh_conversation_packet() triggered\n");

    add_conversation_table_data_with_conv_id(hash,
        &muhhdr->ip_src, &muhhdr->ip_dst, 0, 0,
        (conv_id_t) muhhdr->uh_stream, 1, pinfo->fd->pkt_len, &pinfo->rel_ts, &pinfo->abs_ts,
        &muh_ct_dissector_info, ENDPOINT_MUH);

    return TAP_PACKET_REDRAW;
}
*/

static void muh_init(void) {
    muh_stream_count = 0;
}
/*
static gboolean capture_muh(const guchar *pd _U_, int offset _U_, int len _U_, 
    capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_) {
    
    if(!BYTES_ARE_IN_FRAME(offset, len, 4))
        return FALSE;

    capture_dissector_increment_count(cpinfo, proto_muhproto);

    return TRUE;
}
*/
void
proto_register_muhproto(void) {

    static hf_register_info hf[] = {
        { &hf_muh_data1,
            { "MuhProto Data 1", "muhproto.data1",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_muh_data2,
            { "MuhProto Data 2", "muhproto.data2",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_muh_data3,
            { "MuhProto Data 3", "muhproto.data3",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_muh_stream,
            { "Stream index", "muhproto.stream",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_muhproto
    };

    proto_muhproto = proto_register_protocol(
        "MUHPROTO",
        "MUHPROTO",
        "muhproto"
    );

    proto_register_field_array(proto_muhproto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    
    muh_handle = register_dissector("muhproto", dissect_muhproto, proto_muhproto);
    //register_capture_dissector_table("muhproto", "MUHPROTO");

    //register_conversation_table(proto_muhproto, FALSE, muh_conversation_packet, muh_hostlist_packet);
    //register_conversation_filter("muhproto", "MUHPROTO", muh_filter_valid, muh_build_filter);
    register_follow_stream(proto_muhproto, "muhproto_follow", muhproto_follow_conv_filter,
        muhproto_follow_index_filter, muhproto_follow_address_filter, udp_port_to_display, follow_tvb_tap_listener);

     register_init_routine(muh_init);
}

gboolean capture_muhproto(const guchar *pd _U_, int offset _U_, int len _U_, capture_packet_info_t *cpinfo,
    const union wtap_pseudo_header *pseudo_header _U_) {

    capture_dissector_increment_count(cpinfo, proto_muhproto);
    return TRUE;
}

void
proto_reg_handoff_muhproto(void) {
    capture_dissector_handle_t muh_cap_handle;

    printf("proto_reg_handoff_muhproto() triggered\n");
    
    dissector_add_uint("ip.proto", ICMP_PROTO, muh_handle);

    muh_follow_tap = register_tap("muhproto_follow");
    exported_pdu_tap = find_tap_id(EXPORT_PDU_TAP_NAME_LAYER_3);

    muh_cap_handle = create_capture_dissector_handle(capture_muhproto, proto_muhproto);
    capture_dissector_add_uint("ip.proto", ICMP_PROTO, muh_cap_handle);

}
