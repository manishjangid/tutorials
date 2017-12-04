/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV6 = 0x86DD;
const bit<8>  IPV6_HOP_BY_HOP = 0;
const bit<8> IPV6_OPTION_IOAM_TRACE_TYPE = 6;
const bit<8> HBH_OPTION_TYPE_IOAM_INC_TRACE_DATA_LIST = 0x3d;
const bit<8>  TRACE_TYPE_TS = 0x09; 
const bit<8>  MAX_HOP_COUNT = 0x03; 
const bit<8>  MAX_HOP_BY_HOP_PAD_INIT = 0x02; 
const bit<8>  MAX_HOP_BY_HOP_PAD_COUNT = 0x04; 

const bit<16> HEADER_LENGTH = 0x08;
const bit<16> INC_IOAM_HEADER_LENGTH = 0x04;

const bit<8>  SOURCE_NODE = 1;
const bit<8>  TRANSIT_NODE = 2;
const bit<8>  NO_OP_NODE = 3;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<128> ip6Addr_t;
typedef bit<24>   nodeID_t;
typedef bit<8>   nodeType_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv6_t {
   bit<4>        version;
   bit<8>        trafficClass;
   bit<20>       flowLabel;
   bit<16>       payloadLen;
   bit<8>        nextHdr;
   bit<8>        hopLimit;
   ip6Addr_t     srcAddr;
   ip6Addr_t     dstAddr;
}

header ip6_hop_by_hop_header_t {
  /* Protocol for next header */
  bit<8> protocol;
  /*
   * Length of hop_by_hop header in 8 octet units,
   * not including the first 8 octets
   */
  bit<8> length;
}

header ip6_hop_by_hop_option_t {
  /* Option Type */
  bit<8>        type;
  /* Length in octets of the option data field */
  bit<8>        length;

}

header ioam_trace_hdr_t {
  bit<8> ioam_trace_type;
  bit<8> data_list_elts_added;
}

/*
     0x00001001  iOAM-trace-type is 0x00001001 then the format is:

          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |   Hop_Lim     |              node_id                          |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         +                           timestamp                           +
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

header ioam_trace_ts_t {
  bit<8>     hop_lim;
  nodeID_t   node_id;
  bit<32>    timestamp;
}

header pad_t {
   bit<8> padding;
}


struct ingress_metadata_t {
    bit<16>   count; // for time being count should be max to 30
    bit<8>    hopLimit;
    bit<9>    ingress_port;
    bit<9>    egress_port;
    bit<32>   timestamp;
    bit<8>    node_type_acl;
}

struct parser_metadata_t {
    bit<8>   elts_added;
    bit<8>   ipv6_nextproto;
}

struct metadata {
    ingress_metadata_t   ingress_metadata;
    parser_metadata_t   parser_metadata;
}

struct headers {
    ethernet_t   ethernet;
    ipv6_t       ipv6;
    ip6_hop_by_hop_header_t ip6_hop_by_hop_header;
    ip6_hop_by_hop_option_t ip6_hop_by_hop_option;
    ioam_trace_hdr_t ioam_trace_hdr;
    ioam_trace_ts_t[MAX_HOP_COUNT] ioam_trace_ts; 

    /* This padding "pad1" will be used only when IPV6 packet doesn't have any 
     * HOP_BY_HOP extension header inserted in it. In all cases , we have to 
     * to make sure that the header inserted in the pkt should be multiples of
     * an octet . In this case it will be 14 bytes so we need to need to insert
     * a padding od two bytes. Headers added are explained below :
     * ip6_hop_by_hop_header header which is of 2 bytes + 
     * ip6_hop_by_hop_option header which is 2 bytes + 
     * ioam_trace_hdr , which is also 2 bytes 
     *  ioam_trace_ts which is 8 bytes
     */ 


    pad_t[MAX_HOP_BY_HOP_PAD_INIT] pad1;

    /* This padding "pad2" will be used only when Ipv6 packet already has some 
     * Hop by HOP header , it can be of any type , not necessarily IOAM Trace 
     * header. In that case we need to insert the hop by hop header + ioam 
     * header which is of 12 byte , which means we need to insert 4 byte . 
     * Headers added are explained below :
     * ip6_hop_by_hop_option header which is 2 bytes + 
     * ioam_trace_hdr , which is also 2 bytes + 
     * ioam_trace_ts which is 8 bytes
     */
 
    pad_t[MAX_HOP_BY_HOP_PAD_COUNT] pad2;
}

error { IPHeaderTooShort }

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser ParserImpl(packet_in packet,
out headers hdr,
inout metadata meta,
inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    /* PARSER for parsing in ethernet packet for Ipv6 packet , rest of the packets , just accept 
     * and go for fowarding
     */

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    /* PARSER for parsing theipv6 packet for HOP BY HOP header* 
     * if its a HOP_BY_HOP header , then parse it further for the IOAM Header *
     * ELSE accept it and go for fowarding 
     */

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        meta.parser_metadata.ipv6_nextproto = hdr.ipv6.nextHdr;
        transition select(hdr.ipv6.nextHdr) {
           IPV6_HOP_BY_HOP: parse_ipv6_hop_by_hop;
           default: accept;
        }
    }


    /* PARSER for parsing the HOP_BY_HOP header in the IPV6 header for knowing
     * the trace TYPE   * 
     * if its HBH_OPTION_TYPE_IOAM_INC_TRACE_DATA_LIST type , * 
     * then parse it further for the IOAM TRACE Header *
     * ELSE accept it and go for fowarding 
     */

    state parse_ipv6_hop_by_hop {
        packet.extract(hdr.ip6_hop_by_hop_header);
        transition select(packet.lookahead<ip6_hop_by_hop_option_t>().type) {
           HBH_OPTION_TYPE_IOAM_INC_TRACE_DATA_LIST: parse_ioam_trace_data_list;
           default: accept;
        }
    }

    state parse_ioam_trace_data_list {
        packet.extract(hdr.ip6_hop_by_hop_option);
        packet.extract(hdr.ioam_trace_hdr);
        transition select(hdr.ioam_trace_hdr.ioam_trace_type) {
            TRACE_TYPE_TS : parse_ioam_ts_trace_type;
            default: accept;
        }
    }


    state parse_ioam_ts_trace_type {
        meta.parser_metadata.elts_added = hdr.ioam_trace_hdr.data_list_elts_added;
        transition select(meta.parser_metadata.elts_added) {
            0 : accept; 
            default: parse_ioam_trace_ts;
        }
    }

    state parse_ioam_trace_ts {
        packet.extract(hdr.ioam_trace_ts.next);
        meta.parser_metadata.elts_added = meta.parser_metadata.elts_added  - 1;
        transition select(meta.parser_metadata.elts_added) {
            0 : accept;
            default: parse_ioam_trace_ts;
        }
    }

}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control verifyChecksum(in headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }

    action ipv6_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        meta.ingress_metadata.hopLimit = hdr.ipv6.hopLimit;
        meta.ingress_metadata.ingress_port = standard_metadata.ingress_port;
        meta.ingress_metadata.egress_port = standard_metadata.egress_port;
        meta.ingress_metadata.timestamp = (bit<32>)standard_metadata.ingress_global_timestamp;
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;
    }


    table ipv6_lpm {
        key = {
            hdr.ipv6.dstAddr: lpm;
        }
        actions = {
            ipv6_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
   /* This is the case when we need to add the IPV6 hop by header along with *
    * option header and ioam header. This is when P4 node is the First node *
    * to insert the IOAM trace header and packet doesn't have any hop_by_hop *
    * header in it .
    */

    action add_ipv6_hop_by_hop_and_ioam_option() {
        hdr.ip6_hop_by_hop_header.setValid();
        hdr.ip6_hop_by_hop_option.setValid();
        hdr.ioam_trace_hdr.setValid();
        hdr.ipv6.nextHdr = IPV6_HOP_BY_HOP;
        hdr.ip6_hop_by_hop_header.protocol = meta.parser_metadata.ipv6_nextproto;
        hdr.ip6_hop_by_hop_header.length = 0;
        hdr.ip6_hop_by_hop_option.type = HBH_OPTION_TYPE_IOAM_INC_TRACE_DATA_LIST;
        hdr.ip6_hop_by_hop_option.length = 0x02;
        hdr.ioam_trace_hdr.ioam_trace_type = TRACE_TYPE_TS;
        hdr.ioam_trace_hdr.data_list_elts_added = 0;
        // This is the header length which gets added first time , it includes hop_by_hop header , hop_by_hop option, ioam_trace_hdr and pad 
        //  It doesn't include the ioam_trace_ts which we will be incrementing at each hop by hop 
        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen + HEADER_LENGTH;
        hdr.pad1.push_front(1);
        hdr.pad1[0].padding=0;
        hdr.pad1.push_front(1);
        hdr.pad1[0].padding=0;
    }


   /* This is the case when we need to add the INCREMENTAL trace header in the *
    * hop_by_hop option header and ioam header. This is when P4 node is either *
    * the first node after the VPP node which has inserted the Trace header or *
    * Some other hop_by_hop header is added in the ipv6 packet before it reaches *
    * to the p4 node *
    */

    action add_inc_ioam_option() {
        hdr.ip6_hop_by_hop_option.setValid();
        hdr.ioam_trace_hdr.setValid();
        hdr.ip6_hop_by_hop_option.type = HBH_OPTION_TYPE_IOAM_INC_TRACE_DATA_LIST;
        hdr.ip6_hop_by_hop_option.length = 0x02;
        hdr.ioam_trace_hdr.ioam_trace_type = TRACE_TYPE_TS;
        hdr.ioam_trace_hdr.data_list_elts_added = 0;

        /* This is the header length which gets added first time *
         * it includes hop_by_hop option (2 bytes), ioam_trace_hdr (2 bytes)
         * It doesn't include the ioam_trace_ts which we will be incrementing 
         * at each hop by hop
         */

        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen + INC_IOAM_HEADER_LENGTH;

        /* Updating the Payload length for accomodating the padding required . 
         * The Extension header for ipv6 must be in the octets of 8 .
         * Currently with the incremental header insertion , we will be adding the 
         * ip6_hop_by_hop_option header which is 2 bytes +  
         * ioam_trace_hdr , which is also 2 bytes +  ioam_trace_ts which is 8 bytes 
         * Overall we inserted 12 bytes , so we have to add another 4 bytes to make it 
         * alligned with 8 ocets . This logic is only for the first time when we insert 
         * the ioam incremental header .
         * At the next node , it just needs to update the ioam_trace_ts which is 8 bytes.
         * hence such padding or allignment is not required .
         */

        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen + INC_IOAM_HEADER_LENGTH;
        hdr.ip6_hop_by_hop_option.length = hdr.ip6_hop_by_hop_option.length + 0x04;
        hdr.ip6_hop_by_hop_header.length = hdr.ip6_hop_by_hop_header.length + 1;
        hdr.pad2.push_front(1);
        hdr.pad2[0].padding=0;
        hdr.pad2.push_front(1);
        hdr.pad2[0].padding=0;
        hdr.pad2.push_front(1);
        hdr.pad2[0].padding=0;
        hdr.pad2.push_front(1);
        hdr.pad2[0].padding=0;
        /* Padding update is done ... */ 
    }


    action add_ioam_trace(nodeID_t id) {
        hdr.ioam_trace_hdr.data_list_elts_added = hdr.ioam_trace_hdr.data_list_elts_added + 1;
        hdr.ioam_trace_ts.push_front(1);
        hdr.ioam_trace_ts[0].node_id = id;
        hdr.ioam_trace_ts[0].hop_lim = hdr.ipv6.hopLimit;
        hdr.ioam_trace_ts[0].timestamp = (bit<32>)standard_metadata.ingress_global_timestamp;
        
        /* This includes only the ioam_trace_ts header length 
         * which gets added at each node .. it is incremental header length
         */
         
        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen + HEADER_LENGTH;
        hdr.ip6_hop_by_hop_header.length = hdr.ip6_hop_by_hop_header.length + 1;
        hdr.ip6_hop_by_hop_option.length = hdr.ip6_hop_by_hop_option.length + 0x08;

    }

    action node_sourcing(nodeType_t node_type) {
          meta.ingress_metadata.node_type_acl = node_type;

    }

    table ioam_trace {
        actions        = { add_ioam_trace; NoAction; }
        default_action =  NoAction();
    }
    table node_source {
        actions        = { node_sourcing; NoAction; }
        default_action =  NoAction();
    }



    apply {
        if (hdr.ipv6.isValid()) {
            /* This is the case of the IPV6 packets as we are accepting all 
             * ipv6 traffic . In this ipv6_lpm , we will just change the destination 
             * mac address to src mac adddress and update the egress port so as 
             * to pass it to the egress queue . This happens to 
             * all ipv6 traffic irrespective of ioam header being inserted or not */

            ipv6_lpm.apply();

            node_source.apply();
            if (meta.ingress_metadata.node_type_acl == NO_OP_NODE) {
             return;
            }

            if (!hdr.ip6_hop_by_hop_header.isValid())
            {
                 /* Case 1: When p4 is the first node to insert the header for Ipv6 hop_by_hop */
             
                 add_ipv6_hop_by_hop_and_ioam_option();
                 ioam_trace.apply();
            } else if (hdr.ip6_hop_by_hop_option.isValid()) 
 
            {
                /* Case 2 : When P4 is after VPP node or any device which adds the hop_by_hop option or 
                 * after another p4 node . */

                if(hdr.ip6_hop_by_hop_option.type != HBH_OPTION_TYPE_IOAM_INC_TRACE_DATA_LIST)
                {
                   add_inc_ioam_option();
                }
                ioam_trace.apply();
            } else 
            {
                 /* Case 3 : When p4 is after VPP node .. we have not read hdr.ip6_hop_by_hop_option in the parser if 
                  * if trace type is not HBH_OPTION_TYPE_IOAM_INC_TRACE_DATA_LIST Trace type */

                   add_inc_ioam_option();
                   ioam_trace.apply();

            }

        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/


control computeChecksum(
inout headers  hdr,
inout metadata meta)
{
    apply {
        }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.ip6_hop_by_hop_header);
        packet.emit(hdr.ip6_hop_by_hop_option);
        packet.emit(hdr.ioam_trace_hdr);
        packet.emit(hdr.ioam_trace_ts);
        packet.emit(hdr.pad1);
        packet.emit(hdr.pad2);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
ParserImpl(),
verifyChecksum(),
ingress(),
egress(),
computeChecksum(),
DeparserImpl()
) main;
