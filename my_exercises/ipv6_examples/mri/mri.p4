/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV6 = 0x86DD;
const bit<8>  IPV6_HOP_BY_HOP = 0;
const bit<8> IPV6_OPTION_IOAM_TRACE_TYPE = 6;
const bit<8> HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST = 0x3b; 
const bit<8>  TRACE_TYPE_TS = 0x09; 
const bit<8>  MAX_HOP_COUNT = 0x03; 
const bit<8>  MAX_PAD_COUNT = 0x02; 

const bit<16> HEADER_LENGTH = 0x08;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<128> ip6Addr_t;
typedef bit<24>   nodeID_t;


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
   bit<8>     hopLimit;

}

struct parser_metadata_t {
    bit<8>   elts_left;
    bit<8>   ipv6_nextproto;
    bit<8>   nextprotocol;
    bit<8>   nextlength;
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
    pad_t[MAX_PAD_COUNT] pad;
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

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        meta.parser_metadata.ipv6_nextproto = hdr.ipv6.nextHdr;
        transition select(hdr.ipv6.nextHdr) {
           IPV6_HOP_BY_HOP: parse_ipv6_hop_by_hop;
           default: accept; //We should check in case of the ingress if the ip hop by hop header exists , then we need to add it , just like mri_header
        }
    }


    state parse_ipv6_hop_by_hop {
        packet.extract(hdr.ip6_hop_by_hop_header);
        meta.parser_metadata.nextprotocol = hdr.ip6_hop_by_hop_header.protocol;
        meta.parser_metadata.nextlength = hdr.ip6_hop_by_hop_header.length;
        packet.extract(hdr.ip6_hop_by_hop_option);
        transition select(hdr.ip6_hop_by_hop_option.type) {
            HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST: parse_ioam_trace_data_list;
            default: accept;
        }
    }

    state parse_ioam_trace_data_list {
        packet.extract(hdr.ioam_trace_hdr);
        transition select(hdr.ioam_trace_hdr.ioam_trace_type) {
            TRACE_TYPE_TS : parse_ioam_ts_trace_type;
            default: accept;
        }
    }

    // NEED TO REVISIT THIS //

    state parse_ioam_ts_trace_type {
        packet.extract(hdr.ioam_trace_hdr);
        meta.parser_metadata.elts_left = hdr.ioam_trace_hdr.data_list_elts_added;
        transition select(meta.parser_metadata.elts_left) {
            0 : accept; 
            default: parse_ioam_trace_ts;
        }
    }

    state parse_ioam_trace_ts {
        packet.extract(hdr.ioam_trace_ts.next);
        meta.parser_metadata.elts_left = meta.parser_metadata.elts_left  - 1;
        transition select(meta.parser_metadata.elts_left) {
            0 : accept;   // NEED TO CHECK IF THIS NEEDS TO BE ZERO or -1 //
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

    action add_ioam_option() {
        hdr.ip6_hop_by_hop_header.setValid();
        hdr.ip6_hop_by_hop_option.setValid();
        hdr.ioam_trace_hdr.setValid();
        hdr.ipv6.nextHdr = IPV6_HOP_BY_HOP;
        hdr.ip6_hop_by_hop_header.protocol = meta.parser_metadata.ipv6_nextproto;
        hdr.ip6_hop_by_hop_header.length = 1;
        hdr.ip6_hop_by_hop_option.type = HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST;
        hdr.ip6_hop_by_hop_option.length = 0x02;
        hdr.ioam_trace_hdr.ioam_trace_type = TRACE_TYPE_TS;
        hdr.ioam_trace_hdr.data_list_elts_added = 0;
        // This is the header length which gets added first time , it includes hop_by_hop header , hop_by_hop option, ioam_trace_hdr and pad 
        //  It doesn't include the ioam_trace_ts which we will be incrementing at each hop by hop 
        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen + HEADER_LENGTH;
    }


    action add_ioam_trace(nodeID_t id) {
        hdr.ioam_trace_hdr.data_list_elts_added = hdr.ioam_trace_hdr.data_list_elts_added + 1;
        hdr.ioam_trace_ts.push_front(1);
        hdr.ioam_trace_ts[0].node_id = id;
        hdr.ioam_trace_ts[0].hop_lim = hdr.ipv6.hopLimit;
        hdr.ioam_trace_ts[0].timestamp = 0x123;
        hdr.pad.push_front(1);
        hdr.pad[0].padding=0;
        hdr.pad.push_front(1);
        hdr.pad[0].padding=0;
        
        // This includes only the ioam_trace_ts header length which gets added at each node .. it is incremental header length
        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen + HEADER_LENGTH;
        hdr.ip6_hop_by_hop_header.length = hdr.ip6_hop_by_hop_header.length + 1;
        hdr.ip6_hop_by_hop_option.length = hdr.ip6_hop_by_hop_option.length + 0x08;

    }



    table ioam_trace {
        actions        = { add_ioam_trace; NoAction; }
        default_action =  NoAction();
    }


    apply {
        if (hdr.ipv6.isValid()) {
            ipv6_lpm.apply();

            if ((!hdr.ip6_hop_by_hop_header.isValid()) ||
                 (!hdr.ip6_hop_by_hop_option.isValid()) ||
                 (!hdr.ioam_trace_hdr.isValid())) {
                 
                       add_ioam_option();
              }
              ioam_trace.apply();

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
        packet.emit(hdr.pad);
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
