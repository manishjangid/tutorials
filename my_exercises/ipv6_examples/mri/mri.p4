/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV6 = 0x86DD;
const bit<8>  IPV6_HOP_BY_HOP = 0;
const bit <8> IPV6_OPTION_IOAM_TRACE_TYPE = 6;

#define MAX_HOPS 30

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<128> ip6Addr_t;

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
#define HBH_OPTION_TYPE_SKIP_UNKNOWN (0x00)
#define HBH_OPTION_TYPE_DISCARD_UNKNOWN (0x40)
#define HBH_OPTION_TYPE_DISCARD_UNKNOWN_ICMP (0x80)
#define HBH_OPTION_TYPE_DISCARD_UNKNOWN_ICMP_NOT_MCAST (0xc0)
#define HBH_OPTION_TYPE_HIGH_ORDER_BITS (0xc0)
#define HBH_OPTION_TYPE_DATA_CHANGE_ENROUTE (1<<5)
  bit<8>        type;
  /* Length in octets of the option data field */
  bit<8>        length;

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

#define   TRACE_TYPE_TS   0x09
header ioam_trace_ts_t {
  bit<8>    hop_lim;
  bit<24>   node_id;
  bit<32>   timestamp;
}

header ioam_trace_hdr_t {
  bit<8> ioam_trace_type;
  bit<8> data_list_elts_left;
}


struct ingress_metadata_t {
    bit<16>  count; // for time being count should be max to 30
}

struct parser_metadata_t {
    bit<16>  remaining;
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
    ioam_trace_ts_t[MAX_HOPS] ioam_trace_ts; 
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
            TYPE_IPV6: accept;
            default: accept;
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
    apply {  }
    
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
