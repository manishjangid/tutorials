/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV6 = 0x86DD;
const bit<5>  IPV6_HOP_BY_HOP = 0;
const bit <8> IPV6_OPTION_IOAM_TRACE_TYPE = 6;

#define MAX_HOPS 30

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> switchID_t;

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

header ipv6_option_t {
    bit<8> option_type;
    bit<8> opt_data_len;
/* always mark reserved fields as Zero as per rfc */
    bit<16> reserved;
/* for time being , we are making it as 1024 bits , so as to accomodate 30 HOP data */
    varbit<1024>  option_data;
}

header ioam_trace_t {
    bit<16>  count;
}

header switch_t {
    switchID_t  swid;
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
    ipv6_option_t  ipv6_option;
    ioam_trace_t        ioam_trace;
    switch_t[MAX_HOPS] swids;
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
        transition select(hdr.ipv6.nextHdr) {
            IPV6_HOP_BY_HOP   : parse_ipv6_hop_by_hop_option;
            default       : accept;
        }
    }

    state parse_ipv6_hop_by_hop_option {
        packet.extract(hdr.ipv6_option);
        transition select(hdr.ipv6_option.option_type) {
            IPV6_OPTION_IOAM_TRACE_TYPE: parse_ipv6_ioam_trace;
            default: accept;
        }
    }

    state parse_ioam_trace {
        packet.extract(hdr.ioam_trace);
        meta.parser_metadata.remaining = hdr.ioam_trace.count;
        transition select(meta.parser_metadata.remaining) {
            0 : accept;
            default: parse_swid;
        }
    }

    state parse_swid {
        packet.extract(hdr.swids.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining  - 1;
        transition select(meta.parser_metadata.remaining) {
            0 : accept;
            default: parse_swid;
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
    
    action add_ioam_trace_option() {
        hdr.ipv6_option.setValid();
        hdr.ipv6_option.option_type     =  IPV6_OPTION_IOAM_TRACE_TYPE;
        hdr.ipv6_option.optClass     = 2;  /* Debugging and Measurement */
        hdr.ipv6_option.option       = 0;
        hdr.ipv6_option.optionLength = 1024;  /* sizeof(ipv6_option) + sizeof(ioam_trace) */
        
        hdr.ioam_trace.setValid();
        hdr.ioam_trace.count = 0;
        /*we need to fetch the nexthdr from the ipv6 packet first , copy it into a local var (for time being) and then we need to set it as part of the ioam next header */
        hdr.ipv6.nextHdr = IPV6_HOP_BY_HOP;
    }
    
    action add_swid(switchID_t id) {    
        hdr.ioam_trace.count = hdr.ioam_trace.count + 1;
        hdr.swids.push_front(1);
        hdr.swids[0].swid = id;

        hdr.ipv6.ihl = hdr.ipv6.ihl + 1;
        hdr.ipv6_option.optionLength = hdr.ipv6_option.optionLength + 4;    
    }
    
    action ipv6_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv6.ttl = hdr.ipv6.ttl - 1;
    }

    table swid {
        actions        = { add_swid; NoAction; }
        default_action =  NoAction();      
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
    
    apply {
        if (hdr.ipv6.isValid()) {
            ipv6_lpm.apply();
            
            if (!hdr.ioam_trace.isValid()) {
                add_ioam_trace_option();
            }    
            
            swid.apply();
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
    Checksum16() ipv6_checksum;
    
    apply {
        if (hdr.ipv6.isValid()) {
            hdr.ipv6.hdrChecksum = ipv6_checksum.get(
            {    
                hdr.ipv6.version,
                hdr.ipv6.ihl,
                hdr.ipv6.diffserv,
                hdr.ipv6.totalLen,
                hdr.ipv6.identification,
                hdr.ipv6.flags,
                hdr.ipv6.fragOffset,
                hdr.ipv6.ttl,
                hdr.ipv6.protocol,
                hdr.ipv6.srcAddr,
                hdr.ipv6.dstAddr
            });
        }
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.ipv6_option);
        packet.emit(hdr.ioam_trace);
        packet.emit(hdr.swids);                 
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
