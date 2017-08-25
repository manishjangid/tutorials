/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>



===================

TOPOLOGY


=================== 





                                       -------
                                      |       |
                                      | Host 1|
                                      |       |
                                       -------
                                              \
                                               \
                                                \
                                                 \
                                                  \
                                                   \
                                                    \
                                                     \
                                                 ---------------
                                                |               |
                                                | Switch S1     |
                                                |               |
                                                 ---------------
                                              ETH3    /   \ ETH 2
                                                     /     \
                                                    /       \
                                                   /         \
                                                  /           \
                                                 /             \
                                                /               \
                                               /                 \
                                              /                   \
                                             /                     \
                                            /                       \
                                           /                         \
                                          /                           \
                                         /                             \
                                        /                               \
                                       / ETH 2                           \ ETH 2
                               ---------------                           -------------
                              |               |                         |             |
                              | Switch S2     | ETH3 ---------------ETH3  | Switch3   |
                              |               |                         |             |
                              |               |                         |             |
                               ---------------                           -------------
                                       /                                   \
                                      /                                     \
                                     /                                       \
                                    /                                         \
                                   /                                           \
                                  /                                             \
                                 /                                               \ 
                              --------                                      --------
                             |  Host2 |                                    | Host3  |
                             |        |                                    |        |
                              --------                                      --------


S1 Table 

table_add ipv4_lpm ipv4_forward 10.0.1.10/32 => 00:aa:00:01:00:01 1
table_add ipv4_lpm ipv4_forward 10.0.2.10/32 => f2:ed:e6:df:4e:fa 2
table_add ipv4_lpm ipv4_forward 10.0.3.10/32 => f2:ed:e6:df:4e:fb 3

S2 Table 

table_add ipv4_lpm ipv4_forward 10.0.2.10/32 => 00:aa:00:02:00:02 1
table_add ipv4_lpm ipv4_forward 10.0.1.10/32 => 22:a8:04:41:ab:d3 2
table_add ipv4_lpm ipv4_forward 10.0.3.10/32 => 22:a8:04:41:ab:d4 3

S3 Table 

table_add ipv4_lpm ipv4_forward 10.0.3.10/32 => 00:aa:00:03:00:01 1
table_add ipv4_lpm ipv4_forward 10.0.1.10/32 => f2:ed:e6:df:4e:fb 2
table_add ipv4_lpm ipv4_forward 10.0.2.10/32 => f2:ed:e6:df:4e:fa 3





/*  In this example we are sending packet from H1 to H2 using the send.py 
/*    Src IP : 10.0.1.10    Srcmac : 00:04:00:00:00:01
/*   Dst IP : 10.0.2.10    Dstmac : 00:aa:00:01:00:01

/* In the Switch S1 , we have this P4 programming the hardware . 
* Upon Receiving the pkt , if packet is a lpm_match , then we do ingress and apply the table rules 
/* S1  P4 program – parser ; ingress ; apply ()
/* Table 10.0.2.10/32 => f2:ed:e6:df:4e:fa 2
/* Then we call this function Ipv4_forward () where we are setting the Egress port as 2 and Change the Src & Dest MAC 
/*   Egress port 2 (eth2)
/*   Dstmac (00:aa:00:01:00:01) set it as Srcmac
/*   Set Destmac as f2:ed:e6:df:4e:fa




/* Now the packet is sent to the Switch S2 by S1  with the following inputs
/* Src IP : 10.0.1.10 Srcmac : 00:aa:00:01:00:01
/* Dest IP : 10.0.2.10     Dstmac : f2:ed:e6:df:4e:fa

/* S2  P4 program – parser ; ingress ; apply ()
/* Table 10.0.2.10/32 => 00:aa:00:02:00:02 1
/* In the switch Ipv4_forward ()
/*    Egress port 1 (eth1)
/*    Dstmac (f2:ed:e6:df:4e:fa) set it as Srcmac (f2:ed:e6:df:4e:fa)
/*    Set Destmac as 00:aa:00:02:00:02




const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

/* P4 parser describes a state machine with one start state and two final states. The start state is always named start. 
 * The two final states are named accept (indicating successful parsing) and reject (indicating a parsing failure). 
 * The start state is part of the parser, while the accept and reject states are distinct from the states provided by the programmer and are logically outside of the parser.
 */

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
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
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
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
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
    Checksum16() ipv4_checksum;
    
    apply {
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.hdrChecksum = ipv4_checksum.get(
                {    
                    hdr.ipv4.version,
                    hdr.ipv4.ihl,
                    hdr.ipv4.diffserv,
                    hdr.ipv4.totalLen,
                    hdr.ipv4.identification,
                    hdr.ipv4.flags,
                    hdr.ipv4.fragOffset,
                    hdr.ipv4.ttl,
                    hdr.ipv4.protocol,
                    hdr.ipv4.srcAddr,
                    hdr.ipv4.dstAddr
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
        packet.emit(hdr.ipv4);
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
