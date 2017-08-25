

--------------
TOPOLOGY
-------------


                     ----------------------                         ------------------                              -----------------------
                    | HOST H1              |                        | Switch S1      |                              | HOST H2              |                      
                    | IP 10.0.0.10         | ETH0 <--------> S1-Eth1|                | S1-Eth2 <----------->   ETH0 |IP 10.0.1.10          |                      
                    | MAC 00:04:00:00:00:00|                        |                |                              |MAC 00:04:00:00:00:01 |
                    |                      |                        |                |                              |                      |
                     ----------------------                         ------------------                              -----------------------

==============
Operation : H1 PING to H2 

H2 doesn't responsd for the PING requests . 

In this program , Swicth S1 parsers all packets goings through its ingress queue , parses them to checks if its a arp packet or ICMP packet 


TABLE match for S1 is : table_add ipv4_lpm set_dst_info 10.0.1.10/24 => 00:00:01:00:00:01 00:00:02:00:00:02 1

As Arp or ICMP response are part of the conrol plane protocols , which is outside the scope of P4 , hence in this particular case ,  S1 only creates the ARP reply or ICMP reply based on the type of the packet .

In our observation over the mininet , we Dont see ARP packets getting generated even though ARP for the H2 is NOT learnt on the H1 .
 Where as if we try to ping some other subnet , then we do see arp packets getting generated from the host H1 . 

Also if the swicth S1 receives any packets which are ipv4 packets but not icmp , it just forwards those packets back to the ingress port i.e change the egress port as the ingress port 

==============



/*****************************   MAIN FUNCTION i.e control flow of the P4 program  ***********************/

/* The P4 Program flows in the below form  ... 
 * We have the Ingress parser --> Verify_Checksum --> Ingress MAU --> Ingress Deparser --> Egress parser --> Egress MAU --> Compute_Checksum --> Egress Deparser */ 
 
/* Ingress MAU and Egress MAU are the Control Blocks where we do Matching , applying of the table and take appropriate actions on based on the matching/dropping. 
/* There can be more than one level of parsing i.e multiple parser blocks , foreg in case of Tunnelling/Tagged Vlan we may require two levels of parsing or in case of MIM header we have two level of parsers */ 



V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;


/*****************************   IMPORTANT HEADER TYPES  ***********************/

/* These are the Structures which we will be working on this program */ 


/* Assemble headers in a single struct */
struct my_headers_t {
    ethernet_t   ethernet;
    arp_t        arp;
    arp_ipv4_t   arp_ipv4;
    ipv4_t       ipv4;
    icmp_t       icmp;
}

      

header arp_t {		   /* Assemble headers in a single struct */	 header arp_ipv4_t {		header ipv4_t {				     header icmp_t {
    bit<16> htype;	   struct my_headers_t {			     mac_addr_t  sha;		    bit<4>       version;		         bit<8>  type;
    bit<16> ptype;	       ethernet_t   ethernet;			     ipv4_addr_t spa;		    bit<4>       ihl;			         bit<8>  code;
    bit<8>  hlen;	       arp_t        arp;			     mac_addr_t  tha;		    bit<8>       diffserv;		         bit<16> checksum;
    bit<8>  plen;	       arp_ipv4_t   arp_ipv4;			     ipv4_addr_t tpa;		    bit<16>      totalLen;		     }
    bit<16> oper;	       ipv4_t       ipv4;			 }				    bit<16>      identification;
}			       icmp_t       icmp;							    bit<3>       flags;
			   }										    bit<13>      fragOffset;
													    bit<8>       ttl;
													    bit<8>       protocol;
													    bit<16>      hdrChecksum;
header ethernet_t {											    ipv4_addr_t  srcAddr;
    mac_addr_t dstAddr;											    ipv4_addr_t  dstAddr;
    mac_addr_t srcAddr;											}
    bit<16>    etherType;
}

													
const bit<8> ICMP_ECHO_REQUEST = 8;
const bit<8> ICMP_ECHO_REPLY   = 0;



/***************************** PARSER START ***************************/


/* In this function MyParser() , we fetch the input packet and fetches the ethernet header to 
 * check the Ethertype to matching in either arp and ipv4 (for checking if the pkt is ICMP packet , 
 * then call for icmp_parser from the parse_ipv4 , else just forward the packet (in this program 
 * thats more or less like a drop as we change the src and dst mac and send it back on the port from where it has ingressed */ 

MyParser()
ETHERTYPE_IPV4 : parse_ipv4;
ETHERTYPE_ARP  : parse_arp;


/* As mentioned about in parse_ipv4 , we check for icmp packets */

In parse_ipv4 , it fetches the ICMP packets for processing 
IPPROTO_ICMP : parse_icmp;



/* In the parse_arp , we check is of arp type via checking various feilds of the packet header . If those match , then we call parse_arp_ipv4 fuction 
 */


const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;


/* The execution of the transition statement causes stateExpression to be evaluated, and transfers control to the resulting state.
 * Which means in the parse_arp , we are checking the values from the packet and then call parse_arp_ipv4 if all parameters match 
 */
parse_arp ()

        transition select(hdr.arp.htype, hdr.arp.ptype,
                          hdr.arp.hlen,  hdr.arp.plen) {
            (ARP_HTYPE_ETHERNET, ARP_PTYPE_IPV4,
             ARP_HLEN_ETHERNET,  ARP_PLEN_IPV4) : parse_arp_ipv4;



 /* In the parse_arp_ipv4 , we are just coping the target protocol address (TPA) as the dst_ipv4 
  * address which we will be using in the control functions i.e send_arp_reply () when we will reply the arp packets */

    state parse_arp_ipv4 {
        packet.extract(hdr.arp_ipv4);
        meta.dst_ipv4 = hdr.arp_ipv4.tpa;
        transition accept;   // transitioned to the next state i.e parser ends here
    }
    
    


 /* For the ICMP , it calls the parse packet.extract which extracts the header and then just transitioned to the next state i.e parser ends here */ 
 

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept; // transitioned to the next state i.e parser ends here
    }
    
    
    In the end of both parse_arp_ipv4 and parse_icmp , it has accepted the transition , which means we will move to the next state transition from the main function
    
    MyVerifyChecksum()
    
    empty 
    
    
    Now next state transition i.e MyIngress()




/********************************************************************/
/***************************** PARSER END ***************************/
/********************************************************************/


/***************************** CONTROL START ***************************/

/* The table on the switch S1 has the following entry 
 * table_add ipv4_lpm set_dst_info 10.0.1.10/24 => 00:00:01:00:00:01 00:00:02:00:00:02 1
 * When we ping H2 from H1 , the destination Ip will be 10.0.1.10 , which means the above table entry will be match 
 * hence check for MATCH ACTION rules for this entry
*/

    apply {
        meta.my_mac = 0x000102030405;
        ipv4_lpm.apply();
        forward.apply();
    }




/* if match done i.e if the Dst ip is 10.0.1.10 then call set_dst_info : WHICH is there when we do Ping h2 from H1 * /

ipv4_lpm == if match done i.e if the Dst ip is 10.0.1.10 then call set_dst_info

   table ipv4_lpm {
        key     = { meta.dst_ipv4 : lpm; }
        actions = { set_dst_info; drop;  }
        default_action = drop();
    }



set_dst_info  ==> 00:00:01:00:00:01 00:00:02:00:00:02 1

    action set_dst_info(mac_addr_t mac_da,
                        mac_addr_t mac_sa,
                        port_id_t  egress_port)
    {
        meta.mac_da      = mac_da;   00:00:01:00:00:01        
        meta.mac_sa      = mac_sa;    00:00:02:00:00:02  
        meta.egress_port = egress_port;  1
    }
/* Once the ipv4_lpm table processing is done (match-action) , then control moves to forward Match-Action Unit.  
 */

/* Entries While table entries are typically installed by the control plane, tables may also be initialized at compile-time with a set of entries. 
 * This is useful in situations where tables are used
 * to implement fixed algorithms—defining table entries statically enables expressing 
 * these algorithm directly in P4, which allows the compiler to infer how the table is 
 * actually used and potentially make
 * better allocation decisions for targets with limited resources. 
 * Entries declared in the P4 source are installed in the table when the program is loaded onto the target.
*/
 /* ---------------------------------------------

tableProperty
: KEY '=' '{' keyElementList '}'
| ACTIONS '=' '{' actionList '}'
| CONST ENTRIES '=' '{' entriesList '}' /* immutable entries */
| optAnnotations CONST IDENTIFIER '=' initializer ';'
| optAnnotations IDENTIFIER '=' initializer ';'
;
The standard table properties include:
• key: An expression that describes how the key used for look-up is computed.
• actions: A list of all actions that may be found in the table.
In addition, the tables may optionally define the following property,
• default_action: an action to execute when the lookup in the lookup table fails to find a match for the key used.

 /* ---------------------------------------------


  /* Now lets look at the "forward" table and its entries which are defined as per the above described method , we check for each entry as a different match action rule */

       table forward {
            key = {
                hdr.arp.isValid()      : exact;
                hdr.arp.oper           : ternary;
                hdr.arp_ipv4.isValid() : exact;
                hdr.ipv4.isValid()     : exact;
                hdr.icmp.isValid()     : exact;
                hdr.icmp.type          : ternary;
            }
            actions = {
                forward_ipv4;
                send_arp_reply;
                send_icmp_reply;
                drop;
            }
            const default_action = drop();
            const entries = {
                ( true, ARP_OPER_REQUEST, true, false, false, _  ) :
                                                             send_arp_reply();
                ( false, _,false, true, false, _  ) :
                                                             forward_ipv4();
                ( false, _,false, true, true, ICMP_ECHO_REQUEST ) :
                                                             send_icmp_reply();
            }
        } /*Table forward ends */



--------------------- ARP PACKET RESPONSE -----------------------------------

/* Based on the above Match Action creteria , i.e if the packet meets the criteria 1 i.e 
 * if its a arp packet with valid header , and its arp request , then we call the send_arp_reply action 
 * in which the switch S1 contructs the ARP Response and sends it to H1  */
  
/*( true, ARP_OPER_REQUEST, true, false, false, _  ) */

send_arp_reply  ==> get called for the first ARP request packet .


    action send_arp_reply() {
        hdr.ethernet.dstAddr = hdr.arp_ipv4.sha;   // sender Hardware(mac) address and put it in the destination address for ARP response 
        hdr.ethernet.srcAddr = meta.mac_da;        // set_dst_info ()  meta.mac_da      = mac_da;   00:00:01:00:00:01              
        hdr.arp.oper         = ARP_OPER_REPLY;     // Change to the ARP reply .
        hdr.arp_ipv4.tha     = hdr.arp_ipv4.sha;   // Target Hardware address and we put the sender hardware address in that  
        hdr.arp_ipv4.tpa     = hdr.arp_ipv4.spa;   // Target protocol address and we put the sender protocol address (IP address) in that. 
        hdr.arp_ipv4.sha     = meta.mac_da;        // set_dst_info () meta.mac_da      = mac_da;   00:00:01:00:00:01
        hdr.arp_ipv4.spa     = meta.dst_ipv4;      // This got filled in parse_ipv4_arp : meta.dst_ipv4 = hdr.arp_ipv4.tpa; 

        standard_metadata.egress_spec = standard_metadata.ingress_port;  // Send via the same port from where it came 
    }
    
 
 ******************* After this we take the action i.e ingress (table match-action & control apply) is done so we move to egress pipeline.MyEgress()which is empty apply {    } 





    
--------------------- JUST FORWARD THE PKT -----------------------------------

/* If the packet matches this entry ( false, _,false, true, false, _  ) i.e it is not arp packet , it is a Ipv4 packet and its not ICMP , then just call forward */ 

    
    forward_ipv4   ==> Gets called when its a IPV4 packet and Neither ARP nor ICMP packet  
    
    
        action forward_ipv4() {
            hdr.ethernet.dstAddr = meta.mac_da;  // This was modified in the set_dst_info meta.mac_da      = mac_da;   00:00:01:00:00:01 
            hdr.ethernet.srcAddr = meta.mac_sa;   // This was modified in the set_dst_info  meta.mac_sa      = mac_sa;    00:00:02:00:00:02 
            hdr.ipv4.ttl         = hdr.ipv4.ttl - 1;
    
            standard_metadata.egress_spec = meta.egress_port;   // This was modified in the set_dst_info  meta.egress_port = egress_port;  1
        }

    It just send back the packet by changing the destination mac and sender's mac on the same Port from where the packet has reached . 
    
   ******************* After this we take the action i.e ingress (table match-action & control apply) is done so we move to egress pipeline. MyEgress() which is empty apply {    } 
   
 
--------------------- ICMP PACKET RESPONSE  -----------------------------------

/* If the packet matches this entry ( false, _,false, true, true, ICMP_ECHO_REQUEST )  
/* Based on the above Match Action creteria , i.e if the packet meets the criteria 1 i.e 
 * if its a IPv4 packet and with a ICMP valid header , then we call the send_icmp_reply action 
 * in which the switch S1 contructs the ICMP Response and sends it to H1  */

        action send_icmp_reply() {
            mac_addr_t   tmp_mac;
            ipv4_addr_t  tmp_ip;
    
            tmp_mac              = hdr.ethernet.dstAddr;   // Just toggle the src mac with dest mac and vice versa
            hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
            hdr.ethernet.srcAddr = tmp_mac;
    
            tmp_ip               = hdr.ipv4.dstAddr; // Just toggle the src ip with dest mac and vice versa
            hdr.ipv4.dstAddr     = hdr.ipv4.srcAddr;
            hdr.ipv4.srcAddr     = tmp_ip;
    
            hdr.icmp.type        = ICMP_ECHO_REPLY;  // Change the ICMP type to response 
            hdr.icmp.checksum    = 0; // For now
    
            standard_metadata.egress_spec = standard_metadata.ingress_port;   // Send via the same port 
        }


 ******************* After this we take the action i.e ingress (table match-action & control apply) is done so we move to egress pipeline.  MyEgress() which is empty apply {    }
    
    
/***************************** CONTROL ENDS ***************************/
    
    
/***************************** DEPARSER  START ***************************/

EGRESS MAU : As egress doesnt have any rules to apply , we move to the Deparser function  MyDeparser()
  
 /* The inverse of parsing is deparsing, or packet construction. 
  * P4 does not provide a separate language for packet deparsing; 
  * deparsing is done in a control block that has at least one parameter of type packet_out.
  *  For example, the following code sequence writes first an Ethernet header and then an IPv4 header into a packet_out:
  //                    control TopDeparser(inout Parsed_packet p, packet_out b) {
  //                         apply {
  //                            b.emit(p.ethernet);
  //                            b.emit(p.ip);
  //                         }
  //                      }
  /* Emitting a header appends the header to the packet_out only if the header is valid. Emitting a header stack will emit all elements of the stack in order of increasing indexes.


/*  This is the deparser function where we are just adding the changed header and contruct the packet back and send it out */
    
    control MyDeparser(
        packet_out      packet,
        in my_headers_t hdr)
    {
        apply {
            packet.emit(hdr.ethernet);
            /* ARP Case */
            packet.emit(hdr.arp);
            packet.emit(hdr.arp_ipv4);
            /* IPv4 case */
            packet.emit(hdr.ipv4);
            packet.emit(hdr.icmp);
        }
    }

/***************************** DEPARSER  ENDS  ***************************/
