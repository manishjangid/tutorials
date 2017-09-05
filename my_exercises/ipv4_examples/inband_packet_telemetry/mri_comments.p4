
Problem : 

Sending packet from H1 to H2 via S1 and S2 . At Intermediate hops i.e S1 and S2 , we will implement the p4 data plane programming to parse the packet 

  
  src ip = 10.0.1.10 src mac = 00:04:00:00:00:01
  dst ip = 10.0.2.10 dst-mac = ff:ff:ff:ff:ff:ff




At S1 we receive the packet at eth-1 , 


============== 

Package 

==============


V1Switch(
ParserImpl(),
verifyChecksum(),
ingress(),
egress(),
computeChecksum(),
DeparserImpl()
) main;
                                                                                                                                                                                          278,1         Bot

================



HEADERs Involved 


==================================


struct headers {
    ethernet_t   ethernet;	  header ethernet_t {
    ipv4_t       ipv4;		      macAddr_t dstAddr;    header ipv4_t {
    ipv4_option_t  ipv4_option;	      macAddr_t srcAddr;        bit<4>    version;	   header ipv4_option_t {
    mri_t        mri;		      bit<16>   etherType;      bit<4>    ihl;		       bit<1> copyFlag;	    	header mri_t {
    switch_t[MAX_HOPS] swids;	  }			        bit<8>    diffserv;	       bit<2> optClass;	    	    bit<16>  count;
}							        bit<16>   totalLen;	       bit<5> option;	    	}		     header switch_t {
							        bit<16>   identification;      bit<8> optionLength;			         switchID_t(32 bits)  swid; 
							        bit<3>    flags;	   }						     }
							        bit<13>   fragOffset;
							        bit<8>    ttl;
							        bit<8>    protocol;
							        bit<16>   hdrChecksum;
							        ip4Addr_t srcAddr;
								    ip4Addr_t dstAddr;	
								}	
														
==================================									
									

So the first point is parser for packet reaching from H1 to Switch S1 then hit the table

table_set_default ipv4_lpm drop
table_set_default swid add_swid 1
table_add ipv4_lpm ipv4_forward 10.0.1.10/32 => 00:aa:00:01:00:01 1
table_add ipv4_lpm ipv4_forward 10.0.2.10/32 => f2:ed:e6:df:4e:fa 2
table_add ipv4_lpm ipv4_forward 10.0.3.10/32 => f2:ed:e6:df:4e:fb 3



Since destination ip matches with the entry table_add ipv4_lpm ipv4_forward 10.0.2.10/32 => f2:ed:e6:df:4e:fa 2 , which means we will apply the table ipv4_lpm with action as ipv4_forward




PARSER 




================================



In the parser , we first fetch if its the ethernet header 

parser -> Start --> parse_ethernet : Here it just checks if the TYPE is IPV4 i.e ether_type 0x8000 --> parse_ipv4 --> checks if the IHL is 5 which means no ipv4 options are enabled so just accept the pact and move on , if IHL is greater 5 which means some optional hdr is there --> parse_ipv4_options , in this it just check if the IPV4options is of type MRI i.e 31 , then call parse_mri --> parse_mri : in this it copies the MRI COUNT to metadata.remaining & checks if MRI count > 0 , then call for parsing the switch id --> parse_swid : extracts the switchid header and next till it becomes 0. 


==========================


No checksum check 


===========================

INGRESS : This is the control block where we apply the match action table rules 

table_set_default ipv4_lpm drop
table_set_default swid add_swid 1
table_add ipv4_lpm ipv4_forward 10.0.1.10/32 => 00:aa:00:01:00:01 1
table_add ipv4_lpm ipv4_forward 10.0.2.10/32 => f2:ed:e6:df:4e:fa 2
table_add ipv4_lpm ipv4_forward 10.0.3.10/32 => f2:ed:e6:df:4e:fb 3


===========================



    table ipv4_lpm {			    apply {
        key = {				    if (hdr.ipv4.isValid()) {	      action add_mri_option() {
            hdr.ipv4.dstAddr: lpm;	        ipv4_lpm.apply();	          hdr.ipv4_option.setValid();
        }								          hdr.ipv4_option.copyFlag     = 1;
        actions = {			        if (!hdr.mri.isValid()) {         hdr.ipv4_option.optClass     = 2;  /* Debugging and Measurement */
            ipv4_forward;			add_mri_option();	          hdr.ipv4_option.option       = IPV4_OPTION_MRI;
            drop;			        }			          hdr.ipv4_option.optionLength = 4;  /* sizeof(ipv4_option) + sizeof(mri) */
            NoAction;
        }				        swid.apply();		          hdr.mri.setValid();
        size = 1024;			    }				          hdr.mri.count = 0;
        default_action = NoAction();	    }				          hdr.ipv4.ihl = hdr.ipv4.ihl + 1;
    }									      }

		
		
    							 action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
      							  standard_metadata.egress_spec = port;  // for 10.0.2.10 , egress port is 2 
      							  hdr.ethernet.srcAddr = hdr.ethernet.dstAddr; // copy dst_mac as src_mac
      							  hdr.ethernet.dstAddr = dstAddr;  // copy f2:ed:e6:df:4e:fa in Destination mac 
      							  hdr.ipv4.ttl = hdr.ipv4.ttl - 1; // Decrement the ttl 
      							}
		
						
						
    table swid {					action add_swid(switchID_t id) {
        actions        = { add_swid; NoAction; }	        hdr.mri.count = hdr.mri.count + 1;
        default_action =  NoAction();			        hdr.swids.push_front(1);  // at S1 , we added swicthid as {1}, at s2 , we will first push this to one right which means
    }							        hdr.swids[0].swid = id;   // it becomes { ,1} , now we added at 0th position the new switch id i.e 2 , so its {2,1}
      							        hdr.ipv4.ihl = hdr.ipv4.ihl + 1;
    							        hdr.ipv4_option.optionLength = hdr.ipv4_option.optionLength + 4; /* switchid is 4 bytes */
    							    }
  hs.push_front(int count): shift “right” by count. The first count elements become invalid. The last count elements in the stack are discarded. 
  The hs.nextIndex counter is incremented by count. The count argument must be a positive integer that is a compile-time known value. The return type is void.
  
  
  hs.pop_front(int count): shift “left” by count (i.e., element with index count is copied in stack at index 0). 
  The last count elements become invalid. The hs.nextIndex counter is decremented by count. 
  The count argument must be a positive integer that is a compile-time known value. The return type is void. 
  
  
  
  
  
  =========================
  
  EGRESS MAU IS EMPTY 
    
  =========================
  
  
  
  
  
  ==================
  
  
  DEPARSER 
  
  
  
  =================
  
  
  control DeparserImpl(packet_out packet, in headers hdr) {
      apply {
          packet.emit(hdr.ethernet);
          packet.emit(hdr.ipv4);
          packet.emit(hdr.ipv4_option);
          packet.emit(hdr.mri);
          packet.emit(hdr.swids);
      }
  }

