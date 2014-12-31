/**@file Flow.h
@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@brief This file contains the prototypes of the TFlow class. 
@author Pieter Burghouwt
@version Revision 2.0
@date Tuesday, March 12, 2013
*/

#ifndef FLOW_
#define FLOW_

#include <stdint.h>

#define FLOWHASHSIZE 1024
#define UNDEFINED_DIR 0
#define INGRESS 1
#define EGRESS 2

#define RESOLVER_UNDEFINED 0 
#define RESOLVER_PROTO_STATIC 1
#define RESOLVER_PROTO_DNS 2
#define RESOLVER_PROTO_OTHER 3
#define RESOLVER_NONAME 128
#define RESOLVER_STATICNAME 129
#define RESOLVER_DNSNAME 130
#define RESOLVER_OTHERNAME 131

#define CAUSE_UNKNOWN 0 //cause unknown
#define CAUSE_SERVER  1//flow starts ingress towards a inside server port
#define CAUSE_DNS 2//flow starts after reception of DNS-A-record
#define CAUSE_HTTP_URL 3 //flow starts after reception of a HRRP URL that is IP or a resolved name 
#define CAUSE_HTTP_SOFTURL 4 //flow starts after reception of a HRRP URL that is IP or a resolved part of the name
#define CAUSE_HTTP_REFERER 5 //flow caused by referer
#define CAUSE_HTTP_GEN 6//flow starts after data reception with potential URL
#define CAUSE_HTTPS_GEN 7//flow starts after data reception with potential URL
#define CAUSE_USER 8//flow starts after user interaction 
#define CAUSE_PROTODNS 9 //cause yet unknown because the payload of the DNS has to arrive
#define CAUSE_WHITELIST 10 //domain name or ip-address in whitelisted range
#define CAUSE_ALREADYOPEN 11 //Flow was already open
#define CAUSE_DNS_REPEAT 12 //DNS query is repeated
#define CAUSE_UTREE 13 //Flow belongs to a already classified cluster with cause unknown


//Quality factor of the causal relationships
#define CAUSEQ_NOID_NOTIME 0  //no causal time relation, no causal id relation 
#define CAUSEQ_NOID_SOFTTIME 1 //causal weak time relation, no causal id relation  
#define CAUSEQ_NOID_TIME 2 //causal time relationship, no causal id relation
#define CAUSEQ_TIME 3 //causal time relationship, no causal id relatiosnhip possible (user event)
#define CAUSEQ_SOFTID_NOTIME 4 //no causal time relation, weak causal id relation
#define CAUSEQ_SOFTID_SOFTTIME 5 //weak causal time relation, weak causal id relation
#define CAUSEQ_SOFTID_TIME 6 //causal time relation, weak causal id relation
#define CAUSEQ_ID_NOTIME 7 //no causal time relation, causal id relation
#define CAUSEQ_ID_SOFTTIME 8 //weak causal time relation, causal id relation
#define CAUSEQ_ID_TIME 9 //causal time relation, causal id relation or relation not based on time and ID



class TFlow{
/**<@class TFlow
@brief Storage class for a bidirectional flow. 
*/

  public:
   int32_t 	NextFlowIndex;		///<Links to a next flow by an index (a kind of linked list) -1 = no next flow. 
   uint8_t	Status;			///<Status is the current status of the flow: 0=empty, 1=aggregated from 1 packet, 2=aggregated from more packets 
   int64_t 	StartTime;		///<Time of first packet in Flow in useconds sinze 1970.
   int64_t 	StopTime;		///<Time of last packet in Flow in useconds sinze 1970.
   
   int32_t 	NumberOfTransmittedBytes; 	///<Aggregated number of transmitted bytes
   int32_t 	NumberOfReceivedBytes;		///<Aggregated number of transmitted bytes

   int32_t 	NumberOfTransmittedPackets; 	///<Aggregated number of transmitted bytes
   int32_t 	NumberOfReceivedPackets;	///<Aggregated number of transmitted bytes
  
   uint8_t	Direction;		///<Flow direction: UNDEFINED(0), INGRESS(1), EGRESS(2)

   uint8_t  	Protocol;              	///<1=ICMP, 6=TCP, 17=UDP, 255=IP-other
   uint32_t 	LocalIP; 		///<IP-address of the observed local computer
   uint32_t 	RemoteIP;		///<IP-address of the remote computer
   uint16_t 	LocalPort;        	///<UDP/TCP=Port,  ICMP=identifier,  Other=0
   uint16_t 	RemotePort;          	///<UDP/TCP=Port   ICMP=sequence number, Other=0
   uint16_t	Identification;		///<Identification field (only defined for DNS, 0 for other protocols)
   uint8_t	TCPFlag;		///<Aggregated TCP-Flags if TCP-Flow
   uint32_t     LocalSEQ;		///<Local SEQ (0 if undefined)
   uint32_t     RemoteSEQ;		///<Remote expected SEQ (0 if undefined) 

//DNS-reference
   int32_t	DNSIndex;		///<points to DNS-name in a STRING-table, -1 = no DNS

//HTTP-reference and data
   int32_t      HTTPIndex;		///<if HTTP-flow, this index points to a special object that identifies triggers of new flows, 0 = no HTTP-traffic

//Causal data
   int32_t      TreeIndex;		///<id of the flow tree (tree id)
   int32_t	ParentFlow;		///<id of parent flow in the tree, 0=no parents (root flow)
   uint8_t 	Resolver;		///<bit 0..3=resolver protocol (0=nothing, 1=DNS, 2..15=spare, bit 7=1=resolved)   
   uint8_t 	Cause;			///<Cause of the Flow
   uint8_t 	CauseReliability;	///<Reliability of the cause
   uint64_t 	CausalTime;		///<Timestamp of the cause that created this flow


   TFlow(void);
/**<The constructor. Resets all the data-members, including NextFlow*/

   void clear(void); 
/**<Clears all the data-members, except NextFlow
@return void */

   uint16_t getHash(void); 
/**<Calculates a 10-bit hash by the XOR-sum of SourceIP, DestIP, Sourceport, DestPort and Identification.\n
This can be used for organising a fast lookup by a hash-table.\n
The value of hashes is set by FLOWHASHSIZE (default=1024).
@return HashValue */

   uint8_t match(uint8_t p, uint32_t lIP, uint32_t rIP, uint16_t lP, uint16_t rP, uint16_t id);
/**<Matches a flow by its addresses and port-numbers and protocol.
@return 1 if matches or 251-255 if it does not match (completely).
@param p Protocol number: 1=ICMP, 6=TCP, 17=UDP, 255=IP-other
@param lIP Local Ip-address
@param rIP Remote Ip-address
@param lP Local Port
@param rP Remote Port 
@param id Identication (DNS defined, 0 for other protocols)*/


   void print(char *content); 
/**<Prints a flow in readable format to a string
@return void 
@param *content pointer to content that must be printed. */
};


#endif /*FLOW_*/
