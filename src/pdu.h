/**@file pdu.h
@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@brief This file contains PDU-fields, places and values. 
@author Pieter Burghouwt
@version Revision 2.0
@date Saturday, March 9, 2013
*/

#ifndef PDU_
#define PDU_

#define ETHERNET_LENGTH 14
#define IP_MIN_LENGTH 20
//#define TCP_LENGTH 20
#define UDP_LENGTH 8
#define ICMP_LENGTH 4

#define ETH_PROT_OFFSET 12

#define IP_VERSION_OFFSET 0
#define IP_LENGTH_OFFSET 0
#define IP_PROT_OFFSET 9
#define IP_SOURCE_OFFSET 12
#define IP_DEST_OFFSET 16

#define UDP_LENGTH 8
#define TCP_LENGTH_OFFSET 12   //not 13
#define TCP_SEQ_OFFSET 4
#define TCP_ACK_OFFSET 8
#define TCP_FLAG_OFFSET 13
#define SOURCE_PORT_OFFSET 0
#define DEST_PORT_OFFSET 2

#define ICMP_TYPE_OFFSET 0
#define ICMP_CODE_OFFSET 1
#define ICMP_ID_OFFSET 4
#define ICMP_SEQ_OFFSET 6

#define TCP 6
#define UDP 17
#define ICMP 1
#define OTHER 255

#define DNS_IDENTIFICATION 0
#define DNS_OPCODE_OFFSET 2
#define DNS_RCODE_OFFSET 3
#define DNS_NUMBER_OF_QUESTIONS_OFFSET 4
#define DNS_NUMBER_OF_ANSWERS_OFFSET 6
#define DNS_QUESTIONS_OFFSET 12

#endif /*PDU_*/
