/**@file PacketAnalyzer.h
@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@brief This file contains the prototypes of the TPacketAnalyzer class. 
@author Pieter Burghouwt
@version Revision 2.0
@date Tuesday, March 12, 2013
*/

#ifndef PACKETANALYZER_
#define PACKETANALYZER_

#include <stdint.h>
#include "PCAP.h"
#include "pdu.h"


class TPacketAnalyzer{
/**<@class TPacketAnalyzer
@brief Class for analyzing an arrived packet.

If a packet arrives, this singleton will handle the event.\n
After analysis of L3 and L4, the FlowAnalyzer class is called for further processing.
*/

  private:   
    int8_t makePacket(void);

  public:
    int64_t 	Time; 			///<Time of Packet-arrival in seconds sinze 1970.
    int32_t 	Length; 		///<Number of available packet-bytes.
    uint8_t  	Protocol; 		///<IP-Protocol-Field:1=ICMP, 6=TCP, 17=UDP, 255=IP-other.
    uint32_t 	SourceIP; 		///<IP source sddress
    uint32_t 	DestIP;			///<IP destination address
    uint16_t 	SourcePort;     	///<PORT if UDP/TCP else IDENTIFIER if ICMP or 0 if other L4-protocol
    uint16_t 	DestPort;       	///<PORT if UDP/TCP else SEQUENCE NUMBER if ICMP or 0 if other L4-protocol
    uint8_t	TCPFlag;		///<TCP FlagRegister bit0=FIN, bit1=SYN, bit2=RST, bit3=PSH bit4=ACK, bit 5=URG
    uint32_t	TCPSEQ;			///<TCP SEQ NR
    uint32_t	TCPACK;			///<TCP ACK NR
    uint16_t	Identification; 	///<Identification (DNS)
    int32_t	PayloadIndex;   	///<Start of the Payload after L4 in Packet
    int8_t	TCPValid;		///<1=TCP_Packet expected, 0=Undefined, -1=TCP_Packet unexpected (written from Flow)

    TPacketAnalyzer();
/**<The constructor. Resets all the data-members*/

    void handleEvent(void);	
/**<Analyzes a packet and fills the public members with actual values of the arrived packet. 
@return void */

    void dump(void);    
/**<Dumps packet shortlist to stdout for debug purpose.
@return void*/
};

#endif /*PACKETANALYZER_*/
