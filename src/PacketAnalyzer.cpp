/**@file PacketAnalyzer.cpp
@brief This file contains the operators of the TPacketAnalyzer class. 

@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@author Pieter Burghouwt
@version Revision 2.0
@date Tuesday, March 12, 2013
*/
/*PacketAnalyzer is a part of CITRIC.

CITRIC is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

CITRIC is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with CITRIC.  If not, see <http://www.gnu.org/licenses/>*/

#include <stdio.h>
#include <time.h>
#include "pdu.h"
#include "PacketAnalyzer.h"
#include "PCAP.h" 
#include "FlowAggregator.h"
#include "Settings.h"

extern TPCAP *PCAP;
extern TFlowAggregator *FlowAggregator;
extern TSettings *Settings;

TPacketAnalyzer::TPacketAnalyzer(){
  Time=0;
  Length=0;
  Protocol=0;
  SourceIP=0; 
  DestIP=0;
  SourcePort=0;
  DestPort=0;
  Identification=0;
  PayloadIndex=0;
  TCPFlag=0;
};


void TPacketAnalyzer::handleEvent(void){
  if(makePacket()==0){
    //dump();
    FlowAggregator->add();
  } else {
    //printf("\nWrong Packet!\n"); 
  } 
};


int8_t TPacketAnalyzer::makePacket(void){
  uint16_t index, i;

  //pcap specific data
  Time=PCAP->TimeStamp;
  Length=PCAP->Length;
  
  //Start L2 analysis
  index=0; 
  if(Length<(ETHERNET_LENGTH+IP_MIN_LENGTH)){
    printf("to short\n");
    return -1; // to short
  }
  if((PCAP->Packet[ETH_PROT_OFFSET]!=0x08)||(PCAP->Packet[ETH_PROT_OFFSET+1]!=0x00)){
     //printf("no ARPA: %x\n",(256*(uint16_t)PCAP->Packet[ETH_PROT_OFFSET])+(uint16_t)PCAP->Packet[ETH_PROT_OFFSET+1] );
    return -1; // no ARPA payload or ARP
  }

  //Start L3 analysis
  index+=ETHERNET_LENGTH; //ip offset  
  if((PCAP->Packet[index+IP_VERSION_OFFSET]&0xF0)!=0x40){
    printf("no ipv4: %x\n",PCAP->Packet[index+IP_VERSION_OFFSET] );
    return -1; // no ipv4 with 5 words header
  }
  Protocol=PCAP->Packet[index+IP_PROT_OFFSET];
  SourceIP=((uint32_t)PCAP->Packet[index+IP_SOURCE_OFFSET]<<24)+((uint32_t)PCAP->Packet[index+IP_SOURCE_OFFSET+1]<<16)+((uint32_t)PCAP->Packet[index+IP_SOURCE_OFFSET+2]<<8)+((uint32_t)PCAP->Packet[index+IP_SOURCE_OFFSET+3]);
  DestIP=((uint32_t)PCAP->Packet[index+IP_DEST_OFFSET]<<24)+((uint32_t)PCAP->Packet[index+IP_DEST_OFFSET+1]<<16)+((uint32_t)PCAP->Packet[index+IP_DEST_OFFSET+2]<<8)+((uint32_t)PCAP->Packet[index+IP_DEST_OFFSET+3]);

  //Start L4 or ICMP analysis
  TCPFlag=0;
  TCPValid=0; //Undefined for at this stage
  index+=(PCAP->Packet[index+IP_LENGTH_OFFSET]&0x0F)<<2;
  Identification=0;
  switch(Protocol){
    case TCP:
      SourcePort=((uint16_t)PCAP->Packet[index+SOURCE_PORT_OFFSET]<<8)+((uint16_t)PCAP->Packet[index+SOURCE_PORT_OFFSET+1]);
      DestPort=((uint16_t)PCAP->Packet[index+DEST_PORT_OFFSET]<<8)+((uint16_t)PCAP->Packet[index+DEST_PORT_OFFSET+1]);
      TCPFlag=(uint8_t)PCAP->Packet[index+TCP_FLAG_OFFSET]; //URG, ACK, PSH, RST, SYN, FIN (FIN=bit0)
      TCPSEQ=0; TCPACK=0;
      for(i=0; i<=3; i++){
        TCPSEQ=(TCPSEQ<<8)+PCAP->Packet[index+TCP_SEQ_OFFSET+i];
        TCPACK=(TCPACK<<8)+PCAP->Packet[index+TCP_ACK_OFFSET+i];
      }
      //TCPFlag=(uint8_t)PCAP->Packet[index+TCP_FLAG_OFFSET]&0x0F; //only PSH, RST, SYN, FIN
      /*old stuff that places ACK over PSH
      TCPFlag=(uint8_t)PCAP->Packet[index+TCP_FLAG_OFFSET]&0x1F; //only ACK, PSH, RST, SYN, FIN

      if(TCPFlag>=0x10){
        TCPFlag&=0xEF; //clear ACK-Flag - bit 4
        TCPFlag|=0x08; //and place it in bit 3 (new place ACK-flag)
      } else {
        TCPFlag&=0x07; //clear bit 3 (new place ACK flag)
      }
      */
      index+=(PCAP->Packet[index+TCP_LENGTH_OFFSET]&0xF0)>>2;
      break;
    case UDP:
      SourcePort=((uint16_t)PCAP->Packet[index+SOURCE_PORT_OFFSET]<<8)+((uint16_t)PCAP->Packet[index+SOURCE_PORT_OFFSET+1]);
      DestPort=((uint16_t)PCAP->Packet[index+DEST_PORT_OFFSET]<<8)+((uint16_t)PCAP->Packet[index+DEST_PORT_OFFSET+1]);
      index+=UDP_LENGTH;
      //Patching UDP localport for Windws XP behavior
/*    if(DNS_PORTPATCH==1){
        if((Length-index)>4){
          if(SourcePort==53) {
            DestPort=(uint16_t)((uint16_t)PCAP->Packet[index]<<8)+((uint16_t)PCAP->Packet[index+1]);
          } else  if(DestPort==53){
            SourcePort=(uint16_t)((uint16_t)PCAP->Packet[index]<<8)+((uint16_t)PCAP->Packet[index+1]);
          }
        }
      }*/
      //End of patch
      if(((Length-index)>4)&&((SourcePort==53)||(DestPort==53))&&(DNS_PORTPATCH==1)){
        Identification=((uint16_t)PCAP->Packet[index+DNS_IDENTIFICATION]<<8)+((uint16_t)PCAP->Packet[index+DNS_IDENTIFICATION+1]);
      } 
      break;     
    case ICMP:
      if((PCAP->Packet[index+ICMP_TYPE_OFFSET]==0)||(PCAP->Packet[index+ICMP_TYPE_OFFSET]==8)){
        SourcePort=((uint16_t)PCAP->Packet[index+ICMP_ID_OFFSET]<<8)+((uint16_t)PCAP->Packet[index+ICMP_ID_OFFSET+1]);
        DestPort=((uint16_t)PCAP->Packet[index+ICMP_SEQ_OFFSET]<<8)+((uint16_t)PCAP->Packet[index+ICMP_SEQ_OFFSET+1]);
      } else {
        SourcePort=PCAP->Packet[index+ICMP_TYPE_OFFSET];   
        DestPort=PCAP->Packet[index+ICMP_CODE_OFFSET];   
      };
      //index not increased with ICMP, because payload is in ICMP
      break;     
     default: //not recognized so no flow
       SourcePort=0;
       DestPort=0;
       //printf("Unknown:%d \n", LastFlow->Type);
   }  
   PayloadIndex=index; //for later deep inspection in Packet, points to the first field after L4.
   return 0;
}


void TPacketAnalyzer::dump(void){
uint8_t *temp;

  printf("\nT=%f, L=%d, prot=%d, ", (double)Time/1000000, Length, Protocol);
  printf("TCPFlag=%X, ", TCPFlag);
  printf("PayloadIndex=%d, ",PayloadIndex);
  temp=(uint8_t *)&SourceIP; printf("src=%d.%d.%d.%d:", temp[3], temp[2], temp[1], temp[0]);
  printf("%d, ", SourcePort);
  temp=(uint8_t *)&DestIP; printf("dest=%d.%d.%d.%d:", temp[3], temp[2], temp[1], temp[0]);
  printf("%d\n", DestPort);
  fflush(stdout);
};

