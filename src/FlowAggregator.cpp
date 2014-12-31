/**@file FlowAggregator.cpp
@brief This file contains the operators of the TFlowAggregator class. 

@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@author Pieter Burghouwt
@version Revision 2.0
@date Tuesday, March 12, 2013
*/
/*FlowAggregator is a part of CITRIC.

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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "PacketAnalyzer.h"
#include "FlowAggregator.h"
#include "Flow.h"
#include "DNSHelper.h"
#include "CauseAnalyzer.h"
#include "HTTPHelper.h"
#include "UDPUA.h"
#include "Logger.h"

extern TPCAP *PCAP;
extern TPacketAnalyzer *PacketAnalyzer;
extern TDNSHelper *DNSHelper;
extern TCauseAnalyzer *CauseAnalyzer;
extern THTTPHelper *HTTPHelper;
extern TUDPUA *UDPUA;
extern TLogger *Logger;

int32_t FlowTable[FLOWHASHSIZE];
TFlow Flow[FLOWBUFFERSIZE];



//*****************************************************************************
TFlowAggregator::TFlowAggregator(uint32_t lIP){

  
  uint32_t x;

  Index=-1;  //Optimzation, set after a find
  Size=0;
  WriteIndex=-1;
  LocalIP=lIP;  //determining the LocalIP for later direction determination
  Direction=UNDEFINED_DIR;  //Will be defined EGRESS or INGRESS after a successful find
  //uint8_t *temp; temp=(uint8_t *)&LocalIP; printf("New FlowAggregator with LocalAddress= %d.%d.%d.%d: \n", temp[3], temp[2], temp[1], temp[0]);
  for(x=0; x<FLOWHASHSIZE; x++){
      FlowTable[x]=-1;	//clearing FlowTable 
  }

  //clearing stats;
  TotalPacketCounter=0;
  InPacketCounter=0;
  OutPacketCounter=0;
  NoLocalPacketCounter=0;

  EgressFlowCounter=0;
  IngressFlowCounter=0;
  AlreadyOpenCounter=0;

  EgressUDPFlowCounter=0;
  NonEmptyRRUDPCounter=0;
  IngressUDPFlowCounter=0;
  EgressTCPFlowCounter=0;
  IngressTCPFlowCounter=0;
  EgressICMPFlowCounter=0;    
  IngressICMPFlowCounter=0;
  EgressOtherFlowCounter=0;    
  IngressOtherFlowCounter=0;

  EgressHTTPFlowCounter=0;
  EgressHTTPSFlowCounter=0;
  EgressDNSFlowCounter=0;

  StartTime=0;
};


//*****************************************************************************
uint8_t TFlowAggregator::add(void){
  uint8_t result, exist;

  //usleep(1000);
  TotalPacketCounter++;
  if(StartTime==0) StartTime=PacketAnalyzer->Time;
  exist=find();
  result=0;
  if (exist==1){ 
    //printf("add\n");
    result=addPacket();
  } else if(exist==2) {
    //printf("create %d\n",Size);
    result=addFlow();
  } else {
    NoLocalPacketCounter++;
  }
  return result;
};


//*****************************************************************************
uint8_t TFlowAggregator::find(void){  
  return find(PacketAnalyzer->Protocol, PacketAnalyzer->SourceIP, PacketAnalyzer->DestIP, PacketAnalyzer->SourcePort, PacketAnalyzer->DestPort, PacketAnalyzer->Identification);
};



//*****************************************************************************
uint8_t TFlowAggregator::find(uint8_t p, uint32_t sIP, uint32_t dIP, uint16_t sP,uint16_t dP, uint16_t id){ 
  uint16_t hash, lP, rP;
  uint32_t lIP, rIP;
  int32_t i;
 
  Index=-1;  //resetting Index until we know something better
  Direction=UNDEFINED_DIR; //resetting Direction until we know something better
  //step 1: putting the addresses in local/remote sequence or handling UDP user event
  if(sIP==LocalIP){
    if((PacketAnalyzer->Protocol==17)&&(PacketAnalyzer->DestPort==1234)){
      if(UDPUA->processEvent()!=-1) {
        //UDPUA->dump();
        //return 0; ///udp user event handled so we stop the find
      }
      //udp user event format not recognized so we continue
    }
    lIP=sIP; lP=sP; rIP=dIP; rP=dP;  // egress: no swap
    Direction=EGRESS;
  } else if(dIP==LocalIP){
    if(p!=ICMP){
      lIP=dIP; lP=dP; rIP=sIP; rP=sP; //ingress: swap for non ICMP (UDP, TCP)
    } else {
      lIP=dIP; lP=sP; rIP=sIP; rP=dP;  //ingress: no port swap for ICMP
    }
    Direction=INGRESS;      
  } else {
      //printf("No Local IP address!\n");
      return 0; //no LocalIP found hence no flow to find
  }
    
    
  //step 2: searching in the right table   
  hash=(uint16_t)((lIP^rIP^(uint32_t)lP^(uint32_t)rP^(uint32_t)id)&(FLOWHASHSIZE-1));
  i=FlowTable[hash];
  while(i!=-1){
    Index=i; 				//if not empty hash group
    if(Flow[i].match(p, lIP, rIP, lP, rP, id)==1){  	//match flow
      //printf("match\n");
      return 1;						//match ! Index indicates the Flow
    } else {
      i=Flow[i].NextFlowIndex;			//find next in chain
    }
  }
  //printf("FlowAggregator::find:Nothing found\n");
  return 2; //nothing found, Index points to the last valid Flow with the same hash or 0 if nonexistent
}




//*****************************************************************************
uint8_t TFlowAggregator::addPacket(void){
  //only to be called after a successful find
  int dnsresult;
  //uint32_t seqdiff;

  //printf("Adding to existing flow %d\n",Index);  
  Flow[Index].StopTime=PacketAnalyzer->Time;
  Flow[Index].Status=2; //not the first packet anymore
  if(Direction==INGRESS){
    //INGRESS PACKET
    Flow[Index].NumberOfReceivedBytes+=PacketAnalyzer->Length;
    if(PacketAnalyzer->Protocol==6){
      //TCP-update
      Flow[Index].TCPFlag|=(PacketAnalyzer->TCPFlag)<<4;

      if(PacketAnalyzer->TCPSEQ==Flow[Index].RemoteSEQ){
        //SEQ is as expected
        Flow[Index].RemoteSEQ=PacketAnalyzer->TCPSEQ+(uint32_t)PacketAnalyzer->Length-(uint32_t)PacketAnalyzer->PayloadIndex;
        PacketAnalyzer->TCPValid=1;
      } else {
        PacketAnalyzer->TCPValid=-1;
        if((PCAP->Packet[PacketAnalyzer->PayloadIndex]=='H')&&(PCAP->Packet[PacketAnalyzer->PayloadIndex+1]=='T')){
          //repairing sequence by reset
          PacketAnalyzer->TCPValid=2;
          Flow[Index].RemoteSEQ=PacketAnalyzer->TCPSEQ+(uint32_t)PacketAnalyzer->Length-(uint32_t)PacketAnalyzer->PayloadIndex;
        }
      }
      //printf(" TCPValid:%d\n", PacketAnalyzer->TCPValid);
    }

/*
      seqdiff=PacketAnalyzer->TCPSEQ-Flow[Index].RemoteSEQ;
      //printf("INGRESS PACKET AT:%lu SEQ:%u, LastSEQ:%u Diff:%u", PacketAnalyzer->Time, PacketAnalyzer->TCPSEQ, Flow[Index].RemoteSEQ, seqdiff);      
      if(((seqdiff<2000)&&(seqdiff>0))||(Flow[Index].RemoteSEQ==0)){

        //in sequence
        PacketAnalyzer->TCPValid=1;
        Flow[Index].RemoteSEQ=PacketAnalyzer->TCPSEQ;
      } else {
        //not in sequence
        PacketAnalyzer->TCPValid=-1;
        if((PCAP->Packet[PacketAnalyzer->PayloadIndex]=='H')&&(PCAP->Packet[PacketAnalyzer->PayloadIndex+1]=='T')){
          //repairing sequence by reset
          PacketAnalyzer->TCPValid=2;
          Flow[Index].RemoteSEQ=PacketAnalyzer->TCPSEQ;
        }
      }

*/

    Flow[Index].NumberOfReceivedPackets++;
    InPacketCounter++;  
  } else {
    //EGRESS Packet
    Flow[Index].NumberOfTransmittedBytes+=PacketAnalyzer->Length;
    if(PacketAnalyzer->Protocol==6){
      //TCP-update
      Flow[Index].TCPFlag|=PacketAnalyzer->TCPFlag;
/*      printf("EGRESS:%ld SEQ:%d, ACK:%d, LocalACK:%d, RemoteACK:%d\n", PacketAnalyzer->Time ,PacketAnalyzer->TCPSEQ,PacketAnalyzer->TCPACK,Flow[Index].LocalACK, Flow[Index].RemoteACK);      
      if(PacketAnalyzer->TCPSEQ==Flow[Index].RemoteACK){
        //in sequence
        PacketAnalyzer->TCPValid=1;
        Flow[Index].LocalACK=PacketAnalyzer->TCPACK;
      } else if(Flow[Index].RemoteACK==0) {
        PacketAnalyzer->TCPValid=1;
        Flow[Index].LocalACK=PacketAnalyzer->TCPACK;
      } else {
        //not in sequence
        PacketAnalyzer->TCPValid=-1; 
      }*/
    }
    Flow[Index].NumberOfTransmittedPackets++;
    OutPacketCounter++;	
  }
  //delegate control for deep inspection
  if((Flow[Index].Protocol==6)&&((Flow[Index].RemotePort==80)||(Flow[Index].RemotePort==443))) HTTPHelper->add();
  if((Flow[Index].Protocol==17)&&(Flow[Index].RemotePort==53)){ 
    dnsresult=DNSHelper->add();
    if((dnsresult==1)||(dnsresult==2)) NonEmptyRRUDPCounter++; //count valid DNS answers (A-records)
  }
  return 1;
}


//*****************************************************************************
uint8_t TFlowAggregator::addFlow(void){
  //only to be called after un unsuccesful find !!!!!
  int32_t OldIndex;

  //step 1 saving Index and finding an empty Flow
  OldIndex=Index; //need to save for later linking
  if(Size==FLOWBUFFERSIZE-1) printf(">7 ERROR, FLOW BUFFER FULL, OVERWRITING OLDEST FLOW: %ld\n",PacketAnalyzer->Time);  
  WriteIndex++; if(WriteIndex>=FLOWBUFFERSIZE) WriteIndex=0;
  Index=WriteIndex;
  Size++;
  Flow[Index].clear();
 
  //step 2 fill the flow 
  if(PacketAnalyzer->SourceIP==LocalIP){
    //EGRESS
    Flow[Index].Direction=EGRESS;
    Flow[Index].LocalIP=PacketAnalyzer->SourceIP;
    Flow[Index].LocalPort=PacketAnalyzer->SourcePort;
    Flow[Index].RemoteIP=PacketAnalyzer->DestIP;
    Flow[Index].RemotePort=PacketAnalyzer->DestPort;
    Flow[Index].Identification=PacketAnalyzer->Identification;
    Flow[Index].NumberOfTransmittedBytes=PacketAnalyzer->Length;
    Flow[Index].TCPFlag=PacketAnalyzer->TCPFlag&0x0F; //place in lower nybble
    Flow[Index].Cause=CAUSE_UNKNOWN; //resetting the cause
    Flow[Index].NumberOfTransmittedPackets++;
    OutPacketCounter++; 
    if(PacketAnalyzer->Protocol==6){
      //first test on correct opening of TCP (by FlagRegister bit0=FIN, bit1=SYN, bit2=RST, bit3=PSH)
      if((PacketAnalyzer->TCPFlag&0x12)!=2){
        Flow[Index].Cause=CAUSE_ALREADYOPEN;
        AlreadyOpenCounter++;
        //printf("F");
      }
      EgressTCPFlowCounter++;
      Flow[Index].LocalSEQ=0;  //not in use
      Flow[Index].RemoteSEQ=0;
      if(Flow[Index].RemotePort==80){
        EgressHTTPFlowCounter++;
      } else if(Flow[Index].RemotePort==443){
	EgressHTTPSFlowCounter++;
      }
    }else if(PacketAnalyzer->Protocol==17){
      EgressUDPFlowCounter++;
      if(Flow[Index].RemotePort==53) EgressDNSFlowCounter++;
    } else if(PacketAnalyzer->Protocol==1){
      EgressICMPFlowCounter++;
    } else {
      EgressOtherFlowCounter++;
    }
    //updating statistics
    EgressFlowCounter++;
  } else if(PacketAnalyzer->DestIP==LocalIP){
    //INGRESS
    Flow[Index].Direction=INGRESS;
    Flow[Index].NumberOfTransmittedBytes=PacketAnalyzer->Length;
    Flow[Index].TCPFlag=(PacketAnalyzer->TCPFlag)<<4; //place in higher nybble  
    Flow[Index].Cause=CAUSE_UNKNOWN; //resetting the cause
    Flow[Index].NumberOfTransmittedPackets++;
    InPacketCounter++; 
    if(PacketAnalyzer->Protocol!=1){
      //ingress: swap for non ICMP (UDP, TCP)
      Flow[Index].LocalIP=PacketAnalyzer->DestIP;
      Flow[Index].LocalPort=PacketAnalyzer->DestPort;
      Flow[Index].RemoteIP=PacketAnalyzer->SourceIP;
      Flow[Index].RemotePort=PacketAnalyzer->SourcePort;
      Flow[Index].Identification=PacketAnalyzer->Identification;
      if(PacketAnalyzer->Protocol==6){
        if((PacketAnalyzer->TCPFlag&0x12)!=2){
          Flow[Index].Cause=CAUSE_ALREADYOPEN;
          AlreadyOpenCounter++;
          //printf("F");
        }
        IngressTCPFlowCounter++;
      } else if(PacketAnalyzer->Protocol==17){
        IngressUDPFlowCounter++;
      } else {
        IngressOtherFlowCounter++;
      }
    } else {
      //ingress: no Port swap for ICMP
      Flow[Index].LocalIP=PacketAnalyzer->DestIP;
      Flow[Index].LocalPort=PacketAnalyzer->SourcePort;
      Flow[Index].RemoteIP=PacketAnalyzer->SourceIP;
      Flow[Index].RemotePort=PacketAnalyzer->DestPort;
       Flow[Index].Identification=PacketAnalyzer->Identification;
      IngressICMPFlowCounter++;
    }
    IngressFlowCounter++;
  } else {
    //no local IP-address: just make some debug noise now
    //This cannot happen after a proper find!!
    printf("ERROR!!!!!!!: FlowAggregator::addFlow:NoLocalIPAddress\n");
    PacketAnalyzer->dump();
    //roll back
    WriteIndex--; if(WriteIndex<=-1) WriteIndex=FLOWBUFFERSIZE-1;
    Size--;
    return 0; //no LocalIP hence no flow creation
  }
  Flow[Index].NextFlowIndex=-1;
  Flow[Index].Status=1; //first packet in this flow
  Flow[Index].StartTime=PacketAnalyzer->Time;
  Flow[Index].StopTime=PacketAnalyzer->Time;
  Flow[Index].Protocol=PacketAnalyzer->Protocol;

  //step 3 put the flowindex in the correct link or hash table  
  if(OldIndex!=-1){
    Flow[OldIndex].NextFlowIndex=Index;
  } else {
    FlowTable[Flow[Index].getHash()]=Index;
  }

  //step 4 Classify flow in a new or existing tree
  if((Flow[Index].Protocol==17)&&(Flow[Index].RemotePort==53)){
    DNSHelper->add(); //Analysis of DNS Query
    CauseAnalyzer->add(DNSHelper->getQueryName()); //find cause of DNS Query 
  } else {
    CauseAnalyzer->add(NULL); //find Cause of NON-DNS Query
  }

  //step 5 Do some futher deep inspection in HTTP(S)
  if(Flow[Index].Protocol==6){
    if((Flow[Index].RemotePort==80)||(Flow[Index].RemotePort==443)) HTTPHelper->add();      
  } 

  return 1; 
};



//*****************************************************************************
uint8_t TFlowAggregator::deleteFlow(int32_t i){

  int32_t nextIndex, previousIndex, presentIndex;

  //step 1: find the next flow in the table
  nextIndex=Flow[i].NextFlowIndex;
  Index=0; //derefencing
  
  //step 2: find the previous flow in table
  presentIndex=FlowTable[Flow[i].getHash()];
  previousIndex=-1;
  while((presentIndex!=i)&&(presentIndex!=-1)){
    previousIndex=presentIndex;
    presentIndex=Flow[presentIndex].NextFlowIndex;
  }
  
  //step 3: deleting
  if(presentIndex!=-1){    
    //flow found
    if(previousIndex!=-1){  
      //not the first
      Flow[previousIndex].NextFlowIndex=nextIndex;
    } else {               
      // is the first
      FlowTable[Flow[i].getHash()]=-1;
    }
    Flow[i].clear();
    return 1;
  } else { 
    //flow not found from hashtable
    while(Flow[i].NextFlowIndex!=-1){
      previousIndex=i;
      i=Flow[i].NextFlowIndex;
      Flow[previousIndex].clear();
    }
  }  
  return 0;
}



//*****************************************************************************
void TFlowAggregator::dump(char *dm, int dest){
  uint32_t x;

  sprintf(dm,"FLOW-ID, Tstart, Tstop, Prot, IPlocal, Portlocal, IPremote, Portremote, Identification, TCPFlags,Ptrans, Prec, Ntrans, Nrec, Dir, Status, DNSIndex, HTTPIndex, TreeIndex, Cause, ParentFlow, Name\n");
  for(x=0;x<FLOWBUFFERSIZE; x++){
    if(Flow[x].Status!=0){
      sprintf(dm+strlen(dm), "%d, ",x);
      Flow[x].print(dm);
    }
  }
  if(dest==1){
    Logger->save(".flow", dm);
  } else {
    printf("%s", dm);
  }

  sprintf(dm, "TIME STATISTICS\n");
  sprintf(dm+strlen(dm), "Capture Start Time:\t\t\t%lf s\n", (double)StartTime/1000000);
  sprintf(dm+strlen(dm), "Capture Stop Time:\t\t\t%lf s\n", (double)PacketAnalyzer->Time/1000000);
  sprintf(dm+strlen(dm), "Capture Duration:\t\t\t%lf s\n\n", (double)PacketAnalyzer->Time/1000000-(double)StartTime/1000000);

  sprintf(dm+strlen(dm), "PACKET STATISTICS\n");
  sprintf(dm+strlen(dm), "Total Number of IP Packets:\t\t%d\n", TotalPacketCounter);
  sprintf(dm+strlen(dm), "\tEgress PacketCount:\t\t%d\n", OutPacketCounter);
  sprintf(dm+strlen(dm), "\tIngress PacketCount:\t\t%d\n", InPacketCounter);
  sprintf(dm+strlen(dm), "\tnon-local PacketCount:\t\t%d\n\n", NoLocalPacketCounter);

  sprintf(dm+strlen(dm), "FLOW STATISTICS\n");
  sprintf(dm+strlen(dm), "Total FlowCount:\t\t\t%d\n",Size);
  sprintf(dm+strlen(dm), "\tEgress FlowCount:\t\t%d\n", EgressFlowCounter);
  sprintf(dm+strlen(dm), "\t\tTCP FlowCount:\t\t%d\n", EgressTCPFlowCounter);
  sprintf(dm+strlen(dm), "\t\tHTTP FlowCount:\t\t%d\n", EgressHTTPFlowCounter);
  sprintf(dm+strlen(dm), "\t\tHTTPS FlowCount:\t%d\n", EgressHTTPSFlowCounter);
  sprintf(dm+strlen(dm), "\t\tUDP FlowCount:\t\t%d\n", EgressUDPFlowCounter);
  sprintf(dm+strlen(dm), "\t\tDNS FlowCount:\t\t%d\t(%d answers with valid A records)\n", EgressDNSFlowCounter, NonEmptyRRUDPCounter);
  sprintf(dm+strlen(dm), "\t\tICMP FlowCount:\t\t%d\n", EgressICMPFlowCounter);
  sprintf(dm+strlen(dm), "\t\tOther Flowcount\t\t%d\n", EgressOtherFlowCounter);
  sprintf(dm+strlen(dm), "\tIngress FlowCount:\t\t%d\n", IngressFlowCounter);
  sprintf(dm+strlen(dm), "\t\tTCP FlowCount:\t\t%d\n", IngressTCPFlowCounter);
  sprintf(dm+strlen(dm), "\t\tUDP FlowCount:\t\t%d\n", IngressUDPFlowCounter);
  sprintf(dm+strlen(dm), "\t\tICMP FlowCount:\t\t%d\n", IngressICMPFlowCounter);
  sprintf(dm+strlen(dm), "\t\tOther FlowCount:\t%d\n", IngressOtherFlowCounter);
  sprintf(dm+strlen(dm), "\tAlready open FlowCount:\t\t%d\n\n", AlreadyOpenCounter);

  if(dest==1){
    Logger->saveStatsLog(dm);
  } else {
    printf("%s", dm);
  }
};    


