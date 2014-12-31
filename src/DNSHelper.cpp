/**@file DNSHelper.cpp
@brief This file contains the operators of the TDNSHelper class. 

@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@author Pieter Burghouwt
@version Revision 2.0
@date Thursday, February 28, 2013
*/
/*DNSHelper is a part of CITRIC.

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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "pdu.h"
#include "PCAP.h"
#include "DNSHelper.h"
#include "DNS.h"
#include "FlowAggregator.h"
#include "EventCollector.h"
#include "CauseAnalyzer.h"
#include "Flow.h"
#include "Logger.h"

extern TPCAP *PCAP; //needed for deep inspection in the UDP-payload
extern TPacketAnalyzer *PacketAnalyzer; //needed for deep inspection in the UDP-payload
extern TFlowAggregator *FlowAggregator; //needed to store FlowAggregator->Index
extern TEventCollector *EventCollector;
extern TCauseAnalyzer *CauseAnalyzer;
extern TLogger *Logger;
extern TFlow Flow[FLOWBUFFERSIZE];

TDNS DNS[DNSBUFFERSIZE];

//*****************************************************************************
TDNSHelper::TDNSHelper(void){
  uint32_t i;

  Size=0;
  Index=0;  //Optimzation, set after a find
  srand(time(NULL)); //for new DNS
  for(i=0; i<DNSHASHSIZE; i++){
      DNSTable[i]=-1;	
  }
};


//*****************************************************************************
uint8_t TDNSHelper::add(void){

  uint8_t answer, returnvalue;
  uint16_t offset, start, stop, i, j; 
  uint32_t IP, TTL, newindex;

  clearQueryName();  //clearing storage 
  if(Flow[FlowAggregator->Index].Direction==INGRESS) return 0; //only egress DNS flows are interesting for analysis
  
  returnvalue=1; //addition with no new elements
  //Making easy variables
  Length=(uint16_t)(PacketAnalyzer->Length - PacketAnalyzer->PayloadIndex); //The entire length of DNS payload
  Packet=&PCAP->Packet[PacketAnalyzer->PayloadIndex]; //the same as Packet in PCAP but starting at DNS-header

  //Testing for correct DNS-response
  if(Length<12) return 3; //to small for DNS payload
  if(((Packet[DNS_RCODE_OFFSET])&0x07)!=0x00) return 5;  //error return code 
  if((Packet[DNS_NUMBER_OF_QUESTIONS_OFFSET])!=0x00) return 6;  //not 1 question
  if((Packet[DNS_NUMBER_OF_QUESTIONS_OFFSET+1])!=0x01) return 7;  //not 1 question
  if((Packet[DNS_NUMBER_OF_ANSWERS_OFFSET])!=0x00) return 8;  //to many answers (>255)
  if(((Packet[DNS_OPCODE_OFFSET])&0xF0)==0x80){
    //standard response   
    //How many answers?
    answer=Packet[DNS_NUMBER_OF_ANSWERS_OFFSET+1];
    if(answer==0) return 9; //no answers  
    //printf("\n\nAnswers %d\n",answer);

    //OK we are in business
    //clearQueryName();  //clearing storage
    offset=DNS_QUESTIONS_OFFSET; //start of questionrecord  
    //if(offset==0) return 10; //error no offset = fixed value
    while(Packet[offset]!=0){
      start=offset+1;
      stop=start+Packet[offset];
      if(stop>=Length) return 11; //out of bounds
      for(i=start; i<stop; i++) addToQueryName(Packet[i]);
      addToQueryName('.');
      offset=stop;  
    }
    if(QueryNameIndex>0) QueryName[QueryNameIndex-1]=0;  //removing trailing FQDN dot
    //printf("QUERY:%s\n\n",QueryName);

    //Now through all RR's
    offset+=5; //1+4 fields
    if(offset+1>=Length) return 12; //error out of bounds
    //printf("ANSWER:\n");
    for(j=0; (j<answer); j++){
      if(j!=0){
        offset=offset+8; //move to the resource data length
        if(offset+1>=Length) return 16;
        offset=offset+2+256*(uint16_t)Packet[offset]+(uint16_t)Packet[offset+1];
        if(offset+1>=Length) return 17;    
      }
      clearAnswerName();
      offset=parseName(offset);
      //printf("NR: %d = %s",j,AnswerName);
      if(offset+1>=Length) return 13;    
      if((Packet[offset]==0)&&(Packet[offset+1]==1)){
      //we have a record
        if(offset+13>=Length) return 14;
        IP=((uint32_t)Packet[offset+10]<<24)+((uint32_t)Packet[offset+11]<<16)+((uint32_t)Packet[offset+12]<<8)+((uint32_t)Packet[offset+13]);
        TTL=((uint32_t)Packet[offset+4]<<24)+((uint32_t)Packet[offset+5]<<16)+((uint32_t)Packet[offset+6]<<8)+((uint32_t)Packet[offset+7]);
      
        if(AnswerNameIndex>0) AnswerName[AnswerNameIndex-1]=0;  //removing trailing FQDN dot
  
        //printf("TTL=%d", TTL);
        //temp=(uint8_t *)&IP; printf(" -> A:%d.%d.%d.%d\n", temp[3], temp[2], temp[1], temp[0]);

        //here we have to process the query in either an update or a new DNS-record      
        Index=-1;
        if(find(IP, QueryName)==0){
          //nothing found -> create new DNS record
          returnvalue=2;
          newindex=Size%DNSBUFFERSIZE;      //ALTERNATIVE: newindex=(uint32_t)rand()%(DNSBUFFERSIZE-1);
          i=0;
          while(DNS[newindex].TimeStamp!=0){
            newindex++; if(newindex>=DNSBUFFERSIZE) newindex=0;
            i++;
            if(i>DNSBUFFERSIZE-1) return 15; //buffer full
          }

          //Fill DNS-record
          DNS[newindex].set(FlowAggregator->Index, PacketAnalyzer->Time, IP, TTL, QueryName, AnswerName);
          DNS[newindex].Resolved=0; //for statistics
          //TODO add oldtimestamp to set operation and clear oldtimestamp
          DNS[newindex].NextDNSIndex=-1; //last in the list
          //Connecting in the hashtable
          if(Index!=-1){ 
            DNS[Index].NextDNSIndex=newindex; //penultimate in the lists connects to the new item  
          } else {
            DNSTable[makeIPHash(DNS[newindex].IP)]=newindex; 
          }
          Size++;
          //EventCollector->addDNSEvent(PacketAnalyzer->Time, IP, newindex);
        } else {
          //update existing record
          //TODO move time to oldtimestamp
          DNS[Index].TimeStamp=PacketAnalyzer->Time;
          DNS[Index].FlowIndex=FlowAggregator->Index;
          DNS[Index].TTL=TTL;
          DNS[Index].Resolved=0;
          //EventCollector->addDNSEvent(PacketAnalyzer->Time, IP, Index);
        }
      }//end of we have a record
    }
  } else if((Packet[DNS_OPCODE_OFFSET]&0xF0)==0x00){
    if(Flow[FlowAggregator->Index].NumberOfTransmittedPackets>1) return 16; //flow already open do not process further queries
    //printf("%lf: DNS Query\n", (double)PacketAnalyzer->Time/1000);
    //standard query
    //clearQueryName();  //clearing storage
    offset=DNS_QUESTIONS_OFFSET; //start of questionrecord  
    //if(offset==0) return 10; //error no offset = fixed value
    while(Packet[offset]!=0){
      start=offset+1;
      stop=start+Packet[offset];
      if(stop>=Length) return 11; //out of bounds
      for(i=start; i<stop; i++) addToQueryName(Packet[i]);
      addToQueryName('.');
      offset=stop;  
    }
    if(QueryNameIndex>0) QueryName[QueryNameIndex-1]=0;  //removing trailing FQDN dot
    //printf("QUERY:%s\n\n",QueryName);

    //add as RPT DNS Event
    EventCollector->addRPTDNSEvent(PacketAnalyzer->Time, QueryName, FlowAggregator->Index);
     
    //We do not make DNS-records. It is for now just the flow the queryname
  } else {
    return 4;  //no standard response or query
  }
  return returnvalue;
};

//*****************************************************************************
char* TDNSHelper::getQueryName(void){
  return QueryName;
}

//*****************************************************************************
uint16_t TDNSHelper::parseName(uint16_t offset){
//recursive operation tht parses DNS

uint16_t start, stop, i; 

  while(Packet[offset]!=0){
    if(Packet[offset]>0x3F){
      //pointer field
      parseName(256*(uint16_t)(Packet[offset]&0x3F)+(uint16_t)Packet[offset+1]); 
      offset+=2;
      return offset; //a pointer is always at the end of the name!
    } else {
      //no pointer field
      start=offset+1;
      stop=start+Packet[offset];
      if(stop>=Length) return 0; //out of bounds
      for(i=start; i<stop; i++) addToAnswerName(Packet[i]);
      addToAnswerName('.');
      offset=stop; 
    }
  }
  return offset;
}


//*****************************************************************************
void TDNSHelper::clearQueryName(void){
  uint16_t i;

  for(i=0; i<256; i++) QueryName[i]=0;
  QueryNameIndex=0;
};

//*****************************************************************************
uint8_t TDNSHelper::addToQueryName(char s){
  if(QueryNameIndex>=255) return 0; //overflow
  QueryName[QueryNameIndex]=s;
  QueryNameIndex++;
  return 1;
};

//*****************************************************************************
void TDNSHelper::clearAnswerName(void){
  uint16_t i;

  for(i=0; i<256; i++) AnswerName[i]=0;
  AnswerNameIndex=0;
};

//*****************************************************************************
uint8_t TDNSHelper::addToAnswerName(char s){
  if(AnswerNameIndex>=255) return 0; //overflow
  AnswerName[AnswerNameIndex]=s;
  AnswerNameIndex++;
  return 1;
};

//*****************************************************************************
uint8_t TDNSHelper::deleteRecord(int32_t i){
  return 1;
};

//*****************************************************************************

int TDNSHelper::find(uint32_t ip, char *name){
  int32_t oldindex;
  int searchresult;

  //walk through hashtable and react on a matching IP or NAME
  //if ip match the search will stop with certain status

  oldindex=Index;
  if(Index==-1){  //new search
    Index=DNSTable[makeIPHash(ip)]; //Index starts at the first item
  } else { //continuing search
    Index=DNS[Index].NextDNSIndex; //Index starts one place after the last handled item
  }
  if(Index==-1){
    Index=oldindex;
    return 0; //end of search, pointing to the last valid item in the list or -1 if the list is empty
  } 
  //valid Index, so we really start searching from here
  do{ 
    searchresult=DNS[Index].match(ip, name);
    if (searchresult!=0) return searchresult;  //1=only IP match, 2=name match 3=cname match 
    oldindex=Index;
    Index=DNS[Index].NextDNSIndex;
  }while(Index!=-1);
  Index=oldindex;
  return 0;				//no match and Lastreferenced index points to last valid index.
};

//*****************************************************************************
uint16_t TDNSHelper::makeIPHash(uint32_t ip){
  uint16_t hash;

  hash=(uint16_t)(ip&(DNSHASHSIZE-1));
  //printf("DNShash=%d \n",hash);
  return hash;
}


//*****************************************************************************
void TDNSHelper::dump(char *content){  
  int32_t index, i;

  if(content==NULL){
    printf("\nDumping DNS:\n");
    printf("HASH:INDEX = IP, TTL, NAME, CNAME, FIRSTTIME, FLOW-ID\n");
    for (i=0; i<DNSHASHSIZE; i++){
      index=DNSTable[i];
      while(index!=-1){
        printf("%d:%d = ",i,index);
        DNS[index].print(content);
        index=DNS[index].NextDNSIndex;;
      }
    }
    printf("Total Number of DNS Records: %d\n",Size);
  } else {
    sprintf(content, "HASH:INDEX = IP, TTL, NAME, CNAME, FIRSTTIME, FLOW-ID\n");
    for (i=0; i<DNSHASHSIZE; i++){
      index=DNSTable[i];
      while(index!=-1){
        sprintf(content+strlen(content), "%d:%d = ",i,index);
        DNS[index].print(content);
        index=DNS[index].NextDNSIndex;;
      }
    }
    Logger->save(".dns", content);
  }
};

//*****************************************************************************
/*uint8_t TDNSHelper::add(void){

  uint8_t answer, returnvalue;
  uint16_t offset, start, stop, i, j; 
  uint32_t IP, TTL, newindex;
 
  if(FlowAggregator->Direction==EGRESS) return 0; //only ingress DNS is interesting for analysis
  
  returnvalue=1; //addition with no new elements
  //Making easy variables
  Length=PacketAnalyzer->Length - PacketAnalyzer->PayloadIndex; //The entire length of DNS payload
  Packet=&PCAP->Packet[PacketAnalyzer->PayloadIndex]; //the same as Packet in PCAP but starting at DNS-header

  //Testing for correct DNS-response
  if(Length<12) return 3; //to small for DNS payload
  if(((Packet[DNS_OPCODE_OFFSET])&0xF0)!=0x80) return 4;  //no standard response
  if(((Packet[DNS_RCODE_OFFSET])&0x07)!=0x00) return 5;  //error return code 
  if((Packet[DNS_NUMBER_OF_QUESTIONS_OFFSET])!=0x00) return 6;  //not 1 question
  if((Packet[DNS_NUMBER_OF_QUESTIONS_OFFSET+1])!=0x01) return 7;  //not 1 question
  if((Packet[DNS_NUMBER_OF_ANSWERS_OFFSET])!=0x00) return 8;  //to many answers (>255)

  //How many answers?
  answer=Packet[DNS_NUMBER_OF_ANSWERS_OFFSET+1];
  if(answer==0) return 9; //no answers  
  //printf("\n\nAnswers %d\n",answer);

  //OK we are in business
  clearQueryName();  //clearing storage
  offset=DNS_QUESTIONS_OFFSET; //start of questionrecord  
  if(offset==0) return 10; //error no offset
  while(Packet[offset]!=0){
    start=offset+1;
    stop=start+Packet[offset];
    if(stop>=Length) return 11; //out of bounds
    for(i=start; i<stop; i++) addToQueryName(Packet[i]);
    addToQueryName('.');
    offset=stop;  
  }
  if(QueryNameIndex>0) QueryName[QueryNameIndex-1]=0;  //removing trailing FQDN dot
  //printf("QUERY:%s\n\n",QueryName);

  //before we continue first connecting this flow in the tree
  CauseAnalyzer->add(QueryName);

  
  //Now through all RR's
  offset+=5; //1+4 fields
  if(offset+1>=Length) return 12; //error out of bounds
  //printf("ANSWER:\n");
  for(j=0; (j<answer); j++){
    if(j!=0){
      offset=offset+8; //move to the resource data length
      if(offset+1>=Length) return 16;
      offset=offset+2+256*(uint16_t)Packet[offset]+(uint16_t)Packet[offset+1];
      if(offset+1>=Length) return 17;    
    }
    clearAnswerName();
    offset=parseName(offset);
    //printf("NR: %d = %s",j,AnswerName);
    if(offset+1>=Length) return 13;    
    if((Packet[offset]==0)&&(Packet[offset+1]==1)){
    //we have a record
      if(offset+13>=Length) return 14;
      IP=((uint32_t)Packet[offset+10]<<24)+((uint32_t)Packet[offset+11]<<16)+((uint32_t)Packet[offset+12]<<8)+((uint32_t)Packet[offset+13]);
      TTL=((uint32_t)Packet[offset+4]<<24)+((uint32_t)Packet[offset+5]<<16)+((uint32_t)Packet[offset+6]<<8)+((uint32_t)Packet[offset+7]);
      
      if(AnswerNameIndex>0) AnswerName[AnswerNameIndex-1]=0;  //removing trailing FQDN dot

      //printf("TTL=%d", TTL);
      //temp=(uint8_t *)&IP; printf(" -> A:%d.%d.%d.%d\n", temp[3], temp[2], temp[1], temp[0]);

      //here we have to process the query in either an update or a new DNS-record      
      Index=-1;
      if(find(IP, QueryName)==0){
        //nothing found -> create new DNS record
        returnvalue=2;
        newindex=Size%DNSBUFFERSIZE;      //ALTERNATIVE: newindex=(uint32_t)rand()%(DNSBUFFERSIZE-1);
  	i=0;
  	while(DNS[newindex].TimeStamp!=0){
	  newindex++; if(newindex>=DNSBUFFERSIZE) newindex=0;
    	  i++;
    	  if(i>DNSBUFFERSIZE-1) return 15; //buffer full
        }

        //Fill DNS-record
        DNS[newindex].set(FlowAggregator->Index, PacketAnalyzer->Time, IP, TTL, QueryName, AnswerName);
        DNS[newindex].NextDNSIndex=-1; //last in the list
        //Connecting in the hashtable
        if(Index!=-1){ 
          DNS[Index].NextDNSIndex=newindex; //penultimate in the lists connects to the new item  
        } else {
          DNSTable[makeIPHash(DNS[newindex].IP)]=newindex; 
        }
        Size++;
        //EventCollector->addDNSEvent(PacketAnalyzer->Time, IP, newindex);
      } else {
        //update existing record
	DNS[Index].TimeStamp=PacketAnalyzer->Time;
        DNS[Index].FlowIndex=FlowAggregator->Index;
        DNS[Index].TTL=TTL;
        //EventCollector->addDNSEvent(PacketAnalyzer->Time, IP, Index);
      }


    }//end of we have a record
//    offset=offset+8; //move to the resource data length
//    if(offset+1>=Length) return 16;
//    offset=offset+2+256*(uint16_t)Packet[offset]+(uint16_t)Packet[offset+1];
//    if(offset+1>=Length) return 17;  
  }
  //printf("\nBye\n");
  return returnvalue;
};
*/

