/**@file CauseAnalyzer.cpp
@brief This file contains the operators of the TCauseAnalyzer class. 
@author Pieter Burghouwt
@version Revision 2.0
@date Tuesday, March, 12, 2013
*/
/*CauseAnalyzer is a part of CITRIC.

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
#include <math.h>
#include "FlowAggregator.h"
#include "Flow.h"
#include "DNSHelper.h"
#include "Tree.h"
#include "CauseAnalyzer.h"
#include "HTTPHelper.h"
#include "PacketAnalyzer.h"
#include "EventCollector.h"
#include "Logger.h"
#include "Settings.h"
#include "ConnTrack.h"

extern TFlowAggregator *FlowAggregator;
extern TDNSHelper *DNSHelper;
extern TPCAP *PCAP;
extern TPacketAnalyzer *PacketAnalyzer;
extern TFlow Flow[FLOWBUFFERSIZE];
extern TDNS DNS[DNSBUFFERSIZE];
extern THTTP HTTP[HTTP_BUFFER_SIZE];
extern THTTPHelper *HTTPHelper;
extern TEventCollector *EventCollector;
extern TLogger *Logger;
extern TSettings *Settings;
extern TConnTrack *ConnTrack;
extern int ENDPROG;

TTree Tree[TREE_BUFFER_SIZE];

//*****************************************************************************
TCauseAnalyzer::TCauseAnalyzer(void){
  Size=1; //already reserved tree 0 for potential whitelisted flows
  Index=Size-1;

  CauseCounter=0;
  AlreadyOpenCauseCounter=0;
  SERVERCauseCounter=0;
  DNSCauseCounter=0;
  DELDNSCauseCounter=0;
  RPTDNSCauseCounter=0;
  URLCauseCounter=0;
  DELURLCauseCounter=0;
  SURLCauseCounter=0;
  DELSURLCauseCounter=0;
  HTTPCauseCounter=0;
  HTTPSCauseCounter=0;
  USERCauseCounter=0;
  WhiteListCauseCounter=0;
  UnknownCauseCounter=0;
  UTreeCauseCounter=0;
  DNSUnknownCauseCounter=0;
  ResolvedDNSUnknownCauseCounter=0;
  IDLOverLengthCounter=0;
  IDLOverTokenCounter=0;

  NoNameFlowCounter=0;
  DNSNoNameFlowCounter=0;

  CauseCallCounter=0;
  DNSCounter=0;

  LastUserTimeStamp=0;
  StatDNSTimesCounter=-1;
  StatURLTimesCounter=-1;
};

//*****************************************************************************
uint8_t TCauseAnalyzer::add(char * name){
  //This is called in case of a new flow  
  int result, DNSFlag, i;  
  
  uint8_t *temp;
  int64_t delay;
  int32_t rptdnsflowindex;
  char IPAddress[20];
  int nodnsname, nohttpname;
  int idlength;
  int idtokens;
  
  CauseCallCounter++;
  //Already creating IP as ID 
  temp=(uint8_t *)&Flow[FlowAggregator->Index].RemoteIP; 
  sprintf (ID, "%d.%d.%d.%d",temp[3], temp[2], temp[1], temp[0]);
  sprintf (IPAddress, "%d.%d.%d.%d",temp[3], temp[2], temp[1], temp[0]); //for debug purposes
  nodnsname=1; nohttpname=1;

  //STEP 0 testing for already open
  if(Flow[FlowAggregator->Index].Cause==CAUSE_ALREADYOPEN){
    Size++; Index=Size-1;
    if(Size==TREE_BUFFER_SIZE-1){
      ENDPROG=1;
      printf("To much trees: Last flow to process!\n");
    }
    Tree[Index].StartTime=Flow[FlowAggregator->Index].StartTime;
    Tree[Index].StopTime=Tree[Index].StartTime;
    Tree[Index].RootFlow=FlowAggregator->Index;
    Tree[Index].RootCause=CAUSE_ALREADYOPEN;
    Tree[Index].NumberOfFlows=1;
    Tree[Index].MaxDepth=1;
    Flow[FlowAggregator->Index].TreeIndex=Index;
    Flow[FlowAggregator->Index].ParentFlow=-1;
    Flow[FlowAggregator->Index].Resolver=RESOLVER_UNDEFINED;   
    Flow[FlowAggregator->Index].CauseReliability=CAUSEQ_ID_TIME;
    Flow[FlowAggregator->Index].CausalTime=Flow[FlowAggregator->Index].StartTime;
    //printf(">7 INFORMATION, %ld, CAUSE_ALREADYOPEN, TREE_ID: %d, IP/NAME:%s\n",PacketAnalyzer->Time, Index, ID);
    Logger->log(5, 6, FlowAggregator->Index, ID, 0);
    CauseCounter++;
    AlreadyOpenCauseCounter++;
    return CAUSE_ALREADYOPEN;
  }


  //STEP 1 testing for SERVEREVENT
  if(Flow[FlowAggregator->Index].Direction==INGRESS){
    //setting parameters  
    Size++; Index=Size-1;
    if(Size==TREE_BUFFER_SIZE-1){
      ENDPROG=1;
      printf("To much trees: Last flow to process!\n");
    }
    Tree[Index].StartTime=Flow[FlowAggregator->Index].StartTime;
    Tree[Index].StopTime=Tree[Index].StartTime;
    Tree[Index].RootFlow=FlowAggregator->Index;
    Tree[Index].RootCause=CAUSE_SERVER;
    Tree[Index].NumberOfFlows=1;
    Tree[Index].MaxDepth=1;
    Flow[FlowAggregator->Index].TreeIndex=Index;
    Flow[FlowAggregator->Index].ParentFlow=-1;
    Flow[FlowAggregator->Index].Resolver=RESOLVER_UNDEFINED;   
    Flow[FlowAggregator->Index].Cause=CAUSE_SERVER;
    Flow[FlowAggregator->Index].CauseReliability=CAUSEQ_ID_TIME;
    Flow[FlowAggregator->Index].CausalTime=Flow[FlowAggregator->Index].StartTime;
    printf(">7 INFORMATION, %ld, CAUSE_SERVER, TREE_ID: %d, IP/NAME:%s\n",PacketAnalyzer->Time, Index, ID);
    Logger->log(5, 6, FlowAggregator->Index, ID, 0);
    CauseCounter++;
    SERVERCauseCounter++;
    return CAUSE_SERVER;
  }

  LastUserTimeStamp=EventCollector->getLastUserEvent(); //for max time calculation of DNS and URL responses

  //STEP 2 testing for DNSEVENT
  if(DELTA_T_DNS_DEL<DELTA_T_DNS) DELTA_T_DNS_DEL=DELTA_T_DNS; //correct inconsisent setting
  //resetting DNS-results
  DNSFlag=0;
  FoundDNSCount=0;
  BestDNSTime=0; 
  WorstDNSTime=Flow[FlowAggregator->Index].StartTime; 
  BestDNSPlace=-1;
  WorstDNSPlace=-1;
  DNSHelper->Index=-1; //prepare for complete search
  for(i=0; i<10; i++) FoundDNSIndex[i]=0; //clearing the Best DNS-indices

  if(name==NULL){
    //NON-DNS FLOW -> find one or more (max 10) names, belonging to the IP address and maybe a DNS cause
    do{
      if(DELTA_T_DNS_DEL>0){ //only search names if there is a none zero DNS-interval
        result=DNSHelper->find(Flow[FlowAggregator->Index].RemoteIP, NULL);
      } else {
        result=0;
      }
      if(result>0){
        if(DNS[DNSHelper->Index].TimeStamp < Flow[FlowAggregator->Index].StartTime){
          //found a valid DNS-record
          if(FoundDNSCount<10){
            //add
            FoundDNSIndex[FoundDNSCount]=DNSHelper->Index;
            if(DNS[DNSHelper->Index].TimeStamp > BestDNSTime){
              BestDNSTime=DNS[DNSHelper->Index].TimeStamp;
              BestDNSPlace=FoundDNSCount;
            }
            if(DNS[DNSHelper->Index].TimeStamp < WorstDNSTime){
              WorstDNSTime=DNS[DNSHelper->Index].TimeStamp;
              WorstDNSPlace=FoundDNSCount;
            }
            FoundDNSCount++;
          } else {
            //replace 
            if(DNS[DNSHelper->Index].TimeStamp>WorstDNSTime){
              //there is a better time, replacing the worst time 
              FoundDNSIndex[WorstDNSPlace]=DNSHelper->Index;
              BestDNSTime=0; 
              WorstDNSTime=Flow[FlowAggregator->Index].StartTime; 
              BestDNSPlace=-1;
              WorstDNSPlace=-1;
              for(i=0; i<10; i++){
                //finding again the best and the worsest
                if(DNS[FoundDNSIndex[i]].TimeStamp>BestDNSTime){
                  BestDNSTime=DNS[FoundDNSIndex[i]].TimeStamp;
                  BestDNSPlace=i;
                }
                if(DNS[FoundDNSIndex[i]].TimeStamp<WorstDNSTime){
                  WorstDNSTime=DNS[FoundDNSIndex[i]].TimeStamp;
                  WorstDNSPlace=i;
                }
              }//end of Best/worst redetermination
            }
          } 
        }
      }
    } while(result!=0);
    //Further processing with the FoundDNSCount (max 10) indexes of DNS-records with best and worst timing
    //or nothing found (FoundDNSCount==0)

    if(FoundDNSCount!=0){
      //found at least one name and we give it for now a recent resolved name to determine possible DNS-cause
      //this can be corrected later in relation with URL-events.
      nodnsname=0;
      DNSDelay=Flow[FlowAggregator->Index].StartTime-BestDNSTime;
      strcpy (ID, DNS[FoundDNSIndex[BestDNSPlace]].NAME);
      Flow[FlowAggregator->Index].DNSIndex = FoundDNSIndex[BestDNSPlace];
      Flow[FlowAggregator->Index].Resolver=RESOLVER_DNSNAME;
      if(DNSDelay<DELTA_T_DNS_DEL){
        //found a recent name
        Index=Flow[DNS[FoundDNSIndex[BestDNSPlace]].FlowIndex].TreeIndex; //selecteren tree index of the DNS flow
        Tree[Index].StopTime=Flow[FlowAggregator->Index].StopTime;
        Tree[Index].NumberOfFlows++;
        Flow[FlowAggregator->Index].TreeIndex=Index;      
        Flow[FlowAggregator->Index].ParentFlow=DNS[FoundDNSIndex[BestDNSPlace]].FlowIndex;
	Flow[FlowAggregator->Index].Cause=CAUSE_DNS;
	Flow[FlowAggregator->Index].CausalTime=DNS[FoundDNSIndex[BestDNSPlace]].TimeStamp;
        if(DNSDelay<DELTA_T_DNS){
          //found a very recent name
	  Flow[FlowAggregator->Index].CauseReliability=CAUSEQ_ID_TIME;  //short delay
          DNSCauseCounter++;
        } else {
          //found a not recent name
          Flow[FlowAggregator->Index].CauseReliability=CAUSEQ_ID_SOFTTIME; //long delay
	  DELDNSCauseCounter++;
        }
        //printf(">6 NOTIFICATION, %ld, CAUSEDNS, TREE_ID: %d, IP/NAME:%s, REL:%d, DELAY:%ld (us)\n",PacketAnalyzer->Time, Index, ID, Flow[FlowAggregator->Index].CauseReliability, DNSDelay);
        Logger->log(5, 6, FlowAggregator->Index, ID, DNSDelay);
        CauseCounter++;
        if((IPS_ENABLE==1)&&(Tree[Index].RootCause==CAUSE_UNKNOWN)) ConnTrack->kill(FlowAggregator->Index);
        //update counter if DNS itself has unknown cause
        if((Tree[Index].RootCause==CAUSE_UNKNOWN)&&(Tree[Index].DNSOther==0)) {
          ResolvedDNSUnknownCauseCounter++;
          Tree[Index].DNSOther=1;
          //printf("TREE %d NOW ALSO CONTAINS NON-DNS-DATA\n", Index);
        }
        if(((PacketAnalyzer->Time-DNSDelay)>LastUserTimeStamp)&&(DNS[FoundDNSIndex[BestDNSPlace]].Resolved==0)){
          StatDNSTimesCounter++;
	  StatDNSTimes[StatDNSTimesCounter]=DNSDelay;
          //if(DNSDelay>500000) printf("EXTREME_DELAY: %ld, of DNSIndex %d with name %s\n", DNSDelay, FoundDNSIndex[BestDNSPlace], ID);
        }
        DNS[FoundDNSIndex[BestDNSPlace]].Resolved=1;
        return CAUSE_DNS;
      }
    } else {
      //NONAME
      Flow[FlowAggregator->Index].Resolver=RESOLVER_NONAME;
      //printf(">4 DEBUG, %ld, DNS_NONAME, IP/NAME:%s\n",PacketAnalyzer->Time, ID); //only bad if also not in URL
      DNSNoNameFlowCounter++;
    }
  } else {
    //New DNS Flow
    //printf(">6 DEBUG, %ld, PROTODNS - In routine\n",PacketAnalyzer->Time);
    //TODO check if oldtimestamp is in a certain interval this creates a new cause
    nodnsname=0;
    DNSCounter++;
    Flow[FlowAggregator->Index].Resolver=RESOLVER_PROTO_DNS;
    strcpy(ID, name);
    DNSFlag=1;
    //printf(">6 DEBUG, %ld, PROTODNS - Answer, IP/NAME:%s\n",PacketAnalyzer->Time, ID);
  }


  //STEP 3 FAST URL Testing
  //STEP 3A testing for exact URLEVENT
  delay=DELTA_T_URL;
  BestURLEventIndex = EventCollector->searchURLEvent(ID, &delay, -1);  
  if(BestURLEventIndex>-1){
    nohttpname=0;
    Index=Flow[EventCollector->URLEvent[EventCollector->Hash][BestURLEventIndex].FlowIndex].TreeIndex; //select tree index of URL contained flow
    Tree[Index].StopTime=Flow[FlowAggregator->Index].StopTime;
    Tree[Index].NumberOfFlows++;
    Flow[FlowAggregator->Index].TreeIndex=Index;      
    Flow[FlowAggregator->Index].ParentFlow=EventCollector->URLEvent[EventCollector->Hash][BestURLEventIndex].FlowIndex;
    Flow[FlowAggregator->Index].Cause=CAUSE_HTTP_URL;
    Flow[FlowAggregator->Index].CauseReliability=CAUSEQ_ID_TIME; //exact id, short delay
    EventCollector->URLEvent[EventCollector->Hash][BestURLEventIndex].CauseCount++;
    CauseCounter++;
    URLCauseCounter++;
    Flow[FlowAggregator->Index].CausalTime=EventCollector->URLEvent[EventCollector->Hash][BestURLEventIndex].TimeStamp;
    Logger->log(5, 6, FlowAggregator->Index, ID, delay);
    //printf(">6 NOTIFICATION, %ld, CAUSE_HTTP_URL, TREE_ID:%d, IP/NAME:%s, REL:%d, URLDELAY:%ld (us)\n",PacketAnalyzer->Time, Index, ID, Flow[FlowAggregator->Index].CauseReliability, delay);
    if((IPS_ENABLE==1)&&(Tree[Index].RootCause==CAUSE_UNKNOWN)) ConnTrack->kill(FlowAggregator->Index);
    if((Flow[FlowAggregator->Index].RemotePort==53)&&((PacketAnalyzer->Time-delay)>LastUserTimeStamp)&&(EventCollector->URLEvent[EventCollector->Hash][BestURLEventIndex].CauseCount==1)){
      StatURLTimesCounter++;
      StatURLTimes[StatURLTimesCounter]=delay;
      //if(delay>10000000) printf("EXTREME_DELAY: %ld, tree: %d, name %s\n", delay, Index, ID);
    }
    return CAUSE_HTTP_URL;
  }

  //STEP 3B testing for partial URLEVENT 
    if(nodnsname==0){
    delay=DELTA_T_URL;
    BestURLEventIndex = EventCollector->searchSOFTURLEvent(ID, &delay, -1);  
    if(BestURLEventIndex>-1){
      //printf("%ld SOFTURL Event can be the cause\n",PacketAnalyzer->Time);
      //SOFTURL Event can be the cause
      nohttpname=0;
      Index=Flow[EventCollector->URLEvent[EventCollector->Hash][BestURLEventIndex].FlowIndex].TreeIndex; //select tree index of URL contained flow
      Tree[Index].StopTime=Flow[FlowAggregator->Index].StopTime;
      Tree[Index].NumberOfFlows++;
      Flow[FlowAggregator->Index].TreeIndex=Index;      
      Flow[FlowAggregator->Index].ParentFlow=EventCollector->URLEvent[EventCollector->Hash][BestURLEventIndex].FlowIndex;
      Flow[FlowAggregator->Index].Cause=CAUSE_HTTP_SOFTURL;
      Flow[FlowAggregator->Index].CauseReliability=CAUSEQ_ID_TIME; //exact id, short delay
      EventCollector->URLEvent[EventCollector->Hash][BestURLEventIndex].CauseCount++;
      CauseCounter++;
      SURLCauseCounter++;
      Flow[FlowAggregator->Index].CausalTime=EventCollector->URLEvent[EventCollector->Hash][BestURLEventIndex].TimeStamp;
      Logger->log(5, 6, FlowAggregator->Index, ID, delay);
    //printf(">6 NOTIFICATION, %ld, CAUSE_HTTP_SOFTURL, TREE_ID:%d, IP/NAME:%s, REL:%d, URLDELAY:%ld (us)\n",PacketAnalyzer->Time, Index, ID, Flow[FlowAggregator->Index].CauseReliability, delay);      
      if((IPS_ENABLE==1)&&(Tree[Index].RootCause==CAUSE_UNKNOWN)) ConnTrack->kill(FlowAggregator->Index);
      if((Flow[FlowAggregator->Index].RemotePort==53)&&((PacketAnalyzer->Time-delay)>LastUserTimeStamp)&&(EventCollector->URLEvent[EventCollector->Hash][BestURLEventIndex].CauseCount==1)){
        StatURLTimesCounter++;
        StatURLTimes[StatURLTimesCounter]=delay;
        //if(delay>10000000) printf("EXTREME_DELAY: %ld, tree: %d, name %s\n", delay, Index, ID);
      }
      return CAUSE_HTTP_SOFTURL;
    }
  }

  //STEP 3C testing for MULTIPLE URL-EVENT 
  //Testing max 10 possible Domain names that could match with an URL
  //  if((Flow[FlowAggregator->Index].RemotePort==80)||(Flow[FlowAggregator->Index].RemotePort==443)){
  if(FoundDNSCount>0){ //multiple DNS-results found
    //testing for STEP3D-I URL-EVENTS
    delay=DELTA_T_URL;
    BestURLEventIndex=-1;
    for(i=0; i<=FoundDNSCount; i++) {
      URLEventIndex = EventCollector->searchURLEvent(DNS[FoundDNSIndex[i]].NAME, &delay, -1); 
      if(URLEventIndex>-1){
        BestURLEventIndex=URLEventIndex;
        BestURLHash=EventCollector->Hash;
        strcpy(ID, DNS[FoundDNSIndex[i]].NAME); 
        //TODO: Hash is lost??
        //TODO: ID recovery
      }
    }
    if(BestURLEventIndex>-1){
      //URL Event can be the cause
      nohttpname=0;
      Index=Flow[EventCollector->URLEvent[BestURLHash][BestURLEventIndex].FlowIndex].TreeIndex; //select tree index of URL contained flow
      Tree[Index].StopTime=Flow[FlowAggregator->Index].StopTime;
      Tree[Index].NumberOfFlows++;
      Flow[FlowAggregator->Index].TreeIndex=Index;      
      Flow[FlowAggregator->Index].ParentFlow=EventCollector->URLEvent[BestURLHash][BestURLEventIndex].FlowIndex;
      Flow[FlowAggregator->Index].Cause=CAUSE_HTTP_URL;
      Flow[FlowAggregator->Index].CauseReliability=CAUSEQ_ID_TIME; //exact id, short delay
      EventCollector->URLEvent[BestURLHash][BestURLEventIndex].CauseCount++;
      CauseCounter++;
      URLCauseCounter++;
      Flow[FlowAggregator->Index].CausalTime=EventCollector->URLEvent[BestURLHash][BestURLEventIndex].TimeStamp;
      Logger->log(5, 6, FlowAggregator->Index, ID, delay);
      //printf(">6 NOTIFICATION, %ld, CAUSE_HTTP_URL MULTIPLE1, TREE_ID:%d, IP/NAME:%s, REL:%d, URLDELAY:%ld (us)\n",PacketAnalyzer->Time, Index, ID, Flow[FlowAggregator->Index].CauseReliability, delay);
      if((IPS_ENABLE==1)&&(Tree[Index].RootCause==CAUSE_UNKNOWN)) ConnTrack->kill(FlowAggregator->Index);
      if((Flow[FlowAggregator->Index].RemotePort==53)&&((PacketAnalyzer->Time-delay)>LastUserTimeStamp)&&(EventCollector->URLEvent[BestURLHash][BestURLEventIndex].CauseCount==1)){
        StatURLTimesCounter++;
   	StatURLTimes[StatURLTimesCounter]=delay;
        //if(delay>10000000) printf("EXTREME_DELAY: %ld, tree: %d, name %s\n", delay, Index, ID);
      }
      return CAUSE_HTTP_URL;
    }

    //testing for STEP3D-II SOFTURL-EVENTS 
    if(nodnsname==0){
      delay=DELTA_T_URL;
      BestURLEventIndex=-1;
      for(i=0; i<=FoundDNSCount; i++) {
        URLEventIndex = EventCollector->searchSOFTURLEvent(DNS[FoundDNSIndex[i]].NAME, &delay, -1); 
        if(URLEventIndex>-1){
          BestURLEventIndex=URLEventIndex;
          BestURLHash=EventCollector->Hash;
          strcpy(ID, DNS[FoundDNSIndex[i]].NAME); 
        }
      }
      if(BestURLEventIndex>-1){
      //printf("%ld SOFTURL Event can be the cause\n",PacketAnalyzer->Time);
      //SOFTURL Event can be the cause
      nohttpname=0;
      Index=Flow[EventCollector->URLEvent[BestURLHash][BestURLEventIndex].FlowIndex].TreeIndex; //select tree index of URL contained flow
      Tree[Index].StopTime=Flow[FlowAggregator->Index].StopTime;
      Tree[Index].NumberOfFlows++;
      Flow[FlowAggregator->Index].TreeIndex=Index;      
      Flow[FlowAggregator->Index].ParentFlow=EventCollector->URLEvent[BestURLHash][BestURLEventIndex].FlowIndex;
      Flow[FlowAggregator->Index].Cause=CAUSE_HTTP_SOFTURL;
      Flow[FlowAggregator->Index].CauseReliability=CAUSEQ_ID_TIME; //exact id, short delay
      EventCollector->URLEvent[BestURLHash][BestURLEventIndex].CauseCount++;
      CauseCounter++;
      SURLCauseCounter++;
      Flow[FlowAggregator->Index].CausalTime=EventCollector->URLEvent[BestURLHash][BestURLEventIndex].TimeStamp;
      Logger->log(5, 6, FlowAggregator->Index, ID, delay);
      //printf(">6 NOTIFICATION, %ld, CAUSE_HTTP_SOFTURL, TREE_ID:%d, IP/NAME:%s, REL:%d, URLDELAY:%ld (us)\n",PacketAnalyzer->Time, Index, ID, Flow[FlowAggregator->Index].CauseReliability, delay);      
      if((IPS_ENABLE==1)&&(Tree[Index].RootCause==CAUSE_UNKNOWN)) ConnTrack->kill(FlowAggregator->Index);
      if((Flow[FlowAggregator->Index].RemotePort==53)&&((PacketAnalyzer->Time-delay)>LastUserTimeStamp)&&(EventCollector->URLEvent[BestURLHash][BestURLEventIndex].CauseCount==1)){
        StatURLTimesCounter++;
	StatURLTimes[StatURLTimesCounter]=delay;
        //if(delay>10000000) printf("EXTREME_DELAY: %ld, tree: %d, name %s\n", delay, Index, ID);
      }
      return CAUSE_HTTP_SOFTURL;
    }
    }
  }


  //STEP 5 testing for DNS retransmission
  if(Flow[FlowAggregator->Index].RemotePort==53){
    //find record with the same name
    delay = DELTA_T_DNS_RPT;
    rptdnsflowindex=EventCollector->searchRPTDNSEvent(ID, &delay);
    if(rptdnsflowindex!=-1){
      //found REPEATED DNS
      //printf("DOUBLE DNS %lf %s delay %ld us\n", (double)PacketAnalyzer->Time/1000000, ID, delay);
      Index = Flow[rptdnsflowindex].TreeIndex; //selecteren tree index of the DNS flow
      Tree[Index].StopTime=Flow[FlowAggregator->Index].StopTime;
      Tree[Index].NumberOfFlows++;
      Flow[FlowAggregator->Index].TreeIndex=Index;      
      Flow[FlowAggregator->Index].ParentFlow=rptdnsflowindex;
      Flow[FlowAggregator->Index].Cause=CAUSE_DNS_REPEAT;
      Flow[FlowAggregator->Index].CausalTime=Flow[rptdnsflowindex].StartTime;
      Flow[FlowAggregator->Index].CauseReliability=CAUSEQ_ID_SOFTTIME; //long delay
      RPTDNSCauseCounter++;
      Logger->log(5, 6, FlowAggregator->Index, ID, delay);
      //printf(">6 NOTIFICATION, %ld, CAUSE DNS_REPEAT, TREE_ID:%d, IP/NAME:%s, REL:%d, RPTDELAY:%ld (us)\n",PacketAnalyzer->Time, Index, ID, Flow[FlowAggregator->Index].CauseReliability, delay);      
      if((IPS_ENABLE==1)&&(Tree[Index].RootCause==CAUSE_UNKNOWN)) ConnTrack->kill(FlowAggregator->Index);
      //signalling noname 
      if((nodnsname==1)&&(nohttpname==1)){
        printf(">4 WARNING, %ld, NAME_UNKNOWN, IP/NAME:%s\n",PacketAnalyzer->Time, ID); //only bad if also not in URL
        NoNameFlowCounter++;
      }
      return CAUSE_DNS_REPEAT;
    }
  }



  //STEP 6 testing for USEREVENT     TEventCollector::searchUserEvent(int64_t *delay)
  //delay=DELTA_T_USER;
  //BestUserEventIndex=EventCollector->searchUserEvent(&delay);  //searching most recent UserEvent

  //testing for USEREVENT     TEventCollector::searchUserEvent(int64_t *delay)
  UserDelay=DELTA_T_USER;
  BestUserEventIndex=EventCollector->searchUserEvent(&UserDelay);  //searching most recent UserEvent

  if(BestUserEventIndex>-1){
    Size++; Index=Size-1;
    if(Size==TREE_BUFFER_SIZE-1){
      ENDPROG=1;
      printf("To much trees: Last flow to process!\n");
    }
    Flow[FlowAggregator->Index].TreeIndex=Index;
    Flow[FlowAggregator->Index].ParentFlow=-1;
    Flow[FlowAggregator->Index].CauseReliability=CAUSEQ_TIME;
    Flow[FlowAggregator->Index].CausalTime=EventCollector->UserEvent[BestUserEventIndex].TimeStamp;
    Flow[FlowAggregator->Index].Cause=CAUSE_USER;
    Tree[Index].StartTime=Flow[FlowAggregator->Index].StartTime;
    Tree[Index].StopTime=Tree[Index].StartTime;
    Tree[Index].RootFlow=FlowAggregator->Index;
    Tree[Index].RootCause=CAUSE_USER;
    Tree[Index].NumberOfFlows=1;
    Tree[Index].MaxDepth=1; 
    strcpy(Tree[Index].ID, ID);
    Logger->log(5, 6, FlowAggregator->Index, ID, UserDelay);
    printf(">6 NOTIFICATION, %lf, CAUSE_USER, TREE_ID:%d, IP/NAME:%s, REL:%d, USERDELAY:%ld (us)\n",(double)PacketAnalyzer->Time/1000000, Index, ID, Flow[FlowAggregator->Index].CauseReliability, UserDelay);
    CauseCounter++;
    USERCauseCounter++;
    //signalling noname 
    if((nodnsname==1)&&(nohttpname==1)){
      printf(">4 WARNING, %ld, NAME_UNKNOWN, IP/NAME:%s\n",PacketAnalyzer->Time, ID); //only bad if also not in URL
      NoNameFlowCounter++;
    }
    return CAUSE_USER;
  }




  //STEP 7 LATE URL processing 

  //STEP 7A testing for Late URLEVENT
  if(DELTA_T_URL_DEL<DELTA_T_URL) DELTA_T_URL_DEL=DELTA_T_URL;
  delay=DELTA_T_URL_DEL;
  BestURLEventIndex = EventCollector->searchURLEvent(ID, &delay, -1);  
  if(BestURLEventIndex>-1){
    //Late URL Event is the cause
    nohttpname=0;
    Index=Flow[EventCollector->URLEvent[EventCollector->Hash][BestURLEventIndex].FlowIndex].TreeIndex; //select tree index of URL contained flow
    Tree[Index].StopTime=Flow[FlowAggregator->Index].StopTime;
    Tree[Index].NumberOfFlows++;
    Flow[FlowAggregator->Index].TreeIndex=Index;      
    Flow[FlowAggregator->Index].ParentFlow=EventCollector->URLEvent[EventCollector->Hash][BestURLEventIndex].FlowIndex;
    Flow[FlowAggregator->Index].Cause=CAUSE_HTTP_URL;
    Flow[FlowAggregator->Index].CauseReliability=CAUSEQ_ID_SOFTTIME; //exact id, long delay
    EventCollector->URLEvent[EventCollector->Hash][BestURLEventIndex].CauseCount++;
    CauseCounter++;
    DELURLCauseCounter++;
    Flow[FlowAggregator->Index].CausalTime=EventCollector->URLEvent[EventCollector->Hash][BestURLEventIndex].TimeStamp;
    Logger->log(5, 6, FlowAggregator->Index, ID, delay);
    //printf(">6 NOTIFICATION, %ld, CAUSE_HTTP_URL2, TREE_ID:%d, IP/NAME:%s, REL:%d, URLDELAY:%ld (us)\n",PacketAnalyzer->Time, Index, ID, Flow[FlowAggregator->Index].CauseReliability, delay);
    if((IPS_ENABLE==1)&&(Tree[Index].RootCause==CAUSE_UNKNOWN)) ConnTrack->kill(FlowAggregator->Index);
    if((Flow[FlowAggregator->Index].RemotePort==53)&&((PacketAnalyzer->Time-delay)>LastUserTimeStamp)&&(EventCollector->URLEvent[EventCollector->Hash][BestURLEventIndex].CauseCount==1)){
      StatURLTimesCounter++;
      StatURLTimes[StatURLTimesCounter]=delay;
      //if(delay>10000000) printf("EXTREME_DELAY: %ld, tree: %d, name %s\n", delay, Index, ID);
    }
    return CAUSE_HTTP_URL;
  }


  //STEP 7B testing for late partial URLEVENT 
  if(nodnsname==0){
  delay=DELTA_T_URL_DEL;
  BestURLEventIndex = EventCollector->searchSOFTURLEvent(ID, &delay, -1);  
  if(BestURLEventIndex>-1){
    //printf("%ld SOFTURL Event can be the cause\n",PacketAnalyzer->Time);
    //SOFTURL Event can be the cause
    nohttpname=0;
    Index=Flow[EventCollector->URLEvent[EventCollector->Hash][BestURLEventIndex].FlowIndex].TreeIndex; //select tree index of URL contained flow
    Tree[Index].StopTime=Flow[FlowAggregator->Index].StopTime;
    Tree[Index].NumberOfFlows++;
    Flow[FlowAggregator->Index].TreeIndex=Index;      
    Flow[FlowAggregator->Index].ParentFlow=EventCollector->URLEvent[EventCollector->Hash][BestURLEventIndex].FlowIndex;
    Flow[FlowAggregator->Index].Cause=CAUSE_HTTP_SOFTURL;
    Flow[FlowAggregator->Index].CauseReliability=CAUSEQ_ID_SOFTTIME; //exact id, long delay
    EventCollector->URLEvent[EventCollector->Hash][BestURLEventIndex].CauseCount++;
    CauseCounter++;
    DELSURLCauseCounter++;
    Flow[FlowAggregator->Index].CausalTime=EventCollector->URLEvent[EventCollector->Hash][BestURLEventIndex].TimeStamp;
    Logger->log(5, 6, FlowAggregator->Index, ID, delay);
    //printf(">6 NOTIFICATION, %ld, CAUSE_HTTP_SOFTURL, TREE_ID:%d, IP/NAME:%s, REL:%d, URLDELAY:%ld (us)\n",PacketAnalyzer->Time, Index, ID, Flow[FlowAggregator->Index].CauseReliability, delay);      
    if((IPS_ENABLE==1)&&(Tree[Index].RootCause==CAUSE_UNKNOWN)) ConnTrack->kill(FlowAggregator->Index);
    if((Flow[FlowAggregator->Index].RemotePort==53)&&((PacketAnalyzer->Time-delay)>LastUserTimeStamp)&&(EventCollector->URLEvent[EventCollector->Hash][BestURLEventIndex].CauseCount==1)){
      StatURLTimesCounter++;
      StatURLTimes[StatURLTimesCounter]=delay;
      //if(delay>10000000) printf("EXTREME_DELAY: %ld, tree: %d, name %s\n", delay, Index, ID);
    }
    return CAUSE_HTTP_SOFTURL;
  }
  }

  //STEP 7C testing for late MULTIPLE URL-EVENT 
  //We have here max 10 possible Domain names that could match with an URL
  //The last one is already as ID and that probably failed
  //if((Flow[FlowAggregator->Index].RemotePort==80)||(Flow[FlowAggregator->Index].RemotePort==443)){
  if(FoundDNSCount>0){ //multiple DNS-results found
    delay=DELTA_T_URL_DEL;
    BestURLEventIndex=-1;
    for(i=0; i<=FoundDNSCount; i++) {  //TODO CHANGE INDEX 
      URLEventIndex = EventCollector->searchURLEvent(DNS[FoundDNSIndex[i]].NAME, &delay, -1); 
      if(URLEventIndex>-1){
        BestURLEventIndex=URLEventIndex;
        BestURLHash=EventCollector->Hash;
        strcpy(ID, DNS[FoundDNSIndex[i]].NAME); 
        //TODO: Hash is lost ???
        //TODO: PLace back ID if failure
      }
    }
    if(BestURLEventIndex>-1){
      nohttpname=0;
      Index=Flow[EventCollector->URLEvent[BestURLHash][BestURLEventIndex].FlowIndex].TreeIndex; //select tree index of URL contained flow
      Tree[Index].StopTime=Flow[FlowAggregator->Index].StopTime;
      Tree[Index].NumberOfFlows++;
      Flow[FlowAggregator->Index].TreeIndex=Index;    
      Flow[FlowAggregator->Index].ParentFlow=EventCollector->URLEvent[BestURLHash][BestURLEventIndex].FlowIndex;
      Flow[FlowAggregator->Index].Cause=CAUSE_HTTP_URL;
      Flow[FlowAggregator->Index].CauseReliability=CAUSEQ_ID_SOFTTIME; //exact id, long delay
      EventCollector->URLEvent[BestURLHash][BestURLEventIndex].CauseCount++;
      CauseCounter++;
      DELURLCauseCounter++;
      Flow[FlowAggregator->Index].CausalTime=EventCollector->URLEvent[BestURLHash][BestURLEventIndex].TimeStamp;
      Logger->log(5, 6, FlowAggregator->Index, ID, delay);
      //printf(">6 NOTIFICATION, %ld, CAUSE_HTTP_URL MULTIPLE2, TREE_ID:%d, IP/NAME:%s, REL:%d, URLDELAY:%ld (us)\n",PacketAnalyzer->Time, Index, ID, Flow[FlowAggregator->Index].CauseReliability, delay);
      if((IPS_ENABLE==1)&&(Tree[Index].RootCause==CAUSE_UNKNOWN)) ConnTrack->kill(FlowAggregator->Index);
      if((Flow[FlowAggregator->Index].RemotePort==53)&&((PacketAnalyzer->Time-delay)>LastUserTimeStamp)&&(EventCollector->URLEvent[BestURLHash][BestURLEventIndex].CauseCount==1)){
        StatURLTimesCounter++;
	StatURLTimes[StatURLTimesCounter]=delay;
        //if(delay>10000000) printf("EXTREME_DELAY: %ld, tree: %d, name %s\n", delay, Index, ID);
      }
      return CAUSE_HTTP_URL;
    }

    //STEP 7D testing for late MULTIPLE Partial URL-EVENT
    if(nodnsname==0){
    delay=DELTA_T_URL_DEL;
    BestURLEventIndex=-1;
    for(i=0; i<=FoundDNSCount; i++) {
      URLEventIndex = EventCollector->searchSOFTURLEvent(DNS[FoundDNSIndex[i]].NAME, &delay, -1); 
      if(URLEventIndex>-1){
        BestURLEventIndex=URLEventIndex;
        BestURLHash=EventCollector->Hash;
        strcpy(ID, DNS[FoundDNSIndex[i]].NAME); 
      }
    }
    if(BestURLEventIndex>-1){
      //printf("%ld SOFTURL Event can be the cause\n",PacketAnalyzer->Time);
      //SOFTURL Event can be the cause
      nohttpname=0;
      Index=Flow[EventCollector->URLEvent[BestURLHash][BestURLEventIndex].FlowIndex].TreeIndex; //select tree index of URL contained flow
      Tree[Index].StopTime=Flow[FlowAggregator->Index].StopTime;
      Tree[Index].NumberOfFlows++;
      Flow[FlowAggregator->Index].TreeIndex=Index;      
      Flow[FlowAggregator->Index].ParentFlow=EventCollector->URLEvent[BestURLHash][BestURLEventIndex].FlowIndex;
      Flow[FlowAggregator->Index].Cause=CAUSE_HTTP_SOFTURL;
      Flow[FlowAggregator->Index].CauseReliability=CAUSEQ_ID_SOFTTIME; //exact id, long delay
      EventCollector->URLEvent[BestURLHash][BestURLEventIndex].CauseCount++;
      CauseCounter++;
      DELSURLCauseCounter++;
      Flow[FlowAggregator->Index].CausalTime=EventCollector->URLEvent[BestURLHash][BestURLEventIndex].TimeStamp;
      Logger->log(5, 6, FlowAggregator->Index, ID, delay);
      //printf(">6 NOTIFICATION, %ld, CAUSE_HTTP_SOFTURL, TREE_ID:%d, IP/NAME:%s, REL:%d, URLDELAY:%ld (us)\n",PacketAnalyzer->Time, Index, ID, Flow[FlowAggregator->Index].CauseReliability, delay);      
      if((IPS_ENABLE==1)&&(Tree[Index].RootCause==CAUSE_UNKNOWN)) ConnTrack->kill(FlowAggregator->Index);
      if((Flow[FlowAggregator->Index].RemotePort==53)&&((PacketAnalyzer->Time-delay)>LastUserTimeStamp)&&(EventCollector->URLEvent[BestURLHash][BestURLEventIndex].CauseCount==1)){
        StatURLTimesCounter++;
        StatURLTimes[StatURLTimesCounter]=delay;
        //if(delay>10000000) printf("EXTREME_DELAY: %ld, tree: %d, name %s\n", delay, Index, ID);
      } 
      return CAUSE_HTTP_SOFTURL;
    }
    }
  }




  //STEP 7_END_signalling noname 
  //signalling noname 
  if((nodnsname==1)&&(nohttpname==1)){
    printf(">4 WARNING, %ld, NAME_UNKNOWN, IP/NAME:%s\n",PacketAnalyzer->Time, ID); //only bad if also not in URL
    NoNameFlowCounter++;
  }


  //STEP 8 testing for GENERIC HTTP EVENT  
  //STEP 8A First HTTPS;
  delay=DELTA_T_HTTPS;
  BestHTTPEventIndex=EventCollector->searchHTTPSEvent(&delay, 443);  //searching HTTPS
  if(BestHTTPEventIndex>-1){
    Index=Flow[EventCollector->HTTPSEvent[BestHTTPEventIndex].FlowIndex].TreeIndex; //select tree index of URL contained flow
    Tree[Index].StopTime=Flow[FlowAggregator->Index].StopTime;
    Tree[Index].NumberOfFlows++;
    Flow[FlowAggregator->Index].TreeIndex=Index;      
    Flow[FlowAggregator->Index].ParentFlow=EventCollector->HTTPSEvent[BestHTTPEventIndex].FlowIndex;
    Flow[FlowAggregator->Index].Cause=CAUSE_HTTPS_GEN;
    Flow[FlowAggregator->Index].CauseReliability=CAUSEQ_NOID_SOFTTIME; //no id, long delay
    CauseCounter++;
    HTTPSCauseCounter++;
    Flow[FlowAggregator->Index].CausalTime=EventCollector->HTTPSEvent[BestHTTPEventIndex].TimeStamp;
    Logger->log(5, 6, FlowAggregator->Index, ID, delay);
    //printf("\n>6 NOTIFICATION, %ld, CAUSE_HTTPS_GEN, TREE_ID:%d, IP/NAME:%s, REL:%d, URLDELAY:%ld (us)\n",PacketAnalyzer->Time, Index, ID, Flow[FlowAggregator->Index].CauseReliability, delay);
    if((IPS_ENABLE==1)&&(Tree[Index].RootCause==CAUSE_UNKNOWN)) ConnTrack->kill(FlowAggregator->Index);
    return CAUSE_HTTPS_GEN;
  }

//STEP 8B then HTTP;
  delay=DELTA_T_HTTP;
  BestHTTPEventIndex=EventCollector->searchHTTPEvent(&delay, 80);  //searching HTTP
  if(BestHTTPEventIndex>-1){
    Index=Flow[EventCollector->HTTPEvent[BestHTTPEventIndex].FlowIndex].TreeIndex; //select tree index of URL contained flow
    Tree[Index].StopTime=Flow[FlowAggregator->Index].StopTime;
    Tree[Index].NumberOfFlows++;
    Flow[FlowAggregator->Index].TreeIndex=Index;      
    Flow[FlowAggregator->Index].ParentFlow=EventCollector->HTTPEvent[BestHTTPEventIndex].FlowIndex;
    Flow[FlowAggregator->Index].Cause=CAUSE_HTTP_GEN;
    Flow[FlowAggregator->Index].CauseReliability=CAUSEQ_NOID_TIME; //no id, long delay
    CauseCounter++;
    HTTPCauseCounter++;
    Flow[FlowAggregator->Index].CausalTime=EventCollector->HTTPEvent[BestHTTPEventIndex].TimeStamp;
    Logger->log(5, 6, FlowAggregator->Index, ID, delay);
    //printf("\n>6 NOTIFICATION, %ld, CAUSE_HTTP_GEN, TREE_ID:%d, IP/NAME:%s, REL:%d, URLDELAY:%ld (us)\n",PacketAnalyzer->Time, Index, ID, Flow[FlowAggregator->Index].CauseReliability, delay);
    if((IPS_ENABLE==1)&&(Tree[Index].RootCause==CAUSE_UNKNOWN)) ConnTrack->kill(FlowAggregator->Index);
    return CAUSE_HTTP_GEN;
  }





  //STEP 9 testing for whitelisting

  //testing on ID (name
  if(Settings->testWhiteList(ID)>0){
    //found
    //do not put in tree
    Index=0;
    Flow[FlowAggregator->Index].TreeIndex=0;
    Flow[FlowAggregator->Index].ParentFlow=-1;
    Flow[FlowAggregator->Index].Cause=CAUSE_WHITELIST;
    Flow[FlowAggregator->Index].CausalTime=Flow[FlowAggregator->Index].StartTime;
    if(Tree[Index].StartTime==0){
      Tree[Index].StartTime=Flow[FlowAggregator->Index].StartTime;
      Tree[Index].RootFlow=FlowAggregator->Index;
      Tree[Index].RootCause=CAUSE_WHITELIST;
      Tree[Index].NumberOfFlows=1;
      Tree[Index].MaxDepth=1; 
      strcpy(Tree[Index].ID, "WHITELISTED");
    }
    Tree[Index].StopTime=PacketAnalyzer->Time;
    Tree[Index].NumberOfFlows++;
    CauseCounter++;
    WhiteListCauseCounter++;
    //printf(">6 NOTIFICATION, %ld, CAUSE_WHITELIST BY ID, TREE_ID:%d, NAME:%s, ADDRESS:%s REL:%d\n",PacketAnalyzer->Time, Index, ID, IPAddress, Flow[FlowAggregator->Index].CauseReliability);
    Logger->log(5, 6, FlowAggregator->Index, ID, 0);
    return CAUSE_WHITELIST;
  }
  //testing on IP (except DNS-traffic)
  if((Flow[FlowAggregator->Index].RemotePort!=53)&&(Settings->testWhiteList(Flow[FlowAggregator->Index].RemoteIP)>0)){
    //found
    //do not put in tree
    Index=0;
    Flow[FlowAggregator->Index].TreeIndex=0;
    Flow[FlowAggregator->Index].ParentFlow=-1;
    Flow[FlowAggregator->Index].Cause=CAUSE_WHITELIST;
    Flow[FlowAggregator->Index].CausalTime=  Flow[FlowAggregator->Index].StartTime;
    if(Tree[Index].StartTime==0){
      Tree[Index].StartTime=Flow[FlowAggregator->Index].StartTime;
      Tree[Index].RootFlow=FlowAggregator->Index;
      Tree[Index].RootCause=CAUSE_WHITELIST;
      Tree[Index].NumberOfFlows=1;
      Tree[Index].MaxDepth=1; 
      strcpy(Tree[Index].ID, "WHITELISTED");
    }
    Tree[Index].StopTime=PacketAnalyzer->Time;
    Tree[Index].NumberOfFlows++;
    CauseCounter++;
    WhiteListCauseCounter++;
    NoNameFlowCounter--;
    //printf(">6 NOTIFICATION, %ld, CAUSE_WHITELIST BY IP, TREE_ID:%d, NAME:%s, ADDRESS:%s REL:%d\n",PacketAnalyzer->Time, Index, ID, IPAddress, Flow[FlowAggregator->Index].CauseReliability);
    Logger->log(5, 6, FlowAggregator->Index, ID, 0);
    return CAUSE_WHITELIST;
  }


//STEP 10 testing for recent unknown tree event
  delay=DELTA_T_UTREE;
  if(EventCollector->searchUTreeEvent(&delay)>-1){
    Index=EventCollector->UTreeEvent->TreeIndex;
    Tree[Index].StopTime=Flow[FlowAggregator->Index].StopTime;
    Tree[Index].NumberOfFlows++;
    Flow[FlowAggregator->Index].TreeIndex=Index;      
    Flow[FlowAggregator->Index].ParentFlow=-1;
    Flow[FlowAggregator->Index].Cause=CAUSE_UTREE;
    Flow[FlowAggregator->Index].CauseReliability=CAUSEQ_TIME; 
    CauseCounter++;
    UTreeCauseCounter++;
    Flow[FlowAggregator->Index].CausalTime=PacketAnalyzer->Time-delay;
    Logger->log(5, 6, FlowAggregator->Index, ID, delay);
    //printf("\n>6 NOTIFICATION, %ld, CAUSE_UTREE, TREE_ID:%d, IP/NAME:%s, REL:%d, DELAY:%ld (us)\n",PacketAnalyzer->Time, Index, ID, Flow[FlowAggregator->Index].CauseReliability, delay);
    return CAUSE_UTREE;
  }



//STEP 11 nothing worked so we make a new tree
  Size++;  
  Index=Size-1;
  if(Size==TREE_BUFFER_SIZE-1){
      ENDPROG=1;
      printf("To much trees: Last flow to process!\n");
  }
  Flow[FlowAggregator->Index].TreeIndex=Index;
  Flow[FlowAggregator->Index].ParentFlow=-1;
  Flow[FlowAggregator->Index].CauseReliability=CAUSEQ_NOID_NOTIME;
  Flow[FlowAggregator->Index].CausalTime=Flow[FlowAggregator->Index].StartTime;
  Flow[FlowAggregator->Index].Cause=CAUSE_UNKNOWN;
  Tree[Index].StartTime=Flow[FlowAggregator->Index].StartTime;
  Tree[Index].StopTime=Tree[Index].StartTime;
  Tree[Index].RootFlow=FlowAggregator->Index;
  Tree[Index].RootCause=CAUSE_UNKNOWN;
  Tree[Index].NumberOfFlows=1;
  Tree[Index].MaxDepth=1;
  strcpy(Tree[Index].ID, ID);
  EventCollector->addUTreeEvent(Flow[FlowAggregator->Index].StartTime, Index);
  if(Flow[FlowAggregator->Index].RemotePort==53) Tree[Index].DNSOther=0;
  //printf("<<<No parent, new tree-id = %d at %f >>>\n", Index, (double)Tree[Index].StartTime/1000000);
  Logger->log(4, 6, FlowAggregator->Index, ID, 0);
  printf(">4 WARNING, %lf, CAUSE_UNKNOWN, IP/NAME:%s, TREE:%d, PROTOCOL:%d, PORT%d\n",(double)PacketAnalyzer->Time/1000000, ID, Index, Flow[FlowAggregator->Index].Protocol, Flow[FlowAggregator->Index].RemotePort);
  /*
  //Print all potentially associated ID's
  if((Flow[FlowAggregator->Index].RemotePort==80)||(Flow[FlowAggregator->Index].RemotePort==443)){
    for(i=0; i<FoundDNSCount; i++){
      printf("UNKNOWN %d %s %ld\n", i, DNS[FoundDNSIndex[i]].NAME, DNS[FoundDNSIndex[i]].TimeStamp);
    }
  }
  */


  UnknownCauseCounter++;

  //update counter for DNS unknown flowcounts
  if((Flow[FlowAggregator->Index].Protocol==17)&&(Flow[FlowAggregator->Index].RemotePort==53)){
   DNSUnknownCauseCounter++;
  } 

  //ID analysis and update counters
  idlength=strlen(ID);
  idtokens=0;
  for(i=0; i<(int)strlen(ID); i++) {
    if((ID[i]=='-')||(ID[i]=='.')){
      idtokens++;
    } else if ((ID[i]<=57)&&(ID[i]>=48)){
      idtokens++;
    }
  }  
  if(nodnsname==0){
    if(idlength>IDL_MAX_LENGTH) IDLOverLengthCounter++;
    if((idlength<=IDL_MAX_LENGTH)&&(idtokens>IDL_MAX_TOKENS)) IDLOverTokenCounter++;
  }


  //and we kill the flow
  //printf("**%ld**", IPS_ENABLE); 
  if((IPS_ENABLE==1)&&(DNSFlag==0)) ConnTrack->kill(FlowAggregator->Index);
  return CAUSE_UNKNOWN;
};

  //TODO: implement causal algorithm further below


//*****************************************************************************


void TCauseAnalyzer::dump(char *dm, int dest){
  double temp;
  int32_t i;

  sprintf(dm, "Index, StartTime, StopTime, RootFlow, RootCause, NumberOfFlows, MaxDepth, RootProt, DNSOther, ID\n");
  for(Index=0; Index<Size; Index++){
    sprintf(dm+strlen(dm), "%d, ",Index);
    Tree[Index].print(dm);
  }
  if(dest==1){
    Logger->save(".tree", dm);
  } else {
    printf("%s", dm);
  }

  sprintf(dm, "DNSdelays\n");
  for (i=0; i<=StatDNSTimesCounter; i++) sprintf(dm+strlen(dm),"%ld\n", StatDNSTimes[i]);
  if(dest==1){
    Logger->save(".dnsstats", dm);
  } else {
    //do nothing
    //printf("%s", dm);
  }

  sprintf(dm, "URLdelays\n");
  for (i=0; i<=StatURLTimesCounter; i++) sprintf(dm+strlen(dm),"%ld\n", StatURLTimes[i]);
  if(dest==1){
    Logger->save(".urlstats", dm);
  } else {
    //do nothing
    //printf("%s", dm);
  }


  sprintf(dm, "CAUSAL STATISTICS\n");
  sprintf(dm+strlen(dm), "Total callCount:\t\t\t%d\n", CauseCallCounter);
  sprintf(dm+strlen(dm), "\tDNS callCount:\t\t\t%d\n", DNSCounter);
  sprintf(dm+strlen(dm), "\tNON DNS Flow CallCount:\t\t%d\n",CauseCallCounter-DNSCounter);
  sprintf(dm+strlen(dm), "Total Recognized FlowCount:\t\t%d\n", CauseCounter);
  temp=DELTA_T_DNS;
  sprintf(dm+strlen(dm), "\tDNS caused FlowCount:\t\t%d\t(t<%fms)\n", DNSCauseCounter, temp/1000 );
  temp=DELTA_T_DNS_DEL;
  sprintf(dm+strlen(dm), "\tLate DNS caused FlowCount:\t%d\t(t<%fms)\n", DELDNSCauseCounter, temp/1000 );
  temp=DELTA_T_DNS_RPT;
  sprintf(dm+strlen(dm), "\tRepeat DNS caused FlowCount:\t%d\t(t<%fms)\n", RPTDNSCauseCounter, temp/1000 );
  temp=DELTA_T_URL;
  sprintf(dm+strlen(dm), "\tURL caused FlowCount:\t\t%d\t(t<%fms)\n", URLCauseCounter, temp/1000 );
  temp=DELTA_T_URL_DEL;
  sprintf(dm+strlen(dm), "\tLate URL caused FlowCount:\t%d\t(t<%fms)\n", DELURLCauseCounter, temp/1000 );
  temp=DELTA_T_URL;
  sprintf(dm+strlen(dm), "\tP-URL caused FlowCount:\t\t%d\t(t<%fms)\n", SURLCauseCounter, temp/1000 );
  temp=DELTA_T_URL_DEL;
  sprintf(dm+strlen(dm), "\tLate P-URL caused FlowCount:\t%d\t(t<%fms)\n", DELSURLCauseCounter, temp/1000 );
  temp=DELTA_T_HTTP;
  sprintf(dm+strlen(dm), "\tGeneric HTTP caused FlowCount:\t%d\t(t<%fms)\n", HTTPCauseCounter, temp/1000 );
  temp=DELTA_T_HTTPS;
  sprintf(dm+strlen(dm), "\tGeneric HTTPS caused FlowCount:\t%d\t(t<%fms)\n", HTTPSCauseCounter, temp/1000 );
  temp=DELTA_T_USER;
  sprintf(dm+strlen(dm), "\tUser caused FlowCount:\t\t%d\t(t<%fms)\n", USERCauseCounter, temp/1000 );
  sprintf(dm+strlen(dm), "\tServer caused FlowCount:\t%d\n", SERVERCauseCounter);    
  sprintf(dm+strlen(dm), "\tWhitelisted FlowCount:\t\t%d\n", WhiteListCauseCounter);
  sprintf(dm+strlen(dm), "\tAlready open FLowCount:\t\t%d\n", AlreadyOpenCauseCounter);   
  sprintf(dm+strlen(dm), "\tClustered FLowCount:\t\t%d\n", UTreeCauseCounter);   
  sprintf(dm+strlen(dm), "Total unknown cause FLowCount:\t\t%d\n", UnknownCauseCounter);
  sprintf(dm+strlen(dm), "\tUnknown non-DNS Flowcount:\t%d\n", UnknownCauseCounter-DNSUnknownCauseCounter); 
  sprintf(dm+strlen(dm), "\tUnknown used DNS FLowCount:\t%d\n", ResolvedDNSUnknownCauseCounter);

  sprintf(dm+strlen(dm), "\tIDL OverLengh Count:\t\t%d\t(l>%ld)\n", IDLOverLengthCounter, IDL_MAX_LENGTH);
  sprintf(dm+strlen(dm), "\tIDL OverToken Count:\t\t%d\t(#tokens>%ld)\n", IDLOverTokenCounter, IDL_MAX_TOKENS);
 
  sprintf(dm+strlen(dm), "Total nameless FLowCount:\t\t%d\n", DNSNoNameFlowCounter);
  sprintf(dm+strlen(dm), "\tNetto bare IP FLowCount:\t%d\n", NoNameFlowCounter);
  sprintf(dm+strlen(dm), "Total created TreeCount:\t\t%d\n", Size-1);
  sprintf(dm+strlen(dm), "Total nonTLD UDI Positives:\t\t%d\n\n", IDLOverLengthCounter+IDLOverTokenCounter+NoNameFlowCounter);
 

  if(dest==1){
    Logger->saveStatsLog(dm);
   } else {
    printf("%s", dm);
  }
};    





