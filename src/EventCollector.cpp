/**@file EventCollector.cpp
@brief This file contains the operators of the EventCollector class. 

@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@author Pieter Burghouwt
@version Revision 2.0
@date Monda, March 11, 2013
*/
/*EventCollector is a part of CITRIC.

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
#include <string.h>
#include "FlowAggregator.h"
#include "Flow.h"
#include "HTTP.h"
#include "EventCollector.h"
#include "DNS.h"
#include "PacketAnalyzer.h"
#include "Logger.h"
#include "CauseAnalyzer.h"
#include "Settings.h"

extern TPacketAnalyzer *PacketAnalyzer;
extern TFlowAggregator *FlowAggregator;
extern TLogger *Logger;
extern TFlow Flow[];
extern THTTP HTTP[];
extern TDNS DNS[];
extern TSettings *Settings;

//*****************************************************************************
//*****************************************************************************

TUserEvent::TUserEvent(void){
  clear();
};

void TUserEvent::clear(void){
  TimeStamp=0;
  EventCode=0;
  Process[0]='\0';
  CauseCount=0;
};

void TUserEvent::print(char *content){
  if(content==NULL){
    printf("%f, %d , %s , %d\n",(double)TimeStamp/1000000, EventCode, Process, CauseCount);
  } else {
    sprintf(content+strlen(content),"%f, %d , %s , %d\n",(double)TimeStamp/1000000, EventCode, Process, CauseCount);
  }
};


//*****************************************************************************
//*****************************************************************************
THTTPEvent::THTTPEvent(void){
  clear();
};

void THTTPEvent::clear(void){
  TimeStamp=0;
  EventCode=0;
  FlowIndex=-1;
  CauseCount=0;
  DeltaT=0;
};

void THTTPEvent::print(char *content){
  if(content==NULL){
    printf("%f, %d , %d , %d\n",(double)TimeStamp/1000000, EventCode, FlowIndex, CauseCount);
  } else {
    sprintf(content+strlen(content), "%f, %d , %d , %d\n",(double)TimeStamp/1000000, EventCode, FlowIndex, CauseCount);
  }
};


//*****************************************************************************
//*****************************************************************************
THTTPSEvent::THTTPSEvent(void){
  clear();
};

void THTTPSEvent::clear(void){
  TimeStamp=0;
  EventCode=0;
  FlowIndex=-1;
  CauseCount=0;
  DeltaT=0;
};

void THTTPSEvent::print(char *content){
  if(content==NULL){
    printf("%f, %d , %d , %d\n",(double)TimeStamp/1000000, EventCode, FlowIndex, CauseCount);
  } else {
    sprintf(content+strlen(content), "%f, %d , %d , %d\n",(double)TimeStamp/1000000, EventCode, FlowIndex, CauseCount);
  }
};



//*****************************************************************************
//*****************************************************************************
TURLEvent::TURLEvent(void){
  clear();
};

void TURLEvent::clear(void){
  TimeStamp=0;
  URL[0]='\0';
  SUBURL[0]='\0';
  FlowIndex=-1;
  CauseCount=0;
};

void TURLEvent::print(char *content){
  if(content==NULL){
    printf("%f, %s, %s , %d, %d\n",(double)TimeStamp/1000000, SUBURL, URL, FlowIndex, CauseCount);
  } else {
    sprintf(content+strlen(content), "%f, %s, %s , %d, %d\n",(double)TimeStamp/1000000, SUBURL, URL, FlowIndex, CauseCount);
  }
};


//*****************************************************************************
//*****************************************************************************
TRPTDNSEvent::TRPTDNSEvent(void){
  clear();
};

void TRPTDNSEvent::clear(void){
  TimeStamp=0;
  Name[0]='\0';
  FlowIndex=-1;
  CauseCount=0;
};

void TRPTDNSEvent::print(char *content){
  if(content==NULL){
    printf("%f, %s, %d, %d\n",(double)TimeStamp/1000000, Name, FlowIndex, CauseCount);
  } else {
    sprintf(content+strlen(content), "%f, %s, %d, %d\n",(double)TimeStamp/1000000, Name, FlowIndex, CauseCount);
  }
};


//*****************************************************************************
//*****************************************************************************
TUTreeEvent::TUTreeEvent(void){
  clear();
};

void TUTreeEvent::clear(void){
  TimeStamp=0;
  TreeIndex=-1;
  CauseCount=0;
  DeltaT=0;
};

void TUTreeEvent::print(char *content){
  if(content==NULL){
    printf("%f, %d , %d\n",(double)TimeStamp/1000000, TreeIndex, CauseCount);
  } else {
    sprintf(content+strlen(content), "%f, %d , %d\n",(double)TimeStamp/1000000, TreeIndex, CauseCount);
  }
};

//*****************************************************************************
//*****************************************************************************

TEventCollector::TEventCollector(void){
  uint32_t i, j;

  for(i=0; i<EVENTBUFFERSIZE; i++){
    UserEvent[i].clear();
    HTTPEvent[i].clear();
    HTTPSEvent[i].clear();
    UTreeEvent[i].clear();
  }
  UserEventIndex=-1;
  HTTPEventIndex=-1;
  HTTPSEventIndex=-1;
 UTreeEventIndex=-1;

  for(j=0; j<URLEVENTHASHSIZE; j++){
    URLEventIndex[j]=-1;
    for(i=0; i<URLEVENTBUFFERSIZE; i++){
      URLEvent[j][i].clear();
    }    
  }

  for(j=0; j<URLEVENTHASHSIZE; j++){
    RPTDNSEventIndex[j]=-1;
    for(i=0; i<RPTDNSEVENTBUFFERSIZE; i++){
      RPTDNSEvent[j][i].clear();
    }    
  }

  AggregatedWindowTime=0;
  WindowEndTime=-1;
  UserEventCount=0;
  HTTPEventCount=0;
  HTTPSEventCount=0;
  UTreeEventCount=0;
};


//*****************************************************************************

void TEventCollector::addUserEvent(int64_t timestamp, uint8_t eventcode, char *process){
  //int64_t deltaT;
  int64_t newendtime;

  UserEventIndex++; if(UserEventIndex==EVENTBUFFERSIZE) UserEventIndex=0;
  UserEvent[UserEventIndex].TimeStamp=timestamp;
  UserEvent[UserEventIndex].EventCode=eventcode;
  strcpy(UserEvent[UserEventIndex].Process, process);
  
  UserEventCount++;
   
  //open window calculation
  //step 1 calculate new endtime
  if(WindowEndTime==-1) WindowEndTime=PacketAnalyzer->Time; //first time
  newendtime=PacketAnalyzer->Time+DELTA_T_USER;
  if(WindowEndTime>newendtime){
    //old window overlaps completely
    //nothing to do
    //deltaT=0;
  } else {
    //new window end later then old window
    if(WindowEndTime<PacketAnalyzer->Time){
      //old window finished before present -> no overlap
      AggregatedWindowTime+=DELTA_T_USER;
      //deltaT=DELTA_T_USER;
    }else{
      //partial overlap
      AggregatedWindowTime+=DELTA_T_USER-(WindowEndTime-PacketAnalyzer->Time);      
      //deltaT=DELTA_T_USER-(WindowEndTime-PacketAnalyzer->Time); 
    }
    WindowEndTime=newendtime;
  }

  
/*
  if(WindowEndTime==-1) WindowEndTime=PacketAnalyzer->Time; //first time
  if(WindowEndTime < PacketAnalyzer->Time) {
    deltaT=DELTA_T_USER;
  } else  {
    deltaT=DELTA_T_USER-(WindowEndTime-PacketAnalyzer->Time);
  }  
  if(deltaT<0) deltaT=0; //window cannot decrease
  AggregatedWindowTime+=deltaT;
  if(WindowEndTime < (PacketAnalyzer->Time+DELTA_T_USER)) WindowEndTime=PacketAnalyzer->Time+DELTA_T_USER;*/
  //printf("DEBUG CHECKWINDOW, %d, %lf, %ld, %ld, %lf\n", UserEventCount, (double)PacketAnalyzer->Time/1000000, AggregatedWindowTime, deltaT, (double)WindowEndTime/1000000);
};

//*****************************************************************************

void TEventCollector::addHTTPEvent(int64_t timestamp, uint8_t eventcode, uint32_t flowindex){

  int64_t newendtime;

  HTTPEventIndex++; if(HTTPEventIndex==EVENTBUFFERSIZE) HTTPEventIndex=0;
  HTTPEvent[HTTPEventIndex].TimeStamp=timestamp;
  HTTPEvent[HTTPEventIndex].EventCode=eventcode;
  HTTPEvent[HTTPEventIndex].FlowIndex=flowindex;
  HTTPEvent[HTTPEventIndex].CauseCount=0; 
  HTTPEvent[HTTPEventIndex].DeltaT=0;

  HTTPEventCount++;


  //open window calculation
  //step 1 calculate new endtime
  if(WindowEndTime==-1) WindowEndTime=PacketAnalyzer->Time; //first time
  newendtime=PacketAnalyzer->Time+DELTA_T_HTTP;
  if(WindowEndTime>newendtime){
    //old window overlaps completely
    //nothing to do
    HTTPEvent[HTTPEventIndex].DeltaT=0;
  } else {
    //new window end later then old window
    if(WindowEndTime<PacketAnalyzer->Time){
      //old window finished before present -> no overlap
      AggregatedWindowTime+=DELTA_T_HTTP;
      HTTPEvent[HTTPEventIndex].DeltaT=DELTA_T_HTTP;
    }else{
      //partial overlap
      AggregatedWindowTime+=DELTA_T_HTTP-(WindowEndTime-PacketAnalyzer->Time);      
      HTTPEvent[HTTPEventIndex].DeltaT=DELTA_T_HTTP-(WindowEndTime-PacketAnalyzer->Time); 
    }
    WindowEndTime=newendtime;
  }
/*
  //open window calculation
  if(WindowEndTime==-1) WindowEndTime=PacketAnalyzer->Time;
  if(WindowEndTime < PacketAnalyzer->Time) {
    HTTPEvent[HTTPEventIndex].DeltaT=DELTA_T_HTTP;
  } else  {
    HTTPEvent[HTTPEventIndex].DeltaT=DELTA_T_HTTP-(WindowEndTime-PacketAnalyzer->Time);
  }  
  if(HTTPEvent[HTTPEventIndex].DeltaT<0) HTTPEvent[HTTPEventIndex].DeltaT=0; //window cannot decrease
  AggregatedWindowTime+=HTTPEvent[HTTPEventIndex].DeltaT;
  if(WindowEndTime < (PacketAnalyzer->Time+DELTA_T_HTTP)) WindowEndTime=PacketAnalyzer->Time+DELTA_T_HTTP;
*/
};

//*****************************************************************************

void TEventCollector::addHTTPSEvent(int64_t timestamp, uint8_t eventcode, uint32_t flowindex){

  int64_t newendtime;

  HTTPSEventIndex++; if(HTTPSEventIndex==EVENTBUFFERSIZE) HTTPSEventIndex=0;
  HTTPSEvent[HTTPSEventIndex].TimeStamp=timestamp;
  HTTPSEvent[HTTPSEventIndex].EventCode=eventcode;
  HTTPSEvent[HTTPSEventIndex].FlowIndex=flowindex;
  HTTPSEvent[HTTPSEventIndex].CauseCount=0; 
  HTTPSEvent[HTTPSEventIndex].DeltaT=0;

  HTTPSEventCount++;

  //open window calculation
  //step 1 calculate new endtime
  if(WindowEndTime==-1) WindowEndTime=PacketAnalyzer->Time; //first time
  newendtime=PacketAnalyzer->Time+DELTA_T_HTTPS;
  if(WindowEndTime>newendtime){
    //old window overlaps completely
    //nothing to do
    HTTPSEvent[HTTPSEventIndex].DeltaT=0;
  } else {
    //new window end later then old window
    if(WindowEndTime<PacketAnalyzer->Time){
      //old window finished before present -> no overlap
      AggregatedWindowTime+=DELTA_T_HTTPS;
      HTTPSEvent[HTTPSEventIndex].DeltaT=DELTA_T_HTTPS;
    }else{
      //partial overlap
      AggregatedWindowTime+=DELTA_T_HTTPS-(WindowEndTime-PacketAnalyzer->Time);      
      HTTPSEvent[HTTPSEventIndex].DeltaT=DELTA_T_HTTPS-(WindowEndTime-PacketAnalyzer->Time); 
    }
    WindowEndTime=newendtime;
  }


/*
  if(WindowEndTime==-1) WindowEndTime=PacketAnalyzer->Time;
  if(WindowEndTime < PacketAnalyzer->Time) {
    HTTPSEvent[HTTPSEventIndex].DeltaT=DELTA_T_HTTPS;
  } else  {
    HTTPSEvent[HTTPSEventIndex].DeltaT=DELTA_T_HTTPS-(WindowEndTime-PacketAnalyzer->Time);
  }  
  if(HTTPSEvent[HTTPSEventIndex].DeltaT<0) HTTPSEvent[HTTPSEventIndex].DeltaT=0; //window cannot decrease
  AggregatedWindowTime+=HTTPSEvent[HTTPSEventIndex].DeltaT;
  if(WindowEndTime < (PacketAnalyzer->Time+DELTA_T_HTTPS)) WindowEndTime=PacketAnalyzer->Time+DELTA_T_HTTPS;
*/

};


//*****************************************************************************

void TEventCollector::removeHTTPSEvent(int64_t timestamp, int32_t flowindex){
  int32_t i, j;
  uint8_t withdrawn;

  withdrawn=0;
  //printf("****WITHDRAWN**");
  i=HTTPSEventIndex;
  if(i>=0){
    j=0;
    do{
      if(HTTPSEvent[i].FlowIndex==flowindex){
        HTTPSEvent[i].EventCode=CAUSE_HTTPWITHDRAWN;
        //printf("**%ld**WITHDRAWN**\n", PacketAnalyzer->Time);
        //TODO Backtrace and update flows with removed HTTP-flow as a cause 
        withdrawn=1;
        AggregatedWindowTime-=HTTPSEvent[HTTPSEventIndex].DeltaT;
      }
      i=i-1; if(i==-1) i=EVENTBUFFERSIZE-1;
      j++;
    }while((j<EVENTBUFFERSIZE)&&(HTTPSEvent[i].TimeStamp > Flow[flowindex].StartTime)&&(!withdrawn));
  }
}


//*****************************************************************************
void TEventCollector::addUTreeEvent(int64_t timestamp, uint32_t treeindex){

  int64_t newendtime;

  //printf("%ld, %d UTREEEVENT\n", timestamp, treeindex);
  UTreeEventIndex++; if(UTreeEventIndex==EVENTBUFFERSIZE) UTreeEventIndex=0;
  UTreeEvent[UTreeEventIndex].TimeStamp=timestamp;
  UTreeEvent[UTreeEventIndex].TreeIndex=treeindex;
  UTreeEvent[UTreeEventIndex].CauseCount=0; 
  UTreeEvent[UTreeEventIndex].DeltaT=0;

  UTreeEventCount++;

  //open window calculation
  //step 1 calculate new endtime
  if(WindowEndTime==-1) WindowEndTime=PacketAnalyzer->Time; //first time
  newendtime=PacketAnalyzer->Time+DELTA_T_UTREE;
  if(WindowEndTime>newendtime){
    //old window overlaps completely
    //nothing to do
    UTreeEvent[UTreeEventIndex].DeltaT=0;
  } else {
    //new window end later then old window
    if(WindowEndTime<PacketAnalyzer->Time){
      //old window finished before present -> no overlap
      AggregatedWindowTime+=DELTA_T_UTREE;
      UTreeEvent[UTreeEventIndex].DeltaT=DELTA_T_UTREE;
    }else{
      //partial overlap
      AggregatedWindowTime+=DELTA_T_UTREE-(WindowEndTime-PacketAnalyzer->Time);      
      UTreeEvent[UTreeEventIndex].DeltaT=DELTA_T_UTREE-(WindowEndTime-PacketAnalyzer->Time); 
    }
    WindowEndTime=newendtime;
  }
/*
  if(WindowEndTime==-1) WindowEndTime=PacketAnalyzer->Time;
  if(WindowEndTime < PacketAnalyzer->Time) {
    UTreeEvent[UTreeEventIndex].DeltaT=DELTA_T_UTREE;
  } else  {
    UTreeEvent[UTreeEventIndex].DeltaT=DELTA_T_UTREE-(WindowEndTime-PacketAnalyzer->Time);
  }  
  if(UTreeEvent[UTreeEventIndex].DeltaT<0) UTreeEvent[UTreeEventIndex].DeltaT=0; //window cannot decrease
  AggregatedWindowTime+=UTreeEvent[UTreeEventIndex].DeltaT;
  if(WindowEndTime < (PacketAnalyzer->Time+DELTA_T_UTREE)) WindowEndTime=PacketAnalyzer->Time+DELTA_T_UTREE;
*/

};


//*****************************************************************************

void TEventCollector::addURLEvent(int64_t timestamp, char *url, int32_t flowindex){

  int i, stop, start;

  //printf("%s\n", url);
  makeURLHash(url);
  if(URLEvent[Hash][URLEventIndex[Hash]].FlowIndex!=flowindex){  //not the hash/flow as last time
    //printf("INFO %ld New hash or flow URL %s\n", PacketAnalyzer->Time, url);
    //STEP1 NewEvent updating index
    URLEventIndex[Hash]++; 
    if(URLEventIndex[Hash]==URLEVENTBUFFERSIZE){
      URLEventIndex[Hash]= 0; //next index
      //printf("URL ROLLOVER %d\n", Hash);
    }
    //STEP 2 Copy complete domain name of URL
    strcpy(URLEvent[Hash][URLEventIndex[Hash]].URL, url); //copy complete url string

    //STEP 3 Copy 2nd level part of domain name or minimal 4 characters
    stop=strlen(url); do{ stop=stop-1; }while(url[stop]!='.'); 
    start=stop; do{ start=start-1; } while((url[start]!='.')&&(start!=-1)); 
    if((stop-start<4)&&(start!=-1)){
      do{ start=start-1; }while((url[start]!='.')&&(start!=-1)); 
    }
    if((stop-(start+1))>6) stop=start+7; //to make more soft
    for(i=start+1; i<stop; i++) URLEvent[Hash][URLEventIndex[Hash]].SUBURL[i-(start+1)]=url[i];
    URLEvent[Hash][URLEventIndex[Hash]].SUBURL[stop-(start+1)]='\0';
    //printf("SUBURL: %s \n", URLEvent[Hash][URLEventIndex[Hash]].SUBURL);
    //STEP 4 Setting URLEvent
    URLEvent[Hash][URLEventIndex[Hash]].TimeStamp=timestamp;  //=time of current packet
    URLEvent[Hash][URLEventIndex[Hash]].FlowIndex=flowindex;
    URLEvent[Hash][URLEventIndex[Hash]].CauseCount=0;

  } else if(strcmp(URLEvent[Hash][URLEventIndex[Hash]].URL, url)!=0){ //same flow and hash but url itself not the same
    //printf("INFO %ld New NAME URL %s\n", PacketAnalyzer->Time, url);
    //STEP1 NewEvent updating index
    URLEventIndex[Hash]++; 
    if(URLEventIndex[Hash]==URLEVENTBUFFERSIZE){
      URLEventIndex[Hash]= 0; //next index
      //printf("URL ROLLOVER %d\n", Hash);
    }

    //STEP 2 Copy complete domain name of URL
    strcpy(URLEvent[Hash][URLEventIndex[Hash]].URL, url);

    //STEP 3 Copy 2nd level part of domain name or minimal 4 characters
    stop=strlen(url); do{ stop=stop-1; }while(url[stop]!='.'); 
    start=stop; do{ start=start-1; }while((url[start]!='.')&&(start!=-1)); 
    if((stop-start<4)&&(start!=-1)){
      do{ start=start-1; }while((url[start]!='.')&&(start!=-1)); 
    }
    if((stop-(start+1))>6) stop=start+7; //to make more soft
    for(i=start+1; i<stop; i++) URLEvent[Hash][URLEventIndex[Hash]].SUBURL[i-(start+1)]=url[i];

    //STEP 4 Setting URLEvent
    URLEvent[Hash][URLEventIndex[Hash]].TimeStamp=timestamp;  //=time of current packet
    URLEvent[Hash][URLEventIndex[Hash]].FlowIndex=flowindex;
    URLEvent[Hash][URLEventIndex[Hash]].CauseCount=0;
  } else {
    //printf("INFO %ld Double URL %s\n", PacketAnalyzer->Time, url);
  }
};




//*****************************************************************************

void TEventCollector::addRPTDNSEvent(int64_t timestamp, char *name, int32_t flowindex){


  makeURLHash(name);

  //STEP1 New event -> updating index
  RPTDNSEventIndex[Hash]++; 
  if(RPTDNSEventIndex[Hash]==RPTDNSEVENTBUFFERSIZE){
    RPTDNSEventIndex[Hash]= 0; //next index
  }
  //STEP 2 Copy complete domain name of URL
  strcpy(RPTDNSEvent[Hash][RPTDNSEventIndex[Hash]].Name, name); //copy name

  //STEP 4 Setting URLEvent
  RPTDNSEvent[Hash][RPTDNSEventIndex[Hash]].TimeStamp=timestamp;  //=time of current packet
  RPTDNSEvent[Hash][RPTDNSEventIndex[Hash]].FlowIndex=flowindex;
  RPTDNSEvent[Hash][RPTDNSEventIndex[Hash]].CauseCount=0;
};



//*****************************************************************************

int32_t TEventCollector::searchUserEvent(int64_t *delay){
  //returns the most recent user event (L mouseclick or Enter)

  int32_t i, startIndex;

  i=UserEventIndex;
  if(i==-1) return -1; //empty list
  startIndex=i; //to remember were we started the search
  do{
    if(Flow[FlowAggregator->Index].StartTime - UserEvent[i].TimeStamp >= *delay) return -1; //nothing recent
    if((UserEvent[i].EventCode==1)||(UserEvent[i].EventCode==2)||(UserEvent[i].EventCode==3)){
      *delay=Flow[FlowAggregator->Index].StartTime - UserEvent[i].TimeStamp;
       //printf("*******user--event match i=%d delay=%ld *********", i, *delay);
       return i;
    }
    i--; if(i<0) i=EVENTBUFFERSIZE-1; //next index
  }while(i!=startIndex);
return -1;
};


//*****************************************************************************

int64_t TEventCollector::getLastUserEvent(void){

  int32_t i, startIndex;

  i=UserEventIndex;
  if(i==-1) return 0; //empty list
  startIndex=i; //to remember were we started the search
  do{
    if((UserEvent[i].EventCode==1)||(UserEvent[i].EventCode==2)||(UserEvent[i].EventCode==3)) return UserEvent[i].TimeStamp;
    i--; if(i<0) i=EVENTBUFFERSIZE-1; //next index
  }while(i!=startIndex);
  return 0;
};

 
//*****************************************************************************

int32_t TEventCollector::searchHTTPEvent(int64_t *delay, int prot){
  //returns the most recent HTTP or HTTPS-Event
  //int32_t i, j, startIndex;
  int32_t i, j;
  int64_t TimeInterval;


  //STEP 1 Initializing the indices 
  i=HTTPEventIndex;
  if(i==-1) return -1; //empty list
  j=0;

  

  //STEP 2 //go through all records and return on a decision
  while(j<EVENTBUFFERSIZE){  
    TimeInterval=Flow[FlowAggregator->Index].StartTime - HTTPEvent[i].TimeStamp;
    if(TimeInterval > *delay) return -1; //nothing recent
    if((TimeInterval > 0)&&(prot==Flow[HTTPEvent[i].FlowIndex].RemotePort)){
      //found a valid record
      //but test for WITHDRAWN
      if(HTTPEvent[i].EventCode!=CAUSE_HTTPWITHDRAWN){
        *delay=Flow[FlowAggregator->Index].StartTime - HTTPEvent[i].TimeStamp;
        return i;
      } else {
        //printf("WITHDRAWN\n");
      }
    }
    //time was negative (can happen if dns reply is processed) so try the next
    i--; if(i<0) i=EVENTBUFFERSIZE-1;
    j++;
  }
  return -1;
}

//*****************************************************************************

int32_t TEventCollector::searchHTTPSEvent(int64_t *delay, int prot){
  //returns the most recent HTTP or HTTPS-Event
  //int32_t i, j, startIndex;
  int32_t i, j;
  int64_t TimeInterval;


  //STEP 1 Initializing the indices 
  i=HTTPSEventIndex;
  if(i==-1) return -1; //empty list
  j=0;

  

  //STEP 2 //go through all records and return on a decision
  while(j<EVENTBUFFERSIZE){  
    TimeInterval=Flow[FlowAggregator->Index].StartTime - HTTPSEvent[i].TimeStamp;
    if(TimeInterval > *delay) return -1; //nothing recent
    if((TimeInterval > 0)&&(prot==Flow[HTTPSEvent[i].FlowIndex].RemotePort)){
      //found a valid record
      //but test for WITHDRAWN
      if(HTTPSEvent[i].EventCode!=CAUSE_HTTPWITHDRAWN){
        *delay=Flow[FlowAggregator->Index].StartTime - HTTPSEvent[i].TimeStamp;
        return i;
      } else {
        //printf("WITHDRAWN\n");
      }
    }
    //time was negative (can happen if dns reply is processed) so try the next
    i--; if(i<0) i=EVENTBUFFERSIZE-1;
    j++;
  }
  return -1;
}


//*****************************************************************************
int32_t TEventCollector::searchUTreeEvent(int64_t *delay){
  //returns the most recent UTree-Event
  int32_t i, j;
  int64_t TimeInterval;

  //STEP 1 Initializing the indices 
  i=UTreeEventIndex;
  if(i==-1) return -1; //empty list
  j=0;

  //STEP 2 //go through all records and return on a decision
  while(j<EVENTBUFFERSIZE){  
    TimeInterval=Flow[FlowAggregator->Index].StartTime - UTreeEvent[i].TimeStamp;
    if(TimeInterval > *delay) return -1; //nothing recent
    if(TimeInterval > 0){
      //found a valid record
      *delay=Flow[FlowAggregator->Index].StartTime - UTreeEvent[i].TimeStamp;
      return i;
    }
    i--; if(i<0) i=EVENTBUFFERSIZE-1;
    j++;
  }
  return -1;
}

//*****************************************************************************

int32_t TEventCollector::searchURLEvent(char *url, int64_t *delay, int32_t index){

  int32_t i, startIndex;
  int64_t urltime;

  if(index==-1) makeURLHash(url);  //new search
  i=URLEventIndex[Hash]; //i points to the most recent event 
  if(i==-1) return -1; //empty bucket

  startIndex=i; //to remember were we started the search
  if((index>-1)&&(index<URLEVENTBUFFERSIZE)) {  //received index is valid, so continue from there
    i=index-1; if(i<0) i=URLEVENTBUFFERSIZE-1; //step back one record
  }

  //start searching
  do {            
    //catch the time of the URL-arrival    
    urltime=URLEvent[Hash][i].TimeStamp;
    //correct if last object-tail is later
    if((HTTP[Flow[URLEvent[Hash][i].FlowIndex].HTTPIndex].LastHeaderTime<urltime)&&(HTTP[Flow[URLEvent[Hash][i].FlowIndex].HTTPIndex].LastTailTime>urltime)) urltime=HTTP[Flow[URLEvent[Hash][i].FlowIndex].HTTPIndex].LastTailTime;

    if(Flow[FlowAggregator->Index].StartTime - urltime > *delay) return -1; //to long ago
    if((strcmp(url, URLEvent[Hash][i].URL)==0)&&(Flow[FlowAggregator->Index].StartTime-urltime>=0)){
      //success
      //*delay=Flow[FlowAggregator->Index].StartTime - Flow[URLEvent[Hash][i].FlowIndex].StopTime;
      *delay=Flow[FlowAggregator->Index].StartTime - urltime;
      //if(*delay<0) *delay=Flow[FlowAggregator->Index].StartTime - URLEvent[Hash][i].TimeStamp;
      return i;
    }
    i--; if(i<0) i=URLEVENTBUFFERSIZE-1; //next index
  }while(i!=startIndex); //buffer not completely read      
  return -1 ; //nothing found
};


//*****************************************************************************

int32_t TEventCollector::searchSOFTURLEvent(char *url, int64_t *delay, int32_t index){

  int32_t i, startIndex;
  int j, stop, start;
  char suburl[64];
  int64_t urltime;

  if(index==-1) makeURLHash(url); //search from the start
  //selecting suburl
  if(strrchr(url, '.')==NULL) return -1; //check if there is at least one dot
  stop=strlen(url); do{ stop=stop-1; }while(url[stop]!='.'); //search last dot
  start=stop; do{ start=start-1; } while((url[start]!='.')&&(start!=-1)); //go to start or second last dot 
  if((stop-start<3)&&(start!=-1)){
    do{ start=start-1; }while((url[start]!='.')&&(start!=-1)); 
  } else if(stop-start==3){
    //dealing with special "co" case like co.uk
    if((url[start+1]=='c')&&(url[start+2]=='o')){
      do{ start--; }while((url[start]!='.')&&(start!=-1)); 
      //printf("cocococo: %s ", url);
    }
  }

  for(j=start+1; j<stop; j++) suburl[j-(start+1)]=url[j];
  suburl[stop-(start+1)]='\0';
  suburl[6]='\0'; //to make a match only ont the first 6 characters
  //printf("SOFT SUB URL: %s\n", suburl);

  //..and continuing  
  i=URLEventIndex[Hash]; //i points to the most recent event 
  if(i==-1) return -1; //empty bucket
  startIndex=i; //to remember were we started the search
  if((index>-1)&&(index<URLEVENTBUFFERSIZE)) {  //passed index is valid, so continue there
    i=index-1; 
    if(i<0) i=URLEVENTBUFFERSIZE-1;
  }
  //start searching
  do {    
    //catch the time of the URL-arrival 
    urltime=URLEvent[Hash][i].TimeStamp;
    //correct if last object-tail is later
    if((HTTP[Flow[URLEvent[Hash][i].FlowIndex].HTTPIndex].LastHeaderTime<urltime)&&(HTTP[Flow[URLEvent[Hash][i].FlowIndex].HTTPIndex].LastTailTime>urltime)) urltime=HTTP[Flow[URLEvent[Hash][i].FlowIndex].HTTPIndex].LastTailTime;

    //if(Flow[FlowAggregator->Index].StartTime - Flow[URLEvent[Hash][i].FlowIndex].StopTime > *delay) return -1; //nothing recent
    if(Flow[FlowAggregator->Index].StartTime - urltime > *delay) return -1; //to long ago
    if((strcmp(suburl, URLEvent[Hash][i].SUBURL)==0)&&(Flow[FlowAggregator->Index].StartTime-urltime>=0)){
      //success
      //printf("** MATCH! **");
      //*delay=Flow[FlowAggregator->Index].StartTime - Flow[URLEvent[Hash][i].FlowIndex].StopTime;
      *delay=Flow[FlowAggregator->Index].StartTime - urltime;
      return i; 
    }
    i--;if(i<0) i=URLEVENTBUFFERSIZE-1; //next index
  }while(i!=startIndex); //buffer not completely read      
  return -1 ; //nothing found
};


//*****************************************************************************

int32_t TEventCollector::searchRPTDNSEvent(char *name, int64_t *delay){

  int32_t i, startIndex;

  makeURLHash(name);  //new search
  i=RPTDNSEventIndex[Hash]; //i points to the most recent event 
  if(i==-1) return -1; //empty bucket (impossible)
  i--; if(i<0) i=RPTDNSEVENTBUFFERSIZE-1; //next index
  startIndex=i; //to remember were we started the search

  //start searching
  do {            
    //first time test between start of present flow and stop-time of last flow
    if(Flow[FlowAggregator->Index].StartTime - RPTDNSEvent[Hash][i].TimeStamp > *delay) return -1; //based on repeat dns event time
    if((strcmp(name, RPTDNSEvent[Hash][i].Name)==0)&&(Flow[FlowAggregator->Index].StartTime-RPTDNSEvent[Hash][i].TimeStamp>=0)){
      //success
      *delay=Flow[FlowAggregator->Index].StartTime - RPTDNSEvent[Hash][i].TimeStamp;
      return RPTDNSEvent[Hash][i].FlowIndex;
    }
    i--; if(i<0) i=RPTDNSEVENTBUFFERSIZE-1; //next index
  }while(i!=startIndex); //buffer not completely read      
  return -1 ; //nothing found
};

//*****************************************************************************

void TEventCollector::makeIPHash(uint32_t ip){		
  int i;
  uint8_t *temp;

  temp=(uint8_t *)&ip;

  for(i=0; i<4; i++) Hash+=(int)temp[i]; 
  Hash=Hash%256;
};

//*****************************************************************************

void TEventCollector::makeURLHash(char *url){
  int i, stop, start;

  Hash=0;
  //find position last dot 
  stop=strlen(url);
  do{ stop--; }while(url[stop]!='.'); 
  //find position second last dot or start  
  start=stop;
  do{ start--; }while((url[start]!='.')&&(start!=-1)); 

  //testing on enough entropy  
  if((stop-start<3)&&(start!=-1)){
    do{ start--; }while((url[start]!='.')&&(start!=-1)); 
  } else if(stop-start==3){
    //dealing with special "co" case like co.uk
    if((url[start+1]=='c')&&(url[start+2]=='o')){
      do{ start--; }while((url[start]!='.')&&(start!=-1)); 
      //printf("HASHcocococo: %s ", url);
    }
  }
  //hashing the selected substring
  if((stop-(start+1))>6) stop=start+7; //to make more soft
  for(i=start+1; i<stop; i++){
    Hash=(Hash+(int16_t)url[i])%URLEVENTHASHSIZE;
  }
};

//*****************************************************************************

void TEventCollector:: dump(char *dm, int dest){
  int i, j;

  if(dm==NULL){
    printf("\nDumping URL Events\n");
    for (j=0; j<URLEVENTHASHSIZE; j++){
      for(i=0; i<URLEVENTBUFFERSIZE; i++){
        if(URLEvent[j][i].TimeStamp!=0){
          printf("URLEVENT[%d][%d], ",j, i);
          URLEvent[j][i].print(NULL);
        }
      }
    }
    printf("\nDumping HTTP Events\n");
    for (j=0; j<EVENTBUFFERSIZE; j++){
      if(HTTPEvent[j].TimeStamp!=0){
        printf("HTTPEVENT[%d], ",j);
        HTTPEvent[j].print(NULL);
      }
    }  
    printf("\nDumping HTTPS Events\n");
    for (j=0; j<EVENTBUFFERSIZE; j++){
      if(HTTPSEvent[j].TimeStamp!=0){
        printf("HTTPSEVENT[%d], ",j);
        HTTPSEvent[j].print(NULL);
      }
    }  
    printf("\nDumping User Events\n");
    for (j=0; j<EVENTBUFFERSIZE; j++){
      if(UserEvent[j].TimeStamp!=0){
        printf("USEREVENT[%d], ",j);
        UserEvent[j].print(NULL);
      }
    }  
    printf("\nDumping RPTDNSEvents\n");
    for (j=0; j<URLEVENTHASHSIZE; j++){
      for(i=0; i<RPTDNSEVENTBUFFERSIZE; i++){
        if(URLEvent[j][i].TimeStamp!=0){
          printf("RPTDNSEVENT[%d][%d], ",j, i);
          RPTDNSEvent[j][i].print(NULL);
        }
      }
    }
    printf("\n");
  } else {
    sprintf(dm,"\nDumping URL Events\n");
    for (j=0; j<URLEVENTHASHSIZE; j++){
      for(i=0; i<URLEVENTBUFFERSIZE; i++){
        if(URLEvent[j][i].TimeStamp!=0){
          sprintf(dm+strlen(dm),"URLEVENT[%d][%d], ",j, i);
          URLEvent[j][i].print(dm);
        }
      }
    }
    sprintf(dm+strlen(dm),"\nDumping HTTP Events\n");
    for (j=0; j<EVENTBUFFERSIZE; j++){
      if(HTTPEvent[j].TimeStamp!=0){
        sprintf(dm+strlen(dm), "HTTPEVENT[%d], ",j);
        HTTPEvent[j].print(dm);
      }
    }  
    sprintf(dm+strlen(dm),"\nDumping HTTPS Events\n");
    for (j=0; j<EVENTBUFFERSIZE; j++){
      if(HTTPSEvent[j].TimeStamp!=0){
        sprintf(dm+strlen(dm), "HTTPSEVENT[%d], ",j);
        HTTPSEvent[j].print(dm);
      }
    }  
    sprintf(dm+strlen(dm),"\nDumping User Events\n");
    for (j=0; j<EVENTBUFFERSIZE; j++){
      if(UserEvent[j].TimeStamp!=0){
        sprintf(dm+strlen(dm), "USEREVENT[%d], ",j);
        UserEvent[j].print(dm);
      }
    }  
    sprintf(dm+strlen(dm),"\nDumping RPTDNSEvents\n");
    for (j=0; j<URLEVENTHASHSIZE; j++){
      for(i=0; i<RPTDNSEVENTBUFFERSIZE; i++){
        if(URLEvent[j][i].TimeStamp!=0){
          sprintf(dm+strlen(dm),"RPTDNSEVENT[%d][%d], ",j, i);
          RPTDNSEvent[j][i].print(dm);
        }
      }
    }
    sprintf(dm+strlen(dm),"\nDumping UNKNOWNTreeEvents\n");
    for (j=0; j<EVENTBUFFERSIZE; j++){
      if(UTreeEvent[j].TimeStamp!=0){
        sprintf(dm+strlen(dm), "UTREEEVENT[%d], ",j);
        UTreeEvent[j].print(dm);
      }
    }  
    Logger->save(".event", dm);



  }


  sprintf(dm, "DETECTOR STATISTICS\n");
  sprintf(dm+strlen(dm), "Aggregated open window time:\t\t%lf s\n", (double)AggregatedWindowTime/1000000);
  sprintf(dm+strlen(dm), "UserEventCount:\t\t\t\t%d\n", UserEventCount);
  sprintf(dm+strlen(dm), "HTTPEventCount:\t\t\t\t%d\n", HTTPEventCount);
  sprintf(dm+strlen(dm), "HTTPSEventCount:\t\t\t%d\n", HTTPSEventCount);
  sprintf(dm+strlen(dm), "UnknownTreeEventCount:\t\t\t%d\n\n", UTreeEventCount);

  if(dest==1){
    Logger->saveStatsLog(dm);
  } else {
    printf("%s", dm);
  }

};


