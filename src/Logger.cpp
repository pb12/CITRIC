/**@file Logger.cpp
@brief This file contains the operators of the TLogger class. 

@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@author Pieter Burghouwt
@version Revision 2.0
@date Wednesday, December 5, 2012
*/
/*Logger is a part of CITRIC.

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
#include "HTTPHelper.h"
#include "PacketAnalyzer.h"
#include "EventCollector.h"
#include "HTTP.h"
#include "Logger.h"

extern TFlowAggregator *FlowAggregator;
extern TPCAP *PCAP;
extern TPacketAnalyzer *PacketAnalyzer;
extern TFlow Flow[FLOWBUFFERSIZE];
extern TEventCollector *EventCollector;
extern THTTP *HTTP;

const char *Severity[8]={"EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFORMATIONAL", "DEBUG"};
const char *Facility[7]={"PACKET_ANALYZER", "FLOW_AGGREGATOR", "DNS_HELPER", "HTTP_HELPER", "EVENT_COLLECTOR", "CAUSE_ANALYZER", "MAIN"};
const char *Protocol[7]={"ICMP", "TCP", "UDP", "HTTP", "HTTPS", "DNS", "UNKNOWN"};
const char *CauseDesc[13]={"CAUSE_UNKNOWN", "CAUSE_SERVER", "CAUSE_DNS", "CAUSE_HTTP_URL", "CAUSE_HTTP_SOFTURL", "CAUSE_HTTP_REFERER", "CAUSE_HTTP_GEN", "CAUSE_HTTPS_GEN", "CAUSE_USER", "CAUSE_PROTODNS", "CAUSE_WHITELIST", "CAUSE_ALREADYOPEN", "CAUSE_DNS_REPEAT"};

//*****************************************************************************
TLogger::TLogger(const char *name){
  int i;
  FileName=name;
  Buffer=Log;
  LineCounter=0;
  for(i=0; i<LOGSIZE; i++) Log[i]=0;
  
};

//*****************************************************************************

int TLogger::log(int sev, int fac, char *message){
  return 0;
};

//*****************************************************************************

int TLogger::log(int sev, int fac, int32_t flowindex, char *id, int64_t delay){
  int n, p;
  //char *temp;

  switch(Flow[flowindex].Protocol){
    case 1:
      p=0;  //icmp
    break;
    case 6:
      p=1; //tcp
      if((Flow[flowindex].LocalPort==80)||(Flow[flowindex].RemotePort==80)) p=3; //http
      if((Flow[flowindex].LocalPort==443)||(Flow[flowindex].RemotePort==443)) p=4; //http
    break;
    case 17:
      p=2; //udp
      if((Flow[flowindex].LocalPort==53)||(Flow[flowindex].RemotePort==53)) p=5; //dns
    break;
    default:
      p=6; //unknown
    break;
  }
  //temp=Buffer;
  n=sprintf(Buffer, "%f, %s, TREE:%d, NEWFLOW:%d, %s", (double)PacketAnalyzer->Time/1000000, Facility[fac], Flow[flowindex].TreeIndex, flowindex, Protocol[p]);
  if(n<0) return -1;
  Buffer+=n;
  if((p==1)||(p==2)){
  //unknown protocol
    if(Flow[flowindex].Direction==EGRESS){
       n=sprintf(Buffer, "%d, ", Flow[flowindex].RemotePort);
    } else {
       n=sprintf(Buffer, "%d, ", Flow[flowindex].LocalPort);
    }
  } else {
    n=sprintf(Buffer, ", ");
  }
  Buffer+=n;
  n=sprintf(Buffer, "PARENTFLOW:%d, %ld us, %s, %s, %d\n", Flow[flowindex].ParentFlow, delay, CauseDesc[Flow[flowindex].Cause], id, Flow[flowindex].CauseReliability);
  Buffer+=n;
  //printf("\n%s",temp);
  return 0;
};

//*****************************************************************************

int TLogger::saveLog(void){

  FILE* handle;
  char fn[256];

  fn[0]='\0';
  strcat(fn, FileName);
  strcat(fn, ".log");
  handle=fopen(fn, "w");
  fwrite(Log, strlen(Log), 1, handle);
  fclose(handle);
  return 0;
};

//******************************************************************************

int TLogger::save(const char *ext, char *dm){

  FILE* handle;
  char fn[256];

  fn[0]='\0';
  strcat(fn, FileName);
  strcat(fn, ext);
  handle=fopen(fn, "w");
  fwrite(dm, strlen(dm), 1, handle);
  fclose(handle);
  return 0;
};

//******************************************************************************

int TLogger::initStatsLog(void){

  FILE* handle;
  char fn[256];

  fn[0]='\0';
  strcat(fn, FileName);
  strcat(fn, ".stats");
  handle=fopen(fn, "w");
  strcat(fn, "\n\n");
  fwrite(fn, strlen(fn), 1, handle);
  fclose(handle);
  return 0;
};

//******************************************************************************

int TLogger::saveStatsLog(char *dm){

  FILE* handle;
  char fn[256];

  fn[0]='\0';
  strcat(fn, FileName);
  strcat(fn, ".stats");
  handle=fopen(fn, "a");
  fwrite(dm, strlen(dm), 1, handle);
  fclose(handle);
  return 0;
};

