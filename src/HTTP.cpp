/**@file HTTP.cpp
@brief This file contains the operators of the THTTTP class. 

@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@author Pieter Burghouwt
@version Revision 2.0
@date Tuesday, March 5, 2013
*/
/*HTTP is a part of CITRIC.

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
#include <string.h>
#include "HTTP.h"
#include "HFSM.h"
#include "Flow.h"
#include "FlowAggregator.h"
#include "CauseAnalyzer.h"
#include "Tree.h"

extern TFlow Flow[FLOWBUFFERSIZE];
extern TTree Tree[TREE_BUFFER_SIZE];

//*****************************************************************************
THTTP::THTTP(void){		
  clear();
};

//*****************************************************************************
void THTTP::clear(void){
  Time=0;
  Status=HTTPSTATUS_UNDEFINED;
  InByteCounter=0;
  OutByteCounter=0;
  TotalInByteCounter=0;
  TotalOutByteCounter=0;
  FlowIndex=0;
  //NextIndex=0;		
  //PreviousIndex=0;	
  PayloadSize=0;
  ParseState=HFSM1_IDLE;			
  ParseSubState=HFSM2_IDLE;		
  ParseMicroState=0;		
  ContentType=0;
  Encoding=0;
  Chunked=0;
  GZIPIndex=0;
  PostDotLength=0;
  URLBuffer[0]=0;
  RefBuffer[0]=0;
  RefStat=REFSTAT_UNDEFINED;
  LastHeaderTime=0;
  LastTailTime=0;
}


//*****************************************************************************
void THTTP::print(char *content){

  if(content==NULL){
    printf("%lf, %d, %d, %d, %d %d, %d, %s, %s\n", (double)Time/1000000, FlowIndex, Status, TotalInByteCounter, TotalOutByteCounter, Flow[FlowIndex].RemotePort, RefStat, RefBuffer, Tree[Flow[FlowIndex].TreeIndex].ID);
  } else {
    sprintf(content + strlen(content), "%lf, %d, %d, %d, %d, %d, %d, %s, %s\n", (double)Time/1000000, FlowIndex, Status, TotalInByteCounter, TotalOutByteCounter, Flow[FlowIndex].RemotePort, RefStat, RefBuffer, Tree[Flow[FlowIndex].TreeIndex].ID);
  }
};


