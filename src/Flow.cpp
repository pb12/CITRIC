/**@file Flow.cpp
@brief This file contains the operators of the TFlow class. 

@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@author Pieter Burghouwt
@version Revision 0.9
@date Tuesday, March 12, 2013
*/
/*Flow is a part of CITRIC.

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
#include "pdu.h"
#include "Flow.h"
#include "DNSHelper.h"

extern TDNS DNS[DNSBUFFERSIZE];

//*****************************************************************************
TFlow::TFlow(void){
  clear();
};

//*****************************************************************************
void TFlow::clear(void){

  NextFlowIndex=-1; //no next flow
  Status=0;
  StartTime=0;
  StopTime=0;
  NumberOfTransmittedBytes=0;
  NumberOfReceivedBytes=0;
  NumberOfTransmittedPackets=0;
  NumberOfReceivedPackets=0;
  Direction=UNDEFINED_DIR;
  //skip the 6 tuple
  TCPFlag=0;
  LocalSEQ=0;	
  RemoteSEQ=0;

  DNSIndex=-1;
  HTTPIndex=-1;

  TreeIndex=-1;
  ParentFlow=-1;
  Resolver=0;
  Cause=0;
  CauseReliability=0;
  CausalTime=0;	

}

//*****************************************************************************
uint16_t TFlow::getHash(void){
  uint16_t hash;

  hash=(uint16_t)((LocalIP^RemoteIP^(uint32_t)LocalPort^(uint32_t)RemotePort^(uint32_t)Identification)&(FLOWHASHSIZE-1));
  //printf("hash=%d \n",hash);
  return hash;
}

//*****************************************************************************
uint8_t TFlow::match(uint8_t p, uint32_t lIP, uint32_t rIP, uint16_t lP,uint16_t rP, uint16_t id){
  if(p!=Protocol) return 255;
  if(rIP!=RemoteIP) return 254;
  if(rP!=RemotePort) return 253;
  if(lIP!=LocalIP) return 252;
  if(lP!=LocalPort) return 251;
  if(id!=Identification) return 250;
  return 1;
}


//*****************************************************************************
void TFlow::print(char *content){
uint8_t *temp;

  sprintf(content+strlen(content), "%f,%f,%d,", (double)StartTime/1000000, (double)StopTime/1000000, Protocol);
  temp=(uint8_t *)&LocalIP; sprintf(content+strlen(content), "%d.%d.%d.%d,", temp[3], temp[2], temp[1], temp[0]);
  sprintf(content+strlen(content),"%d,", LocalPort);
  temp=(uint8_t *)&RemoteIP; sprintf(content+strlen(content),"%d.%d.%d.%d,", temp[3], temp[2], temp[1], temp[0]);
  sprintf(content+strlen(content),"%d,", RemotePort);
  sprintf(content+strlen(content),"%d,", Identification);
  sprintf(content+strlen(content),"%X,", TCPFlag);
  sprintf(content+strlen(content),"%d,", NumberOfTransmittedPackets);
  sprintf(content+strlen(content),"%d,", NumberOfReceivedPackets);
  sprintf(content+strlen(content),"%d,", NumberOfTransmittedBytes);
  sprintf(content+strlen(content),"%d,", NumberOfReceivedBytes);
  sprintf(content+strlen(content),"%d, ", Direction);
  sprintf(content+strlen(content),"%d, ", Status);
  sprintf(content+strlen(content),"%d, ", DNSIndex);
  sprintf(content+strlen(content),"%d, ", HTTPIndex);
  sprintf(content+strlen(content),"%d, ", TreeIndex);
  sprintf(content+strlen(content),"%d, ", Cause);
  sprintf(content+strlen(content),"%d, ", ParentFlow);
  //printf("%d, %d, %d, %d %d %f\n", CauseIndex, FlowTree, Resolver, Cause, CauseReliability, (double)CausalTime/1000000);	????
  if(DNSIndex!=-1) {
    sprintf(content+strlen(content),"%s,", DNS[DNSIndex].NAME);	
  } else if(RemotePort==53){
    sprintf(content+strlen(content),"DNS,");	
  } else {
    sprintf(content+strlen(content),"NONE,");	
  }    
  sprintf(content+strlen(content),"\n");
};


