/**@file DNS.cpp
@brief This file contains the operators of the TDNS class. 

@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@author Pieter Burghouwt
@version Revision 2.0
@date Thursday, February 28, 2013
*/

/*DNS is a part of CITRIC.

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
#include "DNS.h"

//*****************************************************************************
TDNS::TDNS(void){
  NextDNSIndex=-1;
  clear();  
};

//*****************************************************************************
void TDNS::clear(void){
  uint16_t i;

  FlowIndex=0;
  TimeStamp=0;
  Resolved=0;
  IP=0;
  TTL=0;
  for(i=0; i<MAXDOMAINNAMELENGTH; i++){
    NAME[i]=0;
    CNAME[i]=0;
  }  
};

//*****************************************************************************
void TDNS::set(int32_t f, int64_t ftime, uint32_t ipaddr, uint32_t t, char* nm, char* cm){
  int16_t i, nmstart, cmstart, nmlength, cmlength;

  FlowIndex=f;
  if(TimeStamp==0) TimeStamp=ftime;
  IP=ipaddr;
  TTL=t;   
  nmlength=strlen(nm);
  cmlength=strlen(cm);
  nmstart=nmlength-(MAXDOMAINNAMELENGTH-1); if(nmstart<0) nmstart=0;
  cmstart=cmlength-(MAXDOMAINNAMELENGTH-1); if(cmstart<0) cmstart=0;
  for(i=0; i<MAXDOMAINNAMELENGTH; i++){
    NAME[i]=nm[nmstart+i];
    CNAME[i]=cm[cmstart+i];
  }
};

//*****************************************************************************

int TDNS::match(uint32_t ip, char *name){

  int start;
  char *searchstring;

  //printf("\n ******* Name=%s*********\n",name);
  if(ip!=IP) return 0;
  if(name==NULL) return 1;
  start=strlen(name)-(MAXDOMAINNAMELENGTH-1); if(start<0) start=0;
  searchstring=&name[start];  
  if(strcmp(searchstring, NAME)==0) return 2;
  //if(strcmp(searchstring, CNAME)==0) return 3;
  return 0;
}


//*****************************************************************************
void TDNS::print(char *content){
  uint8_t *temp;

  temp=(uint8_t *)&IP; 
  if(content==NULL){
    printf("%d.%d.%d.%d, %d, %s, %s, %f, %d\n", temp[3], temp[2], temp[1], temp[0], TTL, NAME, CNAME, (double)TimeStamp/1000000, FlowIndex);
  } else {
    sprintf(content+strlen(content), "%d.%d.%d.%d, %d, %s, %s, %f, %d\n", temp[3], temp[2], temp[1], temp[0], TTL, NAME, CNAME, (double)TimeStamp/1000000, FlowIndex);
  }
};
   


