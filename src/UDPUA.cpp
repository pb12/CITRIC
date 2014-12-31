/**@file UDPUA.cpp
@brief This file contains the operators of the TUDPUA class. 

@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@author Pieter Burghouwt
@version Revision 2.0
@date Wednesday, April 04, 2012
*/
/*UDPUA is a part of CITRIC.

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

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "UDPUA.h"
#include <sys/time.h>
#include "PacketAnalyzer.h"
#include "PCAP.h"
#include "EventCollector.h"

extern TPacketAnalyzer *PacketAnalyzer;
extern TPCAP *PCAP;
extern TEventCollector *EventCollector;

TUDPUA::TUDPUA(void){
  //initializes the object and configures the UDP-server
  int i;
  for(i=0; i<256; i++){
    Message[i]=0;
    Process[i]=0;
    Event[i]=0;
  }
  EventCode=0;
};

//*****************************************************************************

uint8_t TUDPUA::open(void){
	struct sockaddr_in adr_inet;
        int x, z;

	socklen_t adr_inet_len = sizeof(adr_inet);
	SocketDescriptor = socket(AF_INET, SOCK_DGRAM, 0);
	x=fcntl(SocketDescriptor,F_GETFL,0);
  	fcntl(SocketDescriptor,F_SETFL,x | O_NONBLOCK);
	if(SocketDescriptor == -1) { 
          printf("Error setting up server socket");
	  return 1;
        }
	memset(&adr_inet, 0, sizeof(adr_inet));
	adr_inet.sin_family = AF_INET;
	adr_inet.sin_port = htons(UDP_Port);
	adr_inet.sin_addr.s_addr = htonl(INADDR_ANY);
	if (adr_inet.sin_addr.s_addr == INADDR_NONE ){
          printf("bad address.");
          return 2;
        }
	z = bind(SocketDescriptor, (struct sockaddr *)&adr_inet, adr_inet_len);
	if ( z == -1 ) {
	  printf("bind() failed");
          return 3;
 	}
	printf("Bind() succeeded");
        return 0;
};

//*****************************************************************************

void TUDPUA::close(void){
  ::close(SocketDescriptor);
  printf("udp closed!\n");
};

//*****************************************************************************

uint8_t TUDPUA::getEvent(void){
        uint8_t i, length, e;
        int16_t size;
        struct timeval ts;
        
        
	size=recv(SocketDescriptor, Message, sizeof(Message), 0);
        if(size>0){
          printf("KEYEVENT");
          e=0;
          if((Message[1]=='F')&&(Message[2]=='5')) e=1;
          if((Message[1]=='L')&&(Message[2]=='M')&&(Message[3]=='B')) e=2;
          if((Message[1]=='E')&&(Message[2]=='n')&&(Message[3]=='t')) e=3;
          if(e==0) return 0; 
          EventCode=e;
	  gettimeofday(&ts, NULL);
  	  TimeStamp= (ts.tv_sec*1000000)+ts.tv_usec;
          length=(uint8_t)Message[0];
          if((size==6)&(length==0x68)&&(Message[5]==0x21)) return 0;
          for(i=0; i<length; i++){
            Event[i]=Message[i+1];
          }
          Event[i]=0;
          for(i=0; i<size-(length+1); i++){
            Process[i]=Message[i+length+1];
          }
          Process[i]=0;
          return 1;
        }
        return 0;
};

//*****************************************************************************

int TUDPUA::processEvent(void){
   //captures directly fromPCAP
   uint8_t e, length;
   int16_t size, i;
   char * buffer;

   buffer=(char*)&PCAP->Packet[PacketAnalyzer->PayloadIndex];
   size=PacketAnalyzer->Length-PacketAnalyzer->PayloadIndex;
   //printf("\nkeybufferlength=%d\n",size);
   //printf("**");
   //printf("KEY %ld  CONT:", PacketAnalyzer->Time);
   //for(i=1; i<size; i++) printf("%c", buffer[i]);  
   //printf("**\n");

   if(size<5) return -1; //to small
   e=0;
   if((buffer[1]=='F')&&(buffer[2]=='5')) e=1;
   if((buffer[1]=='L')&&(buffer[2]=='M')&&(buffer[3]=='B')) e=2;
   if((buffer[1]=='E')&&(buffer[2]=='n')&&(buffer[3]=='t')) e=3;
   if((buffer[1]=='E')&&(buffer[2]=='N')&&(buffer[3]=='T')) e=3;
   if(e==0) return 0; 
   EventCode=e;
   TimeStamp=PacketAnalyzer->Time;
   length=(uint8_t)buffer[0];
   //printf("\nsignaledlength=%d\n",length);
   if((size==6)&&(length==0x68)&&(buffer[5]==0x21)) return 0;
   for(i=0; i<length; i++){
     Event[i]=buffer[i+1];
   }
   Event[i]=0;
   for(i=0; i<size-(length+1); i++){
     Process[i]=buffer[i+length+1];
   }
   Process[i]=0;
   EventCollector->addUserEvent(TimeStamp, EventCode, Process);
   return 1;


}


//*****************************************************************************

void TUDPUA::dump(void){
    printf("DUMP:Time: %f - Event: %s - Process: %s\n", (double)TimeStamp/1000000, Event, Process);
}
