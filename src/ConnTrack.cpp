/**@file ConnTrack.cpp
@brief This file contains the operators of the TConnTrack class. 

@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@author Pieter Burghouwt
@version Revision 2.0
@date Wednesday, January 2, 2013
*/

/*ConnTrack is a part of CITRIC.

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
#include "Flow.h"
#include "FlowAggregator.h"
#include "ConnTrack.h"
#include "Settings.h"

extern TSettings *Settings;
extern TFlow Flow[FLOWBUFFERSIZE];
//example conntrack -D -s 10.0.0.16 -d 145.52.126.50 -p tcp --orig-port-dst 80



//*****************************************************************************
TConnTrack::TConnTrack(char *ip){
  char command[256];

  if(IPS_ENABLE==1){
    sprintf(command, "./scripts/FW.secure %s", ip);
    printf("\nFW-INIT command: %s\n", command);
    system(command);
  }
};

//*****************************************************************************

int TConnTrack::kill(uint32_t src, uint32_t dst, uint8_t prot, uint16_t psrc, uint16_t pdst){
  char command[256];
  uint8_t *s, *d;

  s=(uint8_t *)&src; 
  d=(uint8_t *)&dst; 
  sprintf(command, "conntrack -D -s %d.%d.%d.%d, -d %d.%d.%d.%d, -p %d, --orig-port-src %d --orig-port-src %d", s[3], s[2], s[1], s[0], d[3], d[2], d[1], d[0], prot, psrc, pdst);
  printf("\nKILL: %s\n", command);
  return 0;
};

//*****************************************************************************

int TConnTrack::kill(uint32_t flowindex){
  char command[256];
  uint8_t *s, *d;

  s=(uint8_t *)&Flow[flowindex].LocalIP; 
  d=(uint8_t *)&Flow[flowindex].RemoteIP; 

  if((Flow[flowindex].Protocol==6)||(Flow[flowindex].Protocol==17)){

    //Remove from ConnTrack
//    sprintf(command, "/usr/sbin/conntrack -D -s %d.%d.%d.%d -d %d.%d.%d.%d -p %d --orig-port-src %d --orig-port-dst %d > /dev/null ", s[3], s[2], s[1], s[0], d[3], d[2], d[1], d[0], Flow[flowindex].Protocol, Flow[flowindex].LocalPort, Flow[flowindex].RemotePort); //2>&1
    //printf("\nKILL: %s\n", command);
//    system(command);

    //Update blocklist of the Firewall
    //iptables -I dbl -s 0.0.0.10 -d 0.0.0.0 -p 6 --sport 0 --dport 0 -j DROP
    sprintf(command, "iptables -D dbl 20");
    printf("\nREMOVE FROM BLOCKLIST: %s\n", command);
    system(command);
    sprintf(command, "iptables -D dbl 19");
    printf("\nREMOVE FROM BLOCKLIST: %s\n", command);
    system(command);
    sprintf(command, "iptables -I dbl -s %d.%d.%d.%d -d %d.%d.%d.%d -p %d --sport %d --dport %d  -j DROP", s[3], s[2], s[1], s[0], d[3], d[2], d[1], d[0], Flow[flowindex].Protocol, Flow[flowindex].LocalPort, Flow[flowindex].RemotePort);
    printf("\nREMOVE FROM BLOCKLIST: %s\n", command);
    system(command);
    sprintf(command, "iptables -I dbl -s %d.%d.%d.%d -d %d.%d.%d.%d -p %d --sport %d --dport %d  -j DROP", d[3], d[2], d[1], d[0], s[3], s[2], s[1], s[0], Flow[flowindex].Protocol, Flow[flowindex].RemotePort, Flow[flowindex].LocalPort);
    printf("\nREMOVE FROM BLOCKLIST: %s\n", command);
    system(command);

  } else if(Flow[flowindex].Protocol==1){

    //Remove from ConnTrack
    //sprintf(command, "/usr/sbin/conntrack -D -s %d.%d.%d.%d -d %d.%d.%d.%d -p %d --icmp-type 8 --icmp-code 0 > /dev/null ", s[3], s[2], s[1], s[0], d[3], d[2], d[1], d[0], Flow[flowindex].Protocol); //2>&1
    //printf("\nICMP KILL: %s\n", command);
    //system(command);

    //Update blocklist of the Firewall
    //iptables -I dbl -s 0.0.0.10 -d 0.0.0.0 -p 6 --sport 0 --dport 0 -j DROP
    sprintf(command, "iptables -D dbl 20");
    printf("\nREMOVE FROM BLOCKLIST: %s\n", command);
    system(command);
    sprintf(command, "iptables -D dbl 19");
    printf("\nREMOVE FROM BLOCKLIST: %s\n", command);
    system(command);
    sprintf(command, "iptables -I dbl -s %d.%d.%d.%d -d %d.%d.%d.%d -p %d --icmp-type 0 -j DROP", s[3], s[2], s[1], s[0], d[3], d[2], d[1], d[0], Flow[flowindex].Protocol);
    printf("\nREMOVE FROM BLOCKLIST: %s\n", command);
    system(command);
    sprintf(command, "iptables -I dbl -s %d.%d.%d.%d -d %d.%d.%d.%d -p %d --icmp-type 0 -j DROP", d[3], d[2], d[1], d[0], s[3], s[2], s[1], s[0], Flow[flowindex].Protocol);
    printf("\nREMOVE FROM BLOCKLIST: %s\n", command);
    system(command);
  }
  return 0;
};



