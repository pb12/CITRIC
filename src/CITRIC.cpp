/**@file CITRIC.cpp

@brief This file contains the main file of CITRIC.
CITRIC is an experimental causal detector that analyzes PCAP-data from a device.It aggregates packets in bidirectional flows and it organizes the flows in causal trees. A causal tree is a group of flows with a causal relationship. Causal relationship is determined by time-intervals and in some cases content. This is an experimental version for research.

@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@author Pieter Burghouwt
@version Revision 2.0
@date Friday, November 16, 2012
*/

/**
\mainpage CITRIC introduction
CITRIC is an experimental causal detector that analyzes PCAP-data from a device.It aggregates packets in bidirectional flows and it organizes the flows in causal trees. \n
A causal tree is a group of flows with a causal relationship. Causal relationship is determined by time-intervals and in some cases content.\n
\n
To start CITRIC: <em>sudo CITRIC x.x.x.x y</em>\n
with <em>x.x.x.x</em> is the address of the observed computer\n
and <em>y</em> is the name of the observed interface.\n
\n
If y ends with a number it is assumed to be a device e.g. eth0.\n
If y ends with something else it assumed to be a file in PCAP-format.\n
\n
In both cases CITRIC is terminated with a Control-C sequence.\n
\n
This is an experimental version for research.

@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@author Pieter Burghouwt
@version Revision 2.0
@date Tuesday, May 7, 2013
*/

/*This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>*/


#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include "PCAP.h" 
#include "PacketAnalyzer.h"
#include "FlowAggregator.h"
#include "DNSHelper.h"
#include "CauseAnalyzer.h"
#include "HTTPHelper.h"
#include "EventCollector.h"
#include "UDPUA.h"
#include "CITRIC.h"
#include "Logger.h"
#include "Settings.h"
#include "ConnTrack.h"

 
TPCAP *PCAP;
TPacketAnalyzer *PacketAnalyzer;
TFlowAggregator *FlowAggregator;
TDNSHelper *DNSHelper;
TCauseAnalyzer *CauseAnalyzer;
THTTPHelper *HTTPHelper;
TUDPUA *UDPUA;
TEventCollector *EventCollector;
TLogger *Logger;
TSettings *Settings;
TConnTrack *ConnTrack;
char DumpMessage[100000000];  //100MB buffer space to dump messages to file
int ENDPROG;

int main(int argc, char *argv[]){
  int dec[4];
  char device[10];
  char rawname[256];
  char name[256];
  char ip[20];
  uint32_t LocalIP;
  uint8_t *temp;  
  int d;
  int live;
  
  //Parsing the command-line parameters
  printf("CITRIC  Causal Flow Analysis Tool P.o.C. v2.0\n");
  if(argc==3){
    //filename=devicename 
    sscanf(argv[1], "%d.%d.%d.%d", &dec[3], &dec[2], &dec[1], &dec[0]);
    temp=(uint8_t *)&LocalIP;
    temp[0]=(uint8_t)dec[0]; temp[1]=(uint8_t)dec[1]; temp[2]=(uint8_t)dec[2]; temp[3]=(uint8_t)dec[3];  
    sscanf(argv[1], "%s", ip);
    sscanf(argv[2], "%s", device);
    strcpy(rawname, device); //needs some processing later
  } else if (argc==4){
    //file name given
    sscanf(argv[1], "%d.%d.%d.%d", &dec[3], &dec[2], &dec[1], &dec[0]);
    temp=(uint8_t *)&LocalIP;
    temp[0]=(uint8_t)dec[0]; temp[1]=(uint8_t)dec[1]; temp[2]=(uint8_t)dec[2]; temp[3]=(uint8_t)dec[3];  
    sscanf(argv[1], "%s", ip);
    sscanf(argv[2], "%s", device);
    sscanf(argv[3], "%s", name); //ready to use 
  } else {
    printf("**** ERROR **** Wrong command line options!\n\n");
    printf("Usage: CITRIC x.x.x.x source [dest]\n\n");
    printf("- x.x.x.x = observed IP address\n");
    printf("- source = the input device or pcap file (pcap files must end with .pcap extension).\n");
    printf("- [dest] = optional output filename. If not present the output will have the source name\n");
    printf("  All output without optional filename is written to ./results direcory\n\n\n");
    return 0;
  }
  //Decide from NIC (live=1) or from file (live=0)
  live=1;
  if(strlen(device)>5){
    if(strcmp(&device[strlen(device)-5], ".pcap")==0){
      //capture from .pcap file
      live=0;
    }
  } 

  if(live==1){
    //Live capture
    if(argc==3){
      sprintf(name, "./results/%s", rawname);
    }
    printf("\tIP:\t%d/%d.%d.%d\n\tSOURCE:\t%s(NIC)\n\tDEST:\t%s.*\n", dec[3], dec[2], dec[1], dec[0], device, name);
  } else {
    //pcap capture
    if(argc==3){
      rawname[strlen(rawname)-5]='\0';
      if(strrchr(rawname, '/')==NULL){
        sprintf(name, "./results/%s", rawname);
      } else {
        sprintf(name, "./results/%s", (strrchr(rawname, '/')+1));
      }
    }
    printf("\tIP:\t%d/%d.%d.%d\n\tSOURCE:\t%s(FILE)\n\tDEST:\t%s.*\n", dec[3], dec[2], dec[1], dec[0], device, name);
  }
  
  //Instantiating & initialiazing objects
  printf("\n1. Instantiating and initializing objects\n" );
  Settings=new TSettings("CITRIC.conf");
  PCAP=new TPCAP();
  PacketAnalyzer=new TPacketAnalyzer();  
  FlowAggregator=new TFlowAggregator(LocalIP);
  DNSHelper=new TDNSHelper();
  HTTPHelper=new THTTPHelper();
  EventCollector=new TEventCollector();
  CauseAnalyzer=new TCauseAnalyzer();
  UDPUA=new TUDPUA();
  Logger=new TLogger(name);
  ConnTrack=new TConnTrack(ip);
  signal(SIGINT, sigproc); //Enabling the CTRL+C hook
  PCAP->openDevice(device, live); 
  printf("4. Inserting Filter (0=ok):%d .\n", PCAP->applyFilter((char *)"ip"));  
  //UDPUA->open();

  //The main event loop
  printf("5. Starting the main event-loop now.\n\n");
  ENDPROG=0;
  do{
    d=PCAP->getPacketEvent();
    if((d==1)&&(ENDPROG==0)){
      PacketAnalyzer->handleEvent();
    } else sigproc(0);
    //if(UDPUA->getEvent()==1) UDPUA->dump();
  }while(1);
 
  //Impossible to reach this
  PCAP->close(DumpMessage, 0);
  printf("EVENTLOOP ENDED?!\n");
  return 0;
}


void sigproc(int signum){
  char *dm;

  printf("\nCapture stopped, now postprocessing and saving the logs...\n");  //Creating some space
  //UDPUA->close();
  dm=DumpMessage;
  //dm=NULL;
  Logger->initStatsLog();
  PCAP->close(dm, 1); 
  FlowAggregator->dump(dm, 1);
  DNSHelper->dump(dm);
  CauseAnalyzer->dump(dm, 1);
  HTTPHelper->dump(dm, 1);
  EventCollector->dump(dm, 1);
  Settings->dump(dm, 1);
  Logger->saveLog();
  printf("\nResults written in map: results/ Have a nice day!\n\n");
  exit(0);
}

