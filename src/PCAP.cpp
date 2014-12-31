/**@file PCAP.cpp
@brief This file contains the operators of the TPCAP class. 

@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@author Pieter Burghouwt
@version Revision 2.0
@date Tuesday, November 22, 2011
*/
/*PCAP is a part of CITRIC.

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

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include "PCAP.h" 
#include "Logger.h"


extern TLogger *Logger;


//*****************************************************************************

TPCAP::TPCAP(void){
    Filter=(char *)"ip";
    DeviceName=NULL;
};

//*****************************************************************************

void TPCAP::openDevice(char *device, int live){
//printf("waarde is: %d\n",device[strlen(device)-1]);
  if(live==1){
    openNIC((char *)device);
  } else {
    openFile((char *)device);
  }
};

//*****************************************************************************

void TPCAP::openNIC(char *dev){

  char errbuf[PCAP_ERRBUF_SIZE];

  //Handle = pcap_open_live(dev, 65000, 0, 1, errbuf);
  Handle = pcap_open_live(dev, 65536, 1, 0, errbuf); //delay of infinite in promisc mode
  if (Handle == 0){
    fprintf(stderr, "Error in pcap_open_live: %s \n", errbuf);
    exit(1);
  }
  if (pcap_setnonblock(Handle, 1, errbuf) != 0) {
    fprintf(stderr, "Error in pcap_non_blocking mode: %s \n", errbuf);
    exit(1);
  }
  DeviceName=dev;
};

//*****************************************************************************

void TPCAP::openFile(char *name){

  char errbuf[PCAP_ERRBUF_SIZE];  

  Handle = pcap_open_offline(name,errbuf);        
  if (Handle == 0){
    fprintf(stderr, "Error in pcap_open_live: %s \n", errbuf);
    exit(1);
  }
  if (pcap_setnonblock(Handle, 1, errbuf) != 0) {
    fprintf(stderr, "Error in pcap_non_blocking mode: %s \n", errbuf);
    exit(1);
  }

};

//*****************************************************************************

int8_t TPCAP::applyFilter(char *f){

  struct bpf_program fp;     
 
//  bpf_u_int32 maskp;          
//  bpf_u_int32 netp;  
  char errbuf[PCAP_ERRBUF_SIZE];  

  if(DeviceName==NULL) return -1;
  Filter=f;
  /*if(pcap_lookupnet(DeviceName,&netp,&maskp,errbuf) == -1){
    fprintf(stderr,"Error calling pcap_compile: %s \n", errbuf);
    exit(1); 
  } */   

  //if(pcap_compile(Handle,&fp,Filter,0,netp) == -1){ 
  if(pcap_compile(Handle,&fp,Filter,0,0) == -1){ 
    fprintf(stderr,"Error calling pcap_compile: %s \n", errbuf);
    exit(1); 
  }
  if(pcap_setfilter(Handle,&fp) == -1){ 
     fprintf(stderr,"Error setting filter: %s \n", errbuf); 
     exit(1); 
  }
  return 0;
};

//*****************************************************************************

int8_t TPCAP::getPacketEvent(void){	
  struct pcap_pkthdr *header;
  uint8_t status;
			
  status=pcap_next_ex(Handle, &header, &Packet);
  TimeStamp=(header->ts.tv_sec)*1000000 + header->ts.tv_usec;
  Length=header->caplen;
  return status;
};

//*****************************************************************************

void TPCAP::close(char *dm, int dest){
  typedef struct pcap_stat Tstat;
  Tstat stat;

  if(pcap_stats(Handle, &stat)==0){
    sprintf(dm, "PCAP LIVE PACKET STATISTICS\n");
    sprintf(dm+strlen(dm), "PCAP: analyzed packets:\t\t\t%d\n", stat.ps_recv);
    sprintf(dm+strlen(dm), "PCAP: dropped packets by system: \t%d\n", stat.ps_drop);
    sprintf(dm+strlen(dm), "PCAP: dropped packets by interface:\t%d\n\n", stat.ps_ifdrop);
    Logger->saveStatsLog(dm);
    printf("%s", dm);
  }
  pcap_close(Handle);
};





