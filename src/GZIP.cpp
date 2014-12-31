/**@file GZIP.cpp
@brief This file contains the operators of the TGZIP class. 

@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@author Pieter Burghouwt
@version Revision 2.0
@date Tuesday, March 12, 2013
*/
/*GZIP is a part of CITRIC.

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
#include <zlib.h>
#include <string.h>
#include "GZIP.h"
#include "PacketAnalyzer.h"

extern TPacketAnalyzer *PacketAnalyzer;

#define windowBits 15		//default window size
#define ENABLE_ZLIB_GZIP 32	//enable GZIP header detection and processing


//*****************************************************************************
TGZIP::TGZIP(void){
  //InUse=0; //object is free
  free();
};


//*****************************************************************************
int TGZIP::isInUse(void){
  return InUse; 
};

//*****************************************************************************
void TGZIP::take(void){
    //strm={0};
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_out = OutBuffer;
    inflateInit2 (& strm, windowBits | ENABLE_ZLIB_GZIP);
    InUse=1;
};


void TGZIP::free(void){
  inflateEnd (& strm);
  InUse=0;
  Processing=0;
};


int TGZIP::uncompress(void){

  //int ret;

  if(InLength>0){	//data available for compression
    if((Processing==0)&&(InBuffer[0]!=31)){   //check presence magic number in de first chunk (Chunked length striping)
      //printf("\n>3 ERROR, %ld, deflate wrong magic number: %d\n",PacketAnalyzer->Time, InBuffer[0]);
      return -1;
    }

    if(Processing==0){
      OutLength=0;				//setting outputlength    
      OutBuffer[0]=0;				//resetting Buffer
    }
    Processing=1;				//processing flag set
    strm.avail_in = InLength;			//initializing length
    strm.next_in=(unsigned char *)InBuffer;     //initializing input buffer 
    //printf("\n>7 DEBUG, %ld, uncompress starting: first byte=%d, last byte=%d, InLength=%d \n",PacketAnalyzer->Time, strm.next_in[0],InBuffer[InLength-1], strm.avail_in);
    
    do {
      strm.avail_out = GZIP_BUFFERSIZE;
      strm.next_out = OutBuffer;
      inflate (& strm, Z_NO_FLUSH);
      //printf("%ld STATUS: %d\n", PacketAnalyzer->Time, inflate (& strm, Z_NO_FLUSH));
    } while (strm.avail_out == 0);
    OutLength=strm.next_out-OutBuffer; 
    //printf("Ucompr size: %d  InLength=%d\n",OutLength,strm.avail_in );
    //for(int i=0; i<30; i++) printf("%c",OutBuffer[i]);
    //printf(" .||||. ");
    //for(int i=0; i<30; i++) printf("%c",OutBuffer[(OutLength-30+i)]);
    //printf("\n");
    //for(int i=0; i<OutLength; i++) printf("%c",OutBuffer[i]);
    //printf("\nSUCCESS!!! >>> Lengte was: %d\n", OutLength);
    return 0;   
  } else {
    //printf("\nZEROLENGTH NO COMPRESSION\n");
    return -2;
  }
}

			

