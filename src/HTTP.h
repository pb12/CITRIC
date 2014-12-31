/**@file HTTP.h
@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@brief This file contains the prototypes of the THTTP class. 
@author Pieter Burghouwt
@version Revision 2.0
@date Tuesday, March 5, 2013
*/

#ifndef HTTP_
#define HTTP_

#define HTTPSTATUS_UNDEFINED 0
#define HTTPSTATUS_WAITINGFORSEND 1
#define HTTPSTATUS_SENT 2
#define HTTPSTATUS_RECEIVED 3

#define REFSTAT_UNDEFINED	0	
#define REFSTAT_REF		1
#define REFSTAT_NOREF		2
#define REFSTAT_GETSEEN		3


#include <stdint.h>
#include "GZIP.h"


class THTTP{
/**<@class THTTP
@brief Storage class for HTTP-events. Every HTTP-flow or HTTPS-flow that can potentially trigger new traffi by embedded URL's has an object of this class.
*/

  public:
   int64_t	Time;			///<Timestamp of the last HTTP-event
   uint8_t	Status;			///<State of the HTTP-dialog
   uint32_t	InByteCounter;		///<Number of ingress bytes during a recieve phase
   uint32_t	OutByteCounter;		///<Number of egress bytes during a send phase
   uint32_t	TotalInByteCounter;	///<Total number of egress payload bytes
   uint32_t	TotalOutByteCounter;	///<Total number of ingress payload bytes
   int32_t	FlowIndex;		///<Index to Flow that created the cause
   //uint16_t 	NextIndex;		///<Links to a next cause by an index (bidirectional linked list). 
   //uint16_t 	PreviousIndex;		///<Links to a previous cause by an index (bidirectional linked list). 

   uint8_t	ParseState;		///<Main State of the FSM for parsing URL's
   uint8_t	ParseSubState;		///<Sub State inside a Main State for parsing URL's
   uint16_t	ParseMicroState;	///<Micro State inside a SubState for parsing URL's
   int32_t      PayloadSize;		///<Size of the HTTP(S) payload in the last received packet

   uint8_t	ContentType;		///<0=unknown, 1=text
   uint8_t	Encoding;		///<0=unknown, 1=gzip
   uint8_t	Chunked;		///<0=unknown, 1=chunked

   int32_t	GZIPIndex;		///<pointer to GZIP-object if Encoding=1
   int		PostDotLength;		///<-1=no dot detected, other is number of characters after the dot
   uint8_t	RefStat;		///<Status of Referrer field (0=waitig , 1= 1=first parse failed, 2=second parse failed 
   char		URLBuffer[256];		///<Buffer to hold URL if it passes over multiple packets
   char		RefBuffer[80];		///<Buffer to hold Referer


   int64_t	LastHeaderTime;
   int64_t	LastTailTime;


   THTTP(void);
/**<The constructor. Resets all the data-members, including NextFlow*/

   void clear(void); 
/**<Clears all the data-members.
@return void */


   void print(char *content); 
/**<Prints a cause in readable format to stdout
@return void 
@param *content pointer to content that must be printed. NULL is print to stdout*/

};


#endif /*HTTP_*/
