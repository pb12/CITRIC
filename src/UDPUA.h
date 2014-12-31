/**@file UDPUA.h
@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@brief This file contains the prototypes of the UDPUA class.
@author Burghouwt:Pieter
@version Revision 2.0
@date Wednesday, April 4, 2012
*/


#ifndef UDPUA_
#define UDPUA_

#define UDP_Port 1234

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>



class TUDPUA{
/**@class TUDPUA
@brief One object of this class (class should be used as singleton) recieves and filters user events, received from UDP with a special agent. Received results can be polled in a Event-loop.
*/

  private:
  int SocketDescriptor;	 ///<Socket descriptor for UDP-communication, listening on port UDP_Port.

  public:
  char Message[256];	///<Received raw message, only used in an opened socket after succesful getEvent
  char Event[256];	///<String, describing the event (LMB=Left Mouse Button, Enter, F5).
  char Process[256];	///<String, describing the generating process that generates the user event
  int64_t TimeStamp;	///<TimeStamp: Time since 1970 in us
  uint8_t EventCode;	///<EventNumber: 0=none, 1=F5, 2=LMB, 3=Enter 
 
  TUDPUA(void);    
/**<The constructor that defines the UDP connection.\n
Clears the strings and EventCode;
*/    

   uint8_t open(void);
/**<Binds the UDP-socket.
@return 0 = ok 1+ = problem*/

   void close(void);
/**<Closes the UDP-socket.
@return void*/

   uint8_t getEvent(void);
/**<Reads UDP received events from an opened socket
@return 0 if no event and something or 1 if something is received.
*/

  int processEvent(void);
/**<Reads potential UDP received events from PCAP-packet. Remember that it will not use an open socket. Thi can result in ICMP-responses in the pcap-trace. 
@return 0=format ok but no event, 1=format ok and event, -1 = format not ok
*/

  void dump(void);
/**<Prints User Events with Timestamp, Event and Process.
@return void
*/

};


#endif /*UDPUA_*/
