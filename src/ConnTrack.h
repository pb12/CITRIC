/**@file ConnTrack.h
@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@brief This file contains the prototypes of the TConnTrack class. 
@author Pieter Burghouwt
@version Revision 2.0
@date Wednesday, January 1, 2013
*/

#ifndef CONNTRACK_
#define CONNTRACK_

#include <stdint.h>
#include "PacketAnalyzer.h"


class TConnTrack{
/**<@class TConnTrack
@brief Class that can kill an establshed connection.
*/

  public: 
  TConnTrack(char *ip);  
/**< Constructor. Initialises Firewall
@param ip local IP-address
*/

  int kill(uint32_t src, uint32_t dst, uint8_t prot, uint16_t psrc, uint16_t pdst);
/**< Kills a flow by specified 5-tuple 
@return 0=success, -1=error 
@param src source IP-address (=local IP-address)
@param dst dest IP-address (=remote IP-address)
@param prot protocol (only 6=TCP or 17=UDP)
@param psrc source port (=local port)
@param pdst dest port (=remote port)*/

int kill(uint32_t flowindex);
/**< Kills a flow by specified flowindex 
@return 0=success, -1=error 
@param flowindex*/

};
#endif /*CONNTRACK_*/
