/**@file FlowAggregator.h
@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@brief This file contains the prototypes of the TFlowAggregator class. 
@author Pieter Burghouwt
@version Revision 2.0
@date Tuesday, December 4, 2012
*/

#ifndef FLOWAGGREGATOR_
#define FLOWAGGREGATOR_

#include <stdint.h>
#include "PacketAnalyzer.h"
#include "Flow.h"
#include "Aggregator.h"
#include "pdu.h"

#define FLOWBUFFERSIZE 65536



class TFlowAggregator : virtual public TAggregator{
/**<@class TFlowAggregator
@brief Important class that manages the flows.

It creates a static array of FLOWBUFFERSIZE (65536) Flow-objects. By inspection of packets it creates or updates flows.
For fast search a hash table is used with FLOWHASHSIZE (1024) entries. Each entry is the start of a linked list of Flows.
Instead of Pointers the array-indices are used in the linked list.New flows are placed in a randomly picked empty flow of the static array. 
*/

  private:   
    uint32_t LocalIP; 	///<IP-address of local  as a reference for the flow direction

    uint8_t addPacket(void); 
/**<adds packet to existing flow or creates a new flow. Important to call first "find", because it uses Index to link with an existing flow.
@return 1=success */

    uint8_t addFlow(void); 
/**<Makes a new flow of the current Packet in PacketAnalyzer
@return 1=ok, 0=Buffer full or no matching LocalIP or No SYN in HTTP(S)*/

    uint8_t deleteFlow(int32_t i); 
/**<Frees a flow. Untested at this moment.
@return 1=ok
@param i Index of the flow in the static array of flows. */

    uint8_t find(void); 
/**<Finds the flow of current packet in PacketAnalyzer if it exists.
@return result of the find action\n
- 1 = Flow found, the index can be found in Index
- 2 = Flow not found, Index=-1
- 0 = No local IP present in the Packet */

    uint8_t find(uint8_t p, uint32_t sIP, uint32_t dIP, uint16_t sP,uint16_t dP, uint16_t id); 
/**<Finds the flow specified IP/Port parameters. return 1=success
@return result of the find action\n
- 1 = Flow found, the index can be found in Index
- 2 = Flow not found, Index=-1
- 0 = No local IP present in the Packet
@param p Protocol number (e.g. 6=TCP)
@param sIP Source IP address
@param dIP Destination IP address
@param sP Source Port
@param dP Destination Port
@param id Identification field, as used in DNS, 0 for other protocols  */




//statistics
    int32_t TotalPacketCounter;
    int32_t InPacketCounter;
    int32_t OutPacketCounter;
    int32_t NoLocalPacketCounter;

    int32_t EgressFlowCounter;
    int32_t IngressFlowCounter;
    int32_t AlreadyOpenCounter;

    int32_t EgressUDPFlowCounter;
    int32_t NonEmptyRRUDPCounter;
    int32_t IngressUDPFlowCounter;
    int32_t EgressTCPFlowCounter;
    int32_t IngressTCPFlowCounter;
    int32_t EgressICMPFlowCounter;
    int32_t IngressICMPFlowCounter;
    int32_t EgressOtherFlowCounter;
    int32_t IngressOtherFlowCounter; 
 
    int32_t EgressHTTPFlowCounter;
    int32_t EgressHTTPSFlowCounter;
    int32_t EgressDNSFlowCounter;

    int64_t StartTime;

 
  public:
    uint8_t Direction; 	///< Flow direction of last analyzed packet: INGRESS, EGRESS or UNDEFINED

    TFlowAggregator(uint32_t lIP);  
/**< Constructor. During creation a fixed array of Flows with hashtable is created for storage.
@param lIP The IP-address of the observed device. This will be the localIP-adddress. */

    uint8_t add(void);
/** updates existing flow or creates a new flow with the current packet in PacketAnalayzer. return 1 = success*/


    void dump(char *content, int dest);    
/**<Dumps the content of all flows to stdout or logfile
@return void
@param *content pointer to content that must be printed. NULL is print to stdout
@param dest destination of the log: 0= to stdout, 1=to logfile*/
};


#endif /*FLOWAGGREGATOR_*/
