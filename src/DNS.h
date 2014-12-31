/**@file DNS.h
@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@brief This file contains the prototypes of the TDNS class. 
@author Pieter Burghouwt
@version Revision 2.0
@date Thursday, February 28, 2013
*/

#ifndef DNS_
#define DNS_

#include <stdint.h>

#define MAXDOMAINNAMELENGTH 64			//used to truncate the domain name strings

class TDNS{
/**<@class TDNS
@brief Storage class for DNS-data. Objects of this class are managed by DNSHelper
*/

  public:
   int64_t	TimeStamp;			///<Timestamp of the recieved data
   uint32_t	IP;				///<IP-address 
   char		NAME[MAXDOMAINNAMELENGTH];	///<Domain name of the original Query
   char		CNAME[MAXDOMAINNAMELENGTH];     ///<Domain name in the RR (possibly a CNAME)
   uint32_t	TTL;				///<Time To Live in seconds
   uint8_t	Resolved;			///<Boolean 0= not used, 1=at least 1 received IP is used
   int32_t	FlowIndex;			///<Index to the most recent DNS Flow that delivered this information
   int32_t 	NextDNSIndex;			///<Links to a next DNS-record by an index (unidirectional linked list). 
  
   TDNS(void);
/**<The constructor. Resets all the data-members */

void clear(void); 
/**<Clears all the data-members, except NextDNSIndex
@return void */

void set(int32_t f, int64_t ftime, uint32_t ipaddr, uint32_t t, char* nm, char* cm);  
/**<Sets a DNS-object except for the linked list pointer\n
@return void 
@param f Index to the DNS Flow that delivered this information 
@param ftime First time the IP-address was referenced in a DNS A record
@param ipaddr IP-address of the RR
@param t TTL in the RR
@param nm Name in the Query
@param cm Name in the Answer RR (probably a CNAME or the same as the Query Name)*/

int match(uint32_t ip, char *name);
/**<Matches IP and Name of DNS-record. If *name is NULL only the IP-address is used in the search\n
@return 0=no match, 1=IP match, 2=NAME match, 3=CNAME match 
@param ip IP-address 
@param *name Pointer to Name */

void print(char *content); 
/**<Prints a flow in readable format to stdout
@return void 
@param *content pointer to content that must be printed. NULL is print to stdout*/

};


#endif /*DNS_*/
