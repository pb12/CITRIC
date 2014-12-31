/**@file DNSHelper.h
@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@brief This file contains the prototypes of the TDNSHelper class. 
@author Pieter Burghouwt
@version Revision 2.0
@date Thursday, February 28, 2013
*/

#ifndef DNSHELPER_
#define DNSHELPER_

#include <stdint.h>
#include "PacketAnalyzer.h"
#include "Flow.h"
#include "DNS.h"
#include "Aggregator.h"


#define DNSBUFFERSIZE 65536	///<total buffer size of DNS-objects
#define DNSHASHSIZE 1024 	///<must be a power of 2. Max is 2^16


class TDNSHelper : virtual public TAggregator{
/**<@class TDNSHelper
@brief Class specialized in aggregating DNS events. It only processes replies from egress UDP DNS-flows.
DNS objects are stored as a chained hashtable of unidirectional linked lists. The hashtable is based on a modulo 256 sum of the IP-address.
This results in a fast looukup by IP-adress. Newer records with the same name and IP-adress are replaced.
TODO: cleanup-routine that checks one record at a time on expiry.
*/

  private:
    const uint8_t *Packet;			///<packet that starts from DNS start
    char QueryName[256];			///<string for parsed query name
    char AnswerName[256];			///<string for parsed answer name
    uint16_t QueryNameIndex;			///<write-pointer in QueryString
    uint16_t AnswerNameIndex;			///<write-pointer in AnswerString
    uint16_t Length;				///<Length of DNS-header and payload
    int32_t DNSTable[DNSHASHSIZE];		///<Hashtable: Array of indexes to the buckets that belong to the hashtable

    uint16_t parseName(uint16_t offset);
/**<Parses an name in an answer from the DNS payload. In case of a pointer it is recursively called.
@return 0=overflow, in all other cases it points to the next field in the packet after the name.
@param offset present index in the packet*/


    void clearQueryName(void);
/**<Clears QueryName array.
@return void*/

    uint8_t addToQueryName(char s); 
/**<Copies a character to the QueryName array.
@return 1=success, 0=array full 
@param s character*/

    void clearAnswerName(void);
/**<Clears AnswerName array.
@return void*/

    uint8_t addToAnswerName(char s); 
/**<Copies a character to the AnswerName array.
@return 1=success, 0=array full 
@param s character*/



  public:
    

    TDNSHelper(void);
/**<The constructor. Resets all the data-members, including NextFlow*/

    uint8_t add(void); 
/**<Processes a DNS-response.
@return 1=success: data updated in existing records, 2=succcess: new DNS-record(s) added, 3+ = error, 0=ingress*/

    char* getQueryName(void);
/**<Gets the Queryname. Ony to be called immediatly after add.
@return Pointer to string with most recent queryname*/

    uint8_t deleteRecord(int32_t i); 
/**<Frees a DNS-record.
@return 1=ok
@param i Index of the DNS-record in the static array of DNS-records. */

    int find(uint32_t ip, char *name); 
/**<Finds a DNS-record by specified IP-address and name. If name=NULL only IP-match.
@return status, 0=no match-no items left, 1=IP-match, 2=name match, 3=cname match, Index points to the last queried item
@param ip IP-address
@param name Name of the Query, if NULL only the ip-adress is used in the search*/


   uint16_t makeIPHash(uint32_t ip); 
/**<Calculates a modulo HASHSIZE of the IP-address\n
This can be used for organising a fast lookup by a hash-table.\n
The hashspace is set by DNSHASHSIZE (default=1024).
@return HashValue */


    void dump(char *content);    
/**<Dumps the content of all DNS-records to stdout
return void
@param *content pointer to content that must be printed. NULL is print to stdout*/

};


#endif /*DNSHELPER_*/
