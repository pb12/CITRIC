/**@file EventCollector.h
@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@brief This file contains the prototypes of the TEventCollector class. 
@author Pieter Burghouwt
@version Revision 2.0
@date Monday, March 11, 2013
*/

#ifndef EVENTCOLLECTOR_
#define EVENTCOLLECTOR_

#include <stdint.h>

#define EVENTBUFFERSIZE 10000		//size of a normal event buffer
#define RPTDNSEVENTBUFFERSIZE 100	//size of the repeat DNS ecent buffer
#define URLEVENTBUFFERSIZE 1000		//size of one URL event buffer
#define URLEVENTHASHSIZE 256		//number of URLBuffers (hashes)	

#define CAUSE_HTTPDATARECEIVED 1
#define CAUSE_HTTPDATAPUSH 2
#define CAUSE_HTTPSIZEDECREASE 3
#define CAUSE_HTTPWITHDRAWN 4

class TUserEvent{
public:
  int64_t TimeStamp;		///<TimeStamp: Time since 1970 in us
  uint8_t EventCode;		///<EventNumber: 0=none, 1=F5, 2=LMB, 3=Enter
  char Process[64];		///<String, describing the generating process that generates the user event in lowercase ending with '/0'(<64)

  uint8_t CauseCount;		///<number of times the event caused new flows
  TUserEvent(void);     	///<The constructor. Clears all the data-members
  void clear(void);     	///<Clears all data-members. @return void 
  void print(char *content); 	///<Prints a cause in readable format to stdout @return void 
};

class THTTPEvent{
public:
  int64_t TimeStamp;		///<TimeStamp: Time since 1970 in us
  uint8_t  EventCode;		///<EventNumber: 0=UNDEFINED, 1=HTTPDATARECEIVED, 2=HTTPDATAPUSH, 3=CAUSE_HTTPWITHDRAWN
  int32_t FlowIndex;		///<Index to flow that contains the event

  uint8_t CauseCount;		///<number of times the event caused new flows
  int64_t DeltaT;		///<Time contributed to openwindow
  THTTPEvent(void);		///<The constructor. Clears all the data-members
  void clear(void);     	///<Clears all data-members. @return void 
  void print(char *content); 	///<Prints a cause in readable format to stdout @return void 
};

class THTTPSEvent{
public:
  int64_t TimeStamp;		///<TimeStamp: Time since 1970 in us
  uint8_t  EventCode;		///<EventNumber: 0=UNDEFINED, 1=HTTPDATARECEIVED, 2=HTTPDATAPUSH, 3=CAUSE_HTTPWITHDRAWN
  int32_t FlowIndex;		///<Index to flow that contains the event

  uint8_t CauseCount;		///<number of times the event caused new flows
  int64_t DeltaT;		///<Time contributed to openwindow
  THTTPSEvent(void);		///<The constructor. Clears all the data-members
  void clear(void);     	///<Clears all data-members. @return void 
  void print(char *content); 	///<Prints a cause in readable format to stdout @return void 
};

class TURLEvent{
public:
  int64_t TimeStamp;		///<TimeStamp: Time since 1970 in us
  char URL[64];			///<domain name in lowercase ending with '/0'(<64)
  char SUBURL[64];		///<2nd level domain name substring for softcompare
  int32_t FlowIndex;		///<Index to flow that contains the event

  uint8_t CauseCount;		///<number of times the event caused new flows
  TURLEvent(void);		///<The constructor. Clears all the data-members
  void clear(void);		///<Clears all data-members. @return void 
  void print(char *content);	///<Prints a cause in readable format to stdout @return void  
};

class TRPTDNSEvent{
public:
  int64_t TimeStamp;		///<TimeStamp: Time since 1970 in us
  char Name[64];		///<domain name in lowercase ending with '/0'(<64)
  int32_t FlowIndex;		///<Index to flow that contains the event

  uint8_t CauseCount;		///<number of times the event caused new flows
  TRPTDNSEvent(void);		///<The constructor. Clears all the data-members
  void clear(void);		///<Clears all data-members. @return void 
  void print(char *content);	///<Prints a cause in readable format to stdout @return void  
};


class TUTreeEvent{
public:
  int64_t TimeStamp;		///<TimeStamp: Time since 1970 in us
  int32_t TreeIndex;		///<Index to tree that contains the event

  uint8_t CauseCount;		///<number of times the event caused new flows
  int64_t DeltaT;		///<Time contributed to openwindow
  TUTreeEvent(void);		///<The constructor. Clears all the data-members
  void clear(void);     	///<Clears all data-members. @return void 
  void print(char *content); 	///<Prints a cause in readable format to stdout @return 
};
  

class TEventCollector{
/**<@class TEventCollector
@brief Class specialized in aggregating events that can cause new traffic. Every potential event is buffered here.
Hashing is used for fast lookup. FIFO's are used to prevent overflow
*/

  private:

  int32_t UserEventIndex;			///<index to most recent event or -1 if empty
  int32_t HTTPEventIndex;			///<index to most recent event or -1 if empty
  int32_t HTTPSEventIndex;			///<index to most recent event or -1 if empty
  int32_t UTreeEventIndex;			///<index to most recent event or -1 if empty
  int32_t URLEventIndex[URLEVENTHASHSIZE];	///<array of indices to most recent URL events or -1 if empty
  int32_t RPTDNSEventIndex[URLEVENTHASHSIZE];   ///<array of indices to most recent REPEAT DNS events or -1 if empty
  
  public:

  TUserEvent UserEvent[EVENTBUFFERSIZE];	///<FIFO of user events
  THTTPEvent HTTPEvent[EVENTBUFFERSIZE];	///<FIFO of generic HTTP events
  THTTPSEvent HTTPSEvent[EVENTBUFFERSIZE];	///<FIFO of generic HTTPS events
  TUTreeEvent UTreeEvent[EVENTBUFFERSIZE];	///<FIFO of Trees with Unknown cause
  TURLEvent URLEvent[URLEVENTHASHSIZE][URLEVENTBUFFERSIZE];	///<Hastable with URLEVENTHASSIZE buckets. Each bucket is a FIFO
  TRPTDNSEvent RPTDNSEvent[URLEVENTHASHSIZE][RPTDNSEVENTBUFFERSIZE];	///<Hastable with URLEVENTHASSIZE buckets. Each bucket is a FIFO
  int16_t Hash;

  TEventCollector(void);

  int64_t AggregatedWindowTime;
  int64_t WindowEndTime;
  int32_t UserEventCount;
  int32_t HTTPEventCount;
  int32_t HTTPSEventCount;
  int32_t UTreeEventCount;

  void addUserEvent(int64_t timestamp, uint8_t eventcode, char *process);
/**<Adds a user event\n
@return void 
@param timestamp  
@param eventcode Describes the type of event: 0=other, 1=F5, 2=LMB, 3=Enter
@param *process Pointer to a string that describes the geerating process (if supported by the agent)*/

  void addHTTPEvent(int64_t timestamp, uint8_t eventcode, uint32_t flowindex);
/**<Adds a HTTP event\n
@return void 
@param timestamp  
@param eventcode Describes the type of event: 0=non trivial data received, 1=push flag received
@param flowindex Index to the HTTP flow*/

void removeHTTPEvent(int64_t timestamp, int32_t flowindex);
/**<Removes a HTTP event, by setting the Eventcode to CAUSE_WITHDRAWN\n
@return void 
@param timestamp  
@param flowindex Index to the HTTP flow*/

  void addHTTPSEvent(int64_t timestamp, uint8_t eventcode, uint32_t flowindex);
/**<Adds a HTTP event\n
@return void 
@param timestamp  
@param eventcode Describes the type of event: 0=non trivial data received, 1=push flag received
@param flowindex Index to the HTTP flow*/

  void addUTreeEvent(int64_t timestamp, uint32_t treeindex);
/**<Adds an Unknown cause Tree event\n
@return void 
@param timestamp  
@param treeindex Index to the Tree*/

void removeHTTPSEvent(int64_t timestamp, int32_t flowindex);
/**<Removes a HTTP event, by setting the Eventcode to CAUSE_WITHDRAWN\n
@return void 
@param timestamp  
@param flowindex Index to the HTTP flow*/

  void addURLEvent(int64_t timestamp, char *url, int32_t flowindex);
/**<Adds a HTTP URL event\n
@return void 
@param timestamp  
@param *url Pointer to the string that contains the received URL
@param flowindex Index to the HTTP flow*/

  void addRPTDNSEvent(int64_t timestamp, char *name, int32_t flowindex);
/**<Adds a REPEAT DNS event\n
@return void 
@param timestamp  
@param *name Pointer to the string that contains the query name
@param flowindex Index to the DNS flow*/


  int32_t searchUserEvent(int64_t *delay); 
/**<Delivers a DNS event, starting with the most recent one and counting back on every call.\n 
@return index to most Event or -1 if empty 
@param *delay max search time to lookup back in history, returns the time between found event and present time*/  

  int32_t searchHTTPEvent(int64_t *delay, int prot); 
/**<Delivers a HTTP event, starting with the most recent one and counting back on every call.\n
@return index to most Event  or -1 if empty 
@param *delay max search time to lookup back in history, returns the time between found event and present time
@param prot 80=http, 443=https*/ 

  int32_t searchHTTPSEvent(int64_t *delay, int prot); 
/**<Delivers a HTTP event, starting with the most recent one and counting back on every call.\n
@return index to most Event  or -1 if empty 
@param *delay max search time to lookup back in history, returns the time between found event and present time
@param prot 80=http, 443=https*/ 

int32_t searchURLEvent(char *url, int64_t *delay, int32_t index);
/**<Delivers a HTTP event by URL, by walking back in history. \n
@return index to most Event  or -1 if empty
@param *url Pointer to the string that must match the URL 
@param *delay max search time to lookup back in history, returns the time between found event and present time
@param index Pointer to Index of Last found event, -1=start new search or as return: nothing found*/

int32_t searchUTreeEvent(int64_t *delay);
/**<Delivers the most recent unknown cause tree event, by walking back in history. \n
@return index to most Event  or -1 if empty
@param *delay pointer to max search time to lookup back in history, returns the time between found event and present time*/

int32_t searchSOFTURLEvent(char *url, int64_t *delay, int32_t index);
/**<Delivers a SOFTHTTP event by URL substring, by walking back in history. \n
@return index to most Event  or -1 if empty
@param *url Pointer to the string that must match the URL 
@param *delay max search time to lookup back in history, returns the time between found event and present time
@param index Last found event, used for search continuation, -1 is start from the most recent entry*/

int32_t searchRPTDNSEvent(char *name, int64_t *delay);
/**<Delivers the flowindex of a REPEAT DNS event, including the name and delay, by walking back in history. \n
@return index to FlowIndex that created the event
@param *name Pointer to the string that must match the query name 
@param *delay max search time to lookup back in history, returns the time between found event and present time*/

int64_t getLastUserEvent(void);
/**<Gives timestamp of last enter/mousclick/F5 event or zero if none.\n
@return timestamp of last enter/mousclick/F5 or 0 if none*/

  void makeIPHash(uint32_t ip);		
/**<Calculates the hash of an IP-address\n
@return hash
@param ip IP-adress */ 

  void makeURLHash(char *url);
/**<Calculates the hash of an URL or name\n
@return hash
@param *url Pointer to name string */ 

  void dump(char *content, int dest);
/**<Dumps the content of all Events to stdout
return void
@param *content pointer to content that must be printed. NULL is print to stdout
@param dest destination of the log: 0= to stdout, 1=to logfile*/
};
#endif /*EVENTCOLLECTOR_*/
