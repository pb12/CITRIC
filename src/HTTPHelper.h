/**@file HTTPHelper.h
@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@brief This file contains the prototypes of the THTTPHelper class. 
@author Pieter Burghouwt
@version Revision 2.0
@date Tuesday, March 5, 2013
*/

#ifndef HTTPHELPER_
#define HTTPHELPER_

#include <stdint.h>
#include "Flow.h"
#include "HTTP.h"
#include "GZIP.h"

#define HTTP_BUFFER_SIZE 65536   //max number of HTTPflows
#define TOTAL_GZIP 2000  //max number of simultanous GZIP-streams
#define BINARYCONTENT 0

class THTTPHelper : virtual public TAggregator{
/**<@class THTTPHelper
@brief Class that aggregates HTTP traffic. It aggregates information that predicts the cause of new traffic flows
THTTPHelper creates a static array of HTTP_BUFFER_SIZE (65536) HTTP-objects. The ClusterAggregator uses this class to check for potential HTTP-parent flows.
TFlowAggregator updates the information of this class. */


  private:

  TGZIP GZIP[TOTAL_GZIP];	///<GZIP-objects
  char DeChunkedContent[32768];  ///<intermediate buffer for chunk header removal
  uint32_t SuccessRefCounter;
  uint32_t RefCounter;
  uint32_t GetRequestCounter;
  int32_t GZIPIndex;		///<index to most recent GZIP-buffer or -1 if empty

  int parse(void);
/**< Parses HTTP. First the header and subsequently the body if the content-type=text. Dechunking and decompression is included if necessary. The domain names of all url's, found in the body, are placed in the URL_EventList. 
@return 0 or positive=number of parsed URL's, negative=failure*/

  int getRef(void);
/**< Parses HTTP get requests for referred domains. 
@return 1 = referred domain found, 2 = referred domain parsed but not found, 0 = no referred domain parsed, -1 =  error*/

  int stripRef(void);
/**< Strips the domain part of the referer from other stuff. 
@return 1 = referred domain successfully stripped */

 
  int checkURL(void);

  public: 
    THTTPHelper(void);  
/**< Constructor. During creation a fixed array of Causes is created for storage.*/

    uint8_t add(void);
/**< Adds HTTP-packets of new or existing flows to the aggregator
@return 1=success: data updated in existing records, 2=succcess: new HTTP-record added, 0 = parse error, 10=Cannot create because HTTPBuffer Full*/

    void dump(char *dm, int dest);    
/**<Dumps the content of all recent causes to stdout
@return void
@param *dm pointer to content that must be printed. NULL is print to stdout
@param dest destination of the log: 0= to stdout, 1=to logfile*/

};


#endif /*HTTPHELPER_*/
