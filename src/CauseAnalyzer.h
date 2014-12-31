/**@file CauseAnalyzer.h
@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@brief This file contains the prototypes of the TCauseAnalyzer class. 
@author Pieter Burghouwt
@version Revision 2.0
@date Tuesday, March, 12, 2013
*/

#ifndef CAUSEANALYZER_
#define CAUSEANALYZER_

#include <stdint.h>
#include "Flow.h"
#include "Tree.h"

#define TREE_BUFFER_SIZE 65536


class TCauseAnalyzer : virtual public TAggregator{
/**<@class TCauseAnalyzer
@brief Class that manages causal trees and sorts new flows in it.

An instance of TCauseAnalyzer creates a static array of TREE_BUFFER_SIZE (65535) empty trees. The FlowAggregator will call 
this object in case of a new flow.
*/


private:
//statistics
  int32_t CauseCounter;
  int32_t DNSCauseCounter;
  int32_t DELDNSCauseCounter;
  int32_t RPTDNSCauseCounter;
  int32_t URLCauseCounter;
  int32_t DELURLCauseCounter;
  int32_t SURLCauseCounter;
  int32_t DELSURLCauseCounter;
  int32_t HTTPCauseCounter;
  int32_t HTTPSCauseCounter;
  int32_t USERCauseCounter;
  int32_t SERVERCauseCounter;
  int32_t WhiteListCauseCounter;
  int32_t AlreadyOpenCauseCounter;
  int32_t UTreeCauseCounter;
  int32_t UnknownCauseCounter;
  int32_t DNSUnknownCauseCounter;
  int32_t ResolvedDNSUnknownCauseCounter;
  int32_t IDLOverLengthCounter;
  int32_t IDLOverTokenCounter;
  int64_t LastUserTimeStamp;			/**For registration of response times  */
  int64_t StatDNSTimes[100000];			/**For registration of response times  */
  int32_t StatDNSTimesCounter;  		/**For registration of response times  */
  int64_t StatURLTimes[100000];			/**For registration of response times  */
  int32_t StatURLTimesCounter;  		/**For registration of response times  */

  int32_t NoNameFlowCounter;
  int32_t DNSNoNameFlowCounter;
  int32_t CauseCallCounter;
  int32_t DNSCounter;

  int32_t FoundDNSIndex[10]; 	/**<DNS-indices that could match */
  int8_t FoundDNSCount; 	/**<Number of valid DNS records*/
  int64_t WorstDNSTime;
  int8_t WorstDNSPlace;
  int8_t BestDNSPlace; 
  int64_t BestDNSTime;
  int64_t DNSDelay;

  int32_t BestURLEventIndex;
  int16_t BestURLHash;
  int64_t BestURLDelay;
  int32_t URLEventIndex;
  int32_t BestHTTPEventIndex;
  int32_t BestUserEventIndex;
  int64_t UserDelay;  


public:
  char ID[256];  /**<String with IP or name of last analyzed flow*/
  char BestID[256];  /**<String with most recent resolved name of last analyzed flow*/

  TCauseAnalyzer(void);  
/**< Constructor. During creation a fixed array of tree is created for fast storage.*/

  uint8_t add(char *name);
/**<Adds a new flow to the appropiate tree.  
@return the result of the addition:
- 1 = succesful update of existing tree, Index points to this tree
- 2 = new tree created, Index points to this tree
- other = error in processing, flow not added
@param *name Pointer to name string in case of a DNS-reply*/
  

      void dump(char *dm, int dest);    
/**<Dumps the content of all non-empty trees to stdout or logfile
@return void
@param *dm pointer to content that must be printed. NULL is print to stdout
@param dest destination of the log: 0= to stdout, 1=to logfile*/
};


#endif /*CauseAnalyzer_*/
