/**@file Logger.h
@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@brief This file contains the prototypes of the TLogger class. 
@author Pieter Burghouwt
@version Revision 2.0
@date Wednesday, December 5, 2012
*/

#ifndef LOGGER_
#define LOGGER_

#include <stdint.h>
#include "PacketAnalyzer.h"

#define LOGSIZE 10000000	//Size of the total log is 10MB

#define DEBUG 7			//just for debugging
#define INFORMATIONAL 6         //also debugging but less noisy
#define NOTICE 5		//new normal flow
#define WARNING 4		//new abnormal flow
#define ERROR 3			//error, program will continue without further problems
#define CRITICAL 2		//error, program will continue without further problems in later flows
#define ALERT 1			//error, program will continue but not function normally
#define EMERGENCY 0		//error, program will stop

#define FAC_PACKET 0
#define FAC_FLOW 1
#define FAC_DNS 2
#define FAC_HTTP 3
#define FAC_EVENT 4
#define FAC_CAUSE 5
#define FAC_MAIN 6


class TLogger{
/**<@class TLogger
@brief Class that aggregates log messages in flat file format in RAM. 

Finally it can save the log in a file. Every field is separated with a comma. Every record is separated with a newline. The format is: \n
Type1:	Timestamp, Severity, Facility, message \n
Type2:  Timestamp, Severity, Facility, message, ID, delay\n
Type3:	Timestamp, Severity, Facility, message, index
*/


  private:
  int LineCounter; /**<Number of lines in the log*/
  char Log[LOGSIZE];  /**<RAM Storage for logging*/
  char *Buffer; /**<Pointer in the storage*/
  const char *FileName; /**<File name after save to non-volatile memory*/

  public: 
  TLogger(const char *name);  
/**< Constructor. During creation a fixed array of Causes is created for storage.
@return void
@param *name filename*/

    int log(int sev, int fac, char *message);
/**< Writes a generic log record 
@return 0=success, -1=error 
@param sev Severity (0 t/m 7)
@param fac Facility (number identifying which functional unit is the source
@param *message string with the message to write*/


   int log(int sev, int fac, int32_t flowindex, char *id, int64_t delay);
/**< Writes a new flow record
@return 0=success, -1=error 
@param sev Severity (0 t/m 7)
@param fac Facility (number identifying which functional unit is the source
@param flowindex Index of the new flow
@param *id IP or name of the new flow
@param delay Time in us between new flow and cause
*/

  

    int saveLog(void);  
/**< Saves the complete log in a file
@return 0=success, -1=error */

    int save(const char *ext, char *dm);  
/**< Saves a string in a file with specified extension
@return 0=success, -1=error 
@param *ext pointer to extension of the filename, starting with a dot e.g. .flow, .dat
@param *dm pointer to complete string that must be saved*/

    int initStatsLog(void);  
/**< Initializes a new file for statistics
@return 0=success, -1=error */

    int saveStatsLog(char *dm);  
/**< Adds a string with statistics to the statistics file
@return 0=success, -1=error 
@param *dm pointer to complete string that must be saved*/

};


#endif /*LOGGER_*/
