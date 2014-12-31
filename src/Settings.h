/**@file Settings.h
@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@brief This file contains the prototypes of the TSettings class. 
@author Pieter Burghouwt
@version Revision 2.0
@date Saturday, December 22, 2012
*/

#ifndef SETTINGS_
#define SETTINGS_

#include <stdint.h>

#define SETTINGSSIZE		13

#define DELTA_T_DNS		Settings->DefinedValues[0]
#define DELTA_T_DNS_DEL		Settings->DefinedValues[1]
#define DELTA_T_DNS_RPT		Settings->DefinedValues[2]
#define DELTA_T_URL		Settings->DefinedValues[3]
#define DELTA_T_URL_DEL		Settings->DefinedValues[4]
#define DELTA_T_HTTP		Settings->DefinedValues[5]
#define DELTA_T_HTTPS		Settings->DefinedValues[6] 
#define DELTA_T_USER		Settings->DefinedValues[7]
#define DELTA_T_UTREE		Settings->DefinedValues[8]
#define IPS_ENABLE		Settings->DefinedValues[9]	
#define DNS_PORTPATCH		Settings->DefinedValues[10]
#define IDL_MAX_TOKENS		Settings->DefinedValues[11]
#define IDL_MAX_LENGTH		Settings->DefinedValues[12]


class TSettings{
/**<@class TSettinggs
@brief Class for parsing and distributing the settings of the application.
*/

  private:
  char Name[100];  /**< Stores the Filename*/
  int WhiteIPTotal;  /**<Total Number of Whitelist IP-ranges*/
  int WhiteNameTotal; /**<Total Number of Whitelist Names*/

  public:
  
  int64_t DefinedValues[SETTINGSSIZE];
  const char *DefinedSettings[SETTINGSSIZE];
  uint32_t WhiteIPLow[256];
  uint32_t WhiteIPHigh[256];
  char WhiteName[256][256];

  

   TSettings(const char * name);
/**<The constructor. Opens file
@param name filename with the settings */

   int parseFile(void);
/**<Parses the settings file.
@return number of recognized lines or -1 if error*/


  int testWhiteList(char *id);
/**<Tests if ID is in the whitelist
@return 0=not in whitelist 1=in whitelist*/

  int testWhiteList(uint32_t ip);
/**<Tests if ip is in the whitelist
@return 0=not in whitelist 1=in whitelist*/

  void dump(char *content, int dest);    
/**<Dumps the settings to stats file
@return void
@param *content pointer to content that must be printed. NULL is print to stdout
@param dest destination of the log: 0= to stdout, 1=to logfile*/


};
#endif /*SETTINGS_*/
