/**@file Settings.cpp
@brief This file contains the operators of the TSettings class. 

@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@author Pieter Burghouwt
@version Revision 2.0
@date Saturday, December 22, 2012
*/
/*Settings is a part of CITRIC.

CITRIC is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

CITRIC is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with CITRIC.  If not, see <http://www.gnu.org/licenses/>*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <pcre.h>
#include "Settings.h"
#include "Logger.h"

extern TLogger *Logger;

//*****************************************************************************
TSettings::TSettings(const char *name){
  int i;

  for(i=0; i<256; i++){
    WhiteIPLow[i]=0;
    WhiteIPHigh[i]=0;
    WhiteName[i][0]=0;
  }
  for(i=0; i<SETTINGSSIZE; i++) DefinedValues[i]=0; 
  WhiteIPTotal=0;
  WhiteNameTotal=0;
  strcpy(Name, name);
  parseFile();
};


//*****************************************************************************
int TSettings::parseFile(void){
  //opens the file and read the settings

  FILE *handle;
  char Line[256];
  pcre *IPReCompiled;
  pcre *NameReCompiled;
  pcre *SettingReCompiled;
  pcre_extra *IPpcreExtra;
  pcre_extra *NamepcreExtra;
  pcre_extra *SettingpcreExtra;
  int pcreExecRet;
  int subStrVec[30];
  const char *pcreErrorStr;
  int pcreErrorOffset;
  const char *IPStrRegex="WHITE_IP\\s+(\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)\\s+(\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)"; 
  const char *NameStrRegex="WHITE_NAME\\s+([^\\s]+)"; 
  const char *SettingStrRegex="SETVAL\\s+([^\\s]+)\\s+(\\d+)"; 
  const char *psubStrMatchStr;
  const char *CONSTDefinedSettings[SETTINGSSIZE]={"DELTA_T_DNS", "DELTA_T_DNS_DEL", "DELTA_T_DNS_RPT", "DELTA_T_URL", "DELTA_T_URL_DEL", "DELTA_T_HTTP", "DELTA_T_HTTPS", "DELTA_T_USER", "DELTA_T_UTREE", "IPS_ENABLE", "DNS_PORTPATCH", "IDL_MAX_TOKENS", "IDL_MAX_LENGTH"}; //was with UNKNOWN  see also parsing REGEXP while loop
  int j, i, l, k;

  for(i=0; i<SETTINGSSIZE; i++) DefinedSettings[i]=CONSTDefinedSettings[i];

  //STEP 1a Preparing IP range expresssion for whitelist
  IPReCompiled = pcre_compile(IPStrRegex, PCRE_MULTILINE, &pcreErrorStr, &pcreErrorOffset, NULL);
  if(IPReCompiled == NULL) {
    printf("ERROR: Could not compile '%s': %s\n", IPStrRegex, pcreErrorStr); 
    exit(1);
  }
  IPpcreExtra = pcre_study(IPReCompiled, 0, &pcreErrorStr);
  if(pcreErrorStr != NULL) {
    printf("ERROR: Could not study '%s': %s\n", IPStrRegex, pcreErrorStr);
    exit(1);
  } 
  //STEP 1b Preparing NAME expresssion for whitelist
  NameReCompiled = pcre_compile(NameStrRegex, PCRE_MULTILINE, &pcreErrorStr, &pcreErrorOffset, NULL);
  if(NameReCompiled == NULL) {
    printf("ERROR: Could not compile '%s': %s\n", NameStrRegex, pcreErrorStr);
    exit(1);
  }
  NamepcreExtra = pcre_study(NameReCompiled, 0, &pcreErrorStr);
  if(pcreErrorStr != NULL) {
    printf("ERROR: Could not study '%s': %s\n", NameStrRegex, pcreErrorStr);
    exit(1);
  } 
  //STEP 1c Preparing Settings expresssion
  SettingReCompiled = pcre_compile(SettingStrRegex, PCRE_MULTILINE, &pcreErrorStr, &pcreErrorOffset, NULL);
  if(SettingReCompiled == NULL) {
    printf("ERROR: Could not compile '%s': %s\n", SettingStrRegex, pcreErrorStr);
    exit(1);
  }
  SettingpcreExtra = pcre_study(SettingReCompiled, 0, &pcreErrorStr);
  if(pcreErrorStr != NULL) {
    printf("ERROR: Could not study '%s': %s\n", SettingStrRegex, pcreErrorStr);
    exit(1);
  } 

  //STEP 2 Opening File and reading line by line
  handle = fopen(Name, "r");
  while(fgets(Line, 256, handle)){
    if(Line[0]!='#'){
      //printf("%s", Line);

      //STEP 3a Parsing whitelisted IP ranges with regexp 
      i=0;
      pcreExecRet = pcre_exec(IPReCompiled, IPpcreExtra, Line, strlen(Line), i, 0, subStrVec, 30);    
      if(pcreExecRet == 9) {
        //ok 9 values found as expected (1 total + 8 sub strings)
        WhiteIPLow[WhiteIPTotal]=0;
        for(j=1; j<5; j++){
          WhiteIPLow[WhiteIPTotal]*=256;
          pcre_get_substring(Line, subStrVec, pcreExecRet, j, &(psubStrMatchStr));
          WhiteIPLow[WhiteIPTotal]+=(uint32_t)atol(psubStrMatchStr);
          //i=subStrVec[j*2+1];
        }
        for(j=5; j<9; j++){
          WhiteIPHigh[WhiteIPTotal]*=256;
          pcre_get_substring(Line, subStrVec, pcreExecRet, j, &(psubStrMatchStr));
          WhiteIPHigh[WhiteIPTotal]+=(uint32_t)atol(psubStrMatchStr);
          //i=subStrVec[j*2+1];
        }
        printf("WL IPRANGE%d: %ld %ld \n", WhiteIPTotal, (long)WhiteIPLow[WhiteIPTotal], (long)WhiteIPHigh[WhiteIPTotal] );
        WhiteIPTotal++;
        pcre_free_substring(psubStrMatchStr);
      }

      //STEP 3b Parsing whitelisted Names with regexp 
      i=0;
      pcreExecRet = pcre_exec(NameReCompiled, NamepcreExtra, Line, strlen(Line), i, 0, subStrVec, 30);    
      if(pcreExecRet == 2) {
        pcre_get_substring(Line, subStrVec, pcreExecRet, 1, &(psubStrMatchStr));
        strcpy(&WhiteName[WhiteNameTotal][0], psubStrMatchStr);
        //i=subStrVec[j*2+1];
        printf("WL NAME%d: %s \n", WhiteNameTotal, &WhiteName[WhiteNameTotal][0]);    
        WhiteNameTotal++;
        pcre_free_substring(psubStrMatchStr);
      }

      //STEP 3c Parsing Settings with regexp 
      i=0;
      pcreExecRet = pcre_exec(SettingReCompiled, SettingpcreExtra, Line, strlen(Line), i, 0, subStrVec, 30);
      if(pcreExecRet == 3) {
        //reading settings name
        pcre_get_substring(Line, subStrVec, pcreExecRet, 1, &(psubStrMatchStr));
        l=0; k=0;
        do{
          if(strcmp(psubStrMatchStr, DefinedSettings[l])==0){
            //i=subStrVec[j*2+1];
            pcre_free_substring(psubStrMatchStr);
            pcre_get_substring(Line, subStrVec, pcreExecRet, 2, &(psubStrMatchStr));
            DefinedValues[l]=(int64_t)atoll(psubStrMatchStr);
            k=1;
          } 
          if(k==0) l++;
        } while( ( l<(SETTINGSSIZE  )) && (k==0) );     //was with UNKNOWN:  SETTINGSIZE-1
        //i=subStrVec[j*2+1];   
        pcre_free_substring(psubStrMatchStr);
        //printf("SETTING: %s = %ld:\n", DefinedSettings[l], DefinedValues[l]); 
      } 

    }
  }
  fclose(handle);
  
  for(i=0; i<SETTINGSSIZE; i++){
    printf("SETTING%d: %s = %ld\n", i, DefinedSettings[i], DefinedValues[i]); 
  }
  
  return 0;
};

//*****************************************************************************
int TSettings::testWhiteList(char *id){
  //returns 1 if match 
  //uint32_t ip, temp0, temp1, temp2, temp3;
  int i;
  char *suburl;
 
  //printf("whitelist ID test:%s\n", id);
  //RANGETESTING
/*  if(sscanf(id,"%d.%d.%d.%d", &temp0, &temp1, &temp2, &temp3)==4){
    ip=(((((temp0*256)+temp1)*256)+temp2)*256)+temp3;
    //printf("RANGETESTING WITH:%s = %ld", id, (long)ip);
    for(i=0; i<WhiteIPTotal; i++){
      if((ip>=WhiteIPLow[i])&&(ip<=WhiteIPHigh[i])){
        //printf("ID->IP RANGE-MATCH:%s", id);
        return 2;
      }
    }
  } */

  //NAMETESTING
  for(i=0; i<WhiteNameTotal; i++){
    //printf("Testing %d : %s with %s\n", i, id, &WhiteName[i][0]);
    if(strlen(id)>=strlen(&WhiteName[i][0])){
      suburl=id+strlen(id)-strlen(&WhiteName[i][0]);
      if(strcmp(&WhiteName[i][0], suburl)==0){
        //printf("ID-MATCH:%s, %s, %s\n", id, suburl, &WhiteName[i][0]);
        return 1;
      }
    }
  }
  return 0;
};

//*****************************************************************************
int TSettings::testWhiteList(uint32_t ip){

  int i;

  //step1 test if IP 
  //printf("whitelist IP test:%ld\n", (long)ip);

  //RANGETESTING
  for(i=0; i<WhiteIPTotal; i++){
    if((ip>=WhiteIPLow[i])&&(ip<=WhiteIPHigh[i])){
      //printf("IP RANGE-MATCH:%ld", (long)ip);
      return 1;
    }
  } 
  return 0;
};

//*****************************************************************************
void TSettings::dump(char *dm, int dest){
  int i;
  uint8_t *lowip, *highip;
  
  sprintf(dm, "SETTINGS\n");
  for(i=0; i<SETTINGSSIZE; i++){
    sprintf(dm+strlen(dm), "\tparameter%d:\t%s\t%ld\n", i, DefinedSettings[i], DefinedValues[i]); 
  }  
  sprintf(dm+strlen(dm), "WHITELISTED NAMES\n");
  for(i=0; i<WhiteNameTotal; i++){
    sprintf(dm+strlen(dm), "\tname%d:\t%s\n", i, &WhiteName[i][0]); 
  }  

  sprintf(dm+strlen(dm), "WHITELISTED IP-RANGES\n");
  for(i=0; i<WhiteIPTotal; i++){
    lowip=(uint8_t *)&WhiteIPLow[i];
    highip=(uint8_t *)&WhiteIPHigh[i];
    sprintf(dm+strlen(dm), "\trange%d:\t%d.%d.%d.%d\t-\t%d.%d.%d.%d\n", i, lowip[3], lowip[2], lowip[1], lowip[0], highip[3], highip[2], highip[1], highip[0]); 
  }  

  if(dest==1){
    Logger->saveStatsLog(dm);
  } else {
    printf("%s", dm);
  }
};    




