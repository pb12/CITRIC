/**@file Tree.cpp
@brief This file contains the operators of the TTree class. 

@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@author Pieter Burghouwt
@version Revision 2.0
@date Friday, March 8, 2013
*/
/*Tree is a part of CITRIC.

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
#include "Tree.h"
#include "Flow.h"
#include "FlowAggregator.h"

extern TFlow Flow[FLOWBUFFERSIZE];

//*****************************************************************************
TTree::TTree(void){		
  clear();
};

//*****************************************************************************
void TTree::clear(void){
  StartTime=0;		
  StopTime=0;		
  RootFlow=0;		
  RootCause=0;	
  NumberOfFlows=0;	
  MaxDepth=0;	
  DNSOther=1;
  strcpy(ID, "NONAME");	
}


//*****************************************************************************
void TTree::print(char *content){
  if(content==NULL){
    printf("%f, %f, %d, %d, %d, %d, %d, %d, %s\n", (double)StartTime/1000000, (double)StopTime/1000000, RootFlow, RootCause, NumberOfFlows, MaxDepth, Flow[RootFlow].RemotePort, DNSOther, ID);
  } else {
    sprintf(content+strlen(content), "%f, %f, %d, %d, %d, %d, %d, %d, %s\n", (double)StartTime/1000000, (double)StopTime/1000000, RootFlow, RootCause, NumberOfFlows, MaxDepth, Flow[RootFlow].RemotePort, DNSOther, ID);
  }
};


