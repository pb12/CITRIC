/**@file Tree.h
@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@brief This file contains the prototypes of the TTree class. 
@author Pieter Burghouwt
@version Revision 2.0
@date Friday, March 8, 2013
*/

#ifndef TREE_
#define TREE_

#include <stdint.h>


class TTree{
/**<@class TTree
@brief Storage class for a tree of network flows with a causal relationship
*/

  public:
   int64_t	StartTime;		///<Timestamp of the root flow
   int64_t	StopTime;		///<Timestamp of any last activity of a flow in the tree
   int32_t 	RootFlow;		///<ID of the root flow
   int8_t	RootCause;		///<Cause of the root flow
   uint16_t	NumberOfFlows;		///<Total number of flows (root + all offspring), 0 = tree empty
   uint16_t	MaxDepth;		///<Longest line of descendants
   uint8_t	DNSOther;		///<Default zero. Will be 1 if there if at least one other flow than a resolver flow
   char 	ID[256];		///<ID of the root Flow

   TTree(void);
/**<The constructor. Resets all the data-members, including NextFlow*/

   void clear(void); 
/**<Clears all the data-members.
@return void */


   void print(char *content); 
/**<Prints a tree in readable format to stdout
@return void 
@param *content pointer to content that must be printed. NULL is print to stdout*/
};


#endif /*TREE_*/
