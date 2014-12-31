/**@file Aggregator.h
@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@brief This file contains the base class TAggregator. 
@author Pieter Burghouwt
@version Revision 2.0
@date Saturday, October 20, 2012
*/

#ifndef AGGREGATOR_
#define AGGREGATOR_


class TAggregator{
/**<@class TAggregator
@brief Baseclass for aggregators. An aggragator is an object dat aggregates multiple data in a combined datastructure or element of a small size.
Examples of aggregating elements are Flows, Tree, and DNS-records
*/

  protected:
  int32_t Size;  		///<Total number of used elements
  int32_t WriteIndex; 		///<Index to the first element to write in an array

  public:
  int32_t Index; 		///<Index of the current element

  virtual uint8_t add(void){return 1;};
/** adds data to the Aggregator. 
@ return the result of the addition:
- 1 = succesful addition in existing element(s)
- 2 = new element(s) created
- other = error in processing, data not added*/
  
  virtual void dump(void){};
/**<Dumps the total aggregation content to stdout.
return void*/

};

#endif /*AGGREGATOR_*/
