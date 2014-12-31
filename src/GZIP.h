/**@file GZIP.h
@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@brief This file contains the prototypes of the TGZIP class. 
@author Pieter Burghouwt
@version Revision 2.0
@date Thursday, February 28, 2013
*/

#ifndef GZIP_
#define GZIP_

#define GZIP_BUFFERSIZE 32768
#include <stdint.h>
#include <zlib.h>


class TGZIP{
/**<@class TGZIP
@brief Class for deflating gzip data. Wraps around zlib.
*/

  private:
   int InUse;
/**<Boolean 0=object is free, 1=object is already taken*/

  public:

   int Processing;

   z_stream strm; 

   unsigned char *InBuffer;  	
/**<Pointer to the input buffer*/

   int InLength;		
/**<Lenth of the input buffer*/

   unsigned char OutBuffer[GZIP_BUFFERSIZE];
/**<Pointer to the output buffer*/

   int OutLength;		
/**<Lenth of the output buffer*/


   TGZIP(void);
/**<The constructor. Resets all the data-members, including NextFlow*/

int isInUse(void);
/**<Tests if the object is free to take.
@return 0=free 1=in use*/


void take(void);
/**<Takes the gzip-object. Memory is assumed to be flushed, cleared
@return void */


void free(void);
/**<Frees the gzip. Memory is flushed cleared etc.
@return void */


int uncompress(void);
/**<Uncompresses a blok of data. Inlength and *Inbuffer must be prepared before this call
@return int 0=ok, -1 wrong magic number, -2=no data left */
};


#endif /*GZIP_*/
