/**@file HFSM.h
@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@brief This file contains HFSM-state definitions. 
@author Pieter Burghouwt
@version Revision 2.0
@date Wednesday, November 28, 2012
*/

#ifndef HFSM_
#define HFSM_

//LEVEL1 STATES

#define HFSM1_IDLE		0	//expecting new HTTP-traffic
#define HFSM1_NO_HTTP		1	//no HTTP-content in this flow (= anomaly?), stubstate
#define HFSM1_HEADER		2	//HTTP-header analysis in progress
#define HFSM1_BODY		3	//Parsable HTTP-body analysis in progress
#define HFSM1_PARSED		4	//Waiting for new HTTP-request
#define HFSM1_CHUNK		5	//Waiting for Chunk header data


//LEVEL2 STATES
#define HFSM2_IDLE		0	//no match, waiting on newline
#define HFSM2_NEWLINERECEIVED	1       //new line received
#define HFSM2_CONTENT		2	//parsing Content-
#define HFSM2_CONTENTTYPE	3	//parsing TYPE: TEXT	-> result in ContentType (1=text)
#define HFSM2_ENCODING		4	//parsing gzip		-> result in Encoding (1=gzip)
#define HFSM2_CHUNKED		5	//parsing Transfer-Encoding: chunked -> result in Chunked (1=chunked)
#define HFSM2_CONTENTLENGTH  	6	//parsing LENGTH: xxxx -> result in int ContentLength
#define HFSM2_WHITELINE		7	//parsing /r/n/r/n
#define HFSM2_CHAR_RECEIVED	8	//valid domain name characters received
#define HFSM2_DOT_RECEIVED	9	//valid dot received
#define HFSM2_OVERFLOW		10	//domain name to long (255+)
#define HFSM2_MOVED		11      //URL in Header

//#define HFSM2_HTTP		12	//no match
//#define HFSM2_S		13	//no match
//#define HFSM2_URL		14	//no match


#define HFSM2_

#endif /*HFSM_*/

