/**@file PCAP.h
@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@brief This file contains the prototypes of the TPCAP class. 
@author Pieter Burghouwt
@version Revision 2.0
@date Tuesday, November 22, 2011
*/
#ifndef PCAP_
#define PCAP_

#include <pcap.h>
#include <stdint.h>


class TPCAP{
/**<@class TPCAP
@brief The "singleton" object of TPCAP is a wrapper around the libpcap library. It can read from a device or a file and return a pointer to a received packet.
*/
  private:
    pcap_t* Handle; 		///<Handle to openened NIC or file
    char *DeviceName; 		///<Name of the Device or File, like "eth0" 
    char *Filter; 		///<Packet filter e.g. "not port 22" , default is "ip"

  public: 
    uint64_t TimeStamp; 	///<Time of Packet-arrival in useconds sinze 1970
    uint32_t Length; 		///<Number of available packet-bytes
    const uint8_t *Packet; 	///<Pointer the datastructure of the received Packet

    TPCAP(void);
/**<The constructor.*/

    void openNIC(char *dev); 
/**<Opens a network device (interface) e.g. "eth0". 
@return void
@param dev The pointer to a string with the name of the device.*/

    void openFile(char *name);
/**<Opens a libpcap file with recorded traffic e.g. "trace.pcap".
@return void
@param name The pointer to a string with the name of the file.*/

    void openDevice(char *device, int live);
/**<Opens a libcap-file or network device with recorded traffic.\n
If the name ends with a number an interface is assumed.\n
In other cases a file is assumed.
@return void
@param live 0=from file, 1=from NIC
@param device The pointer to a string with the name of the interface or file.*/

    int8_t applyFilter(char *filter);  
/**<Applies a libpcap preprocessor filter.
@return 0=ok
@param filter The pointer to a string with the filter equation e.g. "IP".*/

    int8_t getPacketEvent(void);  
/**<Event check with immediate return, for use in a event loop. ; 
@return 0=no event, 1=packet received, -1=error, -2=EOF*/

    void close(char *dm, int dest); //closes the device or file
/**<Closes a network device (interface) e.g. "eth0".
@param *content pointer to content that must be printed. NULL is print to stdout
@param dest destination of the log: 0= to stdout, 1=to logfile 
@return void*/

};


#endif /*PCAP_*/
