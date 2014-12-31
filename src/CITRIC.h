/**@file CITRIC.h
@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@brief This file contains the prototypes of the CITRIC class. 
@author Pieter Burghouwt
@version Revision 2.0
@date Friday, November 16, 2012
*/

/*This program free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>*/

#ifndef CITRIC_
#define CITRIC_

void sigproc(int signum);
/**<
A handler for OS-signals, to catch the CTRL+C\n
@return void
@param signum =2 (SIGINT) that identifies to CTRL+C
*/

#endif /*CITRIC_*/
