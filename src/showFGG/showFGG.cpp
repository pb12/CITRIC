/**@file showFGG.cpp
@brief Visualizes a tree of reconstructed Flow Generation Graph from logfile

\n\n showFGG is a postanalysis tool of CITRIC. It plots one specific tree of the CITRIC logfile.
Usage: showFGG <-d> <filename> <tree number>
@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@author Pieter Burghouwt
@version Revision 0.2
@date Sunday, May 12, 2013
*/

/**
@mainpage
showFGG is a postanalysis tool of CITRIC. It plots one specific tree of the CITRIC logfile.
Usage: showFGG <-d> <filename> <tree number>
*/

/*This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>*/

#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcre.h>

 char DumpMessage[100000000];  //100MB buffer space to dump messages to file


int main(int argc, char *argv[]){
  char name[100];
  char logname[100];
  char dotname[100];
  char svgname[100];
  char command[100];
  int treesel;
  int32_t flow, pflow, tree, quality, delay;
  double time;
  char prot[256];
  char cause[256];
  char id[256];
  FILE *LogHandle, *DotHandle; 
  char Line[256];
  char Log[1000000];
  const char *Header1="digraph g{nodesep=0.5;rankdir=LR;charset=\"latin1\";fixedsize=true; label=\"";
  const char *Header2="\";bgcolor=\"#FFFFFF\";edge[penwidth=2 arrowsize=1, color=black];node [style=\"filled\", penwidth=1, shape=box, fillcolor=\"#FFFFFF\", concentrate=true, regular=0];\n\n";
  const char *DNSColor="\"#70E0FF\"";
  const char *HTTPColor="\"#8DFF7F\"";
  const char *HTTPSColor="\"#E8E6FF\"";
  const char *TCPColor="\"#E8E6FF\"";
  const char *UDPColor="\"#70E0FF\"";
  const char *ICMPColor="\"#C2C2FF\"";
  const char *UNKNOWNColor="\"#FF6666\"";
  const char *USERColor="\"#FFFF00\"";
  const char *NeutralColor="\"#FFFFFF\"";
  const char *color;
  int draw;

  //STEP 2: Analyzing the command-line parameters
  if((argc!=4)&&(argc!=3)){
    printf("\n*****\nUsage: showFGG <-d> <name> <treenumber> \n");
    printf("<name> is a logfile of CITRIC without .log extension\n With -d it will draw the tree immediatly. Without is, it will only produce the .dot and .svg-file.\n\n");
    return 0;
  }

if(argc==3){
  sscanf(argv[1], "%s", name);
  sscanf(argv[2], "%d", &treesel);
  sprintf(logname, "%s.log", name);
  sprintf(dotname, "%s_%d.dot", name, treesel);
  sprintf(svgname, "%s_%d.svg", name, treesel);
  draw=0;
  printf("\nProcessing tree %d from file %s, to file %s and %s ...\n", treesel, logname, dotname, svgname);
} else if(argc==4){
  if(strcmp(argv[1], "-d")!=0) {
    printf("\n*****\nWrong option???\nUsage: <-d> <name> <treenumber> \n");
    printf("<name> is a logfile of CITRIC without .log extension\n With -d it will draw the tree immediatly. \
            Without is, it will only produce the .dot and .svg-file.\n\n");
    return 0;
  }
  sscanf(argv[2], "%s", name);
  sscanf(argv[3], "%d", &treesel);
  sprintf(logname, "%s.log", name);
  sprintf(dotname, "%s_%d.dot", name, treesel);
  sprintf(svgname, "%s_%d.svg", name, treesel);
  draw=1;
  printf("\nProcessing and drawing tree %d from file %s, to file %s and %s ...\n", treesel, logname, dotname, svgname);
}
  //strcpy(Log, Header1);
  sprintf(Log, "%sTree:%d of %s%s", Header1, treesel, name, Header2);
  //STEP 3: Reading the logfile
  LogHandle = fopen(logname, "r");
 
  while(fgets(Line, 256, LogHandle)){
    if(Line[0]!='#'){
      //1356011082.763029, MAIN, TREE:1, NEWFLOW:3, HTTP, PARENTFLOW:-1, 0 us, CAUSE_ALREADYOPEN, 23.62.99.129, 9
      sscanf(Line, "%lf, MAIN, TREE:%d, NEWFLOW:%d, %[^','], PARENTFLOW:%d, %d us, CAUSE_%[^','], %[^','], %d", &time, &tree, &flow, prot, &pflow, &delay, cause, id, &quality );

      if(tree==treesel){
        //sprintf(Log+strlen(Log), "%lf - M:%d - NF:%d - PROT:%s - PF:%d - Time:%d - %s - %s - %d\n", time, tree, flow, prot, pflow, delay, cause, id, quality);
        color=NeutralColor;
        if(strcmp(prot, "HTTPS")==0) color=HTTPSColor;
        if(strcmp(prot, "HTTP")==0) color=HTTPColor;
        if(strcmp(prot, "DNS")==0) color=DNSColor;
        if(strcmp(prot, "ICMP")==0) color=ICMPColor;
        if(strstr(prot, "TCP")!=NULL) color=TCPColor;
        if(strstr(prot, "UDP")!=NULL) color=UDPColor;

        //STEP 3A: node creation "n" flow " " [label=" id "];
        sprintf(Log+strlen(Log), " n%d [label=\"%d (%s)\\n %s\", fillcolor=%s];\n", flow, flow, prot, id, color);

        //STEP 3B: edge creation "n" pflow " -> n" flow [label=" id "];
        if(pflow!=-1){
          sprintf(Log+strlen(Log), " n%d -> n%d [label=\"%s(%dus)\"];\n", pflow, flow, cause, delay);
        } else {
          //STEP 3C extra node with edge created as root
          color=NeutralColor;
          if(strstr(cause, "USER")!=NULL) color=USERColor;
          if(strstr(cause, "UNKNOWN")!=NULL) color=UNKNOWNColor;
          sprintf(Log+strlen(Log), " nr [label=\"Tree:%d\\n%s\", fillcolor=%s];\n", treesel, cause, color);
          sprintf(Log+strlen(Log), " nr -> n%d [label=\"%s(%dus)\"];\n", flow, cause, delay);
        }
      }
    }
  }
  sprintf(Log+strlen(Log), "}\n");
  fclose(LogHandle);

  //STEP 4 writing the dot file
  //printf("Writing to %s ...\n", dotname);
  DotHandle = fopen(dotname, "w");
  fwrite(Log, strlen(Log), 1, DotHandle);
  fclose(DotHandle);

  //STEP 5 running the dot file to svg
  //printf("Running dot, output to %s ...\n", svgname);
  sprintf(command, "rm -f %s", svgname);
  system(command);  
  sprintf(command, "dot -Tsvg %s -o %s", dotname, svgname);
  system(command);
  if(draw==1){
    sprintf(command, "eog %s &", svgname);
    system(command);
  }
  printf("Done! Have a nice day!\n");
  return 0;
}



