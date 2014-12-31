/**@file HTTPHelper.cpp
@brief This file contains the operators of the THTTPAgggregator class. 

@copyright Copyright 2012-2013 Delft University of Technology and The Hague University of Applied Sciences. License: LGPL 3+
@author Pieter Burghouwt
@version Revision 2.0
@date Tuesday, March 12, 2013
*/
/*HTTPHelper is a part of CITRIC.

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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "FlowAggregator.h"
#include "Flow.h"
#include "HTTPHelper.h"
#include "PacketAnalyzer.h"
#include "EventCollector.h"
#include "HTTP.h"
#include "HFSM.h"
#include "GZIP.h"
#include "Logger.h"

extern TFlowAggregator *FlowAggregator;
extern TPCAP *PCAP;
extern TPacketAnalyzer *PacketAnalyzer;
extern TFlow Flow[FLOWBUFFERSIZE];
extern TEventCollector *EventCollector;
extern TLogger *Logger;

THTTP HTTP[HTTP_BUFFER_SIZE];

const char *PatternHTTP="HTTP";					//for header matching
const char *PatternContentTypeText="Content-Type:text                ";	//for header matching
const char *PatternContentTypeJava="Content-Type:application/x-java   "; //for header matching
const char *PatternContentTypeJS="Content-Type:application/javascript "; //for header matching
const char *PatternContentTypeFlash="Content-Type:application/x-shoc  "; //for header matching
const char *PatternContentTypeJSON="Content-Type:application/json  "; //for header matching
const char *PatternEncodingGZIP="Encoding:gzip";		//for header matching
const char *PatternTransfer="Transfer-Encoding:chunked";	//for header matching
const char *PatternLocation="Location:";
const char *PatternWhiteLine="\r\n";			//for header matching
const char *Patternhttp="http";					//for url matching


const char* TLD[26]={
".ac.ad.ae.aero.af.ag.ai.al.am.an.ao.aq.ar.arpa.as.asia.at.au.aw.ax.az",
".ba.bb.bd.be.bf.bg.bh.bi.biz.bj.bl.bm.bn.bo.bq.br.bs.bt.bv.bw.by.bz",
".ca.cat.cc.cd.cf.cg.ch.ci.ck.cl.cm.cn.co.com.coop.cr.cu.cv.cw.cx.cy.cz",
".de.dj.dk.dm.do.dz",
".ec.edu.ee.eg.eh.er.es.et.eu",
".fi.fj.fk.fm.fo.fr",
".ga.gb.gd.ge.gf.gg.gh.gi.gl.gm.gn.gov.gp.gq.gr.gs.gt.gu.gw.gy",
".hk.hm.hn.hr.ht.hu",
".id.ie.il.im.in.info.int.io.iq.ir.is.it",
".je.jm.jo.jobs.jp",
".ke.kg.kh.ki.km.kn.kp.kr.kw.ky.kz",
".la.lb.lc.li.lk.lr.ls.lt.lu.lv.ly",
".ma.mc.md.me.mf.mg.mh.mil.mk.ml.mm.mn.mo.mobi.mp.mq.mr.ms.mt.mu.museum.mv.mw.mx.my.mz",
".na.name.nc.ne.net.nf.ng.ni.nl.no.np.nr.nu.nz",
".om.org",
".pa.pe.pf.pg.ph.pk.pl.pm.pn.post.pr.pro.ps.pt.pw.py",
".qa",
".re.ro.rs.ru.rw",
".sa.sb.sc.sd.se.sg.sh.si.sj.sk.sl.sm.sn.so.sr.ss.st.su.sv.sx.sy.sz",
".tc.td.tel.tf.tg.th.tj.tk.tl.tm.tn.to.tp.tr.travel.tt.tv.tw.tz",
".ua.ug.uk.um.us.uy.uz",
".va.vc.ve.vg.vi.vn.vu",
".wf.ws",
".xxx.xn--",
".ye.yt",
".za.zm.zw"
};


//*****************************************************************************
THTTPHelper::THTTPHelper(void){
int i;

  Size=0;
  WriteIndex=-1;
  Index=-1; 
  for(i=0; i<TOTAL_GZIP; i++) GZIP[i].free(); //Initializing GZIP-buffers
  GZIPIndex=-1;
  SuccessRefCounter=0;
  RefCounter=0;
  GetRequestCounter=0;
};

//*****************************************************************************

uint8_t THTTPHelper::add(void){

  //Called from FlowAggregator in case of a new packet (Status=2) or a new flow (Status=1) both 80 and 443
  //other nice parameters:   
  uint32_t payloadsize;

  //printf("\n>7 DEBUG, %ld, STARTING FSM-CYCLE FROM %d with %d INBYTES and %d OUTBYTES  \n",PacketAnalyzer->Time, HTTP[Index].Status, HTTP[Index].InByteCounter, HTTP[Index].OutByteCounter);


  payloadsize=PacketAnalyzer->Length - (uint32_t)PacketAnalyzer->PayloadIndex;
  if(Flow[FlowAggregator->Index].Status==2){
    //just an update in an existing flow
    //printf("HTTPIndex:%d ",Flow[FlowAggregator->Index].HTTPIndex);
    if(Flow[FlowAggregator->Index].HTTPIndex==-1) return 0; //no reference from Flow to HTTP (impossible?)
    Index=Flow[FlowAggregator->Index].HTTPIndex; //simplifying current HTTP-index

    if(FlowAggregator->Direction==EGRESS){
      HTTP[Index].TotalOutByteCounter+=payloadsize;
    } else {
      HTTP[Index].TotalInByteCounter+=payloadsize;
    }

    switch(HTTP[Index].Status){
       case HTTPSTATUS_WAITINGFORSEND: 
         if(FlowAggregator->Direction==EGRESS){
           //printf("##WAITINGFORSEND##");
	   //HTTP[Index].OutByteCounter+=(PacketAnalyzer->Length - PacketAnalyzer->PayloadIndex);
           HTTP[Index].OutByteCounter+=payloadsize; 
           if(HTTP[Index].OutByteCounter>15){   //client sends potentential get-request
             getRef(); 
             HTTP[Index].Status=HTTPSTATUS_SENT;
             HTTP[Index].InByteCounter=0;
	     HTTP[Index].Time=PacketAnalyzer->Time;
           }
         }     
       break;

       case HTTPSTATUS_SENT:
         if(FlowAggregator->Direction==INGRESS){
         //printf("#SENT##");
           //payloadsize=PacketAnalyzer->Length - (uint32_t)PacketAnalyzer->PayloadIndex;
           HTTP[Index].InByteCounter+=payloadsize; 
	   if(HTTP[Index].InByteCounter>30){     //client receives answer with potential URL's
             HTTP[Index].Status=HTTPSTATUS_RECEIVED;
    	     HTTP[Index].OutByteCounter=0;
	     HTTP[Index].Time=PacketAnalyzer->Time;
             HTTP[Index].PayloadSize=(int16_t)payloadsize;
	     //EventCollector->addHTTPEvent(PacketAnalyzer->Time, CAUSE_HTTPDATARECEIVED, FlowAggregator->Index);

             //Here we reset the HFSM and start naive parsing 
             if(Flow[FlowAggregator->Index].RemotePort==80){
               //printf("New HTTP flow at %ld\n", PacketAnalyzer->Time);
               HTTP[Index].ParseState=HFSM1_IDLE;			
  	       HTTP[Index].ParseSubState=HFSM2_IDLE;		
  	       HTTP[Index].ParseMicroState=0;		
	       HTTP[Index].ContentType=BINARYCONTENT;
	       HTTP[Index].Encoding=0;
  	       HTTP[Index].Chunked=0;
	       parse(); //parse the first packet of an answer
             }
           }
         } else {
           //more egress data
           //payloadsize=PacketAnalyzer->Length - (uint32_t)PacketAnalyzer->PayloadIndex;
           if((payloadsize>10)&&(HTTP[Index].RefStat==REFSTAT_GETSEEN)) getRef(); 
         }
       break;

       case HTTPSTATUS_RECEIVED:
         //payloadsize=PacketAnalyzer->Length - (uint32_t)PacketAnalyzer->PayloadIndex;
         if(FlowAggregator->Direction==EGRESS) {
           //printf("##RECEIVED+EGRESS##");
           if(payloadsize>6)HTTP[Index].OutByteCounter+=payloadsize;
           if(HTTP[Index].OutByteCounter>15){  //removed test for PUSH : &&(PacketAnalyzer->TCPFlag>=8)
             getRef(); 
	     HTTP[Index].Status=HTTPSTATUS_SENT;
             HTTP[Index].InByteCounter=0;
	     HTTP[Index].Time=PacketAnalyzer->Time;
           }
         }else if (FlowAggregator->Direction==INGRESS){
           //printf("##RECEIVED+INGRESS##");
	   HTTP[Index].InByteCounter+=payloadsize;
	   if(HTTP[Index].InByteCounter>500000){ 
             //to much data received: cannot be a trigger
	     HTTP[Index].Status=HTTPSTATUS_WAITINGFORSEND;
	     HTTP[Index].InByteCounter=0;
             HTTP[Index].OutByteCounter=0;
	     HTTP[Index].Time=PacketAnalyzer->Time;
             //EventCollector->removeHTTPEvent(PacketAnalyzer->Time, FlowAggregator->Index); //withdraw the event
           } else {
             //normally we continue unless sequence error (=reset)
             //if(Flow[FlowAggregator->Index].RemotePort==80) parse();
             if(Flow[FlowAggregator->Index].RemotePort==80){
               if(PacketAnalyzer->TCPValid==2){ 
                 //sequence error resetting
                 HTTP[Index].ParseState=HFSM1_IDLE;			
  	         HTTP[Index].ParseSubState=HFSM2_IDLE;		
  	         HTTP[Index].ParseMicroState=0;		
	         HTTP[Index].ContentType=BINARYCONTENT;
	         HTTP[Index].Encoding=0;
  	         HTTP[Index].Chunked=0;
                 PacketAnalyzer->TCPValid=1;
                 parse();
               } else if(PacketAnalyzer->TCPValid==1){  
                 parse();  //first continue parsing
               }
             }

	     HTTP[Index].Time=PacketAnalyzer->Time;
             if((int16_t)payloadsize < HTTP[Index].PayloadSize){
               if(Flow[FlowAggregator->Index].RemotePort==80){
                 EventCollector->addHTTPEvent(PacketAnalyzer->Time, CAUSE_HTTPSIZEDECREASE, FlowAggregator->Index);
               } else if(Flow[FlowAggregator->Index].RemotePort==443) {
                 EventCollector->addHTTPSEvent(PacketAnalyzer->Time, CAUSE_HTTPSIZEDECREASE, FlowAggregator->Index);
               }
               HTTP[Index].LastTailTime=PacketAnalyzer->Time; //indication of total packet received
             }
             HTTP[Index].PayloadSize=payloadsize;
           }
         }
       break;

    }
    //printf("HTTP-Update: ct=%f   : ", (double)PacketAnalyzer->Time/1000000); HTTP[Index].print();
    return 1; //updated by existing flow
  } else if(Flow[FlowAggregator->Index].Status==1){
    //update a new flow
    //Size++; 
    //Index=Size;  

    if(Size==HTTP_BUFFER_SIZE-1) printf(">5 WARNING, HTTP BUFFER FULL AT: %ld OVERWRITING FROM NOW\n",PacketAnalyzer->Time);  
    WriteIndex++; if(WriteIndex>=HTTP_BUFFER_SIZE) WriteIndex=0;
    Index=WriteIndex;
    Size++;


    HTTP[Index].Time=PacketAnalyzer->Time;
    HTTP[Index].Status=HTTPSTATUS_WAITINGFORSEND;
    HTTP[Index].InByteCounter=0;
    HTTP[Index].OutByteCounter=0;
    HTTP[Index].TotalInByteCounter=0;
    HTTP[Index].TotalOutByteCounter=0;
    HTTP[Index].PayloadSize=0;
    HTTP[Index].FlowIndex=FlowAggregator->Index;
    HTTP[Index].URLBuffer[0]=0;
    HTTP[Index].RefBuffer[0]=0;
    HTTP[Index].RefStat=REFSTAT_UNDEFINED;
    Flow[FlowAggregator->Index].HTTPIndex=Index;
    //printf("New HTTPFlow: "); HTTP[Index].print();
    return 2;//updated by new flow
  }
  return 0; //unknown FlowStatus
}
  


//*****************************************************************************

int THTTPHelper::getRef(void){

  char *content; //pointer to the HTTP-content (header+body)
  int l, i, j, k;  

  //First check if referer already parsed
  if((HTTP[Index].RefStat==REFSTAT_REF)||(HTTP[Index].RefStat==REFSTAT_NOREF)) return 0; 

  //resetting bufffer, length etc
  HTTP[Index].RefBuffer[0]=0;
  content=(char*)&PCAP->Packet[PacketAnalyzer->PayloadIndex];	//content points to the payload
  l=PacketAnalyzer->Length - PacketAnalyzer->PayloadIndex;	//l is length of the payload in bytes

  //Check for GET0request or second packet
  if(((content[0]=='G')&&(content[1]=='E')&&(content[2]=='T'))||((content[0]=='P')&&(content[1]=='O')&&(content[2]=='S')&&(content[3]=='T'))||(HTTP[Index].RefStat==REFSTAT_GETSEEN)){
    //GET or POST SEEN
    HTTP[Index].LastHeaderTime=PacketAnalyzer->Time;  //new header started
    HTTP[Index].LastTailTime=PacketAnalyzer->Time;  //new header started
    //Updating state
    if(HTTP[Index].RefStat==REFSTAT_UNDEFINED){
      GetRequestCounter++;  //only counting the first GET-request in a HTTP flow
      HTTP[Index].RefStat=REFSTAT_GETSEEN;
    } else {
      HTTP[Index].RefStat=REFSTAT_NOREF;
    }
    //Searching Referer field
    for(i=0; i<l; i++){
      if((content[i-8]=='R')&&(content[i-7]=='e')&&(content[i-6]=='f')&&(content[i-5]=='e')&&(content[i-4]=='r')&&(content[i-3]=='e')&&(content[i-2]=='r')){
        //Referer found
        RefCounter++;
        j=i;
        while((content[j]!=0x0d)&&(j<l)) j++; //finding the end of the field or of the complete record
        for(k=i; k<j; k++){
          if((k-i)>80) break;
	  HTTP[Index].RefBuffer[k-i]=content[k];          
        }
        HTTP[Index].RefBuffer[k-i]=0;
        //Parsing domain name from raw buffer result
        if(stripRef()>=0){
          //success
          //TODO Check if matches with Routflow
          HTTP[Index].RefStat=REFSTAT_REF;
          SuccessRefCounter++;
          return 1;
        } else {
          //Parsing failed
          strcpy(HTTP[Index].RefBuffer, "_NO_PARSABLE_REF");
          HTTP[Index].RefStat=REFSTAT_NOREF;
          return -1;
        }
        //printf("Referer:>>>%s<<<\n", HTTP[Index].RefBuffer); 
      }
    }
    //Referer string was not found
    if(HTTP[Index].RefStat==REFSTAT_NOREF) strcpy(HTTP[Index].RefBuffer, "_NO_REF");
    return -1;
  }
  //no GET-Request or second Packet found, its a NOREF
  strcpy(HTTP[Index].RefBuffer, "_NO_GET_REQUEST");
  HTTP[Index].RefStat=REFSTAT_NOREF;
  return -1;
}



//*****************************************************************************
int THTTPHelper::parse(void){
//Naive chunkwise parser to extract on the fly URL's over multiple HTTP-packets with chunk and gzip capabilities

  char *content; //pointer to the HTTP-content (header+body)
  int l, i, ii, jj;  
  int32_t gcounter;

  //printf("\n>7 DEBUG, %ld, PARSING AND TCPVALID=%d:\n",PacketAnalyzer->Time, PacketAnalyzer->TCPValid);
  content=(char*)&PCAP->Packet[PacketAnalyzer->PayloadIndex];	//content points to the payload
  l=PacketAnalyzer->Length - PacketAnalyzer->PayloadIndex;	//l is length of the payload in bytes
  i=0;								//index that walks through the payload
  //if(HTTP[Index].ParseState==HFSM1_HEADER) printf("\n>7 DEBUG, %ld, LONG HEADER\n",PacketAnalyzer->Time); 

  //First unpack en repoint if gzipped text body 
  //if((HTTP[Index].Encoding==1)&&(HTTP[Index].ContentType==1)&&(HTTP[Index].ParseState==HFSM1_BODY)&&(PacketAnalyzer->TCPValid==1)){  
  if((HTTP[Index].Encoding==1)&&(HTTP[Index].ContentType==1)&&(HTTP[Index].ParseState==HFSM1_BODY)){  

    //printf("\n>7 DEBUG, %ld, UNZIPPING CONTINUED........:\n",PacketAnalyzer->Time);
    //Workaround for CHUNK-HEADER REMOVAL
    jj=-1;
    for(ii=0; ii<10; ii++){
      if(ii<l-1){
        if((content[ii]==0x0d)&&(content[ii+1]==0x0a)) jj=ii;
      }
    }
    if(jj!=-1){
      //0x0D, 0X0A found in first 10 bytes 
      l=l-jj-2;
      content=&content[jj+2];
    }
    //Workaround for CHUNK-TRAILER REMOVAL
    if(l>=2){
      if((content[l-2]==0x0d)&&(content[l-1]==0x0a)){ 
        l=l-2;
        //printf("Trailer removed, last byte is %d at %ld\n", (uint8_t)content[l-1], PacketAnalyzer->Time);
      }
    }
    //Workaround for CHUNK-MIDDLE REMOVAL
    if(l>7){
      ii=0;
      for(jj=0; jj<l; jj++){
        if((l-jj>4)&&(content[jj]==0x0d)&&(content[jj+1]==0x0a)&&(content[jj+3]==0x0d)&&(content[jj+4]==0x0a)){
          //printf("Middle1 removed, last byte is %d at %ld\n", (uint8_t)content[jj-1], PacketAnalyzer->Time);
          jj=jj+4;
        } else if((l-jj>5)&&(content[jj]==0x0d)&&(content[jj+1]==0x0a)&&(content[jj+4]==0x0d)&&(content[jj+5]==0x0a)){
          //printf("Middle2 removed, last byte is %d at %ld\n", (uint8_t)content[jj-1], PacketAnalyzer->Time);
          jj=jj+5;
        } else if((l-jj>6)&&(content[jj]==0x0d)&&(content[jj+1]==0x0a)&&(content[jj+5]==0x0d)&&(content[jj+6]==0x0a)){
	  //printf("Middle3 removed, last byte is %d at %ld\n", (uint8_t)content[jj-1], PacketAnalyzer->Time);
          jj=jj+6;
        } else if((l-jj>7)&&(content[jj]==0x0d)&&(content[jj+1]==0x0a)&&(content[jj+6]==0x0d)&&(content[jj+7]==0x0a)){
          //printf("Middle4 removed, last byte is %d at %ld\n", (uint8_t)content[jj-1], PacketAnalyzer->Time);
          jj=jj+7;
        } else if((l-jj>8)&&(content[jj]==0x0d)&&(content[jj+1]==0x0a)&&(content[jj+7]==0x0d)&&(content[jj+8]==0x0a)){
          //printf("Middle4 removed, last byte is %d at %ld\n", (uint8_t)content[jj-1], PacketAnalyzer->Time);
          jj=jj+8;
        } else if((l-jj>9)&&(content[jj]==0x0d)&&(content[jj+1]==0x0a)&&(content[jj+8]==0x0d)&&(content[jj+9]==0x0a)){
          //printf("Middle4 removed, last byte is %d at %ld\n", (uint8_t)content[jj-1], PacketAnalyzer->Time);
          jj=jj+9;
        } else if((l-jj>10)&&(content[jj]==0x0d)&&(content[jj+1]==0x0a)&&(content[jj+9]==0x0d)&&(content[jj+10]==0x0a)){
          //printf("Middle4 removed, last byte is %d at %ld\n", (uint8_t)content[jj-1], PacketAnalyzer->Time);
          jj=jj+10;
        } else if((l-jj>11)&&(content[jj]==0x0d)&&(content[jj+1]==0x0a)&&(content[jj+10]==0x0d)&&(content[jj+11]==0x0a)){
          //printf("Middle4 removed, last byte is %d at %ld\n", (uint8_t)content[jj-1], PacketAnalyzer->Time);
          jj=jj+11;
        } else {
          if(jj<l) DeChunkedContent[ii]=content[jj];
          ii++;
        }
      }
      content=&DeChunkedContent[0];
      l=ii;
    }

    //printf("Last byte is now %d %d %d %d \n", (uint8_t)content[l-4], (uint8_t)content[l-3], (uint8_t)content[l-2], (uint8_t)content[l-1]);
    GZIP[HTTP[Index].GZIPIndex].InLength=l;
    GZIP[HTTP[Index].GZIPIndex].InBuffer=(unsigned char *)&content[0];
    if(GZIP[HTTP[Index].GZIPIndex].uncompress()>=0){
      //Now repointing the text
      content=(char *)GZIP[HTTP[Index].GZIPIndex].OutBuffer;
      l=GZIP[HTTP[Index].GZIPIndex].OutLength;
      i=0;
    } else {
     HTTP[Index].ParseState=HFSM1_NO_HTTP; //gzip failed switching to non-http state
     GZIP[HTTP[Index].GZIPIndex].free(); //free the GZIP-buffer
    }
  }

  //Now walking byte by byte through the http-content if http
  while( (i<l) && (HTTP[Index].ParseState!= HFSM1_NO_HTTP) ){

    switch(HTTP[Index].ParseState){
      //---------------------------------
      //MAIN STATE IDLE (testing for immediate "HTTP"-string at the start of the header)
      case HFSM1_IDLE: 
        if(content[i]==PatternHTTP[HTTP[Index].ParseMicroState]) {
          if(HTTP[Index].ParseMicroState==3) {
	    //printf("\n>7 DEBUG, %ld, HEADER STARTS WITH HTTP\n",PacketAnalyzer->Time); 
            HTTP[Index].ParseState=HFSM1_HEADER;
            HTTP[Index].ParseSubState=HFSM2_IDLE;
            HTTP[Index].ParseMicroState=0;
	    HTTP[Index].ContentType=BINARYCONTENT;
	    HTTP[Index].Encoding=0;
	    HTTP[Index].Chunked=0;
          } else {
            HTTP[Index].ParseMicroState++;
          } 
        } else {
	    //printf("\n>3 ERROR, %ld, HEADER DOES NOT START WITH HTTP!\n",PacketAnalyzer->Time); 
	    HTTP[Index].ParseState= HFSM1_NO_HTTP;
        }
      break;

      //-----------------------------------
      //MAIN STATE HEADER (parsing the HTTP header)
      case HFSM1_HEADER:

        switch(HTTP[Index].ParseSubState){

	  case HFSM2_IDLE: //waiting for '\n' as a start of a interesting string
            if(content[i]==10){
              HTTP[Index].ParseSubState=HFSM2_NEWLINERECEIVED; //back to idle header state
              HTTP[Index].ParseMicroState=0; 
            }
          break;

	  case HFSM2_NEWLINERECEIVED: //waiting for 'C', '\r', or 'T' as a start of a interesting string
	    if(content[i]=='C'){
              HTTP[Index].ParseSubState=HFSM2_CONTENTTYPE;
              HTTP[Index].ParseMicroState=1;
	    } else if(content[i]=='T'){
              HTTP[Index].ParseSubState=HFSM2_CHUNKED;
              HTTP[Index].ParseMicroState=1;
            } else if(content[i]=='L'){
              HTTP[Index].ParseSubState=HFSM2_MOVED;
              HTTP[Index].ParseMicroState=1;  //<- trick to include the lf
            } else if (content[i]=='\r'){
              HTTP[Index].ParseSubState=HFSM2_WHITELINE;
              HTTP[Index].ParseMicroState=1;
            } else {
              HTTP[Index].ParseSubState=HFSM2_IDLE; //back to idle header state
            }
          break;

 	  case HFSM2_CHUNKED: //testing for "Transfer-Encoding: Chunked"
            if(content[i]!=32){
 	      if(content[i]==PatternTransfer[HTTP[Index].ParseMicroState]) {
                if(HTTP[Index].ParseMicroState==24) {
              	  //printf(">7 DEBUG, %ld, TRANSFER-ENCODING: CHUNKED \n",PacketAnalyzer->Time); 
		  HTTP[Index].Chunked=1;
            	  HTTP[Index].ParseSubState=HFSM2_IDLE;
            	  HTTP[Index].ParseMicroState=0;
                } else {
                  HTTP[Index].ParseMicroState++;
                } 
              } else {
	        //no Transfer-Encoding
	        HTTP[Index].ParseSubState=HFSM2_IDLE; //back to idle header state
                HTTP[Index].ParseMicroState=0; 
	        i--; //roll back 1 byte
	      }
            }
          break;

	  case HFSM2_MOVED: //testing for "Location:"
 	    if(content[i]==PatternLocation[HTTP[Index].ParseMicroState]) {
              if(HTTP[Index].ParseMicroState==8) {
            	//printf(">7 DEBUG, %ld, LOCATION MOVED \n",PacketAnalyzer->Time);
                HTTP[Index].ParseState=HFSM1_BODY;  
            	HTTP[Index].ParseSubState=HFSM2_IDLE;
            	HTTP[Index].ParseMicroState=0;
              } else {
                HTTP[Index].ParseMicroState++;
              } 
            } else {
	      //no Transfer-Encoding
	      HTTP[Index].ParseSubState=HFSM2_IDLE; //back to idle header state
              HTTP[Index].ParseMicroState=0; 
	      i--; //roll back 1 byte
	    }
          break;

	  case HFSM2_CONTENTTYPE: //testing for "Content-Type: Text" or "Content-E"
            if(content[i]!=32){
 	      if(content[i]==PatternContentTypeText[HTTP[Index].ParseMicroState]) {
                if(HTTP[Index].ParseMicroState==16) {
              	  //printf(">7 DEBUG, %ld, CONTENT-TYPE=TEXT\n",PacketAnalyzer->Time); 
		  HTTP[Index].ContentType=1;
            	  HTTP[Index].ParseSubState=HFSM2_IDLE;
            	  HTTP[Index].ParseMicroState=0;
                } else {
                  HTTP[Index].ParseMicroState++;
                }
              } else if(content[i]==PatternContentTypeJava[HTTP[Index].ParseMicroState]) {
   	        if(HTTP[Index].ParseMicroState==30) {
            	  //printf(">7 DEBUG, %ld, CONTENT-TYPE=JAVA\n",PacketAnalyzer->Time); 
		  HTTP[Index].ContentType=1;
            	  HTTP[Index].ParseSubState=HFSM2_IDLE;
            	  HTTP[Index].ParseMicroState=0;
                } else {
                  HTTP[Index].ParseMicroState++;
                }
	      } else if(content[i]==PatternContentTypeJS[HTTP[Index].ParseMicroState]) {
   	        if(HTTP[Index].ParseMicroState==34) {
            	  //printf(">7 DEBUG, %ld, CONTENT-TYPE=JAVASCRIPT\n",PacketAnalyzer->Time); 
		  HTTP[Index].ContentType=1;
            	  HTTP[Index].ParseSubState=HFSM2_IDLE;
            	  HTTP[Index].ParseMicroState=0;
                } else {
                  HTTP[Index].ParseMicroState++;
                }
              } else if(content[i]==PatternContentTypeFlash[HTTP[Index].ParseMicroState]) {
   	        if(HTTP[Index].ParseMicroState==30) {
              	  //printf(">7 DEBUG, %ld, CONTENT-TYPE=FLASH\n",PacketAnalyzer->Time); 
		  HTTP[Index].ContentType=1;
            	  HTTP[Index].ParseSubState=HFSM2_IDLE;
            	  HTTP[Index].ParseMicroState=0;
                } else {
                  HTTP[Index].ParseMicroState++;
                }
              } else if(content[i]==PatternContentTypeJSON[HTTP[Index].ParseMicroState]) {
   	        if(HTTP[Index].ParseMicroState==28) {
            	  //printf(">7 DEBUG, %ld, CONTENT-TYPE=JSON\n",PacketAnalyzer->Time); 
		  HTTP[Index].ContentType=1;
            	  HTTP[Index].ParseSubState=HFSM2_IDLE;
            	  HTTP[Index].ParseMicroState=0;
                } else {
                  HTTP[Index].ParseMicroState++;
                }
              } else {
 	        if((HTTP[Index].ParseMicroState==8)&&(content[i]=='E')){ 
 	          HTTP[Index].ParseSubState=HFSM2_ENCODING;  //directing to gzip decompression
            	  HTTP[Index].ParseMicroState=0; 
		  i--; //roll back 1 byte to preserve the E for the next state
                  //printf(">7 DEBUG, %ld, FORKING TO CONTENT-E\n",PacketAnalyzer->Time);
	        }  else {
	          HTTP[Index].ParseSubState=HFSM2_IDLE;//back to idle header state
            	  HTTP[Index].ParseMicroState=0;
		  i--; //roll back 1 byte
                }
	      }
            } /*else {
              printf(">>>>: ");
              for(ii=i; ii<i+10; ii++) printf("%c", content[ii]);
              printf("\n");
               
            }*/
          break;
	  case HFSM2_ENCODING: //testing for "Encoding: gzip"
            if(content[i]!=32){
 	      if(content[i]==PatternEncodingGZIP[HTTP[Index].ParseMicroState]) {
                if(HTTP[Index].ParseMicroState==12) {
              	  //printf(">7 DEBUG, %ld, CONTENT-ENCODING=gzip\n",PacketAnalyzer->Time); 
		  HTTP[Index].Encoding=1;
            	  HTTP[Index].ParseSubState=HFSM2_IDLE;
            	  HTTP[Index].ParseMicroState=0;
                } else {
                  HTTP[Index].ParseMicroState++;
                } 
              } else {
		  HTTP[Index].ParseSubState=HFSM2_IDLE;//back to idle header state
            	  HTTP[Index].ParseMicroState=0;
		  i--; //roll back 1 byte
	      }
            }
          break;
	  case HFSM2_WHITELINE: //testing for empty white line (= end of HTTP header)
	    if(content[i]==PatternWhiteLine[HTTP[Index].ParseMicroState]) {
              //if(HTTP[Index].ParseMicroState==3) {  
            	//printf(">7 DEBUG, %ld, END OF HEADER\n",PacketAnalyzer->Time);
		HTTP[Index].ParseState=HFSM1_NO_HTTP; //default state if nothing parsed in the header
		if(HTTP[Index].ContentType==1){ 
                  //SENDING GENERIC EVENT !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                  //EventCollector->addHTTPEvent(PacketAnalyzer->Time, CAUSE_HTTPDATARECEIVED, FlowAggregator->Index);
                  //END SENDING GENERIC EVENT !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		  HTTP[Index].ParseState=HFSM1_BODY;  //state if text 
            	  HTTP[Index].ParseSubState=HFSM2_IDLE;
            	  HTTP[Index].ParseMicroState=0;
		  if(HTTP[Index].Encoding==1){  //gzip
		    //HTTP[Index].GZIP = &GZIP[getGZIP()]; //attach an free gzip object
                    gcounter=0;
                    do{
                      GZIPIndex++; if(GZIPIndex>=TOTAL_GZIP) GZIPIndex=0;  //going to next index for a new buffer
                      gcounter++; if(gcounter>TOTAL_GZIP) printf("GZIP-Buffers full\n"); //checking the max
                    }while((GZIP[GZIPIndex].isInUse()!=0)&&(gcounter<=TOTAL_GZIP)); //stop if free or everything full
                    GZIP[GZIPIndex].free();
                    GZIP[GZIPIndex].take();
                    //printf(">7 DEBUG, %ld, Allocated gzip-Buffer %d\n",PacketAnalyzer->Time ,GZIPIndex);
                    HTTP[Index].GZIPIndex=GZIPIndex;
		    if(HTTP[Index].Chunked==1){
		      //switch to chunked state to remove chunk header
                      //REMOVING GENERIC EVENT!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
                      //EventCollector->removeHTTPEvent(PacketAnalyzer->Time, FlowAggregator->Index); //withdraw the event
                      //END OF REMOVING GENERIC EVENT!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
		      HTTP[Index].ParseState=HFSM1_CHUNK;  
            	      HTTP[Index].ParseSubState=HFSM2_IDLE;
            	      HTTP[Index].ParseMicroState=0;
                    } else{
		      ///Start first gzip
		      //printf(">7 DEBUG, %ld, UNZIPPING FIRST TIME\n",PacketAnalyzer->Time);
		      GZIP[HTTP[Index].GZIPIndex].InLength=l-i-1;
		      GZIP[HTTP[Index].GZIPIndex].InBuffer=(unsigned char *)&content[i+1];
                      //printf(">7 DEBUG, %ld, INLENGTH: %d\n",PacketAnalyzer->Time, GZIP[HTTP[Index].GZIPIndex].InLength);
                      if(GZIP[HTTP[Index].GZIPIndex].InLength==0){
                        //no content left in this packet for decompression
                        l=0;
                        i=0;
                      } else { 
                        if(GZIP[HTTP[Index].GZIPIndex].uncompress()>=0){
                          //Repointing to text
                          content=(char *)GZIP[HTTP[Index].GZIPIndex].OutBuffer;
                          l=GZIP[HTTP[Index].GZIPIndex].OutLength;
                          i=0;
                        } else {
                         //printf(">7 DEBUG, %ld, FAILING FIRST TIME\n",PacketAnalyzer->Time);
                         HTTP[Index].ParseState=HFSM1_NO_HTTP; //gzip failed switching to non-http state
                         GZIP[HTTP[Index].GZIPIndex].free(); //free the GZIP-buffer
                         //REMOVING GENERIC EVENT!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
                         //EventCollector->removeHTTPEvent(PacketAnalyzer->Time, FlowAggregator->Index); //withdraw the event
                        //END OF REMOVING GENERIC EVENT!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
                        }
                      }
                    }
		  }
		  
		}
              /*} else {
                HTTP[Index].ParseMicroState++; //whitespace match in progress
              }*/ 
            } else {
		HTTP[Index].ParseSubState=HFSM2_IDLE; //back to idle header state
            	HTTP[Index].ParseMicroState=0;
		i--;  //roll back 1 byte
	    }
          break;
      }
      break;
      //-----------------------------------
      //MAIN STATE CHUNK (parsing the CHUNK-part of the HTTP body)
      case HFSM1_CHUNK:
         //directly copying chunk data in outputbuffer for later debugging
	 //GZIP[HTTP[Index].GZIPIndex].OutBuffer[HTTP[Index].ParseMicroState]=content[i];  //copying chunk bytes in OutBuffer
         HTTP[Index].ParseMicroState++; //increasing pointer
         if(content[i]==0x0a){ 
           //End of the chunk part 
           //GZIP[HTTP[Index].GZIPIndex].OutBuffer[HTTP[Index].ParseMicroState+1]='\0'; //ending the string in outbuffer                
           if(i+1<l){
             //shift buffer i+1
             content=&content[i+1];
             l=l-(i+1);

             //Workaround for CHUNK-TRAILER REMOVAL  
             if(l>=2){
               if((content[l-2]==0x0d)&&(content[l-1]==0x0a)){
                 l=l-2;
                 //printf(">>>Trailer removed, last byte is %d at %ld\n", (uint8_t)content[l-1], PacketAnalyzer->Time);
               }
             }
             //Workaround for CHUNK-MIDDLE REMOVAL  
             if(l>7){
               ii=0;
               for(jj=0; jj<l; jj++){
                 if((l-jj>4)&&(content[jj]==0x0d)&&(content[jj+1]==0x0a)&&(content[jj+3]==0x0d)&&(content[jj+4]==0x0a)){
                   //printf(">>>Middle1 removed, last byte is %d at %ld\n", (uint8_t)content[jj-1], PacketAnalyzer->Time);
                   jj=jj+4;
                 } else if((l-jj>5)&&(content[jj]==0x0d)&&(content[jj+1]==0x0a)&&(content[jj+4]==0x0d)&&(content[jj+5]==0x0a)){
                   //printf(">>>Middle2 removed, last byte is %d at %ld\n", (uint8_t)content[jj-1], PacketAnalyzer->Time);
                   jj=jj+5;
                 } else if((l-jj>6)&&(content[jj]==0x0d)&&(content[jj+1]==0x0a)&&(content[jj+5]==0x0d)&&(content[jj+6]==0x0a)){
	           //printf(">>>Middle3 removed, last byte is %d at %ld\n", (uint8_t)content[jj-1], PacketAnalyzer->Time);
                   jj=jj+6;
                 } else if((l-jj>7)&&(content[jj]==0x0d)&&(content[jj+1]==0x0a)&&(content[jj+6]==0x0d)&&(content[jj+7]==0x0a)){
                   //printf(">>>Middle4 removed, last byte is %d at %ld\n", (uint8_t)content[jj-1], PacketAnalyzer->Time);
                   jj=jj+7;
                 } else if((l-jj>8)&&(content[jj]==0x0d)&&(content[jj+1]==0x0a)&&(content[jj+7]==0x0d)&&(content[jj+8]==0x0a)){
                   //printf(">>>Middle4 removed, last byte is %d at %ld\n", (uint8_t)content[jj-1], PacketAnalyzer->Time);
                   jj=jj+8;
                 } else if((l-jj>9)&&(content[jj]==0x0d)&&(content[jj+1]==0x0a)&&(content[jj+8]==0x0d)&&(content[jj+9]==0x0a)){
                   //printf(">>>Middle4 removed, last byte is %d at %ld\n", (uint8_t)content[jj-1], PacketAnalyzer->Time);
                   jj=jj+9;
                 } else if((l-jj>10)&&(content[jj]==0x0d)&&(content[jj+1]==0x0a)&&(content[jj+9]==0x0d)&&(content[jj+10]==0x0a)){
                   //printf(">>>Middle4 removed, last byte is %d at %ld\n", (uint8_t)content[jj-1], PacketAnalyzer->Time);
                   jj=jj+10;
                 } else if((l-jj>11)&&(content[jj]==0x0d)&&(content[jj+1]==0x0a)&&(content[jj+10]==0x0d)&&(content[jj+11]==0x0a)){
                   //printf(">>>Middle4 removed, last byte is %d at %ld\n", (uint8_t)content[jj-1], PacketAnalyzer->Time);
                   jj=jj+11;
                 } else {
                   if(jj<l) DeChunkedContent[ii]=content[jj];
                   ii++;
                 } //endif
               }//endfor
               content=&DeChunkedContent[0];
               l=ii;
             }//endif middle removal 

	     //printf(">7 DEBUG, %ld, UNZIPPING FIRST TIME WITH CHUNKED DATAHEADER=%s\n",PacketAnalyzer->Time, GZIP[HTTP[Index].GZIPIndex].OutBuffer);
	     GZIP[HTTP[Index].GZIPIndex].free();
             GZIP[HTTP[Index].GZIPIndex].take();
	     GZIP[HTTP[Index].GZIPIndex].InLength=l;
	     //GZIP[HTTP[Index].GZIPIndex].InLength=l-i-1;
 	     GZIP[HTTP[Index].GZIPIndex].InBuffer=(unsigned char *)content;
 	     //GZIP[HTTP[Index].GZIPIndex].InBuffer=(unsigned char *)&content[i+1];
             if(GZIP[HTTP[Index].GZIPIndex].InLength==0){
               //no content left in this packet for decompression
               l=0;
               i=0;
               HTTP[Index].ParseState=HFSM1_BODY;
               HTTP[Index].ParseSubState=HFSM2_IDLE;
               HTTP[Index].ParseMicroState=0;
             } else { 
	       if(GZIP[HTTP[Index].GZIPIndex].uncompress()>=0){
                 //SENDING GENERIC EVENT !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                 //EventCollector->addHTTPEvent(PacketAnalyzer->Time, CAUSE_HTTPDATARECEIVED, FlowAggregator->Index);
                 //END SENDING GENERIC EVENT !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
      	         //repointing to text
                 content=(char *)GZIP[HTTP[Index].GZIPIndex].OutBuffer;
                 l=GZIP[HTTP[Index].GZIPIndex].OutLength;
                 i=0;
	         HTTP[Index].ParseState=HFSM1_BODY;
                 HTTP[Index].ParseSubState=HFSM2_IDLE;
                 HTTP[Index].ParseMicroState=0;
               } else {
                 HTTP[Index].ParseState=HFSM1_NO_HTTP; //gzip failed switching to non-http state
                 GZIP[HTTP[Index].GZIPIndex].free(); //free the GZIP-buffer
               }
             }
           }
         }
      break;
      //-----------------------------------
      //MAIN STATE BODY (parsing the HTTP body)     
      case HFSM1_BODY:
	//printf("%c",content[i]);
       
	switch(HTTP[Index].ParseSubState){
	  case HFSM2_IDLE: //Hunting for a valid domain name character, except a dot
	    if(((content[i]>=48)&&(content[i]<=57))||((content[i]>=65)&&(content[i]<=90))||
			((content[i]>=97)&&(content[i]<=122))||(content[i]==45)){
	      //dn-character received (nondot) -> preparing next state
              //printf("%c ",content[i]);
              if (content[i]>=65 && content[i]<=90){
	 	HTTP[Index].URLBuffer[0]=content[i]+32; 
	      } else {
		HTTP[Index].URLBuffer[0]=content[i]; 
              }
	      HTTP[Index].PostDotLength=-1; //no potential tld spotted
	      HTTP[Index].ParseSubState=HFSM2_CHAR_RECEIVED; //valid DN character received
              HTTP[Index].ParseMicroState=1; //one character in the buffer
	    } 
	  break;
	  case HFSM2_CHAR_RECEIVED: //Growing domain name
	    if(HTTP[Index].ParseMicroState<255){
	      if ( ((content[i]>=48)&&(content[i]<=57)) || ((content[i]>=65)&&(content[i]<=90)) ||
	      ((content[i]>=97)&&(content[i]<=122)) || (content[i]==45) ){
	        //dn-character received buffer, no overflow
                //printf("%c", content[i]);
                if (content[i]>=65 && content[i]<=90){
	 	  HTTP[Index].URLBuffer[HTTP[Index].ParseMicroState]=content[i]+32; 
		} else {
		  HTTP[Index].URLBuffer[HTTP[Index].ParseMicroState]=content[i]; 
                }
	        if(HTTP[Index].PostDotLength!=-1) HTTP[Index].PostDotLength++; //only start counting if dot detected
	        HTTP[Index].ParseMicroState++;
	      } else if (content[i]=='.'){
	        //dot received
		HTTP[Index].URLBuffer[HTTP[Index].ParseMicroState]=content[i]; 
		HTTP[Index].ParseMicroState++;
		HTTP[Index].ParseSubState=HFSM2_DOT_RECEIVED; 	
	      } else {
		// non-dn-character received  
		HTTP[Index].URLBuffer[HTTP[Index].ParseMicroState]='\0';
   		  //printf(">6 INFO, %ld, place %d, SURL: %s break:%d\n", PacketAnalyzer->Time, i, HTTP[Index].URLBuffer, content[i]);
		if(checkURL()>=0){
	          //printf(">61 INFO, %ld, place %d, URL: %s \n", PacketAnalyzer->Time, i, HTTP[Index].URLBuffer);
		  EventCollector->addURLEvent(PacketAnalyzer->Time, HTTP[Index].URLBuffer, FlowAggregator->Index);
		} else {
                  //should we not reset more here?
	          //printf("\n>3 ERROR, %ld, NON VALID URL %d PostDotLength: %d content : %s \n", PacketAnalyzer->Time, i, HTTP[Index].PostDotLength, HTTP[Index].URLBuffer);
		}
		HTTP[Index].ParseSubState=HFSM2_IDLE;
	      } 
	    } else {
 	      //overflow
	      HTTP[Index].URLBuffer[255]='\0';
	      //printf("\n>3 ERROR, %ld, BUFFEROVERFLOW URL: %s \n", PacketAnalyzer->Time, HTTP[Index].URLBuffer);
	      HTTP[Index].ParseSubState=HFSM2_OVERFLOW;
	    } 
	  break;
	  case HFSM2_OVERFLOW: //Hunting for a non-valid domain name character to escape overflow
	    if(!(((content[i]>=48)&&(content[i]<=57))||((content[i]>=65)&&(content[i]<=90))||
			((content[i]>=97)&&(content[i]<=122))||(content[i]==45))){
	      //non dn received
	      HTTP[Index].ParseSubState=HFSM2_IDLE;
	    } 
	  break;
	  case HFSM2_DOT_RECEIVED: //dot received
	    if(((content[i]>=48)&&(content[i]<=57))||((content[i]>=65)&&(content[i]<=90))||
			((content[i]>=97)&&(content[i]<=122))||(content[i]==45)){
	      //dn-character received (nondot) -> preparing next state
	      if (content[i]>=65 && content[i]<=90){
	        HTTP[Index].URLBuffer[HTTP[Index].ParseMicroState]=content[i]+32; 
	      } else {
	        HTTP[Index].URLBuffer[HTTP[Index].ParseMicroState]=content[i]; 
              }
	      HTTP[Index].ParseMicroState++;
	      HTTP[Index].PostDotLength=1; //potential tld spotted
	      HTTP[Index].ParseSubState=HFSM2_CHAR_RECEIVED; //valid DN character received
	    } else {
	      //second dot or non char recieved
	      if(HTTP[Index].PostDotLength==-1) HTTP[Index].PostDotLength=0;
	      HTTP[Index].URLBuffer[HTTP[Index].ParseMicroState-1]='\0';
	      if(checkURL()>=0){
	        //printf(">62 INFO, %ld, place %d, URL: %s \n", PacketAnalyzer->Time, i, HTTP[Index].URLBuffer);
                EventCollector->addURLEvent(PacketAnalyzer->Time, HTTP[Index].URLBuffer, FlowAggregator->Index);
	      } else {
	        //printf("\n>3 ERROR, %ld, DD NON VALID URL %d PostDotLength: %d content : %s \n", PacketAnalyzer->Time, i, HTTP[Index].PostDotLength, HTTP[Index].URLBuffer);
	      }
	      HTTP[Index].ParseSubState=HFSM2_IDLE;
	      HTTP[Index].ParseMicroState=0;
	    }
	  break;
	}
      break;
	
      default:
        printf("\n>3 ERROR, %ld, Impossible MainParseState: \n",PacketAnalyzer->Time);
      break;
    }//end of main state switch

    i++; //goto next byte

  }//end of while
  return 0; //number of darsed URL's (tbi)

}//end of all


	
//*****************************************************************************
int THTTPHelper::checkURL(void){
  char last[8];
  int j, pointcounter, digitcounter;

  //printf( ">>> %d : %s\n" , HTTP[Index].PostDotLength ,HTTP[Index].URLBuffer);
  if(strlen(HTTP[Index].URLBuffer)<5) return -1;  //no url to small
  if((HTTP[Index].PostDotLength<2)||(HTTP[Index].PostDotLength>15)){
    return -1;  //no url, to  large or to small
  }

  //first check on ip-url
  pointcounter=0; digitcounter=0;
  for(j=0; j<(int)strlen(HTTP[Index].URLBuffer); j++){
    if(HTTP[Index].URLBuffer[j]=='.') pointcounter++;
    if((HTTP[Index].URLBuffer[j]>=48)&&(HTTP[Index].URLBuffer[j]<=57)) digitcounter++;
  }
  //printf( "TEST:%s - %d - %d\n" , HTTP[Index].URLBuffer, pointcounter, digitcounter);
  if((pointcounter==3)&&((digitcounter>3)||(digitcounter<13))) return 0;

  //now continue on name urls
  j=0;
  while( (j<=HTTP[Index].PostDotLength) && (j<=6) ){
   last[j]=HTTP[Index].URLBuffer[HTTP[Index].ParseMicroState-HTTP[Index].PostDotLength+j];
   //printf(" %d ",j);
   j++;
  }
  last[7]='\0'; 
  //printf("** %s **",last);
  j=last[0]-97; 
  if( (j>=0) &&(j<27) ){
    if (strstr(TLD[j], last)!=0) {
      //printf("- OK!\n");
      return 0;
    } 
  }
  return -2;
}

//*****************************************************************************
int THTTPHelper::stripRef(void){
  int i,l, start, stop;

  l=strlen(HTTP[Index].RefBuffer);
  if(l<5) return -1;  //no url to small

  for(i=2; i<l; i++){
    if(HTTP[Index].RefBuffer[i-2]==':') break; 
  }
  if(i>=l) return -1;
  start=i+1;
  for(i=start; i<l; i++){
    if(HTTP[Index].RefBuffer[i]=='/') break; 
  }
  stop=i;
  if((stop-start<3)||(stop-start>64)) return -1;
  for(i=start; i<stop; i++) HTTP[Index].RefBuffer[i-start]=HTTP[Index].RefBuffer[i];
  HTTP[Index].RefBuffer[i-start]=0;
  //printf("Referer:>>>%s<<<\n", HTTP[Index].RefBuffer);
  return 1;
};



//*****************************************************************************
void THTTPHelper::dump(char *dm, int dest){

  sprintf(dm, "Index, Time, FlowIndex, Status, InByteCount, OutByteCount, Port, RefStat, Referer, TreeID\n");
  for(Index=0; Index<Size; Index++){   //TODO 0 -> 1
    sprintf(dm+strlen(dm), "%d, ", Index);
    HTTP[Index].print(dm);
  }
  if(dest==1){
    Logger->save(".http", dm);
  } else {
    printf("%s", dm);
  }


  sprintf(dm, "HTTP STATISTICS\n");
  sprintf(dm+strlen(dm), "HTTP+HTTTPS-records count:\t\t%d\n",Size);
  sprintf(dm+strlen(dm), "\tWith GET-requests count:\t%d\n",GetRequestCounter);
  sprintf(dm+strlen(dm), "\tWith Referer count:\t\t%d\n",RefCounter);
  sprintf(dm+strlen(dm), "\tWith Parsable Referer count:\t%d\n\n",SuccessRefCounter);
  if(dest==1){
    Logger->saveStatsLog(dm);
   } else {
    printf("%s", dm);
  }




















};  

