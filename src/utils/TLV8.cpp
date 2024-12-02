/*********************************************************************************
 *  MIT License
 *  
 *  Copyright (c) 2020-2024 Gregg E. Berman
 *  
 *  https://github.com/HomeSpan/HomeSpan
 *  
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *  
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *  
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 *  
 ********************************************************************************/

#include "TLV8.h"
#include <string.h>

//////////////////////////////////////

tlv_t::tlv_t(uint8_t tag, size_t len, const uint8_t* val) : tag{tag}, len{len} {       
  if(len>0){
    this->val=std::unique_ptr<uint8_t>((uint8_t *)malloc(len));
    if(val!=NULL)
      memcpy((this->val).get(),val,len);      
  }
}

//////////////////////////////////////

void tlv_t::update(size_t addLen, const uint8_t *addVal){
  if(addLen>0){
    uint8_t *p=val.release();
    p=(uint8_t *)realloc(p,len+addLen);
    val=std::unique_ptr<uint8_t>(p);
    if(addVal!=NULL)
      memcpy(p+len,addVal,addLen);
    len+=addLen;        
  }
}

/////////////////////////////////////

void tlv_t::osprint(std::ostream& os){

  uint8_t *p=val.get();       // starting pointer
  uint8_t *pend=p+len;        // ending pointer (may equal starting if len=0)

  do{
    uint8_t nBytes=(pend-p)>255?255:(pend-p);   // max is 255 bytes per TLV record
    os.write((char *)&tag,1);
    os.write((char *)&nBytes,1);
    os.write((char *)p,nBytes);
    p+=nBytes;
  } while(p<pend);
}

/////////////////////////////////////

TLV_it TLV::add(uint8_t tag, size_t len, const uint8_t* val){

  if(!empty() && front().tag==tag)
    front().update(len,val);
  else
    emplace_front(tag,len,val);

  return(begin());
}

/////////////////////////////////////

TLV_it TLV::find(uint8_t tag, TLV_it it1, TLV_it it2){

  auto it=it1;
  while(it!=it2 && (*it).tag!=tag)
    it++;
  return(it==it2?end():it);
}

/////////////////////////////////////

size_t TLV::pack_size(TLV_it it1, TLV_it it2){

  size_t nBytes=0;

  while(it1!=it2){
    nBytes+=2+(*it1).len;
    if((*it1).len>255)
      nBytes+=2*(((*it1).len-1)/255);
    it1++;
  }

  return(nBytes);
}

/////////////////////////////////////

size_t TLV::pack(uint8_t *buf, size_t bufSize){

  size_t nBytes=0;

  while(nBytes<bufSize && currentPackIt!=endPackIt){
    switch(currentPackPhase){

      case 0:
        currentPackBuf=(*currentPackIt).val.get();
        endPackBuf=(*currentPackIt).val.get()+(*currentPackIt).len;
        currentPackPhase=1;
        break;
        
      case 1:
        *buf++=(*currentPackIt).tag;
        nBytes++;
        currentPackPhase=2;
        break;
        
      case 2:
        currentPackLen=endPackBuf-currentPackBuf;
        if(currentPackLen>255)
          currentPackLen=255;
        *buf++=currentPackLen;
        nBytes++;
        currentPackPhase=3;
        break;

      case 3:
        if(currentPackLen==0){
          if(endPackBuf==currentPackBuf){
            currentPackIt++;
            currentPackPhase=0;
          } else {
            currentPackPhase=1;
          }
          break;
        }
        
        size_t copyBytes=(currentPackLen<(bufSize-nBytes)) ? currentPackLen : (bufSize-nBytes);
        memcpy(buf,currentPackBuf,copyBytes);
        buf+=copyBytes;
        currentPackBuf+=copyBytes;
        currentPackLen-=copyBytes;
        nBytes+=copyBytes;
        break;    
    }
  }
  
  return(nBytes);
}

/////////////////////////////////////

void TLV::unpack(uint8_t *buf, size_t bufSize){

  if(empty())
    unpackPhase=0;

  while(bufSize>0){
    switch(unpackPhase){

      case 0:
        unpackTag=*buf++;
        bufSize--;
        unpackPhase=1;
        break;

      case 1:
        unpackBytes=*buf++;
        bufSize--;
        if(unpackBytes==0){
          add(unpackTag);
          unpackPhase = 0;
        } else {
          if (berInput) {
            if (unpackBytes == 0x81 && bufSize > 0) {
              unpackBytes = *buf++;
              bufSize--;
            } else if (unpackBytes == 0x82 && bufSize >= 2 && buf != NULL) {
              unpackBytes = (*buf++ << 8);
              unpackBytes |= *buf++;
              bufSize -= 2;
            } else if (unpackBytes == 0x83 && bufSize >= 3) {
              unpackBytes = (*buf++ << 16);
              unpackBytes |= (*buf++ << 8);
              unpackBytes |= *buf++;
              bufSize -= 3;
            } else if (unpackBytes == 0x84 && bufSize >= 4) {
              unpackBytes = (*buf++ << 24);
              unpackBytes |= (*buf++ << 16);
              unpackBytes |= (*buf++ << 8);
              unpackBytes |= *buf++;
              bufSize -= 4;
            }
          }
          unpackPhase = 2;
        }
        break;

      case 2:
       size_t copyBytes = unpackBytes < bufSize ? unpackBytes : bufSize;
       add(unpackTag,copyBytes,buf);
       buf+=copyBytes;
       unpackBytes-=copyBytes;
       bufSize-=copyBytes;
       if(unpackBytes==0)
        unpackPhase=0;
      break;
    }
  }
}


/////////////////////////////////////

const char *TLV::getName(uint8_t tag){

  if(names==NULL)
    return(NULL);

  for(int i=0;i<nNames;i++){
    if(names[i].tag==tag)
      return(names[i].name);
  }

  return(NULL);
}

/////////////////////////////////////

void TLV::print(TLV_it it1, TLV_it it2){

  while(it1!=it2){
    const char *name=getName((*it1).tag);
    if(name)
      printf("%s",name);
    else
      printf("%d",(*it1).tag);
    printf("(%d) ",(*it1).len);
    for(int i=0;i<(*it1).len;i++)
      printf("%02X",(*it1).val.get()[i]);
    printf("\n");
    it1++;
  }
}
  
//////////////////////////////////////

void TLV::osprint(std::ostream& os, TLV_it it1, TLV_it it2){

  for(auto it=it1;it!=it2;it++)
    (*it).osprint(os);
}

//////////////////////////////////////
