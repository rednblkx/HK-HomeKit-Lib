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
 
#pragma once

#include <sstream>
#include <forward_list>
#include <memory>
#include <cstdint>

struct tlv_t {
  uint8_t tag;
  size_t len;
  std::unique_ptr<uint8_t> val;

  tlv_t(uint8_t tag, size_t len, const uint8_t* val);
  void update(size_t addLen, const uint8_t *addVal);
  void osprint(std::ostream& os);

  operator uint8_t*() const{
    return(val.get());
  }
  
};

/////////////////////////////////////

typedef std::forward_list<tlv_t>::iterator TLV_it;
typedef struct { const uint8_t tag; const char *name; } TLV_names;

/////////////////////////////////////

class TLV : public std::forward_list<tlv_t> {

  TLV_it currentPackIt;
  TLV_it endPackIt;
  uint8_t *currentPackBuf;
  uint8_t *endPackBuf;
  int currentPackPhase;
  size_t currentPackLen;
 
  uint8_t unpackTag;
  size_t unpackBytes;
  int unpackPhase;

  const TLV_names *names=NULL;
  int nNames=0;
  
  public:

  TLV(){};
  TLV(const TLV_names *names, int nNames) : names{names}, nNames{nNames} {};

  TLV_it add(uint8_t tag, size_t len, const uint8_t *val);
  TLV_it add(uint8_t tag, uint8_t val){return(add(tag, 1, &val));}
  TLV_it add(uint8_t tag){return(add(tag, 0, NULL));}

  TLV_it find(uint8_t tag, TLV_it it1, TLV_it it2);
  TLV_it find(uint8_t tag, TLV_it it1){return(find(tag, it1, end()));}
  TLV_it find(uint8_t tag){return(find(tag, begin(), end()));}

  int len(TLV_it it){return(it==end()?-1:(*it).len);} 

  size_t pack_size(TLV_it it1, TLV_it it2);
  size_t pack_size(){return(pack_size(begin(), end()));}

  void pack_init(TLV_it it1, TLV_it it2){currentPackIt=it1; endPackIt=it2; currentPackPhase=0;}
  void pack_init(TLV_it it1){pack_init(it1, it1++);}
  void pack_init(){pack_init(begin(),end());}
  
  size_t pack(uint8_t *buf, size_t bufSize);
  size_t pack(uint8_t *buf){pack_init(); return(pack(buf,pack_size()));}

  const char *getName(uint8_t tag);
  
  void print(TLV_it it1, TLV_it it2);
  void print(TLV_it it1){print(it1, it1++);}
  void print(){print(begin(), end());}

  void osprint(std::ostream& os, TLV_it it1, TLV_it it2);
  void osprint(std::ostream& os, TLV_it it1){osprint(os, it1, it1++);}
  void osprint(std::ostream& os){osprint(os, begin(), end());}

  void unpack(uint8_t *buf, size_t bufSize);

  void wipe(){std::forward_list<tlv_t>().swap(*this);}
  
};
