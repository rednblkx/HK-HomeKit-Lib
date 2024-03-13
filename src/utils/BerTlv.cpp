/*
https://github.com/huckor/BER-TLV

The MIT License (MIT)

Copyright (c) 2023 Robert Hucko

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "BerTlv.h"

//Add tag and value to TLV collection
short BerTlv::Add(std::string Tag, std::string Value) {
    return Add(Tag, AsciiToBin(Value));
}

//Add tag and value to TLV collection
short BerTlv::Add(std::string Tag, std::vector<unsigned char> Value) {
    std::vector<unsigned char> BinTag;
    if(Tag.length() <= 0) {
        return TAG_IS_EMPTY;
    }
    if(Tag.length() % 2 != 0) {
        return TAG_ERROR;
    }
    BinTag = AsciiToBin(Tag);
    if(BinTag.size() <= 0) {
        return TAG_ERROR;
    }
    return Add(BinTag, Value);
}

//Add tag and value to TLV collection
short BerTlv::Add(std::vector<unsigned char> Tag, std::vector<unsigned char> Value) {
    std::vector<unsigned char> BinTmp;
    if(Tag.size() <= 0) {
        return TAG_IS_EMPTY;
    }
    if(Value.size() <= 0) {
        return VALUE_IS_EMPTY;
    }
    //Add TAG to TLV
    for(size_t i = 0; i < Tag.size(); i++) {
        _TlvStruct.push_back(Tag[i]);
    }
    //Calculate Value length and add it to TLV
    BinTmp = CalcSizeOfValue(Value);
    if(BinTmp.size() <= 0) {
        return VALUE_ERROR;
    }
    for(size_t i = 0; i < BinTmp.size(); i++) {
        _TlvStruct.push_back(BinTmp[i]);
    }
    //Add value
    for(size_t i = 0; i < Value.size(); i++) {
        _TlvStruct.push_back(Value[i]);
    }
    return TLV_OK;
}

//Get value of tag from collection
short BerTlv::GetValue(std::string Tag, std::string *ValueOfTag, bool CheckNestedTags) {
    std::vector<unsigned char> out;
    short Ret = GetValue(AsciiToBin(Tag), &out, CheckNestedTags);
    *ValueOfTag = BinToAscii(out);
    return Ret;
}

//Get value of tag from collection
short BerTlv::GetValue(std::string Tag, std::vector<unsigned char> *ValueOfTag, bool CheckNestedTags) {
    return GetValue(AsciiToBin(Tag), ValueOfTag, CheckNestedTags);
}

//Get value of tag from collection
short BerTlv::GetValue(std::vector<unsigned char> Tag, std::string *ValueOfTag, bool CheckNestedTags) {
    std::vector<unsigned char> out;
    short Ret = GetValue(Tag, &out, CheckNestedTags);
    *ValueOfTag = BinToAscii(out);
    return Ret;
}

//Get value of tag from collection
short BerTlv::GetValue(std::vector<unsigned char> Tag, std::vector<unsigned char> *ValueOfTag, bool CheckNestedTags) {
    short TagSize = 0;
    int ValueSize = 0;
    short LengthSize = 0;
    size_t MaxSize = _TlvStruct.size();
    std::vector<unsigned char> TmpTag;
    bool TagFound = false;

    ValueOfTag->clear();
    
    //Traverse through collection
    for(size_t i = 0; i < MaxSize; i++) {
        TmpTag.clear();
        TagSize = GetTagLength(i);
        
        //Check if we found tag which we are looking for
        if(TagSize == Tag.size()) {
            for(size_t j = 0; j < TagSize; j++) {
                TmpTag.push_back(_TlvStruct[i + j]);
            }
            
            if(std::equal(Tag.begin(), Tag.end(), TmpTag.begin())) {
                TagFound = true;
            }
        }
        
        //Increment i + size of tag
        i += TagSize;
        if(MaxSize < i) {
            return TLV_SIZE_ERROR;
        }
        
        //Get size of value and size of length
        LengthSize = GetSizeOfValue(i, &ValueSize);
        if(LengthSize == TLV_SIZE_ERROR 
            || (i + ValueSize + LengthSize) > MaxSize) 
        {
            return TLV_SIZE_ERROR;
        }
        
        //Did we found the tag?
        if(TagFound) {
            //Copy value of tag to output
            for(size_t j = i + LengthSize; j < i + LengthSize + ValueSize; j++) {
                ValueOfTag->push_back(_TlvStruct[j]);
            }
            return TLV_OK;
        }
        //Should we parse inside nested tags?
        else if(CheckNestedTags && IsTagNested(i - TagSize, TagSize)) {
            if(GetValueFromTlv(i + TagSize + LengthSize, ValueSize, Tag, ValueOfTag) == TLV_OK) {
                return TLV_OK;
            }
        } else {
            i += LengthSize + ValueSize - 1;
        }
        
    }
    
    return TLV_FAILED;
}

//Dump all data from TLV collection and save it to 'Output'
short BerTlv::DumpAllTagsAndValues(std::string *Output, bool ParseNestedTags) {
    short TagSize = 0;
    int ValueSize = 0;
    short LengthSize = 0;
    size_t StartPosition = 0;
    size_t OutputActualPosition = 0;

    Output->clear();
    
    //Traverse through collection
    for(size_t i = 0; i < _TlvStruct.size(); i++) {
        StartPosition = i;
        
        //Get and increment i + size of tag
        TagSize = GetTagLength(i);
        i += TagSize;
        if(_TlvStruct.size() < i) {
            return TLV_SIZE_ERROR;
        }
        
        //Get size of value and size of length
        LengthSize = GetSizeOfValue(i, &ValueSize);
        if(LengthSize == TLV_SIZE_ERROR) {
            return TLV_SIZE_ERROR;
        }
        
        //Increment i + size of value
        i += LengthSize + ValueSize - 1;
        
        if(ParseNestedTags && IsTagNested(StartPosition, TagSize)) {
            *Output += BinToAscii(&_TlvStruct[StartPosition], TagSize, false);
            *Output += "[";
            *Output += BinToAscii(&_TlvStruct[StartPosition + TagSize], LengthSize, false);
            *Output += "]";
            OutputActualPosition = Output->length();
            
            if(DumpTlvInsideTag(StartPosition + TagSize + LengthSize, ValueSize, Output) == TLV_OK) {
                Output->insert(OutputActualPosition, "\n{\n");
                *Output += "}";
            } else {
                *Output += " = ";
                *Output += BinToAscii(&_TlvStruct[StartPosition + TagSize + LengthSize], ValueSize, false);
            }
            *Output += i == _TlvStruct.size() - 1 ? "" : "\n";
        } else {
            *Output += BinToAscii(&_TlvStruct[StartPosition], TagSize, false);
            *Output += "[";
            *Output += BinToAscii(&_TlvStruct[StartPosition + TagSize], LengthSize, false);
            *Output += "] = ";
            *Output += BinToAscii(&_TlvStruct[StartPosition + TagSize + LengthSize], ValueSize, false);
            *Output += i == _TlvStruct.size() - 1 ? "" : "\n";
        }
    } //For
    
    return TLV_OK;
}

short BerTlv::DumpTlvInsideTag(size_t StartPosition, int Length, std::string *Output) {
    short TagSize = 0;
    int ValueSize = 0;
    short LengthSize = 0;
    size_t MaxSize = StartPosition + Length;
    size_t TmpStartPosition = 0;
    
    //Traverse through collection
    for(size_t i = StartPosition; i < MaxSize; i++) {
        TmpStartPosition = i;
        
        //Get and increment i + size of tag
        TagSize = GetTagLength(i);
        i += TagSize;
        if(MaxSize < i) {
            return TLV_SIZE_ERROR;
        }
        
        //Get size of value and size of length
        LengthSize = GetSizeOfValue(i, &ValueSize);
        if(LengthSize == TLV_SIZE_ERROR 
            || (ValueSize + StartPosition + TagSize + LengthSize) > MaxSize) 
        {
            return TLV_SIZE_ERROR;
        }
        
        i += LengthSize + ValueSize - 1;
        
        *Output += "  ";
        *Output += BinToAscii(&_TlvStruct[TmpStartPosition], TagSize, false);
        *Output += "[";
        *Output += BinToAscii(&_TlvStruct[TmpStartPosition + TagSize], LengthSize, false);
        *Output += "] = ";
        *Output += BinToAscii(&_TlvStruct[TmpStartPosition + TagSize + LengthSize], ValueSize, false);
        *Output += "\n";
    }
    
    return TLV_OK;
}

short BerTlv::GetValueFromTlv(size_t StartPosition, int Length, std::vector<unsigned char> Tag, std::vector<unsigned char> *Output) {
    short TagSize = 0;
    int ValueSize = 0;
    short LengthSize = 0;
    size_t MaxSize = StartPosition + Length;
    std::vector<unsigned char> TmpTag;
    bool TagFound = false;
    
    //Traverse through collection
    for(size_t i = StartPosition; i < MaxSize; i++) {
        TmpTag.clear();
        TagSize = GetTagLength(i);
        
        //Check if we found tag which we are looking for
        if(TagSize == Tag.size()) {
            for(size_t j = 0; j < TagSize; j++) {
                TmpTag.push_back(_TlvStruct[i + j]);
            }
            if(std::equal(Tag.begin(), Tag.end(), TmpTag.begin())) {
                TagFound = true;
            }
        }
        
        i += TagSize;
        if(MaxSize < i) {
            return TLV_SIZE_ERROR;
        }
        
        //Get size of value and size of length
        LengthSize = GetSizeOfValue(i, &ValueSize);
        if(LengthSize == TLV_SIZE_ERROR 
            || (ValueSize + StartPosition + TagSize + LengthSize) > MaxSize)
        {
            return TLV_SIZE_ERROR;
        }
        
        //Did we find the tag?
        if(TagFound) {
            //Copy value of tag to output
            for(size_t j = i + LengthSize; j < i + LengthSize + ValueSize; j++) {
                Output->push_back(_TlvStruct[j]);
            }
            return TLV_OK;
        } else {
            i += LengthSize + ValueSize - 1;
        }
    } //For
    return TLV_FAILED;
}

bool BerTlv::IsTagNested(size_t StartPosition, short TagSize) {
    if(_TlvStruct[StartPosition] & 0x20) {
        return true;
    }
    return false;
}

short BerTlv::GetSizeOfValue(size_t StartPosition, int *SizeOfValue) {
    //Five bytes long size
    if(_TlvStruct[StartPosition] == 0x84) {
        if(_TlvStruct.size() >= StartPosition + 4) {
            *SizeOfValue = (_TlvStruct[StartPosition + 1] << 24) | (_TlvStruct[StartPosition + 2] << 16) | (_TlvStruct[StartPosition + 3] << 8) | _TlvStruct[StartPosition + 4];
            return 5;
        } else {
            return TLV_SIZE_ERROR;
        }
    }
    //Four bytes long size
    else if(_TlvStruct[StartPosition] == 0x83) {
        if(_TlvStruct.size() >= StartPosition + 3) {
            *SizeOfValue = (_TlvStruct[StartPosition + 1] << 16) | (_TlvStruct[StartPosition + 2] << 8) | _TlvStruct[StartPosition + 3];
            return 4;
        } else {
            return TLV_SIZE_ERROR;
        }
    }
    //Three bytes long size
    else if(_TlvStruct[StartPosition] == 0x82) {
        if(_TlvStruct.size() >= StartPosition + 2) {
            *SizeOfValue = (_TlvStruct[StartPosition + 1] << 8) | _TlvStruct[StartPosition + 2];
            return 3;
        } else {
            return TLV_SIZE_ERROR;
        }
    }
    //Two bytes long size
    else if(_TlvStruct[StartPosition] == 0x81) {
        if(_TlvStruct.size() >= StartPosition + 1) {
            *SizeOfValue = _TlvStruct[StartPosition + 1];
            return 2;
        } else {
            return TLV_SIZE_ERROR;
        }
    }
    //One byte long size
    else {
        *SizeOfValue = _TlvStruct[StartPosition];
        return 1;
    }
}

short BerTlv::GetTagLength(size_t StartPosition) {
    short Length = 1;
    if(_TlvStruct[StartPosition] & 0x01
        && _TlvStruct[StartPosition] & 0x02
        && _TlvStruct[StartPosition] & 0x04
        && _TlvStruct[StartPosition] & 0x08
        && _TlvStruct[StartPosition] & 0x10) 
    {
        Length++;
        for(size_t i = StartPosition + 1; i < _TlvStruct.size(); i++) {
            if(_TlvStruct[i] & 0x80) {
                Length++;
            } else {
                break;
            }
        }
    }
    return Length;
}

std::vector<unsigned char> BerTlv::CalcSizeOfValue(std::vector<unsigned char> Value) {
    std::vector<unsigned char> out = std::vector<unsigned char>(0);
    //One byte long size
    if(Value.size() > 0 && Value.size() <= 127) {
        out.push_back(Value.size());
    }
    //Two bytes long size
    else if(Value.size() > 127 && Value.size() <= 256) {
        out.push_back(0x81);
        out.push_back(Value.size());
    }
    //Three bytes long size
    else if(Value.size() > 256 && Value.size() <= 65535) {
        out.push_back(0x82);
        out.push_back((Value.size() >> 8) & 0xff);
        out.push_back(Value.size() & 0xff);
    }
    //Four bytes long size
    else if(Value.size() > 65535 && Value.size() <= 16777215) {
        out.push_back(0x83);
        out.push_back((Value.size() >> 16) & 0xff);
        out.push_back((Value.size() >> 8) & 0xff);
        out.push_back(Value.size() & 0xff);
    }
    //Five bytes long size
    else if(Value.size() > 16777215 && Value.size() <= 4294967259) {
        out.push_back(0x84);
        out.push_back((Value.size() >> 24) & 0xff);
        out.push_back((Value.size() >> 16) & 0xff);
        out.push_back((Value.size() >> 8) & 0xff);
        out.push_back(Value.size() & 0xff);
    }
    return out;
}

/**
* Convert byte array to string.
* Example: BinData = 0x03, 0x45, 0x35 
*	return string after conversion will contain 
* string = "034535" (if comma parameter is set to false)
* string = "03, 45, 35" (if comma parameter is set to true)
*/
std::string BerTlv::BinToAscii(std::vector<unsigned char> BinData, bool comma)
{
	char AsciiHexNo[5];
	std::string Return;

	for(int i = 0; i < (int)BinData.size(); i++)
	{
		sprintf(AsciiHexNo, "%02X", BinData[i]);
		Return += AsciiHexNo;
		if((i + 1) < (int)BinData.size() && comma)
			Return += ", ";
	}

	return Return;
}

/**
* Convert byte array to string.
* Example: BinData = 0x03, 0x45, 0x35 
*	return string after conversion will contain 
* string = "034535" (if comma parameter is set to false)
* string = "03, 45, 35" (if comma parameter is set to true)
*/
std::string BerTlv::BinToAscii(unsigned char *BinData, int Length, bool comma)
{
	char AsciiHexNo[5];
	std::string Return;

	for(int i = 0; i < Length; i++)
	{
		sprintf(AsciiHexNo, "%02X", BinData[i]);
		Return += AsciiHexNo;
		if((i + 1) < Length && comma)
			Return += ", ";
	}

	return Return;
}

/**
* Convert byte to string.
* Example: BinData = 0x03
*	return string after conversion will contain 
* string = "03"
*/
std::string BerTlv::BinToAscii(unsigned char BinData)
{
  char AsciiHexNo[5];
  std::string Return;

  sprintf(AsciiHexNo, "%02X", BinData);
  Return += AsciiHexNo;

  return Return;
}

/**
* Convert string which contains ASCI HEX values to byte array.
* Example: string = "034535", after conversion byte array will contain 0x03 0x45 0x35
*/
std::vector<unsigned char> BerTlv::AsciiToBin(std::string Ascii) 
{
	std::vector<unsigned char> Return;

	if((Ascii.length() % 2) != 0)
		return Return;

	for(size_t i = 0; i < Ascii.length(); i+=2) 
	{
		std::string Tmp = Ascii.substr(i, 2);
		Return.push_back((char)strtol(Tmp.c_str(), NULL, 16));
	}

	return Return;
}