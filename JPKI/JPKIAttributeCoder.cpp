/*
 *  Copyright (c) 2004 Apple Computer, Inc. All Rights Reserved.
 * 
 *  @APPLE_LICENSE_HEADER_START@
 *  
 *  This file contains Original Code and/or Modifications of Original Code
 *  as defined in and that are subject to the Apple Public Source License
 *  Version 2.0 (the 'License'). You may not use this file except in
 *  compliance with the License. Please obtain a copy of the License at
 *  http://www.opensource.apple.com/apsl/ and read it before using this
 *  file.
 *  
 *  The Original Code and all software distributed under the License are
 *  distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 *  EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 *  INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 *  Please see the License for the specific language governing rights and
 *  limitations under the License.
 *  
 *  @APPLE_LICENSE_HEADER_END@
 */

/*
 *  JPKIAttributeCoder.cpp
 *  TokendMuscle
 */

#include "JPKIAttributeCoder.h"

#include "MetaAttribute.h"
#include "MetaRecord.h"
#include "JPKIRecord.h"
#include "JPKIToken.h"

using namespace Tokend;


//
// JPKIDataAttributeCoder
//
JPKIDataAttributeCoder::~JPKIDataAttributeCoder()
{
}

void JPKIDataAttributeCoder::decode(TokenContext *tokenContext,
	const MetaAttribute &metaAttribute, Record &record)
{
	JPKICertificateRecord &jpkiCertRecord =
		dynamic_cast<JPKICertificateRecord &>(record);
	record.attributeAtIndex(metaAttribute.attributeIndex(),
		jpkiCertRecord.getDataAttribute(tokenContext));
}


/* arch-tag: 6FA560F3-1C88-11D9-ACE1-000A9595DEEE */
