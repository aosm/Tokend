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
 *  JPKISchema.h
 *  TokendMuscle
 */

#ifndef _JPKISCHEMA_H_
#define _JPKISCHEMA_H_

#include "Schema.h"
#include "JPKIAttributeCoder.h"
#include "JPKIKeyHandle.h"

namespace Tokend
{
	class Relation;
	class MetaRecord;
	class AttributeCoder;
}

class JPKISchema : public Tokend::Schema
{
	NOCOPY(JPKISchema)
public:
    JPKISchema();
    virtual ~JPKISchema();

	virtual void create();

protected:
	Tokend::Relation *createKeyRelation(CSSM_DB_RECORDTYPE keyType);

private:
	// Coders we need.
	JPKIDataAttributeCoder mJPKIDataAttributeCoder;

	Tokend::ConstAttributeCoder mKeyAlgorithmCoder;
	Tokend::ConstAttributeCoder mKeySizeCoder;

	JPKIKeyHandleFactory mJPKIKeyHandleFactory;
};

#endif /* !_JPKISCHEMA_H_ */

/* arch-tag: 70A9DD29-1C88-11D9-8910-000A9595DEEE */
