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
 *  JPKIRecord.h
 *  TokendMuscle
 */

#ifndef _JPKIRECORD_H_
#define _JPKIRECORD_H_

#include "Record.h"

#include <security_cdsa_utilities/cssmcred.h>

class JPKIToken;

class JPKIRecord : public Tokend::Record
{
	NOCOPY(JPKIRecord)
public:
	JPKIRecord(const char *description) :
		mDescription(description) {}
	~JPKIRecord();

	virtual const char *description() { return mDescription; }

protected:
	const char *mDescription;
};


class JPKICertificateRecord : public JPKIRecord
{
	NOCOPY(JPKICertificateRecord)
public:
	JPKICertificateRecord(uint8_t shortEFName, const char *description) :
		JPKIRecord(description), mShortEFName(shortEFName) {}
	~JPKICertificateRecord();

	virtual Tokend::Attribute *getDataAttribute(Tokend::TokenContext *tokenContext);

protected:
	uint8_t mShortEFName;
};

class JPKIKeyRecord : public JPKIRecord
{
	NOCOPY(JPKIKeyRecord)
public:
	JPKIKeyRecord(uint8_t shortEFName, const char *description,
		const Tokend::MetaRecord &metaRecord, bool signOnly);
    ~JPKIKeyRecord();

	size_t sizeInBits() const { return 1024; }
	void computeCrypt(JPKIToken &jpkiToken, bool sign,
		const AccessCredentials *cred,
		const unsigned char *data, size_t dataLength,
		unsigned char *result, size_t &resultLength);

	void getAcl(const char *tag, uint32 &count, AclEntryInfo *&acls);

private:
	uint8_t mShortEFName;
	bool mSignOnly;
	AutoAclEntryInfoList mAclEntries;
};


#endif /* !_JPKIRECORD_H_ */

/* arch-tag: 70706DFC-1C88-11D9-B163-000A9595DEEE */

