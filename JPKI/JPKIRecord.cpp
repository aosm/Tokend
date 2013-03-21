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
 *  JPKIRecord.cpp
 *  TokendMuscle
 */

#include "JPKIRecord.h"

#include "JPKIError.h"
#include "JPKIToken.h"
#include "Attribute.h"
#include "MetaAttribute.h"
#include "MetaRecord.h"
#include <security_cdsa_client/aclclient.h>
#include <Security/SecKey.h>


//
// JPKIRecord
//
JPKIRecord::~JPKIRecord()
{
}

//
// JPKICertificateRecord
//
JPKICertificateRecord::~JPKICertificateRecord()
{
}

#define JPKI_MAXSIZE_CERT           4000

Tokend::Attribute *JPKICertificateRecord::getDataAttribute(
	Tokend::TokenContext *tokenContext)
{
	JPKIToken &jpkiToken = dynamic_cast<JPKIToken &>(*tokenContext);
	CssmData data;
#if 0
	if (jpkiToken.cachedObject(0, mDescription, data))
	{
		Tokend::Attribute *attribute =
			new Tokend::Attribute(data.Data, data.Length);
		free(data.Data);
		return attribute;
	}
#endif

	uint8 certificate[JPKI_MAXSIZE_CERT];
	size_t certificateLength = sizeof(certificate);
	jpkiToken.readCertificate(mShortEFName, certificate, certificateLength);
	data.Data = certificate;
	data.Length = certificateLength;
	jpkiToken.cacheObject(0, mDescription, data);

	return new Tokend::Attribute(data.Data, data.Length);
}


//
// JPKIKeyRecord
//
JPKIKeyRecord::JPKIKeyRecord(uint8_t shortEFName,
	const char *description,
	const Tokend::MetaRecord &metaRecord, bool signOnly) :
	JPKIRecord(description),
	mShortEFName(shortEFName),
	mSignOnly(signOnly)
{
    attributeAtIndex(metaRecord.metaAttribute(kSecKeyDecrypt).attributeIndex(),
                     new Tokend::Attribute(!signOnly));
    attributeAtIndex(metaRecord.metaAttribute(kSecKeyUnwrap).attributeIndex(),
                     new Tokend::Attribute(!signOnly));
    attributeAtIndex(metaRecord.metaAttribute(kSecKeySign).attributeIndex(),
                     new Tokend::Attribute(signOnly));
}

JPKIKeyRecord::~JPKIKeyRecord()
{
}

void JPKIKeyRecord::computeCrypt(JPKIToken &jpkiToken, bool sign,
	const AccessCredentials *cred,
	const unsigned char *data, size_t dataLength,
	unsigned char *output, size_t &outputLength)
{
	PCSC::Transaction _(jpkiToken);
	jpkiToken.select(mShortEFName);

#if 0
	if (cred)
	{
		bool found = false;
		uint32 size = cred->size();
		for (uint32 ix = 0; ix < size; ++ix)
		{
			const TypedList &sample = (*cred)[ix];
			if (sample.type() == CSSM_SAMPLE_TYPE_PROMPTED_PASSWORD
                && sample.length() == 2)
            {
                CssmData &pin = sample[1].data();
                if (pin.Length >= 4)
                {
                    jpkiToken.verifyPIN(pin.Data, pin.Length);
                    found = true;
                    break;
                }
			}
		}

		if (!found)
			CssmError::throwMe(CSSM_ERRCODE_ACL_SUBJECT_TYPE_NOT_SUPPORTED);
	}
#endif

	if (dataLength > sizeInBits() / 8)
		CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);

	if (sign != mSignOnly)
		CssmError::throwMe(CSSMERR_CSP_KEY_USAGE_INCORRECT);

	size_t resultLength = sizeInBits() / 8 + 2;
	unsigned char result[resultLength];
	jpkiToken.sign(data, dataLength, result);
	outputLength = resultLength - 2;
	memcpy(output, result, outputLength);
}

void JPKIKeyRecord::getAcl(const char *tag, uint32 &count, AclEntryInfo *&acls)
{
	if (!mAclEntries) {
		mAclEntries.allocator(Allocator::standard());
        // Anyone can read the DB record for this key (which is a reference
		// CSSM_KEY)
        mAclEntries.add(CssmClient::AclFactory::AnySubject(
			mAclEntries.allocator()),
			AclAuthorizationSet(CSSM_ACL_AUTHORIZATION_DB_READ, 0));
        // To sign with this key you need pin1.
		mAclEntries.add(CssmClient::AclFactory::PinSubject(
			mAclEntries.allocator(), 1),
			AclAuthorizationSet(CSSM_ACL_AUTHORIZATION_SIGN, 0));
	}
	count = mAclEntries.size();
	acls = mAclEntries.entries();
}


/* arch-tag: 705491C9-1C88-11D9-912D-000A9595DEEE */
