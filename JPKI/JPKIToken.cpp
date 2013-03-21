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
 *  JPKIToken.cpp
 *  TokendMuscle
 */

#include "JPKIToken.h"

#include "Adornment.h"
#include "AttributeCoder.h"
#include "JPKIError.h"
#include "JPKIRecord.h"
#include "JPKISchema.h"
#include <security_cdsa_client/aclclient.h>
#include <map>
#include <vector>

using CssmClient::AclFactory;

#define USE_TRANSMIT_APDU  1

/* Obsolete */
#define OFF_CLA  0
#define OFF_INS  1
#define OFF_P1   2
#define OFF_P2   3
#define OFF_LC   4
#define OFF_DATA 5


#define JPKI_TOKENINFO_LABEL "JPKIAPICCTOKEN                  "
#define JPKI_TOKENINFO_LABEL_SIZE 32

/* CLA */
#define CLA_STANDARD                     0x00
#define CLA_APPLICATION_SPECIFIC         0x80

/* INS */
#define INS_VERIFY                       0x20
#define INS_CHANGE_REFERENCE_DATA        0x24
#define INS_COMPUTE_DIGITAL_SIGNATURE    0x2A
#define INS_SELECT_FILE                  0xA4
#define INS_READ_BINARY                  0xB0
#define INS_MANAGE_SECURITY_ENVIRONMENT  0x22

/* P1 */
#define P1_SELECT_APPLET                 0x04
#define P1_SELECT_EF                     0x02
#define P1_READ_BINARY_SELECT_SHORT_EF   0x80
#define P1_VERIFY                        0x00
#define P1_CHANGE_REFERENCE_DATA	     0x01
#define P1_SIGNATURE_METHOD_PKCS1PAD     0x00

/* P2 */
#define P2_SELECT_FILE                   0x0C
#define P2_SIGN                          0x02
#define P2_VERIFY_SELECT_SHORT_EF        0x80
#define P2_CHANGE_REFERENCE_DATA         0x80
#define P2_COMPUTE_DIGITAL_SIGNATURE     0x00

#define SHORT_EF_USER_CERTIFICATE        0x01
#define SHORT_EF_CA_CERTIFICATE          0x02
#define SHORT_EF_TOKEN_INFO              0x06

#define SHORT_EF_USER_PRIV_KEY           0x1A
#define SHORT_EF_USER_PASSWORD           0x1B

#define JPKI_APPLETID \
	0xD3, 0x92, 0xF0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00, 0x01

static const unsigned char kJPKIAppletID[] = { JPKI_APPLETID };

static const unsigned char kJPKI_EF_User_Certificate[] =
	{ 0x00, SHORT_EF_USER_CERTIFICATE };
static const unsigned char kJPKI_EF_CA_Certificate[] =
	{ 0x00, SHORT_EF_CA_CERTIFICATE };
static const unsigned char kJPKI_EF_CA_UserPublicKey[] =
	{ 0x00, 0x03 };
static const unsigned char kJPKI_EF_CA_PublicKeySig[] =
	{ 0x00, 0x04 };
static const unsigned char kJPKI_EF_AttrIDInfo[] =
	{ 0x00, 0x05 };
static const unsigned char kJPKI_EF_TokenInfo[] =
	{ 0x00, SHORT_EF_TOKEN_INFO };
static const unsigned char kJPKI_EF_PrivKeyInfo[] =
	{ 0x00, 0x07 };

static const unsigned char kJPKI_EF_UserPrivKey[] =
	{ 0x00, SHORT_EF_USER_PRIV_KEY };
static const unsigned char kJPKI_EF_UserPassword[] =
	{ 0x00, SHORT_EF_USER_PASSWORD };
static const unsigned char kJPKI_EF_PublicKeyFVOC[] =
	{ 0x00, 0x1C };
static const unsigned char kJPKI_EF_3DESK1[] =
	{ 0x00, 0x1D };
static const unsigned char kJPKI_EF_3DESK2[] =
	{ 0x00, 0x1E };


JPKIToken::JPKIToken() :
	mAppletSelected(false),
	mCurrentShortEF(0),
	mPinStatus(0)
{
	mTokenContext = this;
	mSession.open();
}

JPKIToken::~JPKIToken()
{
	delete mSchema;
}

uint32_t JPKIToken::selectApplet()
{
	if (isInTransaction() && mAppletSelected)
		return 0x9000;

#ifdef USE_TRANSMIT_APDU
	uint32_t sw = transmitAPDU(CLA_STANDARD,
		INS_SELECT_FILE,
		P1_SELECT_APPLET,
		P2_SELECT_FILE,
		sizeof(kJPKIAppletID), kJPKIAppletID);
#else
	uint8_t apdu[] =
	{
		CLA_STANDARD,
		INS_SELECT_FILE,
		P1_SELECT_APPLET,
		P2_SELECT_FILE,
		sizeof(kJPKIAppletID),
		JPKI_APPLETID
	};

	unsigned char result[2];
	size_t resultLength = sizeof(result);
	uint32_t sw = exchangeAPDU(apdu, sizeof(apdu), result, resultLength);
#endif
	if (sw == 0x9000 && isInTransaction())
		mAppletSelected = true;
	return sw;
}

void JPKIToken::select(uint8_t shortEFName)
{
	if (isInTransaction() && mCurrentShortEF == shortEFName)
		return;

	JPKIError::check(selectApplet());

#ifdef USE_TRANSMIT_APDU
	uint8_t ef[] = { 0x00, shortEFName };
	JPKIError::check(transmitAPDU(CLA_STANDARD,
		INS_SELECT_FILE,
		P1_SELECT_EF,
		P2_SELECT_FILE,
		sizeof(ef), ef));
#else
	uint8_t apdu[] =
	{
		CLA_STANDARD,
		INS_SELECT_FILE,
		P1_SELECT_EF,
		P2_SELECT_FILE,
		0x02,				// Lc
		0x00, shortEFName   // File ID
	};
	unsigned char result[2];
	size_t resultLength = sizeof(result);

	JPKIError::check(exchangeAPDU(apdu, sizeof(apdu), result, resultLength));
#endif
	if (isInTransaction())
		mCurrentShortEF = shortEFName;
}

void JPKIToken::sign(const uint8_t *toSign, size_t toSignLength,
	uint8_t *signature)
{
	uint8_t apdu[toSignLength + 6];
	apdu[OFF_CLA] = CLA_APPLICATION_SPECIFIC;
	apdu[OFF_INS] = INS_COMPUTE_DIGITAL_SIGNATURE;
	apdu[OFF_P1]  = P1_SIGNATURE_METHOD_PKCS1PAD;
	apdu[OFF_P2]  = P2_COMPUTE_DIGITAL_SIGNATURE;
	apdu[OFF_LC]  = toSignLength;
	memcpy(apdu + 5, toSign, toSignLength);
	size_t signatureLength = 128 + 2;
	/* From the ISO spec:
	   If the Le field contains only bytes set to '00', then Ne is maximum,
	   i.e., within the limit of 256 for a short L field  or 65 536 for an
	   extended L field, all the available bytes should be returned.

	   Since some JPKI cards don't respond well when asked to return a
	   specific number of bytes in Le we ask for all of them instead.  By
	   specifying a 0 Le. */
	apdu[5 + toSignLength] = 0x00; // was: signatureLength - 2;
	JPKIError::check(exchangeAPDU(apdu, sizeof(apdu), signature,
		signatureLength));
	if (signatureLength != 128 + 2)
		PCSC::Error::throwMe(SCARD_E_PROTO_MISMATCH);
}

#define READ_BLOCK_SIZE  0xF4

void JPKIToken::readCertificate(uint8_t shortEFName, uint8_t *result,
	size_t &resultLength)
{
	PCSC::Transaction _(*this);
	JPKIError::check(selectApplet());

	// Attempt to read READ_BLOCK_SIZE bytes
	uint8_t apdu[] =
	{
		CLA_STANDARD,
		INS_READ_BINARY,
		P1_READ_BINARY_SELECT_SHORT_EF | shortEFName,
		0, // offset % 256
		READ_BLOCK_SIZE,
	};

	size_t bytes_read = resultLength;
	JPKIError::check(exchangeAPDU(apdu, sizeof(apdu), result, bytes_read));
	if (bytes_read - 2 != apdu[OFF_LC])
		PCSC::Error::throwMe(SCARD_E_PROTO_MISMATCH);
	mCurrentShortEF = shortEFName;
	uint32_t offset = bytes_read - 2;
	if (result[0] != 0x30)
		PCSC::Error::throwMe(SCARD_E_PROTO_MISMATCH);

	uint32_t certificateLength;
	if (!(result[1] & 0x80))
	{
		certificateLength = result[1] + 2;
	}
	else
	{
		uint32_t llen = result[1] & 0x7F;
		certificateLength = 0;
		for (uint32_t ix = 0; ix < llen; ++ix)
			certificateLength = (certificateLength << 8) + (result[ix + 2]);

		certificateLength += 2 + llen;
	}

	secdebug("read", "readCertificate: %02X length: %u", shortEFName,
		certificateLength);
	for (;offset < certificateLength;)
	{
		apdu[OFF_P1] = offset >> 8;
		apdu[OFF_P2] = offset & 0xFF;
		if ((certificateLength - offset) < READ_BLOCK_SIZE)
			apdu[OFF_LC] = certificateLength - offset;
		// Never read more than we have room for.
		size_t bytes_read = resultLength - offset; 
		JPKIError::check(exchangeAPDU(apdu, sizeof(apdu), result + offset,
			bytes_read));
        if (bytes_read - 2 != apdu[OFF_LC])
            PCSC::Error::throwMe(SCARD_E_PROTO_MISMATCH);

        offset += apdu[OFF_LC];
	}

	resultLength = offset;
}

uint32_t JPKIToken::exchangeAPDU(const uint8_t *apdu, size_t apduLength,
	uint8_t *result, size_t &resultLength)
{
	size_t savedLength = resultLength;

	transmit(apdu, apduLength, result, resultLength);
	if (resultLength == 2 && result[0] == 0x61)
	{
		resultLength = savedLength;
		uint8 expectedLength = result[1];
		unsigned char getResult[] = { 0x00, 0xC0, 0x00, 0x00, expectedLength };
		transmit(getResult, sizeof(getResult), result, resultLength);
		if (resultLength - 2 != expectedLength)
        {
            if (resultLength < 2)
                PCSC::Error::throwMe(SCARD_E_PROTO_MISMATCH);
            else
                JPKIError::throwMe((result[resultLength - 2] << 8)
					+ result[resultLength - 1]);
        }
	}

	if (resultLength < 2)
		PCSC::Error::throwMe(SCARD_E_PROTO_MISMATCH);

    return (result[resultLength - 2] << 8) + result[resultLength - 1];
}

void JPKIToken::didDisconnect()
{
	PCSC::Card::didDisconnect();
	mAppletSelected = false;
	mCurrentShortEF = 0;
}

void JPKIToken::didEnd()
{
	PCSC::Card::didEnd();
	mAppletSelected = false;
	mCurrentShortEF = 0;
}

void JPKIToken::changePIN(int pinNum,
	const unsigned char *oldPin, size_t oldPinLength,
	const unsigned char *newPin, size_t newPinLength)
{
	if (pinNum != 1)
		CssmError::throwMe(CSSM_ERRCODE_SAMPLE_VALUE_NOT_SUPPORTED);

	if (oldPinLength < 4 || oldPinLength > 16 ||
		newPinLength < 4 || newPinLength > 16)
		CssmError::throwMe(CSSM_ERRCODE_INVALID_SAMPLE_VALUE);

	uint8_t apdu[] =
	{
		CLA_STANDARD,
		INS_CHANGE_REFERENCE_DATA,
		P1_CHANGE_REFERENCE_DATA,
		P2_CHANGE_REFERENCE_DATA | SHORT_EF_USER_PASSWORD,
		0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	apdu[OFF_LC] = newPinLength;
	uint32_t offset = OFF_DATA;

	for (uint32_t ix = 0; ix < newPinLength;)
	{
		uint8_t ch = newPin[ix++];
		if (!isalnum(ch))
			CssmError::throwMe(CSSM_ERRCODE_INVALID_SAMPLE_VALUE);

		if (isalpha(ch))
			ch = toupper(ch);

		apdu[offset++] = ch;
	}

	PCSC::Transaction _(*this);
	verifyPIN(pinNum, oldPin, oldPinLength);

	unsigned char result[2];
	size_t resultLength = sizeof(result);

	mPinStatus = exchangeAPDU(apdu, OFF_DATA + newPinLength, result,
		resultLength);
	memset(apdu + OFF_DATA, 0, 16);
	JPKIError::check(mPinStatus);
}

uint32_t JPKIToken::pinStatus(int pinNum)
{
	if (pinNum != 1)
		CssmError::throwMe(CSSM_ERRCODE_SAMPLE_VALUE_NOT_SUPPORTED);

	if (mPinStatus && isInTransaction())
		return mPinStatus;

	// Always checks PIN1
	PCSC::Transaction _(*this);
	JPKIError::check(selectApplet());

	unsigned char result[2];
	size_t resultLength = sizeof(result);
	uint8_t apdu[] =
	{
		CLA_STANDARD,
		INS_VERIFY,
		P1_VERIFY,
		P2_VERIFY_SELECT_SHORT_EF | SHORT_EF_USER_PASSWORD
	};

	mPinStatus = exchangeAPDU(apdu, 4, result, resultLength);
	if ((mPinStatus & 0xFF00) != 0x6300
		&& mPinStatus != SCARD_AUTHENTICATION_BLOCKED)
		JPKIError::check(mPinStatus);

	return mPinStatus;
}

void JPKIToken::verifyPIN(int pinNum, const uint8_t *pin, size_t pinLength)
{
	if (pinNum != 1)
		CssmError::throwMe(CSSM_ERRCODE_SAMPLE_VALUE_NOT_SUPPORTED);

	if (pinLength < 4 || pinLength > 16)
		CssmError::throwMe(CSSM_ERRCODE_INVALID_SAMPLE_VALUE);

	uint8_t apdu[] =
	{
		CLA_STANDARD,
		INS_VERIFY,
		P1_VERIFY,
		P2_VERIFY_SELECT_SHORT_EF | SHORT_EF_USER_PASSWORD,
		0x04,
		0x31, 0x32, 0x33, 0x34, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
#ifdef USE_BUILTIN_PIN
#else
	apdu[OFF_LC] = pinLength;
	uint32_t offset = OFF_DATA;

	for (uint32_t ix = 0; ix < pinLength;)
	{
		uint8_t ch = pin[ix++];
		if (!isalnum(ch))
			CssmError::throwMe(CSSM_ERRCODE_INVALID_SAMPLE_VALUE);

		if (isalpha(ch))
			ch = toupper(ch);

		apdu[offset++] = ch;
	}
#endif

	PCSC::Transaction _(*this);
	JPKIError::check(selectApplet());

	unsigned char result[2];
	size_t resultLength = sizeof(result);
	mPinStatus = exchangeAPDU(apdu, OFF_DATA + pinLength, result,
		resultLength);
	memset(apdu + OFF_DATA, 0, 16);
	if (mPinStatus == 0x6300) {
		secdebug("probe", "unlimited user pin tries left");
	} else if ((mPinStatus & 0xFFF0) == 0x63C0) {
		IFDEBUG(uint32_t tries = mPinStatus & 0x000F);
		secdebug("probe", "%u user pin tries left", tries);
	} else if (mPinStatus == 0x6984) {
		secdebug("probe", "user pin is blocked");
	}
	JPKIError::check(mPinStatus);
	// Start a new transaction which we never get rid of until someone calls
	// unverifyPIN()
	begin();
}

void JPKIToken::unverifyPIN(int pinNum)
{
	if (pinNum != -1)
		CssmError::throwMe(CSSM_ERRCODE_SAMPLE_VALUE_NOT_SUPPORTED);

	end(SCARD_RESET_CARD);
}

uint32 JPKIToken::probe(SecTokendProbeFlags flags,
	char tokenUid[TOKEND_MAX_UID])
{
	uint32 score = Tokend::ISO7816Token::probe(flags, tokenUid);

	bool doDisconnect = true;

	try
	{
		uint8_t tokenInfo[98];
		size_t tokenInfoLength = sizeof(tokenInfo);
		uint32_t sw;

		PCSC::Transaction _(*this);
		sw = selectApplet();
		if (sw == 0x9000) {
			uint8_t apdu[] =
			{
				CLA_STANDARD,
				INS_READ_BINARY,
				P1_READ_BINARY_SELECT_SHORT_EF | SHORT_EF_TOKEN_INFO,
				0, // offset % 256
				sizeof(tokenInfo) - 2,
			};
			sw = exchangeAPDU(apdu, sizeof(apdu), tokenInfo, tokenInfoLength);
		}

		if (sw == 0x9000) {
			score = 100;
			// Setup the tokendUID
			uint32_t offset = 0;
			uint32_t top = sizeof(tokenInfo) - 2;
			// Now stick in the chip serial # as characters.
			// The JPKI client software depends on the first bit being "JPKIAPICCTOKEN" e.g.
			// ScSerialNumber:JPKIAPICCTOKEN0000000000000000000000000000000700000000000000000000000000000000
			// Since they make the cards, we can't complain
			for (uint32_t ix = 0; ix < top; ++ix)
			{
				if (isalnum(tokenInfo[ix])) {
					sprintf(tokenUid + offset, "%c", tokenInfo[ix]);
					offset += 1;
				}
			}
			tokenUid[offset]=0;
			assert(TOKEND_MAX_UID > offset);
			memset(tokenUid + offset, 0, TOKEND_MAX_UID - offset);
			secdebug("probe", "recognized %s", tokenUid);
			doDisconnect = false;
		}
	}
	catch (...)
	{
		doDisconnect = true;
		score = 0;
	}

	if (doDisconnect)
		disconnect();

	return score;
}

void JPKIToken::establish(const CSSM_GUID *guid, uint32 subserviceId,
	SecTokendEstablishFlags flags, const char *cacheDirectory,
	const char *workDirectory, char mdsDirectory[PATH_MAX],
	char printName[PATH_MAX])
{
	::snprintf(printName, 16, "JPKI-card #%d", subserviceId);
	Tokend::ISO7816Token::name(printName);
	Tokend::ISO7816Token::establish(guid, subserviceId, flags,
		cacheDirectory, workDirectory, mdsDirectory, printName);

	mSchema = new JPKISchema();
	mSchema->create();

	populate();

#if 0
	uint8_t cacertificate[4000];
	uint16_t sw;
	sw = transmitAPDU(
		CLA_STANDARD,
		INS_READ_BINARY,
		P1_READ_BINARY_SELECT_SHORT_EF | SHORT_EF_CA_CERTIFICATE,
		0, // offset % 256
		NULL, 0,
		cacertificate, 4);

	if (sw == 0x9000) {
		size_t certRemainingSize = ((cacertificate[2]) << 8)
			+ cacertificate[3];
		secdebug("read", "certRemainingSize %ld", certRemainingSize);
		sw = transmitAPDU(
			CLA_STANDARD,
			INS_READ_BINARY,
			0, // offset / 256
			4, // offset % 256
			NULL, 0,
			cacertificate + 4, certRemainingSize);

		cacheObject(0, "cacert.cer", CssmData(cacertificate,
			certRemainingSize + 3));
	}

		sw = transmitAPDU(
			CLA_STANDARD,
			INS_SELECT_FILE,
			P1_SELECT_APPLET,
			P2_SELECT_FILE,
			kJPKIAppletID, sizeof(kJPKIAppletID),
			NULL, 0);

		if (sw == 0x9000) {
			sw = transmitAPDU(
				CLA_STANDARD,
				INS_READ_BINARY,
				P1_READ_BINARY_SELECT_SHORT_EF | SHORT_EF_TOKEN_INFO,
				0, // offset % 256
				NULL, 0,
				tokenInfo, sizeof(tokenInfo));
		}

#if 1
		uint8_t cacertificate[4000];
		if (sw == 0x9000) {
			sw = transmitAPDU(
				CLA_STANDARD,
				INS_READ_BINARY,
				P1_READ_BINARY_SELECT_SHORT_EF | SHORT_EF_CA_CERTIFICATE,
				0, // offset % 256
				NULL, 0,
				cacertificate, 4);
		}

		if (sw == 0x9000) {
			size_t certRemainingSize = (cacertificate[2] << 8)
				+ cacertificate[3];
			secdebug("probe", "certRemainingSize %ld", certRemainingSize);
			sw = transmitAPDU(
				CLA_STANDARD,
				INS_READ_BINARY,
				0, // offset / 256
				4, // offset % 256
				NULL, 0,
				cacertificate + 4, certRemainingSize);
		}

		if (sw == 0x9000) {
			sw = transmitAPDU(
				CLA_STANDARD,
				INS_VERIFY,
				P1_VERIFY,
				P2_VERIFY_SELECT_SHORT_EF | SHORT_EF_USER_PASSWORD,
				NULL, 0,
				NULL, 0);
		}

		if (sw == 0x6300) {
			secdebug("probe", "unlimited user pin tries left");
			sw = 0x9000;
		} else if ((sw & 0xFFF0) == 0x63C0) {
			uint32_t tries = sw & 0x000F;
			secdebug("probe", "%lu user pin tries left", tries);
			sw = 0x9000;
		} else if (sw == 0x6984) {
			secdebug("probe", "user pin is blocked");
		}

		if (sw == 0x9000) {
			sw = transmitAPDU(
				CLA_STANDARD,
				INS_VERIFY,
				P1_VERIFY,
				P2_VERIFY_SELECT_SHORT_EF | SHORT_EF_USER_PASSWORD,
				"1234", 4,
				NULL, 0);
		}

		uint8_t certificate[4000];
		if (sw == 0x9000) {
			sw = transmitAPDU(
				CLA_STANDARD,
				INS_READ_BINARY,
				P1_READ_BINARY_SELECT_SHORT_EF | SHORT_EF_USER_CERTIFICATE,
				0, // offset % 256
				NULL, 0,
				certificate, 4);
		}

		if (sw == 0x9000) {
			size_t certRemainingSize = (certificate[2] << 8) + certificate[3];
			secdebug("probe", "certRemainingSize %ld", certRemainingSize);
			sw = transmitAPDU(
				CLA_STANDARD,
				INS_READ_BINARY,
				0, // offset / 256
				4, // offset % 256
				NULL, 0,
				certificate + 4, certRemainingSize);
		}

		if (sw == 0x9000) {
			sw = transmitAPDU(
				CLA_STANDARD,
				INS_SELECT_FILE,
				P1_SELECT_EF,
				P2_SELECT_FILE,
				kJPKI_EF_UserPrivKey, sizeof(kJPKI_EF_UserPrivKey),
				NULL, 0);
		}

		uint8_t signature[128];
		if (sw == 0x9000) {
			sw = transmitAPDU(
				CLA_APPLICATION_SPECIFIC,
				INS_COMPUTE_DIGITAL_SIGNATURE,
				P1_SIGNATURE_METHOD_PKCS1PAD,
				P2_COMPUTE_DIGITAL_SIGNATURE,
				"12345678901234567890", 20,
				signature, sizeof(signature));
		}
#endif
#endif
}


//
// Database-level ACLs
//
void JPKIToken::getOwner(AclOwnerPrototype &owner)
{
	// we don't really know (right now), so claim we're owned by PIN #0
	if (!mAclOwner)
	{
		mAclOwner.allocator(Allocator::standard());
		mAclOwner = AclFactory::PinSubject(Allocator::standard(), 0);
	}
	owner = mAclOwner;
}


void JPKIToken::getAcl(const char *tag, uint32 &count, AclEntryInfo *&acls)
{
	Allocator &alloc = Allocator::standard();
	// get pin list, then for each pin
	if (!mAclEntries)
	{
		mAclEntries.allocator(alloc);
        // Reading objects from this token requires pin1 (Strictly speaking
		// you can read the CA cert without PIN1, but we currently have now way
		// to express that distinction).
		mAclEntries.add(CssmClient::AclFactory::PinSubject(
			mAclEntries.allocator(), 1),
			AclAuthorizationSet(CSSM_ACL_AUTHORIZATION_DB_READ, 0));
        // We support PIN1 with either a passed in password
        // subject or a prompted password subject.
		mAclEntries.addPin(AclFactory::PWSubject(alloc), 1);
		mAclEntries.addPin(AclFactory::PromptPWSubject(alloc, CssmData()), 1);
	}
	count = mAclEntries.size();
	acls = mAclEntries.entries();
}


#pragma mark ---------------- JPKI Specific --------------

void JPKIToken::populate()
{
	secdebug("populate", "JPKIToken::populate() begin");
	Tokend::Relation &certRelation =
		mSchema->findRelation(CSSM_DL_DB_RECORD_X509_CERTIFICATE);
	Tokend::Relation &privateKeyRelation =
		mSchema->findRelation(CSSM_DL_DB_RECORD_PRIVATE_KEY);
	//Tokend::Relation &dataRelation =
		mSchema->findRelation(CSSM_DL_DB_RECORD_GENERIC);

	RefPointer<Tokend::Record> userCert(new JPKICertificateRecord(
		SHORT_EF_USER_CERTIFICATE, "User Certificate"));
	RefPointer<Tokend::Record> caCert(new JPKICertificateRecord(
		SHORT_EF_CA_CERTIFICATE, "CA Certificate"));

	certRelation.insertRecord(userCert);
	certRelation.insertRecord(caCert);

	RefPointer<Tokend::Record> userPrivKey(new JPKIKeyRecord(
		SHORT_EF_USER_PRIV_KEY, "User Private Key",
		privateKeyRelation.metaRecord(), true));

	privateKeyRelation.insertRecord(userPrivKey);

	userPrivKey->setAdornment(mSchema->publicKeyHashCoder().certificateKey(),
		new Tokend::LinkedRecordAdornment(userCert));

	//dataRelation.insertRecord(new JPKIBinaryFileRecord(NULL,
	//	kJPKI_EF_AttrIDInfo, "Attribute Identification Info"));

	secdebug("populate", "JPKIToken::populate() end");
}

/* arch-tag: 70C45B8A-1C88-11D9-9B46-000A9595DEEE */
