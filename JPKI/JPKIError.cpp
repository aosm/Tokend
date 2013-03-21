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
 *  JPKIError.cpp
 *  TokendMuscle
 */

#include "JPKIError.h"

#include <Security/cssmerr.h>

//
// JPKIError exceptions
//
JPKIError::JPKIError(uint16_t sw) : SCardError(sw)
{
	IFDEBUG(debugDiagnose(this));
}

OSStatus JPKIError::osStatus() const
{
    switch (statusWord)
    {
	case JPKI_BAD_SECURITY_ENV:
	case JPKI_BAD_EF_IN_SECURITY_ENV:
        return CSSM_ERRCODE_INTERNAL_ERROR;
	case JPKI_AUTHENTICATION_BLOCKED:
        return CSSM_ERRCODE_OPERATION_AUTH_DENIED;
    default:
        return SCardError::osStatus();
    }
}

const char *JPKIError::what() const throw ()
{ return "JPKI error"; }

void JPKIError::throwMe(uint16_t sw)
{ throw JPKIError(sw); }

#if !defined(NDEBUG)

void JPKIError::debugDiagnose(const void *id) const
{
    secdebug("exception", "%p JPKIError %s (%04hX)",
             id, errorstr(statusWord), statusWord);
}

const char *JPKIError::errorstr(uint16_t sw)
{
	switch (sw)
	{
	case JPKI_BAD_SECURITY_ENV:
		return "Abnormality in Security environment.";
	case JPKI_BAD_EF_IN_SECURITY_ENV:
		return "Abnormality with IEF specified by Security environment.";
	case JPKI_AUTHENTICATION_BLOCKED:
		return "Authentication method invalidated (blocked).";
	default:
		return SCardError::errorstr(sw);
	}
}

#endif //NDEBUG


/* arch-tag: 6FE27D1B-1C88-11D9-9BE0-000A9595DEEE */
