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
 *  JPKIError.h
 *  TokendMuscle
 */

#ifndef _JPKIERROR_H_
#define _JPKIERROR_H_

#include "SCardError.h"

/* '66XX'	Security-related issues. */

/** Abnormality in Security environment. */
#define JPKI_BAD_SECURITY_ENV                0x66F1

/** Abnormality with IEF specified by Security environment. */
#define JPKI_BAD_EF_IN_SECURITY_ENV          0x66F2


/* Normally this is: Referenced data invalidated. */
/** Authentication method invalidated (blocked). */
#define JPKI_AUTHENTICATION_BLOCKED          0x6984


class JPKIError : public Tokend::SCardError
{
protected:
    JPKIError(uint16_t sw);
public:
	OSStatus osStatus() const;
    virtual const char *what () const throw ();

    static void check(uint16_t sw)	{ if (sw != SCARD_SUCCESS) throwMe(sw); }
    static void throwMe(uint16_t sw) __attribute__((noreturn));
    
protected:
    IFDEBUG(void debugDiagnose(const void *id) const;)
    IFDEBUG(static const char *errorstr(uint16_t sw);)
};

#endif /* !_JPKIERROR_H_ */


/* arch-tag: 6FFD641F-1C88-11D9-917B-000A9595DEEE */
