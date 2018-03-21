//----------------------------------------------------------------------------------------
// mechtype.h
//
// This source code is licensed under the GPL v2 license found in the
// LICENSE.txt file in the root directory of this source tree.
//
// Written by Benton Stark (benton.stark@gmail.com)
// Sept. 7, 2016
//----------------------------------------------------------------------------------------

#ifndef _MECHTYPE_H
#define _MECHTYPE_H


#include "oasis/cryptoki.h"

char* __mechanism_type_to_str(CK_MECHANISM_TYPE mech_type);


#endif // #ifndef MECHTYPE_H
