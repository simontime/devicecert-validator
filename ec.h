// Copyright 2007,2008  Segher Boessenkool  <segher@kernel.crashing.org>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
// obtained from http://git.infradead.org/?p=users/segher/wii.git

#ifndef EC_H
#define EC_H

#include <string.h>
#include <stdio.h>

#include "types.h"

int check_ecdsa(u8 *Q, u8 *R, u8 *S, u8 *hash);

#endif