/** 
 * Debug support
 */

#ifndef _COMMON_H_
#define _COMMON_H_

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/afc.h>

#include "device.h"
#include "file.h"
#include "afc.h"
#include "backup.h"
#include "backup_file.h"
#include "lockdown.h"
#include "mbdb.h"

#include "hell.h"

int jailbreak_device(const char *uuid);

#undef DEBUG

#define DEBUG(x...) \
 	printf("[debug] "), printf(x)

#define ERROR(x...) \
 	do { printf("[error] "), printf(x), exit(-1); } while(0);

#define WARN(x...) \
 	printf("[warn] "), printf(x)

#endif
