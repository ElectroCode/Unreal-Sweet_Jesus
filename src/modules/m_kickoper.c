/*
 * =================================================================
 * Filename:          m_kickoper.c
 * Description:       Hooks Umode and checks if Oper uses /mode -o
 * Author:            Cards <cards@420-hightimes.com
 * Version: 1.0
 * Documentation:    
 *		This Module hooks UMODE_CHANGE and detects if an oper deops
 * themselves.  If so, it removed them from all AdminOnly and 
 * OperOnly Channels.  Tested on Win32.
 * =================================================================
 */

#include "config.h"
#include "struct.h"
#include "common.h"
#include "channel.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "proto.h"
#include "channel.h"
#include <time.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <io.h>
#endif
#include <fcntl.h>
#include "h.h"
#ifdef STRIPBADWORDS
#include "badwords.h"
#endif
#ifdef _WIN32
#include "version.h"
#endif

extern void             sendto_one(aClient *to, char *pattern, ...);
DLLFUNC char *check_oper(aClient *sptr, long oldflags, long newflags);

//Hook *HookDeop = NULL;
#define DelCommand(x)	if (x) CommandDel(x); x = NULL


ModuleHeader MOD_HEADER(m_kickoper)
  = {
	"check_oper",
	"$Id: m_checkoper.c,v 1.1 2012/07/13 cards",
	"hook UMODE",
	"3.2-b8-1",
	NULL 
    };

DLLFUNC int MOD_INIT(m_kickoper)(ModuleInfo *modinfo)
{
	HookAddPCharEx(modinfo->handle, HOOKTYPE_UMODE_CHANGE, check_oper);
        return MOD_SUCCESS;
}

DLLFUNC int MOD_LOAD(m_kickoper)(int module_load)
{
	return MOD_SUCCESS;
}

DLLFUNC int MOD_UNLOAD(m_kickoper)(int module_unload)
{
	//DelCommand(HookDeop);
	return MOD_SUCCESS;
}

/*  This is the command to execute on Umode2
UMODE_SERVNOTICE

*/
DLLFUNC char *check_oper(aClient *sptr, long oldflags, long newflags)
{
	aClient *cptr;
	Membership *lp;
	aChannel *chptr;
	aChannel *kchan[50];  // Max 50 channels.  Not really needing this many, but they are opers
	int count = 0;
	int c;
	if (oldflags & UMODE_OPER){
		if (newflags & UMODE_OPER) {
			return HOOK_CONTINUE;
		}

		for (lp = sptr->user->channel; lp; lp = lp->next)
			{
				chptr = lp->chptr;
				if (chptr->mode.mode & MODE_OPERONLY || chptr->mode.mode & MODE_ADMONLY)
				{
					//Build list of channels the user is on that they need to be removed from.  We cannot remove here due to read-after-free issues
						kchan[count] = chptr;
						++count;
				}
				
			}
		for (c=0; c<count; c++) { 
			//send kick to client and remove them from channel list
			sendnotice(sptr, "You are being removed from the Oper/Admin Only Channels");
			sendto_prefix_one(sptr, sptr, ":%s KICK %s %s :You are no longer an oper!", me.name, kchan[c]->chname, sptr->name);
			remove_user_from_channel(sptr, kchan[c]);
		} 
		/* Remove Snomasks +s -All */
		sptr->umodes &= ~UMODE_SERVNOTICE;
		sptr->user->snomask = 0;
		return HOOK_CONTINUE;
	} else {
		return HOOK_CONTINUE;
	}
return HOOK_CONTINUE;
}