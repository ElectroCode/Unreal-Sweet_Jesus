/*
 * this module adds a new chanmode +B
 * syntax: /mode #chan +B #otherchan
 * banned users are transferred to #otherchan
 *
 *
 *  			<DukePyrolator@FantasyIRC.net>
 */

/* Changes:
 *
 * v1.1	changed modversion in MOD_HEADER from "3.2.2" to "3.2-b8-1"
 * 
 */ 

#include "config.h"
#include "struct.h"
#include "common.h"
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
#include <version.h>
#endif
#include <fcntl.h>
#include "h.h"


ModuleHeader MOD_HEADER(m_banlink)
  = {
	"m_banlink",	/* Name of module */
	"$Id: m_banlink.c, v1.1 2004/11/21 DukePyrolator Exp $", /* Version */
	"new channelmode +B <#chan>", /* Short description of module */
	"3.2-b8-1",
	NULL,
    };

Cmode_t EXTCMODE_BANLINK = 0L; /* Just for testing */

int mode_is_ok(aClient *sptr, aChannel *chptr, char *para, int checkt, int what);
CmodeParam * mode_put_param(CmodeParam *lst, char *para);
char *mode_get_param(CmodeParam *lst);
char *mode_conv_param(char *param);
void mode_free_param(CmodeParam *lst);
CmodeParam *mode_dup_struct(CmodeParam *src);
int mode_sjoin_check(aChannel *chptr, CmodeParam *ourx, CmodeParam *theirx);
CmodeParam *mode_dup_struct(CmodeParam *src);
Hook *HookJoin = NULL;
static int cb_join(aClient *sptr, aChannel *chptr, char *parv[]);

typedef struct {
	EXTCM_PAR_HEADER
	char val[64];
} aModeB;


Cmode *ModeBANLINK = NULL;


DLLFUNC int MOD_INIT(m_banlink)(ModuleInfo *modinfo)
{
	CmodeInfo req;
	ModuleSetOptions(modinfo->handle, MOD_OPT_PERM);

	memset(&req, 0, sizeof(req));
	req.paracount = 1;
	req.is_ok = mode_is_ok;
	req.put_param = mode_put_param;
	req.get_param = mode_get_param;
	req.free_param = mode_free_param;
	req.sjoin_check = mode_sjoin_check;
	req.conv_param = mode_conv_param;
	req.dup_struct = mode_dup_struct;
	req.flag = 'B';
	ModeBANLINK = CmodeAdd(modinfo->handle, req, &EXTCMODE_BANLINK);

	HookJoin	= HookAddEx(modinfo->handle, HOOKTYPE_PRE_LOCAL_JOIN, cb_join);

	return MOD_SUCCESS;
}

DLLFUNC int MOD_LOAD(m_banlink)(int module_load)
{
	return MOD_SUCCESS;
}


DLLFUNC int MOD_UNLOAD(m_banlink)(int module_unload)
{
	return MOD_FAILED;
}

int mode_is_ok(aClient *sptr, aChannel *chptr, char *para, int checkt, int what)
{
	if ((checkt == EXCHK_ACCESS) || (checkt == EXCHK_ACCESS_ERR))
	{
		if (!is_chanowner(sptr, chptr))
		{
			if (checkt == EXCHK_ACCESS_ERR)
				sendto_one(sptr, err_str(ERR_CHANOWNPRIVNEEDED), me.name, sptr->name, chptr->chname);
			return 0;
		} else {
			return 1;
		}
	} else
	if (checkt == EXCHK_PARAM)
	{
		if (!para) 
		{
			sendto_one(sptr, ":%s NOTICE %s :chanmode +B requires a channel as parameter", me.name, sptr->name);
			return 0;
		}
		if (strlen(para) > 32) 
		{
                        sendto_one(sptr, ":%s NOTICE %s :invalid parameter for chanmode +B", me.name, sptr->name);
                        return 0;
		}
		if (!IsChannelName(para))
		{
			sendto_one(sptr, ":%s NOTICE %s :invalid parameter for chanmode +B", me.name, sptr->name);
			return 0;
		}
		return 1;
	}
	return 0;
}

CmodeParam * mode_put_param(CmodeParam *Bpara, char *para)
{
	aModeB *r = (aModeB *)Bpara;
	if (!r)
	{
		/* Need to create one */
		r = (aModeB *)malloc(sizeof(aModeB));
		memset(r, 0, sizeof(aModeB));
		r->flag = 'B';
	}
	snprintf(r->val,33, "%s",para);
	return (CmodeParam *)r;
}

char *mode_get_param(CmodeParam *ypara)
{
	aModeB *r = (aModeB *)ypara;

	if (!r) 
		return NULL;

	return r->val;
}

char *mode_conv_param(char *param)
{
    clean_channelname(param);
    return param;
}


void mode_free_param(CmodeParam *ypara)
{
	aModeB *r = (aModeB *)ypara;
	free(r);
}

CmodeParam *mode_dup_struct(CmodeParam *src)
{
	aModeB *n = (aModeB *)malloc(sizeof(aModeB));
	memcpy(n, src, sizeof(aModeB));
	return (CmodeParam *)n;
}

int mode_sjoin_check(aChannel *chptr, CmodeParam *ourx, CmodeParam *theirx)
{
aModeB *our = (aModeB *)ourx;
aModeB *their = (aModeB *)theirx;

	if (our->val == their->val)
		return EXSJ_SAME;
	if (our->val > their->val)
		return EXSJ_WEWON;
	else
		return EXSJ_THEYWON;
}

static int cb_join(aClient *sptr, aChannel *chptr, char *parv[]) {
    aModeB	*p = NULL;	

    
    if (!can_join(sptr, sptr, chptr, NULL, NULL, parv))  /* test for operoverride or invite */
    {
	return HOOK_CONTINUE;
    }
 
    if (chptr->mode.extmode & EXTCMODE_BANLINK) /* mode +B set? */
    {
        if (is_banned(sptr, chptr, BANCHK_JOIN))  /* user is banned? */
	{
	    p = (aModeB *) extcmode_get_struct(chptr->mode.extmodeparam, 'B');
	    if (p && p->val)
	    { 

                sendto_one(sptr, ":%s 470 %s %s (you are banned) transferring you to %s", 
				    me.name, sptr->name, chptr->chname, p->val);

                parv[0] = sptr->name;
                parv[1] = p->val;
		do_join(sptr, sptr, 2, parv);

		return HOOK_DENY;
	    }
	}
    }
    return HOOK_CONTINUE;
}
