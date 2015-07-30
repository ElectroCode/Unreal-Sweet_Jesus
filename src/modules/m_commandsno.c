/*
 * =================================================================
 * Filename:             m_commandsno.c
 * Description:          Snomask +C: lets you see command usages.
 * Written by:           AngryWolf <angrywolf@flashmail.com>
 * Requested by:         DarKSeID
 * Documentation:        commandsno.txt (comes with the package)
 * =================================================================
 */

#include "config.h"
#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
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

typedef struct _cmdovr CmdOvr;

struct _cmdovr
{
	CmdOvr			*prev, *next;
	Cmdoverride		*ovr;
	char			*cmd;
};

extern void			sendto_one(aClient *to, char *pattern, ...);
extern void			sendto_realops(char *pattern, ...);

#define FLAG_CMD		'C'
#define DelOverride(cmd, ovr)	if (ovr && CommandExists(cmd)) CmdoverrideDel(ovr); ovr = NULL
#define DelHook(x)      	if (x) HookDel(x); x = NULL
#define DelSnomask(x)		if (x) SnomaskDel(x); x = NULL
#define MaxSize			(sizeof(mybuf) - strlen(mybuf) - 1)

static Cmdoverride		*AddOverride(char *msg, iFP cb);
static Snomask			*AddSnomask(Module *module, char flag, iFP allowed, long *mode);
static int			override_cmd(Cmdoverride *, aClient *, aClient *, int, char *[]);
static int			cb_config_test(ConfigFile *, ConfigEntry *, int, int *);
static int			cb_config_run(ConfigFile *, ConfigEntry *, int);
static int			cb_stats(aClient *sptr, char *stats);
static int			cb_config_rehash();
static int			cb_rehash_complete();
static inline void		InitConf();
static void			FreeConf();

Cmdoverride			*OvrMap, *OvrLinks;
Hook				*HookConfTest, *HookConfRun;
Hook				*HookConfRehash, *HookStats;
Hook				*HookConfRehash, *HookRehashDone;
Snomask				*SnomaskCmd;
CmdOvr				*OvrList;
char				*cmdlist, mybuf[BUFSIZE];
long				SNO_COMMAND;
static u_char			module_loaded = 0;

#ifndef STATIC_LINKING
static ModuleInfo		*MyModInfo;
 #define MyMod			MyModInfo->handle
 #define SAVE_MODINFO		MyModInfo = modinfo;
#else
 #define MyMod			NULL
 #define SAVE_MODINFO
#endif

ModuleHeader MOD_HEADER(commandsno)
  = {
	"m_commandsno",
	"$Id: m_commandsno.c,v 1.13 2004/08/10 20:15:19 angrywolf Exp $",
	"Snomask +C: lets you see command usages",
	"3.2-b8-1",
	NULL 
    };

DLLFUNC int MOD_TEST(commandsno)(ModuleInfo *modinfo)
{
	HookConfTest = HookAddEx(modinfo->handle, HOOKTYPE_CONFIGTEST, cb_config_test);
	return MOD_SUCCESS;
}

DLLFUNC int MOD_INIT(commandsno)(ModuleInfo *modinfo)
{
	SAVE_MODINFO
#ifndef STATIC_LINKING
	ModuleSetOptions(modinfo->handle, MOD_OPT_PERM);
#endif
	OvrList = NULL;
	InitConf();

	HookConfRun	= HookAddEx(modinfo->handle, HOOKTYPE_CONFIGRUN, cb_config_run);
	HookConfRehash	= HookAddEx(modinfo->handle, HOOKTYPE_REHASH, cb_config_rehash);
	HookStats	= HookAddEx(modinfo->handle, HOOKTYPE_STATS, cb_stats);
	HookRehashDone	= HookAddEx(modinfo->handle, HOOKTYPE_REHASH_COMPLETE, cb_rehash_complete);
	SnomaskCmd	= AddSnomask(modinfo->handle, FLAG_CMD, umode_allow_opers, &SNO_COMMAND);

	if (!SnomaskCmd)
		return MOD_FAILED;

        return MOD_SUCCESS;
}

DLLFUNC int MOD_LOAD(commandsno)(int module_load)
{
	cb_rehash_complete();
	return MOD_SUCCESS;
}

DLLFUNC int MOD_UNLOAD(commandsno)(int module_unload)
{
	FreeConf();

	DelHook(HookRehashDone);
	DelHook(HookStats);
	DelHook(HookConfRehash);
	DelHook(HookConfRun);
	DelHook(HookConfTest);

	return MOD_SUCCESS;
}

static inline void InitConf()
{
	cmdlist = NULL;
}

static void FreeConf()
{
	CmdOvr		*o;
	ListStruct	*next;

	for (o = OvrList; o; o = (CmdOvr *) next)
	{
		next = (ListStruct *) o->next;
		DelListItem(o, OvrList);
		DelOverride(o->cmd, o->ovr);
		MyFree(o->cmd);
		MyFree(o);
	}

	MyFree(cmdlist);
}

static int cb_config_rehash()
{
	module_loaded = 0;
	FreeConf();
	InitConf();

	return 1;
}

static int cb_rehash_complete()
{
	if (!module_loaded)
	{
		module_loaded = 1;

		if (cmdlist)
		{
			char		*cmd, *tmp, *p;
			Cmdoverride	*ovr;
			CmdOvr		*o;

			tmp = strdup(cmdlist);
			for (cmd = strtoken(&p, tmp, ","); cmd;
			    cmd = strtoken(&p, NULL, ","))
	        	{
				if (!(ovr = AddOverride(cmd, override_cmd)))
					continue;

				o = (CmdOvr *) MyMallocEx(sizeof(CmdOvr));
				o->ovr = ovr;
				o->cmd = strdup(cmd);
				AddListItem(o, OvrList);
			}
			MyFree(tmp);
		}
	}

	return 0;
}

static int cb_config_test(ConfigFile *cf, ConfigEntry *ce, int type, int *errs)
{
	int errors = 0;

	if (type != CONFIG_SET)
		return 0;

	if (!strcmp(ce->ce_varname, "notify-commands"))
	{
		if (!ce->ce_vardata)
		{
			config_error("%s:%i: set::%s without contents",
					ce->ce_fileptr->cf_filename,
					ce->ce_varlinenum, ce->ce_varname);
			errors++;
		}

		*errs = errors;
		return errors ? -1 : 1;
	}

	return 0;
}

static int cb_config_run(ConfigFile *cf, ConfigEntry *ce, int type)
{
	if (type != CONFIG_SET)
		return 0;

	if (!strcmp(ce->ce_varname, "notify-commands"))
	{
		if (!cmdlist)
			cmdlist = strdup(ce->ce_vardata);

		return 1;		
	}

	return 0;
}

static int cb_stats(aClient *sptr, char *stats)
{
	if (*stats == 'S')
	{
		sendto_one(sptr, ":%s %i %s :notify-commands: %s",
			me.name, RPL_TEXT, sptr->name, cmdlist ? cmdlist : "<none>");
	}

        return 0;
}

Cmdoverride *AddOverride(char *msg, iFP cb)
{
	Cmdoverride *ovr = CmdoverrideAdd(MyMod, msg, cb);

#ifndef STATIC_LINKING
        if (ModuleGetError(MyMod) != MODERR_NOERROR || !ovr)
#else
        if (!ovr)
#endif
	{
#ifndef STATIC_LINKING
		config_error("Error replacing command %s when loading module %s: %s",
			msg, MOD_HEADER(commandsno).name, ModuleGetErrorStr(MyMod));
#else
		config_error("Error replacing command %s when loading module %s",
			msg, MOD_HEADER(commandsno).name);
#endif
		return NULL;
	}

	return ovr;
}

static Snomask *AddSnomask(Module *module, char flag, iFP allowed, long *mode)
{
	Snomask *s;

	*mode = 0;
	s = SnomaskAdd(module, flag, allowed, mode);

#ifndef STATIC_LINKING
	if ((ModuleGetError(module) != MODERR_NOERROR) || !s)
#else
	if (!s)
#endif
	{
#ifndef STATIC_LINKING
		sendto_realops("Error adding snomask %c: %s",
			flag, ModuleGetErrorStr(module));
#else
                sendto_realops("Error adding snomask %c",
			flag);
#endif
		return NULL;
	}

	return s;
}

static int override_cmd(Cmdoverride *ovr, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
	if (IsPerson(sptr))
	{
		int i;

		mybuf[0] = 0;

		for (i = 1; i < parc; i++)
		{
			if (mybuf[0])
				strncat(mybuf, " ", MaxSize);
			strncat(mybuf, parv[i], MaxSize);
		}

		if (!mybuf[0])
			strcpy(mybuf, "<none>");

		sendto_snomask_global(SNO_COMMAND,
			"%s (%s@%s) used command %s (params: %s)",
			sptr->name, sptr->user->username, sptr->user->realhost,
			ovr->command->cmd, mybuf);
	}

	return CallCmdoverride(ovr, cptr, sptr, parc, parv);
}
