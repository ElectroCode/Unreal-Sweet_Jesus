/*
 * =================================================================
 * Filename:      m_servlist.c
 * =================================================================
 * Description:   Command /servlist: gives the list of services
 *                currently present on the IRC network.
 *                Usage:
 *                     /servlist [<nickmask>]
 *                Examples:
 *                     /servlist --> gives you the list of all services
 *                     /servlist *serv --> only those whose names end in "serv"
 *                     /servlist nickserv --> show the Nick Service only (if present)
 * =================================================================
 * Author:        AngryWolf
 * Email:         angrywolf@flashmail.com
 * =================================================================
 *
 * I accept bugreports, ideas and opinions, and if you have
 * questions, just send an email for me!
 *
 * Thank you for using my module!
 *
 * =================================================================
 * Requirements:
 * =================================================================
 *
 * o Unreal >=3.2-beta18
 * o One of the supported operating systems (see unreal32docs.html)
 *
 * =================================================================
 * Installation:
 * =================================================================
 *
 * See http://angrywolf.linktipp.org/compiling.php?lang=en
 *
 * =================================================================
 * Mirror files:
 * =================================================================
 *
 * http://angrywolf.linktipp.org/m_servlist.c [Germany]
 * http://angrywolf.uw.hu/m_servlist.c [Hungary]
 * http://angrywolf.fw.hu/m_servlist.c [Hungary]
 *
 * =================================================================
 * Changes:
 * =================================================================
 *
 * $Log: m_servlist.c,v $
 * Revision 1.3  2004/03/08 21:25:53  angrywolf
 * - Fixed some bugs that could cause crash if you compile the module
 *   statically (for example, under Windows).
 *
 * Revision 1.2  2003/12/01 18:18:43  angrywolf
 * - Replaced add_Command and del_Command with CommandAdd and CommandDel.
 *
 * Revision 1.1  2003/10/26 11:55:30  angrywolf
 * Initial revision
 *
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

extern void			sendto_one(aClient *to, char *pattern, ...);

#define MSG_SERVLIST 		"SERVLIST"
#define TOK_SERVLIST 		"SL"
#define TEXT_SERVLIST		":%s 234 %s Service %s (%s@%s) using %s %d :%s"
#define TEXT_SERVLISTEND	":%s 235 %s :End of Service listing"
#define IsParam(x)		(parc > (x) && !BadPtr(parv[(x)]))
#define IsNotParam(x)		(parc <= (x) || BadPtr(parv[(x)]))
#define DelCommand(x)		if (x) CommandDel(x); x = NULL

static Command			*AddCommand(Module *module, char *msg, char *token, iFP func);
DLLFUNC int			m_servlist(aClient *cptr, aClient *sptr, int parc, char *parv[]);

Command				*CmdServlist;

ModuleHeader MOD_HEADER(m_servlist)
  = {
	"servlist",
	"$Id: m_servlist.c,v 1.3 2004/03/08 21:25:53 angrywolf Exp $",
	"command /servlist",
	"3.2-b8-1",
	NULL 
    };

DLLFUNC int MOD_INIT(m_servlist)(ModuleInfo *modinfo)
{
	CmdServlist = AddCommand(modinfo->handle, MSG_SERVLIST, TOK_SERVLIST, m_servlist);

	if (!CmdServlist)
		return MOD_FAILED;

	return MOD_SUCCESS;
}

DLLFUNC int MOD_LOAD(m_servlist)(int module_load)
{
	return MOD_SUCCESS;
}

DLLFUNC int MOD_UNLOAD(m_servlist)(int module_unload)
{
	DelCommand(CmdServlist);

	return MOD_SUCCESS;
}

static Command *AddCommand(Module *module, char *msg, char *token, iFP func)
{
	Command *cmd;

	if (CommandExists(msg))
    	{
		config_error("Command %s already exists", msg);
		return NULL;
    	}
    	if (CommandExists(token))
	{
		config_error("Token %s already exists", token);
		return NULL;
    	}

	cmd = CommandAdd(module, msg, token, func, MAXPARA, 0);

#ifndef STATIC_LINKING
	if (ModuleGetError(module) != MODERR_NOERROR || !cmd)
#else
	if (!cmd)
#endif
	{
#ifndef STATIC_LINKING
		config_error("Error adding command %s: %s", msg,
			ModuleGetErrorStr(module));
#else
		config_error("Error adding command %s", msg);
#endif
		return NULL;
	}

	return cmd;
}

/*
 * m_servlist
 *
 *     parv[0]: sender prefix
 *
 *     Output based on TR-IRCd's /servlist
 *
 *     Once there was a support for listing Services? RFC1459 describes
 *     numerics 234 and 235 as reserved ones. Probably they are part
 *     of a non-generic feature.
 */

int m_servlist(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
	aClient		*acptr;
	char		*mask;

	mask = IsParam(1) ? parv[1] : NULL;

	for (acptr = client; acptr; acptr = acptr->next)
	{
		if (!IsPerson(acptr) || !IsServices(acptr))
			continue;
		if (mask && _match(mask, acptr->name))
			continue;

		sendto_one(sptr, TEXT_SERVLIST,
			me.name, sptr->name,
			acptr->name, acptr->user->username, GetHost(acptr),
			acptr->srvptr->name, acptr->srvptr->hopcount,
			acptr->info);
	}

	sendto_one(sptr, TEXT_SERVLISTEND,
		me.name, sptr->name,
		mask ? mask : "*");

	return 0;
}
