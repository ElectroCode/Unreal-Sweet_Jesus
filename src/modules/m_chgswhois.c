/*
 * =================================================================
 * Filename:		m_chgswhois.c
 * Description:         Commands /chgswhois & /setswhois
 * Author:		AngryWolf <angrywolf@flashmail.com>
 * Requested by:        alenor
 * Documentation:       m_chgswhois.txt (comes with the package)
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

extern void		sendto_one(aClient *to, char *pattern, ...);
extern void		sendto_serv_butone_token(aClient *one, char *prefix, char *command, char *token, char *pattern, ...);

#define MSG_CHGSWHOIS 	"CHGSWHOIS"
#define TOK_CHGSWHOIS 	"CSW"
#define MSG_SETSWHOIS 	"SETSWHOIS"
#define TOK_SETSWHOIS 	"SSW"
#define DelCommand(x)	if (x) CommandDel(x); x = NULL
#define IsParam(x)      (parc > (x) && !BadPtr(parv[(x)]))
#define IsNotParam(x)   (parc <= (x) || BadPtr(parv[(x)]))

static Command		*AddCommand(Module *module, char *msg, char *token, iFP func, int params);
static int		m_chgswhois(aClient *cptr, aClient *sptr, int parc, char *parv[]);
static int		m_setswhois(aClient *cptr, aClient *sptr, int parc, char *parv[]);

Command			*CmdChgswhois, *CmdSetswhois;

ModuleHeader MOD_HEADER(m_chgswhois)
  = {
	"m_chgswhois",
	"$Id: m_chgswhois.c,v 1.3 2004/04/24 18:37:27 angrywolf Exp $",
	"commands /chgswhois & /setswhois",
	"3.2-b8-1",
	NULL 
    };

DLLFUNC int MOD_INIT(m_chgswhois)(ModuleInfo *modinfo)
{
	CmdChgswhois = AddCommand(modinfo->handle, MSG_CHGSWHOIS, TOK_CHGSWHOIS, m_chgswhois, 2);
	CmdSetswhois = AddCommand(modinfo->handle, MSG_SETSWHOIS, TOK_SETSWHOIS, m_setswhois, 1);

	if (!CmdChgswhois || !CmdSetswhois)
		return MOD_FAILED;

	return MOD_SUCCESS;
}

DLLFUNC int MOD_LOAD(m_chgswhois)(int module_load)
{
	return MOD_SUCCESS;
}

DLLFUNC int MOD_UNLOAD(m_chgswhois)(int module_unload)
{
	DelCommand(CmdChgswhois);
	DelCommand(CmdSetswhois);

	return MOD_SUCCESS;
}

static Command *AddCommand(Module *module, char *msg, char *token, iFP func, int params)
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

	cmd = CommandAdd(module, msg, token, func, params, 0);

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
** m_chgswhois
**      parv[0] = sender prefix
**      parv[1] = nickname
**      parv[2] = swhois text
*/

static int m_chgswhois(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
	aClient *acptr;

	if (MyClient(sptr) && !IsAnOper(sptr))
	{
		sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
		return 0;
	}
	if (IsNotParam(1))
	{
		sendnotice(sptr, "Usage: /chgswhois <nick> [<text>]");
		return 0;
	}
	if (!(acptr = find_person(parv[1], NULL)))
	{
		sendto_one(sptr, err_str(ERR_NOSUCHNICK),
			me.name, sptr->name, parv[1]);
		return 0;
	}

	if (acptr->user->swhois)
		MyFree(acptr->user->swhois);

	if (IsParam(2))
	{
		acptr->user->swhois = strdup(parv[2]);

		sendto_snomask(SNO_EYES,
			"%s changed the SWHOIS of %s (%s@%s) to be %s",
			sptr->name, acptr->name, acptr->user->username,
			acptr->user->realhost, parv[2]);
		ircd_log(LOG_CHGCMDS,
			"CHGSWHOIS: %s changed the SWHOIS of %s (%s@%s) to be %s", 
			sptr->name, acptr->name, acptr->user->username,
			acptr->user->realhost, parv[2]);
	}
	else
	{
		acptr->user->swhois = NULL;

		sendto_snomask(SNO_EYES,
			"%s cleared the SWHOIS of %s (%s@%s)",
			sptr->name, acptr->name, acptr->user->username,
			acptr->user->realhost);
		ircd_log(LOG_CHGCMDS,
			"CHGSWHOIS: %s cleared the SWHOIS of %s (%s@%s)", 
			sptr->name, acptr->name, acptr->user->username,
			acptr->user->realhost);
	}

        sendto_serv_butone_token(NULL, sptr->name,
		MSG_CHGSWHOIS, TOK_CHGSWHOIS, "%s :%s",
		parv[1], IsParam(2) ? parv[2] : "");

	return 0;
}

static int m_setswhois(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
	if (MyClient(sptr) && !IsAnOper(sptr))
	{
		sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
		return 0;
	}

	if (sptr->user->swhois)
		MyFree(sptr->user->swhois);

	if (IsParam(1))
	{
		sptr->user->swhois = strdup(parv[1]);

		if (MyClient(sptr))
			sendnotice(sptr, "*** Your SWHOIS is now set to be %s",
				parv[1]);
	}
	else
	{
		sptr->user->swhois = NULL;

		if (MyClient(sptr))
			sendnotice(sptr, "*** Your SWHOIS is now cleared");
	}

        sendto_serv_butone_token(NULL, sptr->name,
		MSG_SETSWHOIS, TOK_SETSWHOIS, "%s",
		IsParam(1) ? parv[1] : "");

	return 0;
}
