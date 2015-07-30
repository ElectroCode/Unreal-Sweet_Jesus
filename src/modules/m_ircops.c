/*
 *   m_ircops - /IRCOPS command that lists IRC Operators
 *   (C) Copyright 2004-2005 Syzop <syzop@vulnscan.org>
 *   (C) Copyright 2003-2004 AngryWolf <angrywolf@flashmail.com>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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
#endif
#include <fcntl.h>
#include "h.h"
#ifdef STRIPBADWORDS
#include "badwords.h"
#endif
#ifdef _WIN32
#include "version.h"
#endif

typedef struct
{
	long *umode;
	char *text;
} oflag;

/*
 * Ultimate uses numerics 386 and 387 for RPL_IRCOPS and RPL_ENDOFIRCOPS,
 * but these numerics are RPL_QLIST and RPL_ENDOFQLIST in UnrealIRCd
 * (numeric conflict). I had to choose other numerics.
 */

#define RPL_IRCOPS        337
#define RPL_ENDOFIRCOPS   338
#define MSG_IRCOPS        "IRCOPS"
#define TOK_IRCOPS        NULL
#define IsAway(x)         (x)->user->away

#if !defined(IsSkoAdmin)
#define IsSkoAdmin(sptr)  (IsAdmin(sptr) || IsNetAdmin(sptr) || IsSAdmin(sptr) || IsCoAdmin(sptr))
#endif

static int m_ircops(aClient *cptr, aClient *sptr, int parc, char *parv[]);

static oflag otypes[7];

ModuleHeader MOD_HEADER(m_ircops)
  = {
	"ircops",
	"v3.6",
	"/IRCOPS command that lists IRC Operators",
	"3.2-b8-1",
	NULL 
    };

DLLFUNC int MOD_INIT(m_ircops)(ModuleInfo *modinfo)
{
	otypes[0].umode = &UMODE_NETADMIN;
	otypes[0].text = "a Network Administrator";
	otypes[1].umode = &UMODE_SADMIN;
	otypes[1].text = "a Services Administrator";
	otypes[2].umode = &UMODE_ADMIN;
	otypes[2].text = "a Server Administrator";
	otypes[3].umode = &UMODE_COADMIN;
	otypes[3].text = "a Co Administrator";
	otypes[4].umode = &UMODE_OPER;
	otypes[4].text = "an IRC Operator";
	otypes[5].umode = &UMODE_LOCOP;
	otypes[5].text = "a Local Operator";
	otypes[6].umode = NULL;
	otypes[6].text = NULL;

	if (CommandExists(MSG_IRCOPS))
	{
		config_error("Command " MSG_IRCOPS " already exists");
		return MOD_FAILED;
	}
	CommandAdd(modinfo->handle, MSG_IRCOPS, TOK_IRCOPS, m_ircops, MAXPARA, M_USER);

	if (ModuleGetError(modinfo->handle) != MODERR_NOERROR)
	{
		config_error("Error adding command " MSG_IRCOPS ": %s",
			ModuleGetErrorStr(modinfo->handle));
		return MOD_FAILED;
	}

	return MOD_SUCCESS;
}

DLLFUNC int MOD_LOAD(m_ircops)(int module_load)
{
	return MOD_SUCCESS;
}

DLLFUNC int MOD_UNLOAD(m_ircops)(int module_unload)
{
	return MOD_SUCCESS;
}


static char *find_otype(long umodes)
{
	unsigned int i;
	
	for (i = 0; otypes[i].umode; i++)
		if (*otypes[i].umode & umodes)
			return otypes[i].text;

	return "an unknown operator";
}

/*
 * m_ircops
 *
 *     parv[0]: sender prefix
 *
 *     Originally comes from TR-IRCD, but I changed it in several places.
 *     In addition, I didn't like to display network name. In addition,
 *     instead of realname, servername is shown. See the original
 *     header below.
 */

/************************************************************************
 * IRC - Internet Relay Chat, modules/m_ircops.c
 *
 *   Copyright (C) 2000-2002 TR-IRCD Development
 *
 *   Copyright (C) 1990 Jarkko Oikarinen and
 *                      University of Oulu, Co Center
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

static int m_ircops(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
aClient *acptr;
char buf[BUFSIZE];
int opers = 0, admins = 0, globs = 0, aways = 0;

	for (acptr = client; acptr; acptr = acptr->next)
	{
		/* List only real IRC Operators */
		if (IsULine(acptr) || !IsPerson(acptr) || !IsAnOper(acptr))
			continue;
		/* Don't list +H users */
		if (!IsAnOper(sptr) && IsHideOper(acptr))
			continue;

		sendto_one(sptr, ":%s %d %s :\2%s\2 is %s on %s" "%s",
			me.name, RPL_IRCOPS, sptr->name,
			acptr->name,
			find_otype(acptr->umodes),
			acptr->user->server,
			(IsAway(acptr) ? " [Away]" : IsHelpOp(acptr) ? " [Helpop]" : ""));

		if (IsAway(acptr))
			aways++;
		else if (IsSkoAdmin(acptr))
			admins++;
		else
			opers++;

	}

	globs = opers + admins + aways;

	sprintf(buf,
		"Total: \2%d\2 IRCOP%s online - \2%d\2 Admin%s, \2%d\2 Oper%s and \2%d\2 Away",
		globs, (globs) > 1 ? "s" : "", admins, admins > 1 ? "s" : "",
		opers, opers > 1 ? "s" : "", aways);

	sendto_one(sptr, ":%s %d %s :%s", me.name, RPL_IRCOPS, sptr->name, buf);
	sendto_one(sptr, ":%s %d %s :End of /IRCOPS list", me.name, RPL_ENDOFIRCOPS, sptr->name);

	return 0;
}
