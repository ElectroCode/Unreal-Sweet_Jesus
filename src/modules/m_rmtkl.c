/*
 *   m_rmtkl - /RMTKL command to remove *lines matching certain patterns.
 *   (C) Copyright 2004-2006 Syzop <syzop@vulnscan.org>
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

#ifndef MODVAR
 #error "requires Unreal3.2.2"
#endif

#define IsParam(x)      (parc > (x) && !BadPtr(parv[(x)]))
#define IsNotParam(x)   (parc <= (x) || BadPtr(parv[(x)]))
#define DelCommand(x)	if (x) CommandDel(x); x = NULL

/* Externs */
#if !defined(UNREAL_VERSION_MINOR)
extern aTKline		*tkl_del_line(aTKline *tkl);
extern MODVAR int	tkl_hash(char c);
extern MODVAR aTKline	*tklines[TKLISTLEN];
#endif

/* Forward declarations */
DLLFUNC int m_rmtkl(aClient *cptr, aClient *sptr, int parc, char *parv[]);

ModuleHeader MOD_HEADER(m_rmtkl)
  = {
	"rmtkl",
	"v3.6",
	"/RMTKL oper command to remove *lines",
	"3.2-b8-1",
	NULL 
    };


DLLFUNC int MOD_INIT(m_rmtkl)(ModuleInfo *modinfo)
{
	if (!CommandAdd(modinfo->handle, "RMTKL", NULL, m_rmtkl, 3, 0) ||
	    (ModuleGetError(modinfo->handle) != MODERR_NOERROR))
	{
		config_error("Error adding command RMTKL: %s",
			ModuleGetErrorStr(modinfo->handle));
		return MOD_FAILED;
	}

	return MOD_SUCCESS;
}

DLLFUNC int MOD_LOAD(m_rmtkl)(int module_load)
{
	return MOD_SUCCESS;
}

DLLFUNC int MOD_UNLOAD(m_rmtkl)(int module_unload)
{
	return MOD_SUCCESS;
}

#if !defined(UNREAL_VERSION_MINOR)
/*
 * =================================================================
 * tkl_check_local_remove_shun:
 *     Copied from src/s_kline.c (because it's declared statically,
 *     but I want to use it).
 * =================================================================
 */

/* NOTE OF SYZOP: No longer used for Unreal 3.2.4 and above */
static void tkl_check_local_remove_shun(aTKline *tmp)
{
long i1, i;
char *chost, *cname, *cip;
int  is_ip;
aClient *acptr;

	for (i1 = 0; i1 <= 5; i1++)
	{
		for (i = 0; i <= LastSlot; ++i)
		{
			if ((acptr = local[i]))
				if (MyClient(acptr) && IsShunned(acptr))
				{
					chost = acptr->sockhost;
					cname = acptr->user->username;

	
					cip = GetIP(acptr);

					if (!(*tmp->hostmask < '0') && (*tmp->hostmask > '9'))
						is_ip = 1;
					else
						is_ip = 0;

					if (is_ip ==
					    0 ? (!match(tmp->hostmask,
					    chost)
					    && !match(tmp->usermask,
					    cname)) : (!match(tmp->
					    hostmask, chost)
					    || !match(tmp->hostmask,
					    cip))
					    && !match(tmp->usermask,
					    cname))
					{
						ClearShunned(acptr);
#ifdef SHUN_NOTICES
						sendto_one(acptr,
						    ":%s NOTICE %s :*** You are no longer shunned",
						    me.name,
						    acptr->name);
#endif
					}
				}
		}
	}
}
#endif /* <3.2.4 */

/*
 * =================================================================
 * my_tkl_del_line:
 *     Modified version of tkl_del_line (from src/s_kline.c),
 *     because using loops is unnecessary here). Also, I don't
 *     delete any spamfilter entries with this module either.
 * =================================================================
 */
void my_tkl_del_line(aTKline *p, int tklindex)
{
	MyFree(p->hostmask);
	MyFree(p->reason);
	MyFree(p->setby);
	if ((p->type & TKL_KILL || p->type & TKL_ZAP || p->type & TKL_SHUN)
	    && p->ptr.netmask)
		MyFree(p->ptr.netmask);
	DelListItem(p, tklines[tklindex]);
	MyFree(p);
}

/*
 * =================================================================
 * dumpit:
 *     Dump a NULL-terminated array of strings to user sptr using
 *     the numeric rplnum, and then return 0.
 *     (Taken from DarkFire IRCd)
 * =================================================================
 */

static int dumpit(aClient *sptr, char **p)
{
        for (; *p != NULL; p++)
                sendto_one(sptr, ":%s %03d %s :%s",
                        me.name, RPL_TEXT, sptr->name, *p);
        /* let user take 8 seconds to read it! */
        sptr->since += 8;
        return 0;
}

/* help for /rmtkl command */

static char *rmtkl_help[] =
{
	"*** \002Help on /rmtkl\002 *** ",
	"COMMAND - Removes all TKLs matching the given conditions from the",
	"local server or the IRC Network depending on it's a global ban or not.",
	"With this command you can remove any type of TKLs (including K:Line",
	"G:Line, Z:Line, Global Z:Line and Shun).",
	"Syntax:",
	"    \002/rmtkl\002 type user@host [comment]",
	"The type field may contain any number of the following characters:",
	"    K, z, G, Z, q, Q and *",
	"    (asterix includes every types but q & Q).",
	"The user@host field is a wildcard mask to match an user@host which",
        "    a ban was set on.",
	"The comment field is also wildcard mask that you can match the",
	"    text of the reason for a ban.",
	"Examples:",
	"    - \002/rmtkl * *\002",
	"        [remove all TKLs but q and Q lines]",
	"    - \002/rmtkl GZ *@*.mx\002",
	"        [remove all Mexican G/Z:Lines]",
	"    - \002/rmtkl * * *Zombie*\002",
	"        [remove all non-nick bans having Zombie in their reasons]",
	"*** \002End of help\002 ***",
	NULL
};

// =================================================================
// Array of TKL types
// =================================================================

typedef struct _tkl_type TKLType;

struct _tkl_type
{
	int	type;
	char	flag;
	char	*txt;
	u_long	oflag;
};

TKLType tkl_types[] =
{
	{ TKL_KILL,			'K',	"K:Line",		OFLAG_KLINE	},
	{ TKL_ZAP,			'z',	"Z:Line",		OFLAG_ZLINE	},
	{ TKL_KILL | TKL_GLOBAL,	'G',	"G:Line",		OFLAG_TKL	},
	{ TKL_ZAP | TKL_GLOBAL,		'Z',	"Global Z:Line",	OFLAG_GZL	},
	{ TKL_SHUN | TKL_GLOBAL,	's',	"Shun",			OFLAG_TKL	},
	{ TKL_NICK,			'q',	"Q:Line",		OFLAG_TKL	},
	{ TKL_NICK | TKL_GLOBAL,	'Q',	"Global Q:Line",	OFLAG_TKL	},
	{ 0,				0,	"Unknown *:Line",	0		},
};

static TKLType *find_TKLType_by_type(int type)
{
	TKLType *t;

	for (t = tkl_types; t->type; t++)
		if (t->type == type)
			break;

	return t;
}

static TKLType *find_TKLType_by_flag(char flag)
{
	TKLType *t;

	for (t = tkl_types; t->type; t++)
		if (t->flag == flag)
			break;

	return t;
}

/*
 * =================================================================
 * m_rmtkl -- Remove all matching TKLs from the network
 *     parv[0] = sender prefix
 *     parv[1] = ban types
 *     parv[2] = userhost mask
 *     parv[3] = comment mask (optional)
 * =================================================================
 */

DLLFUNC int m_rmtkl(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
aTKline *tk, *next = NULL;
TKLType *tkltype;
char *types, *uhmask, *cmask, *p;
char gmt[256], flag;
int tklindex;

	if (!IsULine(sptr) && !(IsPerson(sptr) && IsAnOper(sptr)))
	{
		sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
		return -1;
	}

	if (IsNotParam(1))
		return dumpit(sptr, rmtkl_help);

	if (IsNotParam(2))
	{
		sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "RMTKL");
		sendnotice(sptr, "Type '/RMTKL' for help");
		return 0;
	}

	types	= parv[1];
	uhmask	= parv[2];
	cmask	= IsParam(3) ? parv[3] : NULL;

	/* I don't add 'q' and 'Q' here. They are different. */
	if (strchr(types, '*'))
		types = "KzGZs";

	/* check access */
	if (!IsULine(sptr))
		for (p = types; *p; p++)
		{
			tkltype = find_TKLType_by_flag(*p);
			if (!tkltype->type)
				continue;
			if (((tkltype->type & TKL_GLOBAL) && !IsOper(sptr))
			    || !(sptr->oflag & tkltype->oflag))
			{
				sendto_one(sptr, err_str(ERR_NOPRIVILEGES),
					me.name, parv[0]);
				return -1;
			}
		}

	for (tkltype = tkl_types; tkltype->type; tkltype++)
	{
		flag		= tkltype->flag;
		tklindex	= tkl_hash(flag);

		if (!strchr(types, flag))
			continue;

		for (tk = tklines[tklindex]; tk; tk = next)
		{
			next = tk->next;

			if (tk->type != tkltype->type)
				continue;
			if (tk->type & TKL_NICK)
			{
				/*
				 * If it's a services hold (ie. NickServ is holding
				 * a nick), it's better not to touch it
				 */
				if (*tk->usermask == 'H')
					continue;
				if (match(uhmask, tk->hostmask))
					continue;
			}
			else
				if (match(uhmask, make_user_host(tk->usermask, tk->hostmask)))
					continue;

			if (cmask && _match(cmask, tk->reason))
				continue;

			strncpyzt(gmt, asctime(gmtime((TS *)&tk->set_at)),
				sizeof gmt);
			iCstrip(gmt);

			if (tk->type & TKL_NICK)
			{
				sendto_snomask(SNO_TKL, "%s removed %s %s (set at %s "
					"- reason: %s)",
					sptr->name, tkltype->txt, tk->hostmask, gmt,
					tk->reason);
				ircd_log(LOG_TKL, "%s removed %s %s (set at %s "
					"- reason: %s)",
					sptr->name, tkltype->txt, tk->hostmask,
					gmt, tk->reason);
			}
			else
			{
				sendto_snomask(SNO_TKL, "%s removed %s %s@%s (set at "
					"%s - reason: %s)",
					sptr->name, tkltype->txt, tk->usermask,
					tk->hostmask, gmt, tk->reason);
				ircd_log(LOG_TKL, "%s removed %s %s@%s (set at "
					"%s - reason: %s)",
					sptr->name, tkltype->txt, tk->usermask,
					tk->hostmask, gmt, tk->reason);
			}

			if ((tk->type & TKL_GLOBAL) && flag)
				sendto_serv_butone_token(&me, me.name, MSG_TKL, TOK_TKL,
					"- %c %s %s %s",
					flag, tk->usermask, tk->hostmask, parv[0]);
			if (tk->type & TKL_SHUN)
				tkl_check_local_remove_shun(tk);
			my_tkl_del_line(tk, tklindex);
		}
	}

	return 0;
}
