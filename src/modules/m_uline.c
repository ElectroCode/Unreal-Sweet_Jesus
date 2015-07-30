/*
 * =================================================================
 * Filename:            m_uline.c
 * =================================================================
 * Description:         Command /uline: gives someone an U:Line.
 *                      This module is required to be loaded on all
 *                      servers to avoid desynch problems. Only 
 *                      NetAdmins may use /uline, or if you set
 *                      a password for it, only those of them who
 *                      knows the password. Notifications are sent
 *                      to snomask +U. It's strongly recommended
 *                      to be used by advanced users only! See more
 *                      information below.
 * =================================================================
 * Author:		AngryWolf
 * Email:		angrywolf@flashmail.com
 * =================================================================
 * Feedback:
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
 * Configuration:
 * =================================================================
 *
 * You may optionally set a password to be used with /uline. It's
 * not required but recommended in order to avoid possible abuses.
 * The configuration looks like this:
 *
 *         set {
 *             uline-password <password>;
 *         }; 
 *
 * As you can see, directive uline-password goes into your
 * set {} block. Example:
 *
 *         set {
 *             uline-password "xxx";
 *         }; 
 *
 * The password may be encoded, then the syntax is:
 *
 *         set {
 *             uline-password <password> { <auth-type>; };
 *         }; 
 *
 * <auth-type> allows you to specify an authentication method for
 * this password, valid auth-types are crypt, md5, sha1 and ripemd-160.
 * Example for setting up an encrypted password:
 *
 *         set {
 *             uline-password "06Y0jDVtnwVBk" { crypt; };
 *         }; 
 *
 * =================================================================
 * Usage:
 * =================================================================
 *
 * Command ULINE:
 * --------------
 *
 * Syntax: /uline [+|-]<nickname> [<password>]
 *
 * <password> is only required when set::uline-password is
 * configured. Examples:
 *
 * - To set an U:Line on yourself:
 *       /uline YourNick
 * - To remove U:Line from SomeOne:
 *       /uline -SomeOne
 *
 * Snomask +U:
 * -----------
 *
 * With this you'll be notified when someone uses the /uline
 * command.
 *
 * =================================================================
 * Mirror files:
 * =================================================================
 *
 * http://angrywolf.linktipp.org/m_uline.c [Germany]
 * http://angrywolf.uw.hu/m_uline.c [Hungary]
 * http://angrywolf.fw.hu/m_uline.c [Hungary]
 *
 * =================================================================
 * Changes:
 * =================================================================
 *
 * $Log: m_uline.c,v $
 * Revision 1.13  2004/03/09 10:32:28  angrywolf
 * - Fixed a typo made by the previous change that resulted
 *   in a compilation error (reported by Stoebi).
 *
 * Revision 1.12  2004/03/08 21:26:24  angrywolf
 * - Fixed some bugs that could cause crash if you compile the module
 *   statically (for example, under Windows).
 *
 * Revision 1.11  2004/02/04 08:53:05  angrywolf
 * - Fixed a win32 crash bug, reported by Zell.
 *
 * Revision 1.10  2004/02/03 10:48:56  angrywolf
 * - Windows compilation fixes.
 *
 * Revision 1.9  2004/01/16 16:42:28  angrywolf
 * - Fix for a memory leak bug.
 *
 * Revision 1.8  2004/01/16 13:06:23  angrywolf
 * - Added snomask +U (requested by gauntlet) and made the
 *   module be permanent so the snomask remains in the memory
 *   even if you do a /rehash.
 *
 * Revision 1.7  2003/12/01 18:45:07  angrywolf
 * - Replaced add_Command and del_Command with CommandAdd and CommandDel.
 *
 * Revision 1.6  2003/11/27 13:33:44  angrywolf
 * - Minor fix on hooks.
 *
 * Revision 1.5  2003/11/06 08:08:59  angrywolf
 * - Fixed a bug reported by JUBAiR that passwords were
 *   checked also on remote servers.
 *
 * Revision 1.4  2003/10/24 10:15:51  angrywolf
 * - Fixed a typo in description.
 *
 * Revision 1.3  2003/10/24 09:52:15  angrywolf
 * - Fixed a bug that resulted U:Lines weren't set globally.
 *   Reported by bleh.
 * - Added password protection and support to set U:Line
 *   on anyone you want. As a result, one parameter (namely
 *   the nickname of a person) is always required to be given.
 *
 * Revision 1.2  2003/10/15 18:20:38  angrywolf
 * - Doc updates
 *
 * Revision 1.1  2003/10/15 17:46:10  angrywolf
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

extern ConfigEntry	*config_find_entry(ConfigEntry *ce, char *name);
extern void		sendto_one(aClient *to, char *pattern, ...);
extern void		sendto_realops(char *pattern, ...);
extern void		sendto_serv_butone_token(aClient *one, char *prefix, char *command, char *token, char *pattern, ...);

#define MSG_ULINE	"ULINE"
#define TOK_ULINE	"UL"
#define FlagUline	'U'
#define IsParam(x)      (parc > (x) && !BadPtr(parv[(x)]))
#define IsNotParam(x)   (parc <= (x) || BadPtr(parv[(x)]))
#define DelHook(x)	if (x) HookDel(x); x = NULL
#define DelCommand(x)	if (x) CommandDel(x); x = NULL
#define DelSnomask(x)	if (x) SnomaskDel(x); x = NULL

static Command		*AddCommand(Module *module, char *msg, char *token, iFP func);
static Snomask		*AddSnomask(Module *module, char flag, iFP allowed, long *mode);
static int		m_uline(aClient *, aClient *, int, char *[]);
static int		cb_test(ConfigFile *, ConfigEntry *, int, int *);
static int		cb_conf(ConfigFile *, ConfigEntry *, int);
static int		cb_stats(aClient *sptr, char *stats);

static Command		*CmdUline;
static Hook		*HookConfTest = NULL, *HookConfRun = NULL;
static Hook		*HookStats = NULL;
static anAuthStruct	*uline_auth;
static Snomask		*SnomaskUline = NULL;
long			SNO_ULINE = 0;

ModuleHeader MOD_HEADER(m_uline)
  = {
	"m_uline",
	"$Id: m_uline.c,v 1.13 2004/03/09 10:32:28 angrywolf Exp $",
	"Command /uline",
	"3.2-b8-1",
	NULL 
    };

static void InitConf()
{
	uline_auth = NULL;
}

static void FreeConf()
{
	if (uline_auth)
		Auth_DeleteAuthStruct(uline_auth);
}

DLLFUNC int MOD_TEST(m_uline)(ModuleInfo *modinfo)
{
	HookConfTest = HookAddEx(modinfo->handle, HOOKTYPE_CONFIGTEST, cb_test);
	return MOD_SUCCESS;
}

DLLFUNC int MOD_INIT(m_uline)(ModuleInfo *modinfo)
{
#ifndef STATIC_LINKING
	ModuleSetOptions(modinfo->handle, MOD_OPT_PERM);
#endif
	InitConf();

	HookConfRun	= HookAddEx(modinfo->handle, HOOKTYPE_CONFIGRUN, cb_conf);
	HookStats	= HookAddEx(modinfo->handle, HOOKTYPE_STATS, cb_stats);
	CmdUline	= AddCommand(modinfo->handle, MSG_ULINE, TOK_ULINE, m_uline);
        SnomaskUline	= AddSnomask(modinfo->handle, FlagUline, umode_allow_opers, &SNO_ULINE);

	if (!CmdUline || !SnomaskUline)
		return MOD_FAILED;

	return MOD_SUCCESS;
}

DLLFUNC int MOD_LOAD(m_uline)(int module_load)
{
	return MOD_SUCCESS;
}

DLLFUNC int MOD_UNLOAD(m_uline)(int module_unload)
{
	FreeConf();

	DelHook(HookStats);
	DelHook(HookConfRun);
	DelHook(HookConfTest);
	DelCommand(CmdUline);
	DelSnomask(SnomaskUline);

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
                sendto_realops("[\2remotenick\2] Error adding snomask %c: %s",
                        flag, ModuleGetErrorStr(module));
#else
                sendto_realops("[\2remotenick\2] Error adding snomask %c",
                        flag);
#endif
		return NULL;
        }

	return s;
}

static int cb_test(ConfigFile *cf, ConfigEntry *ce, int type, int *errs)
{
	int errors = 0;

	if (type != CONFIG_SET)
		return 0;

	if (!strcmp(ce->ce_varname, "uline-password"))
	{
		if (!ce->ce_vardata)
		{
			config_error("%s:%i: set::uline-password without contents",
					ce->ce_fileptr->cf_filename,
					ce->ce_varlinenum);
			errors++;
		}
		else if (Auth_CheckError(ce) < 0)
			errors++;

		*errs = errors;
		return errors ? -1 : 1;
	}
	else
		return 0;
}

static int cb_conf(ConfigFile *cf, ConfigEntry *ce, int type)
{
	if (type != CONFIG_SET)
		return 0;

	if (!strcmp(ce->ce_varname, "uline-password"))
	{
		if (uline_auth)
			Auth_DeleteAuthStruct(uline_auth);
		uline_auth = Auth_ConvertConf2AuthStruct(ce);

		return 1;		
	}

	return 0;
}

static int cb_stats(aClient *sptr, char *stats)
{
	if (*stats == 'S')
	{
		sendto_one(sptr, ":%s %i %s :uline-password: <%s>",
			me.name, RPL_TEXT, sptr->name, uline_auth ? "hidden" : "none");
	}
        return 0;
}

int m_uline(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
	aClient		*acptr		= NULL;
	char		*nick		= NULL;
	char		*passwd		= NULL;
	int		add		= 1;
	int		i		= 0;

	if (IsPerson(sptr) && !IsNetAdmin(sptr))
	{
    		sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name,
            		parv[0]);
                return -1;
	}

	nick = IsParam(1) ? parv[1] : NULL;

	if (nick)
	{
		if (*nick == '+')
			nick++;
		else if (*nick == '-')
		{
			nick++;
			add = 0;
		}
		if (!*nick)
			nick = NULL;
	}

        if (!nick)
	{
	        if (!IsServer(sptr))
	    		sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
				me.name, parv[0], "ULINE");
		return -1;
	}

	if (MyConnect(sptr) && IsPerson(sptr) && uline_auth)
	{
		passwd = IsParam(2) ? parv[2] : NULL;

		if (!passwd)
		{
			sendto_one(sptr,
				":%s %s %s :*** missing password",
				me.name, IsWebTV(sptr) ? "PRIVMSG" : "NOTICE",
				sptr->name);
			return 0;
		}

		i = Auth_Check(cptr, uline_auth, passwd);

    		if (i == -1)
		{
			sendto_one(sptr, err_str(ERR_PASSWDMISMATCH),
				me.name, parv[0]);
			sendto_snomask(SNO_ULINE, "*** %s!%s@%s tried to use /uline with a wrong password",
				sptr->name, sptr->user->username,
				GetHost(sptr));
			return 0;
		}
	}

	acptr = find_person(nick, NULL);

	if (!acptr)
	{
		if (!IsServer(sptr))
	    		sendto_one(sptr, err_str(ERR_NOSUCHNICK),
				me.name, sptr->name, nick);
	        return 0;
	}

	if (add)
	{
		if (IsULine(acptr))
		{
			if (!IsServer(sptr))
				sendto_one(sptr,
					":%s %s %s :*** %s is already U:Lined",
					me.name, IsWebTV(sptr) ? "PRIVMSG" : "NOTICE",
					sptr->name, acptr->name);
			return 0;
		}

		acptr->flags |= FLAGS_ULINE;

		sendto_snomask(SNO_ULINE, "*** U:Line added for %s!%s@%s by %s",
			acptr->name, acptr->user->username,
			GetHost(acptr), sptr->name);

		if (MyConnect(acptr))
			sendto_one(acptr,
				":%s %s %s :*** You are now U:Lined",
				me.name, IsWebTV(acptr) ? "PRIVMSG" : "NOTICE",
				acptr->name);
		if (MyConnect(sptr) && acptr != sptr)
			sendto_one(sptr,
				":%s %s %s :*** %s is now U:Lined",
				me.name, IsWebTV(acptr) ? "PRIVMSG" : "NOTICE",
				sptr->name, acptr->name);
	}
	else
	{
		if (!IsULine(acptr))
		{
			if (!IsServer(sptr))
				sendto_one(sptr,
					":%s %s %s :*** %s is not U:Lined",
					me.name, IsWebTV(sptr) ? "PRIVMSG" : "NOTICE",
					sptr->name, acptr->name);
			return 0;
		}

		acptr->flags &= ~FLAGS_ULINE;

		sendto_snomask(SNO_ULINE, "*** %s removed U:Line from %s!%s@%s",
			sptr->name, acptr->name,
			acptr->user->username, GetHost(acptr));

		if (MyConnect(acptr))
			sendto_one(acptr,
				":%s %s %s :*** You are no longer U:Lined",
				me.name, IsWebTV(acptr) ? "PRIVMSG" : "NOTICE",
				acptr->name);
		if (MyConnect(sptr) && acptr != sptr)
			sendto_one(sptr,
				":%s %s %s :*** %s is no longer U:Lined",
				me.name, IsWebTV(acptr) ? "PRIVMSG" : "NOTICE",
				sptr->name, acptr->name);
	}

	sendto_serv_butone_token(MyClient(cptr) ? &me : cptr,
		sptr->name, MSG_ULINE, TOK_ULINE,
		"%c%s", add ? '+' : '-', acptr->name);

	return 0;
}
