/*
 * ==================================================================
 * Filename:             m_chansno.c
 * Description:          Server notices in channels
 * Written by:           AngryWolf <angrywolf@flashmail.com>
 * Requested by:         Rafe
 * Documentation:        chansno.txt (comes with the package)
 * ==================================================================
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

typedef struct _conf_operflag OperFlag;
typedef struct _chansnoflag ChanSnoFlag;

struct _conf_operflag
{
	long		flag;
	char		*name;
};

struct _chansnoflag
{
	ChanSnoFlag	*prev, *next;
	char		*channel;
	long		flags;
};

typedef struct oper_umode_ {
	long *umode;
	char *announce;
} oper_umode_t;

extern void			sendto_one(aClient *to, char *pattern, ...);
extern ConfigEntry		*config_find_entry(ConfigEntry *, char *);
extern OperFlag			*config_binary_flags_search(OperFlag *table, char *cmd, int size);

#define MSG_CHANSNO		"CHANSNO"
#define TOK_CHANSNO		"CR"
#define CHSNO_TABLESIZE		sizeof(_ChanSnoFlags)/sizeof(_ChanSnoFlags[0])
#define MaxSize			(sizeof(msgbuf) - strlen(msgbuf) - 1)

#define ircstrdup(x,y)		if (x) MyFree(x); if (!y) x = NULL; else x = strdup(y)
#define IsParam(x)		(parc > (x) && !BadPtr(parv[(x)]))
#define IsNotParam(x)		(parc <= (x) || BadPtr(parv[(x)]))
#define DelHook(x)		if (x) HookDel(x); x = NULL
#define DelCommand(x)		if (x) CommandDel(x); x = NULL
#define DelOverride(cmd, ovr)	if (ovr && CommandExists(cmd)) CmdoverrideDel(ovr); ovr = NULL

/* Some helpful abbreviations */
#define UserName(cptr)		((cptr)->user->username)
#define RealHost(cptr)		((cptr)->user->realhost)

/* Messages types */
#define MT_PRIVMSG		0x00
#define MT_NOTICE		0x01
#define MsgType			(msgtype == MT_PRIVMSG ? "PRIVMSG" : "NOTICE")

/* Channel server notice masks */
#define CHSNO_CONNECT		0x0001
#define CHSNO_DISCONNECT	0x0002
#define CHSNO_NICKCHANGE	0x0004
#define CHSNO_JOIN		0x0008
#define CHSNO_PART		0x0010
#define CHSNO_KICK		0x0020
#define CHSNO_CHANMODE		0x0040
#define CHSNO_SCONNECT		0x0080
#define CHSNO_SQUIT		0x0100
#define CHSNO_TOPIC		0x0200
#define CHSNO_UNKUSER_QUIT	0x0400
#define CHSNO_CHANNEL_CREATE	0x0800
#define CHSNO_CHANNEL_DESTROY	0x1000
#define CHSNO_OPER		0x2000

/* This MUST be alphabetized */
OperFlag _ChanSnoFlags[] =
{
	{ CHSNO_CHANNEL_CREATE,		"channel-creations"	},
	{ CHSNO_CHANNEL_DESTROY,	"channel-destructions"	},
	{ CHSNO_CONNECT,		"connects"		},
	{ CHSNO_DISCONNECT,		"disconnects"		},
	{ CHSNO_JOIN,			"joins"			},
	{ CHSNO_KICK,			"kicks"			},
	{ CHSNO_CHANMODE,		"mode-changes"		},
	{ CHSNO_NICKCHANGE,		"nickchanges"		},
	{ CHSNO_OPER,			"oper-ups"		},
	{ CHSNO_PART,			"parts"			},
	{ CHSNO_SCONNECT,		"server-connects"	},
	{ CHSNO_SQUIT,			"squits"		},
	{ CHSNO_TOPIC,			"topics"		},
	{ CHSNO_UNKUSER_QUIT,		"unknown-users"		}
};

static Command		*AddCommand(Module *module, char *msg, char *token, iFP func);
static Cmdoverride	*AddOverride(char *msg, iFP cb);
static int		m_chansno(aClient *cptr, aClient *sptr, int parc, char *parv[]);
static int		cb_test(ConfigFile *, ConfigEntry *, int, int *);
static int		cb_conf(ConfigFile *, ConfigEntry *, int);
static int		cb_rehash();

static int		cb_mode(aClient *, aClient *, aChannel *, char *, char *, TS, int);
static int		cb_connect(aClient *);
static int		cb_quit(aClient *, char *);
static int		cb_join(aClient *, aClient *, aChannel *, char *[]);
static int		cb_kick(aClient *, aClient *, aClient *, aChannel *, char *);
static int		cb_nickchange(aClient *, char *);
static int		cb_part(aClient *, aClient *, aChannel *, char *);
static int		cb_server_connect(aClient *);
static int		cb_server_quit(aClient *);
static int		cb_topic();
static int		cb_unkuser_quit(aClient *, char *);
static int		cb_channel_create(aClient *cptr, aChannel *chptr);
static int		cb_channel_destroy(aChannel *chptr);
static int		ovr_oper(Cmdoverride *, aClient *, aClient *, int, char *[]);

Command			*CmdChanSno = NULL;
Cmdoverride		*OvrOper = NULL;
ChanSnoFlag		*ConfChanSno;
Hook			*HookConfTest, *HookConfRun, *HookConfRehash;
Hook			*HookMode = NULL, *HookConnect = NULL, *HookQuit = NULL;
Hook			*HookJoin = NULL, *HookKick = NULL, *HookTopic = NULL;
Hook			*HookPart = NULL, *HookServerConnect = NULL;
Hook			*HookServerQuit = NULL, *HookNickChange = NULL;
Hook			*HookUnkUserQuit = NULL, *HookChannelCreate = NULL;
Hook			*HookChannelDestroy = NULL;
char			msgbuf[BUFSIZE+1];
u_int			msgtype = MT_PRIVMSG;
static oper_umode_t	oper_umodes[6];

#ifndef STATIC_LINKING
static ModuleInfo	*MyModInfo;
 #define MyMod		MyModInfo->handle
 #define SAVE_MODINFO	MyModInfo = modinfo;
#else
 #define MyMod		NULL
 #define SAVE_MODINFO
#endif

ModuleHeader MOD_HEADER(chansno)
  = {
	"m_chansno",
	"$Id: m_chansno.c,v 1.16 2004/07/12 18:53:30 angrywolf Exp $",
	"server notices in channels",
	"3.2-b8-1",
	NULL
    };

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

static Cmdoverride *AddOverride(char *msg, iFP cb)
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
			msg, MOD_HEADER(chansno).name, ModuleGetErrorStr(MyMod));
#else
		config_error("Error replacing command %s when loading module %s",
			msg, MOD_HEADER(chansno).name);
#endif
		return NULL;
	}

	return ovr;
}

// =================================================================
// Functions related to loading/unloading configuration
// =================================================================

static void InitConf()
{
	ConfChanSno	= NULL;
	msgtype		= MT_PRIVMSG;
}

static void FreeConf()
{
	ChanSnoFlag	*c;
	ListStruct 	*next;

	for (c = ConfChanSno; c; c = (ChanSnoFlag *) next)
	{
		next = (ListStruct *) c->next;
		DelListItem(c, ConfChanSno);
		MyFree(c->channel);
		MyFree(c);
	}
}

// =================================================================
// Module functions
// =================================================================

DLLFUNC int MOD_TEST(chansno)(ModuleInfo *modinfo)
{
	SAVE_MODINFO
	HookConfTest	= HookAddEx(modinfo->handle, HOOKTYPE_CONFIGTEST, cb_test);

	return MOD_SUCCESS;
}

DLLFUNC int MOD_INIT(chansno)(ModuleInfo *modinfo)
{
	SAVE_MODINFO
	InitConf();

	oper_umodes[0].umode = &UMODE_NETADMIN;
	oper_umodes[0].announce = "is now a network administrator (N)"; 
	oper_umodes[1].umode = &UMODE_SADMIN;
	oper_umodes[1].announce = "is now a services administrator (a)"; 
	oper_umodes[2].umode = &UMODE_ADMIN;
	oper_umodes[2].announce = "is now a server admin (A)"; 
	oper_umodes[3].umode = &UMODE_COADMIN;
	oper_umodes[3].announce = "is now a co administrator (C)"; 
	oper_umodes[4].umode = &UMODE_OPER;
	oper_umodes[4].announce = "is now an operator (O)"; 
	oper_umodes[5].umode = NULL;
	oper_umodes[5].announce = "is now a local operator (o)"; 

	CmdChanSno = AddCommand(modinfo->handle, MSG_CHANSNO, TOK_CHANSNO, m_chansno);
	HookConfRun = HookAddEx(modinfo->handle, HOOKTYPE_CONFIGRUN, cb_conf);
	HookConfRehash = HookAddEx(modinfo->handle, HOOKTYPE_REHASH, cb_rehash);

	if (!CmdChanSno)
		return MOD_FAILED;

	HookMode = HookAddEx(modinfo->handle, HOOKTYPE_LOCAL_CHANMODE, cb_mode);
	HookConnect = HookAddEx(modinfo->handle, HOOKTYPE_LOCAL_CONNECT, cb_connect);
	HookQuit = HookAddEx(modinfo->handle, HOOKTYPE_LOCAL_QUIT, cb_quit);
	HookJoin = HookAddEx(modinfo->handle, HOOKTYPE_LOCAL_JOIN, cb_join);
	HookKick = HookAddEx(modinfo->handle, HOOKTYPE_LOCAL_KICK, cb_kick);
	HookNickChange = HookAddEx(modinfo->handle, HOOKTYPE_LOCAL_NICKCHANGE, cb_nickchange);
	HookPart = HookAddEx(modinfo->handle, HOOKTYPE_LOCAL_PART, cb_part);
	HookServerConnect = HookAddEx(modinfo->handle, HOOKTYPE_SERVER_CONNECT, cb_server_connect);
	HookServerQuit = HookAddEx(modinfo->handle, HOOKTYPE_SERVER_QUIT, cb_server_quit);
	HookTopic = HookAddEx(modinfo->handle, HOOKTYPE_LOCAL_TOPIC, cb_topic);
	HookUnkUserQuit = HookAddEx(modinfo->handle, HOOKTYPE_UNKUSER_QUIT, cb_unkuser_quit);
	HookChannelCreate = HookAddEx(modinfo->handle, HOOKTYPE_CHANNEL_CREATE, cb_channel_create);
	HookChannelDestroy = HookAddEx(modinfo->handle, HOOKTYPE_CHANNEL_DESTROY, cb_channel_destroy);

	return MOD_SUCCESS;
}

DLLFUNC int MOD_LOAD(userauth)(int module_load)
{
	OvrOper = AddOverride("oper", ovr_oper);
	return MOD_SUCCESS;
}

DLLFUNC int MOD_UNLOAD(m_chansno)(int module_unload)
{
	DelHook(HookChannelDestroy);
	DelHook(HookChannelCreate);
	DelHook(HookUnkUserQuit);
	DelHook(HookTopic);
	DelHook(HookServerQuit);
	DelHook(HookServerConnect);
	DelHook(HookPart);
	DelHook(HookNickChange);
	DelHook(HookKick);
	DelHook(HookJoin);
	DelHook(HookQuit);
	DelHook(HookConnect);
	DelHook(HookMode);

	DelHook(HookConfRehash);
	DelHook(HookConfRun);
	DelHook(HookConfTest);
	DelCommand(CmdChanSno);
	DelOverride("oper", OvrOper);

	FreeConf();
	return MOD_SUCCESS;
}

// =================================================================
// Config file interfacing
// =================================================================

static int cb_rehash()
{
	FreeConf();
	InitConf();

	return 1;
}

static int cb_test(ConfigFile *cf, ConfigEntry *ce, int type, int *errs)
{
	ConfigEntry	*cep, *cepp;
	int		errors = 0;

	if (type != CONFIG_MAIN)
		return 0;

	if (!strcmp(ce->ce_varname, "chansno"))
	{
		for (cep = ce->ce_entries; cep; cep = cep->ce_next)
		{
			if (!cep->ce_varname)
			{
				config_error("%s:%i: blank chansno item",
					cep->ce_fileptr->cf_filename,
					cep->ce_varlinenum);
				errors++;
				continue;
			}
			if (!cep->ce_vardata)
			{
				config_error("%s:%i: chansno::%s item without value",
					cep->ce_fileptr->cf_filename,
					cep->ce_varlinenum, cep->ce_varname);
				errors++;
				continue;
			}
			if (!strcmp(cep->ce_varname, "channel"))
			{
				if (!cep->ce_entries)
				{
					config_error("%s:%i: chansno::channel without contents",
						cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
					errors++;
					continue;
				}
				for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next)
				{
					if (!cepp->ce_varname)
					{
						config_error("%s:%i: chansno::channel item without variable name",
							cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum);
						errors++;
						continue;
					}
					if (!config_binary_flags_search(_ChanSnoFlags, cepp->ce_varname, CHSNO_TABLESIZE))
					{
						config_error("%s:%i: unknown chansno::channel flag '%s'",
							cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum,
							cepp->ce_varname);
						errors++;
					}
				}
			}
			else if (!strcmp(cep->ce_varname, "msgtype"))
			{
				if (!strcmp(cep->ce_vardata, "privmsg"))
					;
				else if (!strcmp(cep->ce_vardata, "notice"))
					;
				else
				{
					config_error("%s:%i: unknown chansno::msgtype '%s'",
						cep->ce_fileptr->cf_filename, cep->ce_varlinenum,
						cep->ce_varname);
					errors++;
				}
			}
			else
			{
				config_error("%s:%i: unknown directive chansno::%s",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum, cep->ce_varname);
				errors++;
			}
		}
		*errs = errors;
		return errors ? -1 : 1;
	}
	else
		return 0;
}

static int cb_conf(ConfigFile *cf, ConfigEntry *ce, int type)
{
	ConfigEntry	*cep, *cepp;
	OperFlag	*ofp;
	ChanSnoFlag	*ca;

	if (type != CONFIG_MAIN)
		return 0;

	if (!strcmp(ce->ce_varname, "chansno"))
	{
		for (cep = ce->ce_entries; cep; cep = cep->ce_next)
		{
			if (!strcmp(cep->ce_varname, "channel"))
			{
				ca = MyMallocEx(sizeof(ChanSnoFlag));
				ircstrdup(ca->channel, cep->ce_vardata);

				for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next)
				{
					if ((ofp = config_binary_flags_search(_ChanSnoFlags, cepp->ce_varname, CHSNO_TABLESIZE)))
						ca->flags |= ofp->flag;
				}

				AddListItem(ca, ConfChanSno);
			}
			else if (!strcmp(cep->ce_varname, "msgtype"))
			{
				if (!strcmp(cep->ce_vardata, "privmsg"))
					msgtype = MT_PRIVMSG;
				else if (!strcmp(cep->ce_vardata, "notice"))
					msgtype = MT_NOTICE;
			}
		}

		return 1;
	}

	return 0;
}

// ===============================================================
// Functions used by m_chansno
// ===============================================================

static char *get_flag_names(long flags)
{
	u_int	i, found = 0;

	memset(&msgbuf, 0, sizeof msgbuf);

	for (i = 0; i < CHSNO_TABLESIZE; i++)
        	if (flags & _ChanSnoFlags[i].flag)
		{
			if (found)
				strncat(msgbuf, ", ", MaxSize);
			else
				found = 1;

			strncat(msgbuf, _ChanSnoFlags[i].name, MaxSize);
		}

	if (!strlen(msgbuf))
		strcpy(msgbuf, "<None>");

	return msgbuf;
}

static void stats_chansno_channels(aClient *sptr)
{
	ChanSnoFlag	*c;
	
	for (c = ConfChanSno; c; c = c->next)
		sendto_one(sptr, ":%s %i %s :channel %s: %s",
			me.name, RPL_TEXT, sptr->name,
			c->channel, get_flag_names(c->flags));

	sendto_one(sptr, rpl_str(RPL_ENDOFSTATS), me.name, sptr->name, 'S');
}

static void stats_chansno_config(aClient *sptr)
{
	sendto_one(sptr, ":%s %i %s :msgtype: %s",
		me.name, RPL_TEXT, sptr->name, MsgType);
	sendto_one(sptr, rpl_str(RPL_ENDOFSTATS), me.name, sptr->name, 'S');
}

// ===============================================================
// m_chansno
//      parv[0]: sender prefix
//      parv[1]: option
//      parv[2]: server name (optional)
// ===============================================================

static int m_chansno(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
	if (!IsPerson(sptr))
		return -1;

	if (!IsAnOper(sptr))
	{
		sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
		return -1;
	}

	if (!IsParam(1))
	{
		sendto_one(sptr, ":%s NOTICE %s :Usage:",
			me.name, sptr->name);
		sendto_one(sptr, ":%s NOTICE %s :    /chansno <option> [<servername>]",
			me.name, sptr->name);
		sendto_one(sptr, ":%s NOTICE %s :Options:",
			me.name, sptr->name);
		sendto_one(sptr, ":%s NOTICE %s :    list: displays the chansno::channel block list",
			me.name, sptr->name);
		sendto_one(sptr, ":%s NOTICE %s :    config: shows the rest of chansno configuration",
			me.name, sptr->name);
		return 0;
	}

        if (IsParam(2))
        {
                if (hunt_server_token(cptr, sptr, MSG_CHANSNO, TOK_CHANSNO,
                    "%s", 2, parc, parv) != HUNTED_ISME)
                        return 0;
        }

	if (!strcasecmp(parv[1], "list"))
		stats_chansno_channels(sptr);
	else if (!strcasecmp(parv[1], "config"))
		stats_chansno_config(sptr);
	else
	{
		sendto_one(sptr, ":%s NOTICE %s :Unknown option %s."
			" Valid options are: list | config",
			me.name, sptr->name, parv[1]);
		return -1;
	}

	return 0;
}

// ===============================================================
// Interface for sending notifications
// ===============================================================

#define SendBuf_simple \
	if ((sendto = find_channel(c->channel, NullChn)) != NullChn) \
		sendto_channel_butone(&me, &me, sendto, ":%s %s %s :%s", \
			me.name, MsgType, sendto->chname, msgbuf)

#define SendBuf_channel \
	if (!find_sno_channel(chptr) && (sendto = find_channel(c->channel, NullChn)) != NullChn) \
		sendto_channel_butone(&me, &me, sendto, ":%s %s %s :[%s] %s", \
			me.name, MsgType, sendto->chname, chptr->chname, msgbuf)

static u_int find_sno_channel(aChannel *chptr)
{
	ChanSnoFlag	*c;
	
	for (c = ConfChanSno; c; c = c->next)
		if (!strcasecmp(chptr->chname, c->channel))
			return 1;

	return 0;
}

static void SendNotice_simple(long type)
{
	ChanSnoFlag	*c;
	aChannel	*sendto;

	for (c = ConfChanSno; c; c = c->next)
	{
		if (c->flags & type)
			SendBuf_simple;
	}
}

static void SendNotice_channel(aChannel *chptr, long type)
{
	ChanSnoFlag	*c;
	aChannel	*sendto;

	for (c = ConfChanSno; c; c = c->next)
	{
		if (c->flags & type)
			SendBuf_channel;
	}
}

static int cb_mode(aClient *cptr, aClient *sptr, aChannel *chptr,
  char *modebuf, char *parabuf, TS sendts, int samode)
{
	snprintf(msgbuf, BUFSIZE, "%s sets mode: %s%s%s",
		sptr->name, modebuf,
		BadPtr(parabuf) ? "" : " ",
		BadPtr(parabuf) ? "" : parabuf);

	SendNotice_channel(chptr, CHSNO_CHANMODE);
	return 0;
}

static int cb_connect(aClient *sptr)
{
	snprintf(msgbuf, BUFSIZE, "Client connecting on port %d: %s (%s@%s) [%s] %s%s%s",
		sptr->listener->port, sptr->name, UserName(sptr), RealHost(sptr),
		sptr->class ? sptr->class->name : "",
#ifdef USE_SSL
		IsSecure(sptr) ? "[secure " : "",
		IsSecure(sptr) ? SSL_get_cipher((SSL *)sptr->ssl) : "",
		IsSecure(sptr) ? "]" : "");
#else
		"", "", "");
#endif

	SendNotice_simple(CHSNO_CONNECT);
	return 0;
}

static int cb_quit(aClient *sptr, char *comment)
{
	snprintf(msgbuf, BUFSIZE, "Client exiting: %s!%s@%s (%s)",
		sptr->name, UserName(sptr), RealHost(sptr), comment);

	SendNotice_simple(CHSNO_DISCONNECT);
	return 0;
}

static int cb_unkuser_quit(aClient *sptr, char *comment)
{
	if (BadPtr(comment))
		snprintf(msgbuf, BUFSIZE, "Unknown client exiting: %s",
	    		Inet_ia2p(&sptr->ip));
	else
		snprintf(msgbuf, BUFSIZE, "Unknown client exiting: %s (%s)",
			Inet_ia2p(&sptr->ip), comment);

	SendNotice_simple(CHSNO_UNKUSER_QUIT);
	return 0;
}

static int cb_join(aClient *cptr, aClient *sptr, aChannel *chptr, char *parv[])
{
	snprintf(msgbuf, BUFSIZE, "%s (%s@%s) has joined %s",
		sptr->name, UserName(sptr), RealHost(sptr), chptr->chname);

	SendNotice_channel(chptr, CHSNO_JOIN);
	return 0;
}

static int cb_kick(aClient *cptr, aClient *sptr, aClient *who, aChannel *chptr, char *comment)
{
	snprintf(msgbuf, BUFSIZE, "%s has kicked %s (%s)",
		sptr->name, who->name, comment);

	SendNotice_channel(chptr, CHSNO_KICK);
	return 0;
}

static int cb_nickchange(aClient *sptr, char *nick)
{
	snprintf(msgbuf, BUFSIZE, "%s (%s@%s) has changed his/her nickname to %s",
		sptr->name, UserName(sptr), RealHost(sptr), nick);

	SendNotice_simple(CHSNO_NICKCHANGE);
	return 0;
}

static int cb_part(aClient *cptr, aClient *sptr, aChannel *chptr, char *comment)
{
	snprintf(msgbuf, BUFSIZE, "%s (%s@%s) has left %s (%s)",
		sptr->name, UserName(sptr), RealHost(sptr),
		chptr->chname, comment ? comment : sptr->name);

	SendNotice_channel(chptr, CHSNO_PART);
	return 0;
}

static int cb_server_connect(aClient *sptr)
{
	if (!MyConnect(sptr))
		return 0;

	snprintf(msgbuf, BUFSIZE, "Server connecting on port %d: %s (%s) [%s] %s%s%s%s",
		sptr->listener->port, sptr->name, sptr->info,
		    sptr->class ? sptr->class->name : "",
#ifdef USE_SSL
		IsSecure(sptr) ? "[secure " : "",
		IsSecure(sptr) ? SSL_get_cipher((SSL *)sptr->ssl) : "",
		IsSecure(sptr) ? "]" : "",
#else
		"", "", "",
#endif

#ifdef ZIP_LINKS
		IsZipped(sptr) ? " [zip]" : "");
#else
		"");
#endif

	SendNotice_simple(CHSNO_SCONNECT);
	return 0;
}

static int cb_server_quit(aClient *sptr)
{
	if (!MyConnect(sptr))
		return 0;

	/* The hook supports no reason :-( */
	snprintf(msgbuf, BUFSIZE, "Server exiting: %s",
		sptr->name);

	SendNotice_simple(CHSNO_SQUIT);
	return 0;
}

static int cb_topic(aClient *cptr, aClient *sptr, aChannel *chptr, char *topic)
{
	snprintf(msgbuf, BUFSIZE, "%s changes topic to: %s",
		sptr->name, topic);

	SendNotice_channel(chptr, CHSNO_TOPIC);
	return 0;
}

static int cb_channel_create(aClient *cptr, aChannel *chptr)
{
	if (!find_sno_channel(chptr))
	{
		snprintf(msgbuf, BUFSIZE, "%s created channel %s",
			cptr->name, chptr->chname);

		SendNotice_simple(CHSNO_CHANNEL_CREATE);
	}

	return 0;
}

static int cb_channel_destroy(aChannel *chptr)
{
	if (!find_sno_channel(chptr))
	{
		snprintf(msgbuf, BUFSIZE, "Channel %s has been destroyed",
			chptr->chname);

		SendNotice_simple(CHSNO_CHANNEL_DESTROY);
	}

	return 0;
}

static int ovr_oper(Cmdoverride *ovr, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
	int	ret, i;

	if (!IsPerson(sptr) || !MyClient(sptr) || IsAnOper(sptr))
		return CallCmdoverride(ovr, cptr, sptr, parc, parv);

	ret = CallCmdoverride(ovr, cptr, sptr, parc, parv);

	if (IsAnOper(sptr))
	{
		for (i = 0; oper_umodes[i].umode; i++)
			if (sptr->umodes & *oper_umodes[i].umode)
				break;

		snprintf(msgbuf, BUFSIZE, "%s (%s@%s) [%s] %s",
			sptr->name, UserName(sptr), GetHost(sptr),
			parv[1], oper_umodes[i].announce);

		SendNotice_simple(CHSNO_OPER);
	}

	return ret;
}
