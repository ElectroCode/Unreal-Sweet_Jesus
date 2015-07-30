/*
 * =================================================================
 * Filename:          m_vhosts.c
 * Description:       Vhosts manager module
 * Author:            AngryWolf <angrywolf@flashmail.com>
 * Documentation:     vhosts.txt (comes with the package)
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

typedef struct _conf_operflag OperFlag;
typedef struct _blocklist BlockList;
typedef struct _cmdinfo CmdInfo;

struct _conf_operflag
{
	long			flag;
	char			*name;
};

struct _blocklist
{
	BlockList		*prev, *next;
	ConfigItem_vhost	*vhost;
};

struct _cmdinfo
{
	char			*msg, *tok;
	iFP			func;
	Command			*cmd;
};

extern void			sendto_one(aClient *to, char *pattern, ...);
extern void			sendto_serv_butone_token(aClient *one, char *prefix, char *command, char *token, char *pattern, ...);
extern OperFlag			*config_binary_flags_search(OperFlag *table, char *cmd, int size);
extern anAuthStruct		AuthTypes[];

#define VHOST_DB		"vhost.db"
#define VHOST_DB_VERSION	1001

#define IsParam(x)      	(parc > (x) && !BadPtr(parv[(x)]))
#define IsNotParam(x)		(parc <= (x) || BadPtr(parv[(x)]))
#define ircfree(x)		if (x) MyFree(x); x = NULL
#define ircstrdup(x,y)		if (x) MyFree(x); if (!y) x = NULL; else x = strdup(y)
#define DelCommand(x)		if (x) CommandDel(x); x = NULL
#define DelHook(x)		if (x) HookDel(x); x = NULL
#define IsSkoAdmin(sptr)	(IsAdmin(sptr) || IsNetAdmin(sptr) || IsSAdmin(sptr))

#define VF_VHOST		0x01
#define VF_USERHOST		0x02
#define VF_LOGIN		0x04
#define VF_PASSWORD		0x08
#define VF_SWHOIS		0x10

/* Helpful macros to make the code a bit more readable */
#define FromLoop(counter, list) \
    	for (counter = (ConfigItem_oper_from *) list; \
    	        counter; counter = (ConfigItem_oper_from *) (counter)->next)
#define FromLoop2(counter, list, next) \
	for (counter = (ConfigItem_oper_from *) list; \
		counter; counter = (ConfigItem_oper_from *) next)
#define NewFrom \
	(ConfigItem_oper_from *) MyMallocEx(sizeof(ConfigItem_oper_from))

static CMD_FUNC(m_addvhost);
static CMD_FUNC(m_addrvhost);
static CMD_FUNC(m_addgvhost);
static CMD_FUNC(m_delvhost);
static CMD_FUNC(m_delrvhost);
static CMD_FUNC(m_delgvhost);
static CMD_FUNC(m_modvhost);
static CMD_FUNC(m_modrvhost);
static CMD_FUNC(m_modgvhost);
static CMD_FUNC(m_confvhost);
static CMD_FUNC(m_confrvhost);

static Command			*AddCommand(Module *module, char *msg, char *token, iFP func);
static int			add_commands(Module *module);
static void			del_commands();
#ifdef STATIC_LINKING
static int			cb_config_rehash();
static int			cb_rehash_complete();
#endif
static int			save_vhosts();
static int			load_vhosts();
static void			free_extvhosts();

#ifdef STATIC_LINKING
Hook				*HookConfRehash;
Hook				*HookRehashDone;
#endif
BlockList			*ExternalVhosts;
static char			buf[1024];
static unsigned			vhost_db_version = VHOST_DB_VERSION;

static CmdInfo VhostCommands[] =
{
	{ "ADDVHOST",		"VA",		m_addvhost,	NULL	},
	{ "ADDRVHOST",		"VRA",		m_addrvhost,	NULL	},
	{ "ADDGVHOST",		"VGA",		m_addgvhost,	NULL	},
	{ "DELVHOST",		"VD",		m_delvhost,	NULL	},
	{ "DELRVHOST",		"VRD",		m_delrvhost,	NULL	},
	{ "DELGVHOST",		"VGD",		m_delgvhost,	NULL	},
	{ "MODVHOST",		"VM",		m_modvhost,	NULL	},
	{ "MODRVHOST",		"VRM",		m_modrvhost,	NULL	},
	{ "MODGVHOST",		"VGM",		m_modgvhost,	NULL	},
	{ "CONFVHOST",		"VC",		m_confvhost,	NULL	},
	{ "CONFRVHOST",		"VRC",		m_confrvhost,	NULL	},
	{ NULL,			NULL,		NULL,		NULL	}
};

/* This MUST be alphabetized */
static OperFlag _VhostFields[] =
{
	{ VF_LOGIN,		"login"		},
	{ VF_PASSWORD,		"password"	},
	{ VF_SWHOIS,		"swhois"	},
	{ VF_USERHOST,		"userhost"	},
	{ VF_VHOST,		"vhost"		},
};

ModuleHeader MOD_HEADER(vhosts)
  = {
	"m_vhosts",
	"$Id: m_vhosts.c,v 2.4 2004/06/07 09:07:05 angrywolf Exp $",
	"Vhosts manager",
	"3.2-b8-1",
	NULL 
    };

DLLFUNC int MOD_INIT(vhosts)(ModuleInfo *modinfo)
{
	ExternalVhosts	= NULL;

#ifdef STATIC_LINKING
	HookConfRehash	= HookAddEx(modinfo->handle, HOOKTYPE_REHASH, cb_config_rehash);
	HookRehashDone	= HookAddEx(modinfo->handle, HOOKTYPE_REHASH_COMPLETE, cb_rehash_complete);
#endif

	return add_commands(modinfo->handle);
}

DLLFUNC int MOD_LOAD(vhosts)(int module_load)
{
	load_vhosts();
	return MOD_SUCCESS;
}

DLLFUNC int MOD_UNLOAD(vhosts)(int module_unload)
{
	free_extvhosts();
	del_commands();

#ifdef STATIC_LINKING
	DelHook(HookRehashDone);
	DelHook(HookConfRehash);
#endif

	return MOD_SUCCESS;
}

#ifdef STATIC_LINKING
static int cb_config_rehash()
{
	free_extvhosts();
	return 0;
}

static int cb_rehash_complete()
{
	load_vhosts();
	return 0;
}
#endif

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

static int add_commands(Module *module)
{
	CmdInfo		*p;
	int		ret = MOD_SUCCESS;

	for (p = VhostCommands; p->msg; p++)
	{
		p->cmd = AddCommand(module, p->msg, p->tok, p->func);
		if (!p->cmd)
			ret = MOD_FAILED;
	}

	return ret;
}

static void del_commands()
{
	CmdInfo *p;

	for (p = VhostCommands; p->msg; p++)
	{
		DelCommand(p->cmd);
	}	
}

// =========================================================================

static void free_vhost(ConfigItem_vhost *vhost)
{
	ListStruct		*next;
	ConfigItem_oper_from	*from;

	ircfree(vhost->login);
	ircfree(vhost->virthost);
	ircfree(vhost->virtuser);
	ircfree(vhost->swhois);
	Auth_DeleteAuthStruct(vhost->auth);

	FromLoop2(from, vhost->from, next)
	{
		next = (ListStruct *) from->next;
		DelListItem(from, vhost->from);
		ircfree(from->name);
		MyFree(from);
	}

	MyFree(vhost);
}

static void free_extvhosts()
{
	BlockList		*p;
	ListStruct		*next;

	for (p = ExternalVhosts; p; p = (BlockList *) next)
	{
		next = (ListStruct *) p->next;
		DelListItem(p, ExternalVhosts);
		MyFree(p);
	}
}

static BlockList *FindExternalVhost(ConfigItem_vhost *vhost)
{
	BlockList *p;
	
	for (p = ExternalVhosts; p; p = p->next)
		if (p->vhost == vhost)
			break;

	return p;
}

static void AddExternalVhost(ConfigItem_vhost *vhost)
{
	BlockList *p;

	p = (BlockList *) MyMalloc(sizeof(BlockList));
	p->vhost = vhost;

	AddListItem(p, ExternalVhosts);
}

inline static void DelExternalVhost(BlockList *extvhost)
{
	DelListItem(extvhost, ExternalVhosts);
	MyFree(extvhost);
}

// =========================================================================

#define VF_TABLESIZE		sizeof(_VhostFields)/sizeof(_VhostFields[0])

#ifndef _WIN32
 #define OpenFile(fd, file, flags) fd = open(file, flags, S_IRUSR|S_IWUSR)
#else
 #define OpenFile(fd, file, flags) fd = open(file, flags, S_IREAD|S_IWRITE)
#endif

#define R_SAFE(x) \
	do { \
		if ((x)) \
		{ \
			close(fd); \
			if (vhost) \
				free_vhost(vhost); \
			config_error("Read error on %s", VHOST_DB); \
			return -1; \
		} \
	} while (0)

#define RF_SAFE(x) \
	do { \
		if ((x)) \
		{ \
			close(fd); \
			if (vhost) \
				free_vhost(vhost); \
			ircfree(from); \
			config_error("Read error on %s", VHOST_DB); \
			return -1; \
		} \
	} while (0)

#define W_SAFE(x) \
	do { \
		if ((x)) \
		{ \
			close(fd); \
			config_error("Write error on %s", VHOST_DB); \
			return -1; \
		} \
	} while (0)

static inline int read_data(int fd, void *buf, size_t count)
{
	if ((size_t) read(fd, buf, count) < count)
		return -1;

	return 0;
}

static inline int write_data(int fd, void *buf, size_t count)
{
	if ((size_t) write(fd, buf, count) < count)
		return -1;

	return 0;
}

static int write_str(int fd, char *x)
{
	size_t count = x ? strlen(x) : 0;

	if (write_data(fd, &count, sizeof count))
		return -1;
	if (count)
	{
		if (write_data(fd, x, sizeof(char) * count))
			return -1;
	}

	return 0;
}

static int read_str(int fd, char **x)
{
	size_t count;

	if (read_data(fd, &count, sizeof count))
		return -1;
	if (!count)
	{
		*x = NULL;
		return 0;
	}
	*x = (char *) MyMalloc(sizeof(char) * count + 1);
	if (read_data(fd, *x, sizeof(char) * count))
	{
		MyFree(*x);
		*x = NULL;
		return -1;
	}
	(*x)[count] = 0;

	return 0;
}

static int save_vhosts()
{
	ConfigItem_vhost	*vhost;
	ConfigItem_oper_from	*from;
	int			fd;
	size_t			count, fromcount;

	OpenFile(fd, VHOST_DB, O_CREAT | O_WRONLY | O_TRUNC);

	if (fd == -1)
	{
		config_status("error opening %s for writing: %s",
			VHOST_DB, strerror(errno));
		return -1;
	}

	W_SAFE(write_data(fd, &vhost_db_version, sizeof vhost_db_version));

	count = 0;
	for (vhost = conf_vhost; vhost; vhost = (ConfigItem_vhost *) vhost->next)
		if (FindExternalVhost(vhost))
			count++;
	W_SAFE(write_data(fd, &count, sizeof count));

	for (vhost = conf_vhost; vhost; vhost = (ConfigItem_vhost *) vhost->next)
	{
		if (!FindExternalVhost(vhost))
			continue;

		W_SAFE(write_str(fd, vhost->login));
		W_SAFE(write_str(fd, vhost->virthost));
		W_SAFE(write_str(fd, vhost->virtuser));
		W_SAFE(write_str(fd, vhost->swhois));
		W_SAFE(write_str(fd, vhost->auth->data));
		W_SAFE(write_data(fd, &vhost->auth->type, sizeof vhost->auth->type));

		fromcount = 0;
		FromLoop(from, vhost->from)
			fromcount++;
		W_SAFE(write_data(fd, &fromcount, sizeof fromcount));
		
		FromLoop(from, vhost->from)
			W_SAFE(write_str(fd, from->name));
	}

	close(fd);
	return 0;
}

static int load_vhosts()
{
	ConfigItem_vhost	*vhost = NULL;
	ConfigItem_oper_from	*from = NULL;
	int			fd;
	size_t			count, fromcount, i, j;
	unsigned		version;

	OpenFile(fd, VHOST_DB, O_RDONLY);

	if (fd == -1)
	{
		if (errno != ENOENT)
			config_status("error opening %s for reading: %s",
				VHOST_DB, strerror(errno));
		return -1;
	}

	R_SAFE(read_data(fd, &version, sizeof version));

	if (version != vhost_db_version)
	{
		config_status("File %s has a wrong database version (expected: %u, got: %u)",
			VHOST_DB, vhost_db_version, version);
		close(fd);
		return -1;
	}

	R_SAFE(read_data(fd, &count, sizeof count));

	for (i = 1; i <= count; i++)
	{
		from = NULL;
		vhost = MyMallocEx(sizeof(ConfigItem_vhost));
		vhost->auth = (anAuthStruct *) MyMallocEx(sizeof(anAuthStruct));

		R_SAFE(read_str(fd, &vhost->login));
		R_SAFE(read_str(fd, &vhost->virthost));
		R_SAFE(read_str(fd, &vhost->virtuser));
		R_SAFE(read_str(fd, &vhost->swhois));
		R_SAFE(read_str(fd, &vhost->auth->data));
		R_SAFE(read_data(fd, &vhost->auth->type, sizeof vhost->auth->type));
		R_SAFE(read_data(fd, &fromcount, sizeof fromcount));

		for (j = 1; j <= fromcount; j++)
		{
			from = NewFrom;
			RF_SAFE(read_str(fd, &from->name));
			AddListItem(from, vhost->from);
		}

		if (Find_vhost(vhost->login))
		{
			char *oldlogin = vhost->login;

			config_status("Warning: can't add an external vhost block with login '%s', "
				"an other one with the same login already exists; renaming the new one to '_%s'",
				oldlogin, oldlogin);

			vhost->login = (char *) MyMallocEx(strlen(oldlogin) + 2);
			*vhost->login = '_';
			strcat(vhost->login, oldlogin);
			MyFree(oldlogin);
		}

		AddListItem(vhost, conf_vhost);
		AddExternalVhost(vhost);
	}

	close(fd);
	return 0;
}

// =========================================================================

/*
 * Auth_CheckError2:
 *	makes sure password and authtype are valid
 */
 
static int Auth_CheckError2(aClient *sptr, char *password, short type)
{
#ifdef AUTHENABLE_SSL_CLIENTCERT
        X509 *x509_filecert = NULL;
        FILE *x509_f = NULL;
#endif

        switch (type)
        {
#ifdef AUTHENABLE_UNIXCRYPT
                case AUTHTYPE_UNIXCRYPT:
                        /* If our data is like 1 or none, we just let em through .. */
                        if (strlen(password) < 2)
                        {
    				sendnotice(sptr, "*** AUTHTYPE_UNIXCRYPT: no salt (crypt strings will always be >2 in length)");
				return 0;
                        }
                        break;
#endif
#ifdef AUTHENABLE_SSL_CLIENTCERT
                case AUTHTYPE_SSL_CLIENTCERT:
                        if (!(x509_f = fopen(password, "r")))
                        {
    				sendnotice(sptr, "*** AUTHTYPE_SSL_CLIENTCERT: error opening file %s",
					password);
				return 0;
                        }
                        x509_filecert = PEM_read_X509(x509_f, NULL, NULL, NULL);
                        fclose(x509_f);
                        if (!x509_filecert)
                        {
    				sendnotice(sptr, "*** AUTHTYPE_SSL_CLIENTCERT: PEM_read_X509 errored in file %s (format error?)",
					password);
                                return 0;
                        }
                        X509_free(x509_filecert);
                        break;
#endif
                default: ;
	}

	return 1;
}

/*
 * Auth_Convert2:
 *	converts password and authtype to anAuthStruct
 */

static anAuthStruct *Auth_Convert2(char *password, short type)
{
        anAuthStruct    *as;

        as		= (anAuthStruct *) MyMalloc(sizeof(anAuthStruct));
        as->data	= strdup(password);
	as->type	= type; 

        return as;
}

/*
 * Auth_FindName:
 *	finds an authentication method name (used by /confvhost)
 */
 
static char *Auth_FindName(short type)
{
        anAuthStruct *p;

	for (p = AuthTypes; p->data; p++)
                if (p->type == type)
                        break;

	return p->data;
}

static anAuthStruct *Auth_DoAll(aClient *sptr, char *password, char *authtype)
{
	short	type;
	char	*encpass = NULL;

	if ((type = Auth_FindType(authtype)) == -1)
	{
		sendnotice(sptr, "*** %s is not a supported authentication method",
			authtype);
		return NULL;
	}
	if (!Auth_CheckError2(sptr, password, type))
	{
		/* error message already sent */
		return NULL;
	}

	if (type == AUTHTYPE_SSL_CLIENTCERT)
		encpass = password;
	else if (!(encpass = Auth_Make(type, password)))
	{
    		sendnotice(sptr, "*** Authentication method %s failed", authtype);
		return NULL;
	}

	return Auth_Convert2(encpass, type);
}

// =========================================================================

static u_int check_userhost(char **user, char **host, u_int needuser, u_int charscheck)
{
	char *p;

	*user = NULL;

	if ((p = strchr(*host, '@')))
	{
		if (p == *host || !p[1])
			return 0;

		*p = 0;
		*user = *host;
		*host = p+1;
	}
	else if (needuser)
		return 0;

	if (charscheck)
	{
		if (*user)
		{
			if (**user != '~' && !isallowed(**user))
				return 0;
			for (p = *user + 1; *p; p++)
				if (!isallowed(*p))
					return 0;
		}

		if (!valid_host(*host))
			return 0;
	}

	return 1;
}

/*
 * is_valid_mask: 
 *	checks whether a mask is in a correct user@host form
 *      returns NULL on error, otherwise a pointer to '@'.
 */

static char *is_valid_mask(char *mask)
{
        char *p, *mid;

	/* '@' */
        if (!*mask || (!(mid = strchr(mask, '@'))))
		return NULL;
        if (mid == mask || !mid[1])
                return NULL;

	/* username */
	if (*mask != '~' && *mask != '*' && *mask != '?' && !isallowed(*mask))
		return NULL;
	for (p = mask + 1; p < mid; p++)
		if (*p != '*' && *p != '?' && !isallowed(*p))
			return NULL;

	/* hostname */
	for (p = mid + 1; *p; p++)
		if ((*p != '*') && (*p != '?') && (*p != '_') && (*p != '-')
		    && (*p != '.') && (*p != ':') && !isalnum(*p))
			return NULL;

        return mid;
}

/*
 * check_all_masks:
 * 	Checks all user@host masks for validity in a string separated by
 *      spaces. Returns the first bad mask, or NULL if all masks are valid.
 */

static char *check_all_masks(char *userhosts)
{
	char	*m, *p = NULL;
	char	*str = strdup(userhosts);

	for (m = strtoken(&p, str, " "); m; m = strtoken(&p, NULL, " "))
		if (!is_valid_mask(m))
		{
			strcpy(buf, m);
			ircfree(str);
			return buf;
		}

	ircfree(str);
	return NULL;
}

static void add_userhosts(ConfigItem_vhost *vhost, char *userhosts)
{
	ConfigItem_oper_from	*from;
	char			*str = strdup(userhosts);
	char			*tmp, *p = NULL;

	for (tmp = strtoken(&p, str, " "); tmp; tmp = strtoken(&p, NULL, " "))
	{
		FromLoop(from, vhost->from)
            		if (!strcmp(from->name, tmp))
            			break;
		if (from)
			continue;

		from = NewFrom;
		from->name = strdup(tmp);
		AddListItem(from, vhost->from);
	}

	ircfree(str);
}

static int check_target(aClient *cptr, aClient *sptr, char *command,
                        char *token, int global, int parc, char *parv[])
{
	static char	format[] = "%s %s %s %s %s %s %s %s";
	int		ret = 0;

	/* parc > 1 */
	format[(parc - 1) * 3 - 1] = 0;

	if (global)
		sendto_serv_butone_token(cptr, sptr->name, command, token,
			format, parv[1], parv[2], parv[3], parv[4],
			parv[5], parv[6], parv[7], parv[8]);
	else
		ret = hunt_server_token(cptr, sptr, command, token,
			format, 1, parc, parv);
	
	format[(parc - 1) * 3 - 1] = ' ';
	return ret;
}

static unsigned has_privileges(aClient *sptr, int remote)
{
	if (!IsPerson(sptr))
		return 0;

	if (!remote)
	{
		if (!IsSAdmin(sptr) && !IsNetAdmin(sptr))
			return 0;
	}
	else
	{
    		if (!IsSkoAdmin(sptr))
			return 0;
	}

	return 1;
}

static char *make_vhost(char *user, char *host)
{
	static char buf[BUFSIZE + 1];

	if (user)
		return make_user_host(user, host);

	return strcpy(buf, host);
}

/*
** 		ADDVHOST/ADDGVHOST	ADDRVHOST
** parv[0] =	sender prefix		sender prefix
** parv[1] =	login			server mask
** parv[2] =	password		login
** parv[3] =	vhost (user@host)	password
** parv[4] =	userhosts		vhost (user@host)
** parv[5] =				userhosts
*/

static int add_vhost(aClient *sptr, char *login, char *password, char *host,
                     char *userhosts)
{
	ConfigItem_vhost	*vhost = NULL;
	anAuthStruct		*auth;
	char			*authtype, *user, *tmp;

	if (Find_vhost(login))
	{
    		sendnotice(sptr, "*** A vhost with login %s already exists", login);
		return 0;
	}
	if (!check_userhost(&authtype, &password, 0, 0)) /* <== trick :) */
	{
    		sendnotice(sptr, "*** Bad syntax for password");
		return 0;
	}
	if (!check_userhost(&user, &host, 0, 1))
	{
    		sendnotice(sptr, "*** Bad syntax for vhost or it has invalid characters");
		return 0;
	}
	if (userhosts && (tmp = check_all_masks(userhosts)))
	{
    		sendnotice(sptr, "*** Bad mask '%s'", tmp);
		return 0;
	}

	if (!authtype)
		authtype = "plain";
	if (!(auth = Auth_DoAll(sptr, password, authtype)))
		return 0;

	vhost		= MyMallocEx(sizeof(ConfigItem_vhost));
	vhost->login	= strdup(login);
	vhost->virthost	= strdup(host);
	vhost->virtuser	= user ? strdup(user) : NULL;
	vhost->auth	= auth;

	add_userhosts(vhost, userhosts ? userhosts : "*@*");
	AddListItem(vhost, conf_vhost);
	AddExternalVhost(vhost);
	save_vhosts();

	tmp = make_vhost(user, host);
    	sendnotice(sptr, "*** Vhost %s added succesfully", tmp);
	ircsprintf(buf, "*** [%s] Vhost %s added by %s (login: %s, userhosts: %s)",
		me.name, tmp, sptr->name, login,
		userhosts ? userhosts : "*@*");
	sendto_snomask(SNO_EYES, "%s", buf);
	sendto_serv_butone_token(NULL, me.name, MSG_SENDSNO, TOK_SENDSNO, "e :%s", buf);

	return 0;
}

static CMD_FUNC(m_addvhost)
{
        if (!has_privileges(sptr, 0))
        {
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
                return -1;
        }
        if (IsNotParam(3))
	{
    		sendnotice(sptr, "*** Usage:    /addvhost <login> [<auth-type>@]<password> [<user>@]<vhost> [:][<userhost masks>]");
    		sendnotice(sptr, "*** Examples: /addvhost newlogin newpass user@domain.com");
    		sendnotice(sptr, "***           /addvhost newlogin crypt@newpass new.domain.com :*@host1.* *@host2.*");
                return 0;
        }

	add_vhost(sptr, parv[1], parv[2], parv[3],
		IsParam(4) ? parv[4] : NULL);

	return 0;
}

static CMD_FUNC(m_addrvhost)
{
        if (!has_privileges(sptr, 1))
        {
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
                return 0;
        }
        if (IsNotParam(4))
	{
    		sendnotice(sptr, "*** Usage:    /addvhost <servermask> <login> [<auth-type>@]<password> [<user>@]<vhost> [:][<userhost masks>]");
    		sendnotice(sptr, "*** Examples: /addvhost irc.server.com newlogin newpass user@domain.com");
    		sendnotice(sptr, "***           /addvhost server2.* newlogin crypt@newpass new.domain.com :*@host1.* *@host2.*");
                return 0;
        }

	if (check_target(cptr, sptr, "ADDRVHOST", "VRA", 0, parc,
	    parv) == HUNTED_ISME)
	{
		add_vhost(sptr, parv[2], parv[3], parv[4],
			IsParam(5) ? parv[5] : NULL);
	}

	return 0;
}

static CMD_FUNC(m_addgvhost)
{
        if (!has_privileges(sptr, 1))
        {
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
                return 0;
        }
        if (IsNotParam(3))
	{
    		sendnotice(sptr, "*** Usage:    /addgvhost <login> [<auth-type>@]<password> [<user>@]<vhost> [:][<userhost masks>]");
    		sendnotice(sptr, "*** Examples: /addgvhost newlogin newpass user@domain.com");
    		sendnotice(sptr, "***           /addgvhost newlogin crypt@newpass new.domain.com :*@host1.* *@host2.*");
                return 0;
        }

	check_target(cptr, sptr, "ADDGVHOST", "VGA", 1, parc, parv);
	add_vhost(sptr, parv[1], parv[2], parv[3],
		IsParam(4) ? parv[4] : NULL);

	return 0;
}

/*
** 		DELVHOST/DELGVHOST	DELRVHOST
** parv[0] =	sender prefix		sender prefix
** parv[1] =	login name		server mask
** parv[2] =				login name
*/

static int del_vhost(aClient *sptr, char *login)
{
        ConfigItem_vhost	*vhost;
	BlockList		*extvhost;
	char			*tmp;

        if (!(vhost = Find_vhost(login)))
	{
    		sendnotice(sptr, "*** Couldn't find a vhost with login name %s",
			login);
		return 0;
	}
        if (!(extvhost = FindExternalVhost(vhost)))
	{
    		sendnotice(sptr, "*** No vhost is not present with login name %s in the external O:Line database",
	                login);
		return 0;
	}

	tmp = make_vhost(vhost->virtuser, vhost->virthost);

	DelListItem(vhost, conf_vhost);
	DelExternalVhost(extvhost);
	free_vhost(vhost);
	save_vhosts();

    	sendnotice(sptr, "*** Vhost %s deleted succesfully", tmp);
	ircsprintf(buf, "*** [%s] Vhost %s deleted by %s", me.name, tmp, sptr->name);
	sendto_snomask(SNO_EYES, "%s", buf);
	sendto_serv_butone_token(NULL, me.name, MSG_SENDSNO, TOK_SENDSNO, "e :%s", buf);

	return 0;
}

static CMD_FUNC(m_delvhost)
{
        if (!has_privileges(sptr, 0))
        {
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
                return -1;
        }
        if (IsNotParam(1))
	{
    		sendnotice(sptr, "*** Usage: /delvhost <login>");
                return 0;
        }

	del_vhost(sptr, parv[1]);
	return 0;
}

static CMD_FUNC(m_delrvhost)
{
        if (!has_privileges(sptr, 1))
        {
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
                return -1;
        }
        if (IsNotParam(2))
	{
    		sendnotice(sptr, "*** Usage: /delrvhost <servermask> <login>");
                return 0;
        }

	if (check_target(cptr, sptr, "DELRVHOST", "VRD", 0, parc,
	    parv) == HUNTED_ISME)
		del_vhost(sptr, parv[2]);
	
	return 0;
}

static CMD_FUNC(m_delgvhost)
{
        if (!has_privileges(sptr, 1))
        {
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
                return -1;
        }
        if (IsNotParam(1))
	{
    		sendnotice(sptr, "*** Usage: /delgvhost <login>");
                return 0;
        }

	check_target(cptr, sptr, "DELGVHOST", "VGD", 1, parc, parv);
	del_vhost(sptr, parv[1]);

	return 0;
}

/*
** 		MODVHOST/MODGVHOST	MODRVHOST
** parv[0] =	sender prefix		sender prefix
** parv[1] =	login			server mask
** parv[2] =	option			login
** parv[3] =	value			option
** parv[4] =	encryption type		value
** parv[5] =				encryption type
*/

#define CHECKVALUE \
		if (!value) \
		{ \
            		sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), \
                		me.name, sptr->name, cmd); \
            		return 0; \
    		}

static int mod_vhost(aClient *sptr, char *cmd, char *login, char *option,
                    char *value, char *enctype)
{
        ConfigItem_vhost	*vhost;
	char			*virthost;
	OperFlag		*vf;

	if (!(vf = config_binary_flags_search(_VhostFields, option, VF_TABLESIZE)))
	{
    		sendnotice(sptr, "*** Invalid option %s", option);
		return 0;
	}
        if (!(vhost = Find_vhost(login)))
	{
    		sendnotice(sptr, "*** Couldn't find a vhost with login name %s", login);
		return 0;
	}
        if (!FindExternalVhost(vhost))
	{
    		sendnotice(sptr, "*** No vhost is not present with login name %s in the external O:Line database",
	                login);
		return 0;
	}

	virthost = make_vhost(vhost->virtuser, vhost->virthost);

	switch (vf->flag)
	{
		/* login */
		case VF_LOGIN:
		{
			CHECKVALUE

			if (strchr(value, SPACE))
			{
    				sendnotice(sptr, "*** Login names may not contain spaces");
				return 0;
			}
    			if (Find_vhost(value))
			{
    				sendnotice(sptr, "*** A vhost with login name %s already exists",
					value);
				return 0;
			}

    			ircfree(vhost->login);
			vhost->login = strdup(value);

			ircsprintf(buf, "%s changed the login name for vhost %s to %s",
				sptr->name, virthost, value);
			break;
		}

		/* swhois */
		case VF_SWHOIS:
		{
    			ircfree(vhost->swhois);

			if (value)
			{
				vhost->swhois = strdup(value);

				ircsprintf(buf, "%s changed the SWHOIS information of vhost %s to %s",
					sptr->name, virthost, value);
			}
			else
				ircsprintf(buf, "%s removed the SWHOIS information from vhost %s",
					sptr->name, virthost);
			break;
		}

		/* vhost */
		case VF_VHOST:
		{
			char *user;

			CHECKVALUE

			if (strchr(value, SPACE))
			{
    				sendnotice(sptr, "*** Vhosts may not contain spaces");
				return 0;
			}
			if (!check_userhost(&user, &value, 0, 1))
			{
    				sendnotice(sptr, "*** Bad syntax for vhost or it has invalid characters");
				return 0;
			}

    	    		ircfree(vhost->virtuser);
    	    		ircfree(vhost->virthost);
			vhost->virtuser = user ? strdup(user) : NULL;
			vhost->virthost = strdup(value);

			ircsprintf(buf, "%s changed vhost %s to %s%s%s",
				sptr->name, virthost,
				user ? user : "", user ? "@" : "",
				value);

			break;
		}

		/* userhost */
		case VF_USERHOST:
		{
    			unsigned		add = 1;
    			ConfigItem_oper_from	*from;

			CHECKVALUE

			if (strchr(value, SPACE))
			{
    				sendnotice(sptr, "*** Userhosts may not contain spaces");
				return 0;
			}

    			if (*value == '-')
    			{
            			add = 0;
                		value++;
        		}
        		else if (*value == '+')
        	    		value++;

			if (!is_valid_mask(value))
			{
    				sendnotice(sptr, "*** Bad mask '%s'", value);
				return 0;
			}

			FromLoop(from, vhost->from)
            			if (!strcmp(from->name, value))
                    			break;

			if (add)
			{
				if (from)
				{
    					sendnotice(sptr, "*** Mask %s already added",
						value);
					return 0;
				}

				from = NewFrom;
				from->name = strdup(value);
				AddListItem(from, vhost->from);

				ircsprintf(buf, "%s added userhost '%s' for vhost %s",
					sptr->name, value, virthost);
    			}
			else /* del */
			{
				if (!from)
				{
    					sendnotice(sptr, "*** Mask %s not found",
						value);
					return 0;
				}

            			DelListItem(from, vhost->from);
            			ircfree(from->name);
            			MyFree(from);

				/* add mask *@* if vhost->from is NULL */
				if (!vhost->from)
				{
					from = NewFrom;
					from->name = strdup("*@*");
					AddListItem(from, vhost->from);
				}

				ircsprintf(buf, "%s removed userhost '%s' from vhost %s",
					sptr->name, value, virthost);
   			}
			break;
		}

		/* password */
		case VF_PASSWORD:
		{
			anAuthStruct	*auth;
			char		*authtype;

			CHECKVALUE

			if (enctype)
			{
				authtype = value;
				value    = enctype;
			}
			else
				authtype = "plain";

			if (strchr(value, SPACE))
			{
    				sendnotice(sptr, "*** Passwords may not contain spaces");
				return 0;
			}
			if (!(auth = Auth_DoAll(sptr, value, authtype)))
				return 0;

    			Auth_DeleteAuthStruct(vhost->auth);
			vhost->auth = auth;

			ircsprintf(buf, "%s set a new password for vhost %s",
				sptr->name, virthost);
			break;
		}
	}

	save_vhosts();

	sendnotice(sptr, "*** Vhost %s modified succesfully", virthost);
	sendto_snomask(SNO_EYES, "*** [%s] %s", me.name, buf);
	sendto_serv_butone_token(NULL, me.name, MSG_SENDSNO, TOK_SENDSNO,
		"e :*** [%s] %s", me.name, buf);

	return 0;
}

static CMD_FUNC(m_modvhost)
{
        if (!has_privileges(sptr, 0))
        {
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
                return -1;
        }
        if (IsNotParam(2))
	{
    		sendnotice(sptr, "*** Usage:    /modvhost <login> login|vhost <value>");
    		sendnotice(sptr, "***           /modvhost <login> swhois [:][<value>]");
    		sendnotice(sptr, "***           /modvhost <login> password [<auth method>] <password>");
    		sendnotice(sptr, "***           /modvhost <login> userhost +|-<mask>");
    		sendnotice(sptr, "*** Examples: /modvhost someone vhost someone@somewhere.com");
    		sendnotice(sptr, "***           /modvhost someone swhois :This is the new swhois info");
    		sendnotice(sptr, "***           /modvhost someone password crypt newpass");
                return 0;
        }

	mod_vhost(sptr, "MODVHOST", parv[1], parv[2],
		IsParam(3) ? parv[3] : NULL,
		IsParam(4) ? parv[4] : NULL);

	return 0;
}

static CMD_FUNC(m_modrvhost)
{
        if (!has_privileges(sptr, 1))
        {
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
                return 0;
        }
        if (IsNotParam(3))
	{
    		sendnotice(sptr, "*** Usage:    /modvhost <servermask> <login> login|vhost <value>");
    		sendnotice(sptr, "***           /modvhost <servermask> <login> swhois [:][<value>]");
    		sendnotice(sptr, "***           /modvhost <servermask> <login> password [<auth method>] <password>");
    		sendnotice(sptr, "***           /modvhost <servermask> <login> userhost +|-<mask>");
    		sendnotice(sptr, "*** Examples: /modvhost server2.* someone vhost someone@somewhere.com");
    		sendnotice(sptr, "***           /modvhost irc.* someone swhois :This is the new swhois info");
    		sendnotice(sptr, "***           /modvhost server1.* someone password crypt newpass");
                return 0;
        }

	if (check_target(cptr, sptr, "MODRVHOST", "VRM", 0, parc,
	    parv) == HUNTED_ISME)
	{
		mod_vhost(sptr, "MODRVHOST", parv[2], parv[3],
			IsParam(4) ? parv[4] : NULL,
			IsParam(5) ? parv[5] : NULL);
	}

	return 0;
}

static CMD_FUNC(m_modgvhost)
{
        if (!has_privileges(sptr, 1))
        {
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
                return 0;
        }
        if (IsNotParam(2))
	{
    		sendnotice(sptr, "*** Usage:    /modvhost <login> login|vhost <value>");
    		sendnotice(sptr, "***           /modvhost <login> swhois [:][<value>]");
    		sendnotice(sptr, "***           /modvhost <login> password [<auth method>] <password>");
    		sendnotice(sptr, "***           /modvhost <login> userhost +|-<mask>");
    		sendnotice(sptr, "*** Examples: /modvhost someone vhost someone@somewhere.com");
    		sendnotice(sptr, "***           /modvhost someone swhois :This is the new swhois info");
    		sendnotice(sptr, "***           /modvhost someone password crypt newpass");
                return 0;
        }

	check_target(cptr, sptr, "MODGVHOST", "VGM", 1, parc, parv);
	mod_vhost(sptr, "MODGVHOST", parv[1], parv[2],
		IsParam(3) ? parv[3] : NULL,
		IsParam(4) ? parv[4] : NULL);

	return 0;
}

/*
** 		CONFVHOST		CONFRVHOST
** parv[0] =	sender prefix		sender prefix
** parv[1] =	login name		server mask
** parv[2] =				login name
*/

#define MaxSize		(sizeof(confstr) - strlen(confstr) - 1)

static int show_vhost(aClient *sptr, char *login)
{
	static char		confstr[BUFSIZE+1], tmp[BUFSIZE+1];
        ConfigItem_vhost	*vhost;
        ConfigItem_oper_from	*from;
	char			*authtype, *virthost;

        if (!(vhost = Find_vhost(login)))
	{
    		sendnotice(sptr, "*** Vhost %s does not exist", login);
		return 0;
	}

	memset(&confstr, 0, sizeof confstr);
	memset(&tmp, 0, sizeof tmp);
	virthost = make_vhost(vhost->virtuser, vhost->virthost);

	snprintf(confstr, sizeof confstr, "vhost { vhost %s; ",
		virthost);
	strncat(confstr, "from { ", MaxSize);
	FromLoop(from, vhost->from)
	{
		snprintf(tmp, sizeof tmp, "userhost \"%s\"; ", from->name);
		strncat(confstr, tmp, MaxSize);
	}
	strncat(confstr, "}; ", MaxSize);
	snprintf(tmp, sizeof tmp, "login %s; password \"%s\" { %s; }; ",
		vhost->login, vhost->auth->data,
		(authtype = Auth_FindName(vhost->auth->type)) ?
		authtype : "plain");
	strncat(confstr, tmp, MaxSize);
	if (vhost->swhois)
	{
		snprintf(tmp, sizeof tmp, "swhois \"%s\"; ", vhost->swhois);
		strncat(confstr, tmp, MaxSize);
	}
	strncat(confstr, "};", MaxSize);

    	sendnotice(sptr, "*** %s", confstr);
	return 0;
}

static CMD_FUNC(m_confvhost)
{
        if (!has_privileges(sptr, 0))
        {
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
                return -1;
        }
        if (IsNotParam(1))
	{
    		sendnotice(sptr, "*** Usage: /confvhost <login>");
                return 0;
        }

	show_vhost(sptr, parv[1]);
	return 0;
}

static CMD_FUNC(m_confrvhost)
{
        if (!has_privileges(sptr, 1))
        {
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
                return 0;
        }
        if (IsNotParam(2))
	{
    		sendnotice(sptr, "*** Usage: /confrvhost <servermask> <login>");
                return 0;
        }

	if (check_target(cptr, sptr, "CONFRVHOST", "VRC", 0, parc,
	    parv) == HUNTED_ISME)
		show_vhost(sptr, parv[2]);

	return 0;
}
