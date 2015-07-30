/*
 *   m_listconnected - /LCON command that lists users on a server
 *     by NovaSquirrel in 2012 to 2013
 *
 *   heavily based on an ircop lister by these people:
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

/*
 * Ultimate uses numerics 386 and 387 for RPL_IRCOPS and RPL_ENDOFIRCOPS,
 * but these numerics are RPL_QLIST and RPL_ENDOFQLIST in UnrealIRCd
 * (numeric conflict). I had to choose other numerics.
 */

#define RPL_IRCOPS        337
#define RPL_ENDOFIRCOPS   338
#define MSG_LISTCONNECTED        "LCON"
#define TOK_LISTCONNECTED        NULL
#define IsAway(x)         (x)->user->away

static int m_listconnected(aClient *cptr, aClient *sptr, int parc, char *parv[]);

ModuleHeader MOD_HEADER(m_listconnected)
  = {
    "listconnected",
    "0.06",
    "/LCON command that lists users on a server",
    "3.2-b8-1",
    NULL 
    };

DLLFUNC int MOD_INIT(m_listconnected)(ModuleInfo *modinfo) {
    if (CommandExists(MSG_LISTCONNECTED)) {
        config_error("Command " MSG_LISTCONNECTED " already exists");
        return MOD_FAILED;
    }
    CommandAdd(modinfo->handle, MSG_LISTCONNECTED, TOK_LISTCONNECTED, m_listconnected, MAXPARA, M_USER);

    if (ModuleGetError(modinfo->handle) != MODERR_NOERROR) {
        config_error("Error adding command " MSG_LISTCONNECTED ": %s",
            ModuleGetErrorStr(modinfo->handle));
        return MOD_FAILED;
    }

    return MOD_SUCCESS;
}

DLLFUNC int MOD_LOAD(m_listconnected)(int module_load) {
    return MOD_SUCCESS;
}

DLLFUNC int MOD_UNLOAD(m_listconnected)(int module_unload) {
    return MOD_SUCCESS;
}

static char *CreateChannelsString(char *Temp, aClient *acptr, int MaxChannels, int MaxChars) {
  strcpy(Temp, "");
  int ChanCount = 0;
  Membership *lp;
  for (lp = acptr->user->channel; lp; lp = lp->next, ChanCount++) {
    int access = get_access(acptr, lp->chptr);
    if(ChanCount > MaxChannels) {
      strcat(Temp, "...");
      break;
    }
    if (access & CHFL_CHANOWNER)
      strcat(Temp, "~");
    else if (access & CHFL_CHANPROT)
      strcat(Temp, "&");
    else if (access & CHFL_CHANOP)
      strcat(Temp, "@");
    else if (access & CHFL_HALFOP)
      strcat(Temp, "%");
    else if (access & CHFL_VOICE)
      strcat(Temp, "+");
    strcat(Temp, lp->chptr->chname);
    strcat(Temp, ", ");
  }
  if(strlen(Temp) < MaxChars)
    return Temp;
  else
    return "Channel list too long";
}

static int m_listconnected(aClient *cptr, aClient *sptr, int parc, char *parv[]) {
    if (!IsAnOper(sptr)) {
        sendto_one(sptr, ":%s %d %s :Access denied - this command is restricted to opers only", me.name, ERR_OPERONLY, sptr->name);
        return 0;
    }
    aClient *acptr;
    char Buffer[BUFSIZE];
    char Temp[256];

    int global = 0;
    int oper = 0;
    char *RequiredServer = me.name;
    int MaxChan = 9999;
    int MinChan = -1;

    int ShowChanCount = 1;
    int ShowRealHost = 0;
    int ShowCloakedHost = 0;
    int ShowServer = 0;
    int ShowVirtHost = 0;
    int ShowUmodes = 0;
    int ULinesOkay = 0;
    int OnlyUlines = 0;
    int JanusOkay = 0;
    int OnlyJanus = 0;
    int ShowChannels = 0;
    int ChannelsToShow = 8;

    int i;
    int UserCount = 0;
    for(i = 1; i < parc; i++) {
      if(!strcasecmp(parv[i],"-global"))
        RequiredServer = NULL;
      if(!strcasecmp(parv[i],"-oper"))
        oper = 1;
      if(!strcasecmp(parv[i],"-server") && i != parc-1)
        RequiredServer = parv[i+1];
      if(!strcasecmp(parv[i],"-minchan") && i != parc-1)
        MinChan = strtol(parv[i+1],NULL,10);
      if(!strcasecmp(parv[i],"-maxchan") && i != parc-1)
        MaxChan = strtol(parv[i+1],NULL,10);
      if(!strcasecmp(parv[i],"-nochan"))
        MaxChan = 0;
      if(!strcasecmp(parv[i],"-count"))       ShowChanCount = 1;
      if(!strcasecmp(parv[i],"-rhost"))        ShowRealHost = 1;
      if(!strcasecmp(parv[i],"-chost"))     ShowCloakedHost = 1;
      if(!strcasecmp(parv[i],"!showvirthost"))        ShowVirtHost = 1;
      if(!strcasecmp(parv[i],"!showserver"))          ShowServer = 1;
      if(!strcasecmp(parv[i],"!showumodes"))          ShowUmodes = 1;
      if(!strcasecmp(parv[i],"!ulinesokay"))          ULinesOkay = 1;
      if(!strcasecmp(parv[i],"!onlyulines"))          OnlyUlines = 1;
      if(!strcasecmp(parv[i],"!janusokay"))           JanusOkay = 1;
      if(!strcasecmp(parv[i],"!onlyjanus"))           OnlyJanus = 1;
      if(!strcasecmp(parv[i],"!showchannels"))        ShowChannels = 1;
      if(!strcasecmp(parv[i],"!showchannels#") && i != parc-1) {
        ShowChannels = 1;
        ChannelsToShow = strtol(parv[i+1],NULL,10);
      }
      if(!strcasecmp(parv[i],"!whois")) {
        if(i == parc-1) {
          sendto_one(sptr, ":%s %d %s :Help: /LCON !whois Nick", me.name, RPL_ENDOFIRCOPS, sptr->name);
          return 0;
        } else {
          char *Nick = parv[i+1];
          acptr = find_client(Nick, NULL);
          if(acptr == NULL) {
            sendto_one(sptr, ":%s %d %s :No client named \"%s\"?", me.name, ERR_NOSUCHNICK, sptr->name, Nick); 
            return 0;
          }
          if(IsServer(acptr) || !acptr->user || acptr->serv) {
            sendto_one(sptr, ":%s %d %s :Sorry, /LCON !Whois can't view servers (yet)", me.name, ERR_NOSUCHNICK, sptr->name);
            return 0;
          }

          sendto_one(sptr, ":%s %d %s :-Info for \2%s\2- (%i):%s", me.name, RPL_IRCOPS, sptr->name, acptr->name,
            acptr->hopcount, acptr->srvptr->name);

          sendto_one(sptr, ":%s %d %s :Modes:%.8x %s", me.name, RPL_IRCOPS, sptr->name, (unsigned int)acptr->umodes, get_mode_str(acptr));

          if(acptr->user->virthost)
            sendto_one(sptr, ":%s %d %s :%s@%s (%s)", me.name, RPL_IRCOPS, sptr->name, acptr->user->username, acptr->user->virthost, acptr->user->realhost);
          else
            sendto_one(sptr, ":%s %d %s :%s@%s", me.name, RPL_IRCOPS, sptr->name, acptr->user->username, acptr->user->realhost);
          if(acptr->user->away)
              sendto_one(sptr, ":%s %d %s :User is away: %s", me.name, RPL_IRCOPS, sptr->name, acptr->user->away);

          char Temp[4096] = "";
          sendto_one(sptr, ":%s %d %s :Chan#:%i %s", me.name, RPL_IRCOPS, sptr->name, acptr->user->joined, CreateChannelsString(Temp, acptr, 24, 300));
          sendto_one(sptr, ":%s %d %s :End of /LCON !Whois", me.name, RPL_ENDOFIRCOPS, sptr->name);
          return 0;

        }
      }
      if(!strcasecmp(parv[i],"!help")) {
        if(i == parc-1) {
          sendto_one(sptr, ":%s %d %s :Criteria: !global !oper !server !min !max !nochan !janusokay !ulinesokay", me.name, RPL_ENDOFIRCOPS, sptr->name);
          sendto_one(sptr, ":%s %d %s :What to view: !rhost !chost !vrthost !showserver !showchanels !showchannels# !showumodes", me.name, RPL_ENDOFIRCOPS, sptr->name);
        } else {
          char *HelpMsg = NULL;

          if(!strcasecmp(parv[i+1],"-global"))
            HelpMsg = "-global - All servers are searched";
          if(!strcasecmp(parv[i+1],"-oper"))
            HelpMsg = "-oper - Only ircops are shown";
          if(!strcasecmp(parv[i+1],"-server"))
            HelpMsg = "-server <server> - Search a different server than the one you are on";
          if(!strcasecmp(parv[i+1],"-minchan") || !strcasecmp(parv[i+1],"-maxchan"))
            HelpMsg = "-max/-min <#> - Set a max or min number of channels for users to show";
          if(!strcasecmp(parv[i+1],"-nochan"))
            HelpMsg = "-nochan - Only show users that aren't in any channels";
          if(!strcasecmp(parv[i+1],"-rhost") || !strcasecmp(parv[i+1],"-chost") || !strcasecmp(parv[i+1],"-vrthost"))
            HelpMsg = "-rhost/-chost/-vrthost | rhost - Shows the real host / chost - Shows the cloaked host / vrthost - Shows the virtual host";
          if(!strcasecmp(parv[i+1],"-showserver"))
            HelpMsg = "-showserver - Display the name of the server the user is on beside their nick";
          if(!strcasecmp(parv[i+1],"-showumodes"))
            HelpMsg = "-showumodes - Display the usermodes user has on beside their nick";
          if(!strcasecmp(parv[i+1],"-topchan"))
            HelpMsg = "-topchan - shows up to 8 channels the user is in";
          if(!strcasecmp(parv[i+1],"-chans"))
            HelpMsg = "-chans <#> - shows up to <#> channels the user is in";
          if(!strcasecmp(parv[i+1],"-janusokay"))
            HelpMsg = "-janusokay - users with / in their nicks are shown too";
          if(!strcasecmp(parv[i+1],"-onlyjanus"))
            HelpMsg = "-onlyjanus - only users with / in their nicks are shown";
          if(!strcasecmp(parv[i+1],"-ulinesokay"))
            HelpMsg = "-ulinesokay - ulined users are shown too";
          if(!strcasecmp(parv[i+1],"-onlyulines"))
            HelpMsg = "-onlyulines - only ulined users are shown";
          if(HelpMsg != NULL)
            sendto_one(sptr, ":%s %d %s :Help: %s", me.name, RPL_ENDOFIRCOPS, sptr->name, HelpMsg);
          else
            sendto_one(sptr, ":%s %d %s :No help for that parameter?", me.name, RPL_ENDOFIRCOPS, sptr->name);
        }
        return 0;
      }
    }

    for(acptr = client; acptr; acptr = acptr->next) {
        if(!IsPerson(acptr) || (IsULine(acptr)&&!ULinesOkay))
            continue;
        if((!IsULine(acptr)) && OnlyUlines)
            continue;
        if(oper && (!IsAnOper(acptr)))
            continue;
        if(acptr->user->joined > MaxChan || acptr->user->joined < MinChan)
            continue;
        if(strchr(acptr->name, '/') && !JanusOkay)
            continue;
//        if((!strchr(acptr->name, '/')) && OnlyJanus)
//            continue;
        if((RequiredServer==NULL) || !strcasecmp(acptr->user->server, RequiredServer)) {
            UserCount++;
            sprintf(Buffer, "%-16s - ", acptr->name);
            if(ShowChanCount) {
                sprintf(Temp, "Chan#:%2i, ", acptr->user->joined);
                strcat(Buffer, Temp);
            }
            if(ShowRealHost && acptr->user->realhost) {
                sprintf(Temp, "RHost: %s, ", acptr->user->realhost);
                strcat(Buffer, Temp);
            }
            if(ShowCloakedHost && acptr->user->cloakedhost) {
                sprintf(Temp, "CHost: %s, ", acptr->user->cloakedhost);
                strcat(Buffer, Temp);
            }
            if(ShowVirtHost && acptr->user->virthost) {
                sprintf(Temp, "VHost: %s, ", acptr->user->virthost);
                strcat(Buffer, Temp);
            }
            if(ShowServer) {
                sprintf(Temp, "Serv: %s, ", acptr->user->server);
                strcat(Buffer, Temp);
            }
            if(ShowUmodes) {
                sprintf(Temp, "Mode: %s, ", get_mode_str(acptr));
                strcat(Buffer, Temp);
            }
            if(ShowChannels) {
                char Chans[4096];
                sprintf(Temp, "Chan: (%s), ", CreateChannelsString(Chans, acptr, ChannelsToShow, 300));
                strcat(Buffer, Temp);
            }
            sendto_one(sptr, ":%s %d %s :%s", me.name, RPL_IRCOPS, sptr->name, Buffer);
        }
    }

    sendto_one(sptr, ":%s %d %s :End of /LCON list; %i users found", me.name, RPL_ENDOFIRCOPS, sptr->name, UserCount);
    return 0;
}
