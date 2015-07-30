    /*
     * This module implements a robust forwarding system
     * +F <#chan> channel mode to forward users to another channel
     * +B channel mode to prevent users from being forwarded to your channel
     * +Q user mode to prevent yourself from being forwarded to other channels
     * ~f extended bantype to forward specific users to another channel (overrides +F)
     *
     * Module copyright (c) 2009-2010 Ryan Schmidt <skizzerz@shoutwiki.com>
     * Licensed under the Creative Commons Attribution-Noncommercial-Share Alike 3.0 Unported License.
     * (CC-BY-NC-SA). See more details here: http://creativecommons.org/licenses/by-nc-sa/3.0/
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
    #ifdef STRIPBADWORDS
    #include "badwords.h"
    #endif
    #include <fcntl.h>
    #include "h.h"

    /***********
    ** CONFIG **
    ***********/
    //uncomment the line below if you wish to
    //allow opers with OperOverride to join +i,
    //etc. channels without having to explicitly
    // /invite themselves (still gets logged as OO)
    //#define BETTER_OVERRIDE

    ModuleHeader MOD_HEADER(m_forward)
      = {
       "m_forward",   /* Name of module */
       "$Id: m_forward.c, v1.0 2009/02/16 Skizzerz Exp $", /* Version */
       "robust forwarding system", /* Short description of module */
       "3.2-b8-1",
       NULL,
        };

    Cmode_t EXTCMODE_BANLINK = 0L;
    Cmode_t EXTCMODE_FORWARD = 0L;
    Cmode_t EXTCMODE_NOFORWARD = 0L;
    long EXTUMODE_NOFORWARD = 0;

    int Fmode_is_ok(aClient *sptr, aChannel *chptr, char *para, int checkt, int what);
    int Nmode_is_ok(aClient *sptr, aChannel *chptr, char *para, int checkt, int what);
    CmodeParam * Fmode_put_param(CmodeParam *lst, char *para);
    char *Fmode_get_param(CmodeParam *lst);
    char *Fmode_conv_param(char *param);
    void Fmode_free_param(CmodeParam *lst);
    CmodeParam *Fmode_dup_struct(CmodeParam *src);
    int mode_sjoin_check(aChannel *chptr, CmodeParam *ourx, CmodeParam *theirx);
    CmodeParam *Fmode_dup_struct(CmodeParam *src);
    Hook *HookJoin = NULL;
    static int cb_join(aClient *sptr, aChannel *chptr, char *parv[]);
    int do_forward(aClient *sptr, aChannel *chptr, char *channel, int type);
    char *hf_param(char *param);
    int hf_isBanned(aClient *sptr, aChannel *chptr, char *ban, int chktype);

    typedef struct {
       EXTCM_PAR_HEADER
       char val[68];
    } aModeF;

    #define BANLINK_TYPE_BAN 1     //mode +b
    #define BANLINK_TYPE_INVITE 2  //mode +i
    #define BANLINK_TYPE_OPER 3    //mode +O
    #define BANLINK_TYPE_ADMIN 4   //mode +A
    #define BANLINK_TYPE_SSL 5     //mode +z
    #define BANLINK_TYPE_REG 6     //mode +R
    #define HFBANCHAR 'f' //extended ban character for forwards
    #define FORWARD_SUCCESS 1

    Cmode *ModeFORWARD = NULL;
    Cmode *CmodeNOFORWARD = NULL;
    Umode *UmodeNOFORWARD = NULL;
    Extban *hfExtBan;

    DLLFUNC int MOD_INIT(m_forward)(ModuleInfo *modinfo)
    {
       ModuleSetOptions(modinfo->handle, MOD_OPT_PERM);
       
       CmodeInfo Freq;
       memset(&Freq, 0, sizeof(Freq));
       Freq.paracount = 1;
       Freq.is_ok = Fmode_is_ok;
       Freq.put_param = Fmode_put_param;
       Freq.get_param = Fmode_get_param;
       Freq.free_param = Fmode_free_param;
       Freq.sjoin_check = mode_sjoin_check;
       Freq.conv_param = Fmode_conv_param;
       Freq.dup_struct = Fmode_dup_struct;
       Freq.flag = 'F';
       ModeFORWARD = CmodeAdd(modinfo->handle, Freq, &EXTCMODE_BANLINK);
       HookJoin   = HookAddEx(modinfo->handle, HOOKTYPE_PRE_LOCAL_JOIN, cb_join);

       CmodeInfo Nreq;
       memset(&Nreq, 0, sizeof(Nreq));
       Nreq.paracount = 0;
       Nreq.is_ok = Nmode_is_ok;
       Nreq.sjoin_check = mode_sjoin_check;
       Nreq.flag = 'B';
       CmodeNOFORWARD = CmodeAdd(modinfo->handle, Nreq, &EXTCMODE_NOFORWARD);
       
       UmodeNOFORWARD = UmodeAdd(modinfo->handle, 'Q', UMODE_GLOBAL, NULL, &EXTUMODE_NOFORWARD);
       
       ExtbanInfo hfInfo;
       memset(&hfInfo, 0, sizeof(ExtbanInfo));
       hfInfo.flag = HFBANCHAR;
       hfInfo.conv_param = hf_param;
       hfInfo.is_banned = hf_isBanned;
       hfExtBan = ExtbanAdd(modinfo->handle, hfInfo);
       
       return MOD_SUCCESS;
    }

    DLLFUNC int MOD_LOAD(m_forward)(int module_load)
    {
       return MOD_SUCCESS;
    }


    DLLFUNC int MOD_UNLOAD(m_forward)(int module_unload)
    {
       return MOD_FAILED;
    }

    int Fmode_is_ok(aClient *sptr, aChannel *chptr, char *para, int checkt, int what)
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
       }
       else if (checkt == EXCHK_PARAM)
       {
          if (!para)
          {
             sendto_one(sptr, ":%s NOTICE %s :chanmode +F requires a channel as parameter", me.name, sptr->name);
             return 0;
          }
          if (strlen(para) > 32)
          {
                sendto_one(sptr, ":%s NOTICE %s :invalid parameter for chanmode +F", me.name, sptr->name);
                return 0;
          }
          if (!IsChannelName(para))
          {
             sendto_one(sptr, ":%s NOTICE %s :invalid parameter for chanmode +F", me.name, sptr->name);
             return 0;
          }
          return 1;
       }
       return 0;
    }

    int Nmode_is_ok(aClient *sptr, aChannel *chptr, char *para, int checkt, int what)
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
       }

       return 0;
    }

    CmodeParam * Fmode_put_param(CmodeParam *Fpara, char *para)
    {
       aModeF *r = (aModeF *)Fpara;
       if (!r)
       {
          /* Need to create one */
          r = (aModeF *)malloc(sizeof(aModeF));
          memset(r, 0, sizeof(aModeF));
          r->flag = 'F';
       }
       snprintf(r->val,33, "%s",para);
       return (CmodeParam *)r;
    }

    char *Fmode_get_param(CmodeParam *ypara)
    {
       aModeF *r = (aModeF *)ypara;

       if (!r)
          return NULL;

       return r->val;
    }

    char *Fmode_conv_param(char *param)
    {
        clean_channelname(param);
        return param;
    }


    void Fmode_free_param(CmodeParam *ypara)
    {
       aModeF *r = (aModeF *)ypara;
       free(r);
    }

    CmodeParam *Fmode_dup_struct(CmodeParam *src)
    {
       aModeF *n = (aModeF *)malloc(sizeof(aModeF));
       memcpy(n, src, sizeof(aModeF));
       return (CmodeParam *)n;
    }

    int mode_sjoin_check(aChannel *chptr, CmodeParam *ourx, CmodeParam *theirx)
    {
    aModeF *our = (aModeF *)ourx;
    aModeF *their = (aModeF *)theirx;

       if (our->val == their->val)
          return EXSJ_SAME;
       if (our->val > their->val)
          return EXSJ_WEWON;
       else
          return EXSJ_THEYWON;
    }

    static int cb_join(aClient *sptr, aChannel *chptr, char *parv[]) {
       aModeF   *p = NULL;
       aChannel *c = NULL;
       Ban *b = NULL;
       char banstr[512];
       char *rtype, *rchan, *rmask;
       int chmodeF = 0;
       int override = 0;
       char canjoin[6];
       char oomsg[512];

       if (can_join(sptr, sptr, chptr, NULL, NULL, parv) == 0)
       {
          //don't even bother
          return HOOK_CONTINUE;
       }
       
       canjoin[1] = '1';
       canjoin[2] = '1';
       canjoin[3] = '1';
       canjoin[4] = '1';
       canjoin[5] = '1';
       canjoin[6] = '1';
       override = ((IsAnOper(sptr) && OPCanOverride(sptr)) || IsULine(sptr));
       
    #ifndef BETTER_OVERRIDE
       // cool OperOverride feature disabled
       override = 0;
    #endif
       
       // Test for +F chmode
       if (chptr->mode.extmode & EXTCMODE_BANLINK)
       {
          p = (aModeF *) extcmode_get_struct(chptr->mode.extmodeparam, 'F');
          if (p && p->val)
          {
             // Test for +B chmode on target channel
             if (ChannelExists(p->val))
             {
                c = get_channel(sptr, p->val, 0);
                chmodeF = !(c->mode.extmode & EXTCMODE_NOFORWARD);
             }
             else
             {
                chmodeF = 1;
             }
          }
       }
       // Test for +Q umode
       if (sptr->umodes & EXTUMODE_NOFORWARD)
       {
          chmodeF = 0;
       }
       
       /* Testing order
        * 1: +A
        * 2: +O
        * 3: +z
        * 4: +R
        * 5: +i
        * 6: +b
        */
       if ((chptr->mode.mode & MODE_ADMONLY) && !IsSkoAdmin(sptr)) /* Admin-only chan */
       {
          canjoin[1] = '0';
          // No OperOverride allowed for this one
          if (chmodeF)
          {
             if (do_forward(sptr, chptr, p->val, BANLINK_TYPE_ADMIN) == FORWARD_SUCCESS)
             {
                return HOOK_DENY;
             }
             else
             {
                return HOOK_CONTINUE;
             }
          }
       }
       if ((chptr->mode.mode & MODE_OPERONLY) && !IsAnOper(sptr)) /* Oper-only chan */
       {
          canjoin[2] = '0';
          // No OperOverride allowed for this one
          if (chmodeF)
          {
             if (do_forward(sptr, chptr, p->val, BANLINK_TYPE_OPER) == FORWARD_SUCCESS)
             {
                return HOOK_DENY;
             }
             else
             {
                return HOOK_CONTINUE;
             }
          }
       }
       if ((chptr->mode.mode & MODE_ONLYSECURE) && !(sptr->umodes & UMODE_SECURE)) /* SSL connections only */
       {
          canjoin[3] = '0';
          // OperOverride is checked for in can_join() for this one
          if (chmodeF)
          {
             if (do_forward(sptr, chptr, p->val, BANLINK_TYPE_SSL) == FORWARD_SUCCESS)
             {
                return HOOK_DENY;
             }
             else
             {
                return HOOK_CONTINUE;
             }
          }
       }
       if ((chptr->mode.mode & MODE_RGSTRONLY) && !IsARegNick(sptr)) /* registered users only */
       {
          canjoin[4] = '0';
          if (override)
          {
             canjoin[4] = '1';
             sprintf(oomsg, "joined +R channel %s without invite", chptr->chname);
          }
          else if(chmodeF)
          {
             if (do_forward(sptr, chptr, p->val, BANLINK_TYPE_REG) == FORWARD_SUCCESS)
             {
                return HOOK_DENY;
             }
             else
             {
                return HOOK_CONTINUE;
             }
          }
       }
       if ((chptr->mode.mode & MODE_INVITEONLY) && !find_invex(chptr, sptr)) /* invite only */
       {
          canjoin[5] = '0';
          if (override)
          {
             canjoin[5] = '1';
             sprintf(oomsg, "joined +i channel %s without invite", chptr->chname);
          }
          else if(chmodeF)
          {
             if (do_forward(sptr, chptr, p->val, BANLINK_TYPE_INVITE) == FORWARD_SUCCESS)
             {
                return HOOK_DENY;
             }
             else
             {
                return HOOK_CONTINUE;
             }
          }
       }
       if (b = is_banned(sptr, chptr, BANCHK_JOIN))  /* user is banned? */
       {
          canjoin[6] = '0';
          if (override)
          {
             canjoin[6] = '1';
             sprintf(oomsg, "joined %s through ban", chptr->chname);
          }
          else
          {
             strncpy(banstr, b->banstr, sizeof(banstr));
             rtype = strtok(banstr, ":");
             if (strncmp(rtype, "~f", sizeof(rtype)) == 0 && !(sptr->umodes & EXTUMODE_NOFORWARD))
             {
                rchan = strtok(NULL, ":");
                rmask = strtok(NULL, ":");
                if ((!rchan || !rmask) && chmodeF)
                {
                   if (do_forward(sptr, chptr, p->val, BANLINK_TYPE_BAN) == FORWARD_SUCCESS)
                   {
                      return HOOK_DENY;
                   }
                   else
                   {
                      return HOOK_CONTINUE;
                   }
                }
                // Test for +B chmode on target channel
                if (ChannelExists(rchan))
                {
                   c = get_channel(sptr, rchan, 0);
                   if (!(c->mode.extmode & EXTCMODE_NOFORWARD))
                   {
                      if (do_forward(sptr, chptr, rchan, BANLINK_TYPE_BAN) == FORWARD_SUCCESS)
                      {
                         return HOOK_DENY;
                      }
                      else
                      {
                         return HOOK_CONTINUE;
                      }
                   }
                }
                else
                {
                   if (do_forward(sptr, chptr, rchan, BANLINK_TYPE_BAN) == FORWARD_SUCCESS)
                   {
                      return HOOK_DENY;
                   }
                   else
                   {
                      return HOOK_CONTINUE;
                   }
                }
             }
             else if (chmodeF)
             {
                if (do_forward(sptr, chptr, p->val, BANLINK_TYPE_BAN) == FORWARD_SUCCESS)
                {
                   return HOOK_DENY;
                }
                else
                {
                   return HOOK_CONTINUE;
                }
             }
          }
       }
       int i = 1;
       for (i; i<7; i++)
       {
          if (canjoin[i] == '0')
          {
             return HOOK_CONTINUE;
          }
       }
       if (override && oomsg != "")
       {
          if (!IsULine(sptr))
          {
             sendto_snomask(SNO_EYES,
                "*** OperOverride -- %s (%s@%s) %s",
                sptr->name, sptr->user->username, sptr->user->realhost,
                oomsg);

             ircd_log(LOG_OVERRIDE,"OVERRIDE: %s (%s@%s) %s",
                sptr->name, sptr->user->username, sptr->user->realhost,
                oomsg);
          }
          return HOOK_ALLOW;
       }
       // catches +k and stuff
       return HOOK_CONTINUE;
    }

    int do_forward(aClient *sptr, aChannel *chptr, char *channel, int type) {
       char desc[32];
       char *parv[3];
       aChannel *c;
       // if we can't join the target channel, quit early
       if(ChannelExists(channel))
       {
          c = get_channel(sptr, channel, 0);
          if(can_join(sptr, sptr, c, NULL, NULL, parv) != 0)
          {
             return 0;
          }
       }
       switch (type)
       {
          case BANLINK_TYPE_BAN:
             strncpy(desc, "you are banned", sizeof(desc));
             break;
          case BANLINK_TYPE_INVITE:
             strncpy(desc, "channel is invite only", sizeof(desc));
             break;
          case BANLINK_TYPE_OPER:
             strncpy(desc, "channel is oper only", sizeof(desc));
             break;
          case BANLINK_TYPE_ADMIN:
             strncpy(desc, "channel is admin only", sizeof(desc));
             break;
          case BANLINK_TYPE_SSL:
             strncpy(desc, "channel requires SSL", sizeof(desc));
             break;
          case BANLINK_TYPE_REG:
             strncpy(desc, "channel requires registration", sizeof(desc));
             break;
          default:
             strncpy(desc, "no reason specified", sizeof(desc));
             break;
       }
       sendto_one(sptr, ":%s 470 %s Cannot join %s (%s) -- transferring you to %s", me.name, sptr->name, chptr->chname, desc, channel);
       parv[0] = sptr->name;
       parv[1] = channel;
       parv[2] = NULL;
       do_join(sptr, sptr, 2, parv);
       return FORWARD_SUCCESS;
    }

    // Fix the parameter if it is incorrect

    char *hf_param(char *param)
    {
       if (match("~?:#*:*!*@*", param) || strchr(param, ',') != NULL)
       {
          return NULL;
       }
       return param;
    }

    // Check if a user should be banned

    int hf_isBanned(aClient *sptr, aChannel *chptr, char *ban, int chktype)
    {
       char banstr[512], *rchan, *rmask;
       if (chktype != BANCHK_JOIN)
       {
          return 0;
       }
       strncpy(banstr, ban, sizeof(banstr));
       // Get rid of the first token (~f)
       (void) strtok(banstr, ":");
       // Second token is the channel to redirect to..
       rchan = strtok(NULL, ":");
       // Third token is the mask.
       rmask = strtok(NULL, ":");
       if (!rmask || !rchan)
       {
          return 0;
       }
       if (!match(rmask, ban_ip) || !match(rmask, ban_realhost) || !match(rmask, ban_virthost))
       {
          // User is banned and should be forwarded
          return 1;
       }
       return 0;
    }

