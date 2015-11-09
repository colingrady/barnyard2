/*
** Copyright (C) 2015 Colin Grady (@colingrady)
** Copyright (C) 2002-2009 Sourcefire, Inc.
** Copyright (C) 2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <sys/types.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* !WIN32 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "barnyard2.h"
#include "decode.h"
#include "plugbase.h"
#include "debug.h"
#include "parser.h"
#include "util.h"
#include "log.h"
#include "mstring.h"
#include "map.h"
#include "unified2.h"

#include "sfutil/sf_textlog.h"
#include "log_text.h"

#include "spo_log_key_value.h"



#define DEFAULT_FILE  "keyvalue.log"
#define DEFAULT_LIMIT (128 * M_BYTES)
#define LOG_BUFFER    (4 * K_BYTES)

#define ENCODING_NONE -1

#define TO_IP(x) x >> 24, (x >> 16) & 0xff, (x >> 8) & 0xff, x & 0xff



typedef struct _LogKeyValueData
{
    int pid;

    TextLog* log;

    u_int8_t like_syslog;
    u_int8_t encoding;

    char **extra_data_types;
    int types_count;
} LogKeyValueData;



static void logKeyValueRegister (char *);
static LogKeyValueData *logKeyValueParseArgs (char *);
static void logKeyValueHandler (Packet *, void *, uint32_t, void *);
static void logKeyValueEventHandler (Packet *, void *, uint32_t, LogKeyValueData *);
static void logKeyValueExtraDataHandler (void *, uint32_t, LogKeyValueData *);
static void logKeyValuePrintLogHeader (void *, LogKeyValueData *, char *);
static void logKeyValueExit (int, void *);
static void logKeyValueRestart (int, void *);
static void logKeyValueCleanup (int, void *, const char *);
char *logKeyValueAscii (const u_char *, int);



void logKeyValueSetup (void)
{
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "log_key_value: Setting up output plugin\n"););

    RegisterOutputPlugin("log_key_value", OUTPUT_TYPE_FLAG__LOG, logKeyValueRegister);
}


static void logKeyValueRegister (char *args)
{
    LogKeyValueData *data;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "log_key_value: Registering output plugin\n"););

    data = logKeyValueParseArgs(args);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "log_key_value: Linking functions to call lists\n"););

    AddFuncToOutputList(logKeyValueHandler, OUTPUT_TYPE__LOG, data);
    AddFuncToOutputList(logKeyValueHandler, OUTPUT_TYPE__EXTRA_DATA, data);

    AddFuncToCleanExitList(logKeyValueExit, data);
    AddFuncToShutdownList(logKeyValueExit, data);
    AddFuncToRestartList(logKeyValueRestart, data);

    data->extra_data_types = mSplit(",HTTP XFF,HTTP XFF,Reviewed By,gzip Data" \
                                    ",SMTP Filename,SMTP MAIL FROM,SMTP RCPT TO" \
                                    ",SMTP Email Headers,HTTP URI,HTTP Hostname" \
                                    ",IPv6 Source,IPv6 Destination,", \
                                    ",", EVENT_INFO_MAX, &data->types_count, '\\');
}


static LogKeyValueData *logKeyValueParseArgs (char *args)
{
    LogKeyValueData *data;
    char **toks;
    int num_toks = 0;
    int i;
    char *filename = NULL;
    unsigned long limit = DEFAULT_LIMIT;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "log_key_value: Parsing output plugin arguments: %s\n", args););

    data = (LogKeyValueData *)SnortAlloc(sizeof(LogKeyValueData));

    if (!data)
        FatalError("log_key_value: Unable to allocate memory for data!\n");

    data->pid = (int) getpid();
    data->like_syslog = false;
    data->encoding = ENCODING_ASCII;

    if (!args)
        args = "";

    toks = mSplit(args, ",", 4, &num_toks, '\\');
    for (i = 0; i < num_toks; i++)
    {
        const char *tok = toks[i];
        char **subtoks;
        int num_subtoks = 0;
        
        subtoks = mSplit(tok, " ", 2, &num_subtoks, 0);

        if (!strcasecmp("filename", subtoks[0]))
        {
            if (num_subtoks > 1)
                filename = ProcessFileOption(barnyard2_conf_for_parsing, subtoks[1]);
            else
                LogMessage("log_key_value: Missing value for \"%s\"\n", tok);
        }
        else if (!strcasecmp("limit", subtoks[0]))
        {
            if (num_subtoks > 1)
            {
                char *end;

                limit = strtol(subtoks[1], &end, 10);

                if (subtoks[1] == end)
                    FatalError("log_key_value: Value error with \"%s\"\n", subtoks[1]);

                if (end && toupper(*end) == 'G')
                    limit <<= 30; /* GB */
                else if (end && toupper(*end) == 'M')
                    limit <<= 20; /* MB */
                else if (end && toupper(*end) == 'K')
                    limit <<= 10; /* KB */
            }
            else
                LogMessage("log_key_value: Missing value for \"%s\"\n", tok);
        }
        else if (!strcasecmp("encoding", subtoks[0]))
        {
            if (num_subtoks > 1)
            {
                if (!strcasecmp("none", subtoks[1]))
                    data->encoding = ENCODING_NONE;
                else if (!strcasecmp("ascii", subtoks[1]))
                    data->encoding = ENCODING_ASCII;
                else if (!strcasecmp("hex", subtoks[1]))
                    data->encoding = ENCODING_HEX;
                else
                    FatalError("log_key_value: Unknown encoding type \"%s\"\n", subtoks[1]);
            }
            else
                LogMessage("log_key_value: Missing value for \"%s\"\n", tok);
        }
        else if (!strcasecmp("like_syslog", subtoks[0]))
        {
            data->like_syslog = true;
        }

        mSplitFree(&subtoks, num_subtoks);
    }

    mSplitFree(&toks, num_toks);

    if (filename == NULL)
        filename = ProcessFileOption(barnyard2_conf_for_parsing, DEFAULT_FILE);

    data->log = TextLog_Init(filename, LOG_BUFFER, limit);

    if (filename != NULL)
        free(filename);

    return data;
}


static void logKeyValueHandler (Packet *p, void *orig_event, uint32_t event_type, void *arg)
{
    LogKeyValueData *data = (LogKeyValueData *)arg;

    switch (event_type)
    {
        case UNIFIED2_EXTRA_DATA:
            logKeyValueExtraDataHandler(orig_event, event_type, data);
            break;

        case UNIFIED2_IDS_EVENT:
        case UNIFIED2_IDS_EVENT_IPV6:
        case UNIFIED2_IDS_EVENT_MPLS:
        case UNIFIED2_IDS_EVENT_IPV6_MPLS:
        case UNIFIED2_IDS_EVENT_VLAN:
        case UNIFIED2_IDS_EVENT_IPV6_VLAN:
        default:
            logKeyValueEventHandler(p, orig_event, event_type, data);
            break;
    }
}


static void logKeyValueEventHandler (Packet *p, void *orig_event, uint32_t event_type, LogKeyValueData *data)
{
    Unified2EventCommon *event = (Unified2EventCommon *)orig_event;
    SigNode *sn;
    ClassType *cn;
    char *packet_data;

    if (p == NULL)
        return;

    if (event == NULL || data == NULL)
    {
        LogMessage("log_key_value: Event handler called with null arguments for event type %u\n", event_type);
        return;
    }

    logKeyValuePrintLogHeader(orig_event, data, "EVENT");

    TextLog_Print(data->log, "sigid=\"%lu:%lu\" sigrev=%lu ", (unsigned long) ntohl(event->generator_id), (unsigned long) ntohl(event->signature_id), (unsigned long) ntohl(event->signature_revision));

    sn = GetSigByGidSid(ntohl(event->generator_id), ntohl(event->signature_id), ntohl(event->signature_revision));
    if (sn != NULL)
    {
        TextLog_Puts(data->log, "signature=");
        TextLog_Quote(data->log, sn->msg);
        TextLog_Puts(data->log, " ");
    }
    else
        TextLog_Puts(data->log, "signature=\"Snort Alert\" ");

    cn = ClassTypeLookupById(barnyard2_conf, ntohl(event->classification_id));
    if (cn != NULL)
        TextLog_Print(data->log, "class=\"%s\" priority=%d ", cn->name, cn->priority);
    else
        TextLog_Print(data->log, "class=%d priority=%d ", ntohl(event->classification_id), ntohl(event->priority_id));

    if (IPH_IS_VALID(p))
    {
        TextLog_Print(data->log, "proto=%s ", protocol_names[GET_IPH_PROTO(p)]);

        TextLog_Print(data->log, "sip=%s ", inet_ntoa(GET_SRC_ADDR(p)));
        if (!p->frag_flag && p->sp)
            TextLog_Print(data->log, "sport=%d ", p->sp);
        TextLog_Print(data->log, "dip=%s ", inet_ntoa(GET_DST_ADDR(p)));
        if (!p->frag_flag && p->dp)
            TextLog_Print(data->log, "dport=%d ", p->dp);
        
        if (p->dsize && data->encoding != ENCODING_NONE)
        {
            switch (data->encoding)
            {
                case ENCODING_HEX:
                    packet_data = fasthex(p->data, p->dsize);
                    break;
                case ENCODING_ASCII:
                    packet_data = logKeyValueAscii(p->data, p->dsize);
                    break;
            }

            if (packet_data != NULL)
            {
                TextLog_Puts(data->log, "payload=");
                TextLog_Quote(data->log, packet_data);

                free(packet_data);
            }
            else
                LogMessage("log_key_value: Unable to encode the payload\n");
        }
    }

    TextLog_NewLine(data->log);
    TextLog_Flush(data->log);
}


static void logKeyValueExtraDataHandler (void *orig_event, uint32_t event_type, LogKeyValueData *data)
{
    Unified2ExtraDataHdr *extra_header = NULL;
    Unified2ExtraData *extra_event = NULL;
    u_char *extra_data = NULL;
    int extra_data_len;
    uint32_t ip;
    struct in6_addr ip6;
    char ip6_buffer[INET6_ADDRSTRLEN + 1];

    if (event_type != UNIFIED2_EXTRA_DATA)
        return;

    if (orig_event == NULL || data == NULL)
    {
        LogMessage("log_key_value: Extra data handler called with null arguments for event type %u\n", event_type);
        return;
    }

    extra_header = (Unified2ExtraDataHdr *)orig_event;
    extra_event = (Unified2ExtraData *)(orig_event + sizeof(Unified2ExtraDataHdr));
    extra_data_len = ntohl(extra_event->blob_length) - sizeof(extra_event->blob_length) - sizeof(extra_event->data_type);

    extra_event->type = ntohl(extra_event->type);

    if (extra_data_len)
    {
        /*
            TODO
        extra_data = SnortAlloc(extra_data_len + 1);
        memcpy(extra_data, (char *) extra_event + sizeof(Unified2ExtraData), extra_data_len);
        extra_data[extra_data_len] = '\0';

        */

        logKeyValuePrintLogHeader(extra_event, data, "EXTRA");

        if (extra_event->type && extra_event->type < EVENT_INFO_MAX)
            TextLog_Print(data->log, "extratype=\"%s\" ", data->extra_data_types[extra_event->type]);
        else
        {
            TextLog_Puts(data->log, "extratype=Unsupported ");
            return;
        }

        switch (extra_event->type)
        {
            case EVENT_INFO_XFF_IPV4:
                memcpy(&ip, orig_event + sizeof(Unified2ExtraDataHdr) + sizeof(Unified2ExtraData), sizeof(uint32_t));
                TextLog_Print(data->log, "data=%u.%u.%u.%u", TO_IP(ntohl(ip)));
                break;

            case EVENT_INFO_XFF_IPV6:
            case EVENT_INFO_IPV6_SRC:
            case EVENT_INFO_IPV6_DST:
                memcpy(&ip6, orig_event + sizeof(Unified2ExtraDataHdr) + sizeof(Unified2ExtraData), sizeof(struct in6_addr));
                inet_ntop(AF_INET6, &ip6, ip6_buffer, INET6_ADDRSTRLEN);
                TextLog_Print(data->log, "data=\"%s\"", ip6_buffer);
                break;

            case EVENT_INFO_REVIEWED_BY:
            case EVENT_INFO_SMTP_FILENAME:
            case EVENT_INFO_SMTP_MAILFROM:
            case EVENT_INFO_SMTP_RCPTTO:
            case EVENT_INFO_SMTP_EMAIL_HDRS:
            case EVENT_INFO_HTTP_URI:
            case EVENT_INFO_HTTP_HOSTNAME:
                TextLog_Print(data->log, "data=\"%.*s\"", extra_data_len, orig_event + sizeof(Unified2ExtraDataHdr) + sizeof(Unified2ExtraData));
                break;

            default:
                break;
        }

        TextLog_NewLine(data->log);
        TextLog_Flush(data->log);
    }
}


static void logKeyValuePrintLogHeader (void *orig_event, LogKeyValueData *data, char *log_type)
{
    Unified2CacheCommon *event = (Unified2CacheCommon *)orig_event;

    if (data->like_syslog)
    {
        char timestamp[20];
        int localzone;
        time_t t;
        struct tm *lt;

        localzone = barnyard2_conf->thiszone;
        if (BcOutputUseUtc())
            localzone = 0;

        t = ntohl(event->event_second) + localzone;
        lt = gmtime(&t);

        if (strftime(timestamp, sizeof(timestamp), "%h %e %T", lt))
            TextLog_Print(data->log, "%s ", timestamp);
        else
        {
            LogMessage("log_key_value: Unable to parse the event timestamp\n");
            TextLog_Puts(data->log, "Jan  1 00:00:00");
        }

        if (barnyard2_conf->hostname != NULL)
            TextLog_Print(data->log, "%s ", barnyard2_conf->hostname);
        else
            TextLog_Puts(data->log, "sensor ");

        TextLog_Print(data->log, "barnyard[%d]: %%snortids ", data->pid);
    }
    else
    {
        TextLog_Print(data->log, "%%snortids eventsec=%d ", ntohl(event->event_second));

        if (barnyard2_conf->hostname != NULL)
            TextLog_Print(data->log, "host=%s ", barnyard2_conf->hostname);
        else
            TextLog_Puts(data->log, "host=sensor ");
    }

    TextLog_Print(data->log, "logtype=%s ", log_type);

    if (BcAlertInterface())
        TextLog_Print(data->log, "iface=%s ", PRINT_INTERFACE(barnyard2_conf->interface));

    TextLog_Print(data->log, "eventid=%lu ", (unsigned long) ntohl(event->event_id));

    if (data->like_syslog)
        TextLog_Print(data->log, "eventsec=%d ", ntohl(event->event_second));
}


static void logKeyValueExit (int signal, void *arg)
{
    logKeyValueCleanup(signal, arg, "exit");
}


static void logKeyValueRestart (int signal, void *arg)
{
    logKeyValueCleanup(signal, arg, "restart");
}


static void logKeyValueCleanup (int signal, void *arg, const char *msg)
{
    LogKeyValueData *data = (LogKeyValueData *)arg;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "log_key_value: Cleaning up in prep for %s\n", msg););

    if (data)
    {
        if (data->extra_data_types)
            mSplitFree(&data->extra_data_types, data->types_count);

        if (data->log)
            TextLog_Term(data->log);

        free(data);
    }
}


char *logKeyValueAscii (const u_char *xdata, int length)
{
    char *d_ptr, *ret_val;
    int i, count = 0;
    int size;

    if (xdata == NULL)
        return NULL;

    for (i = 0; i < length; i++)
    {
        if (xdata[i] == '"')
            count += 6;      /* &quot; */
    }

    size = length + count + 1;
    ret_val = (char *) calloc(1, size);

    if (ret_val == NULL)
    {
        LogMessage("log_key_value: logKeyValueAscii(): Out of memory!\n");
        return NULL;
    }

    d_ptr = ret_val;

    for (i = 0; i < length; i++)
    {
        if ((xdata[i] > 0x1F) && (xdata[i] < 0x7F))
        {
            if(xdata[i] == '"')
            {
                SnortStrncpy(d_ptr, "&quot;", size - (d_ptr - ret_val));
                d_ptr += 6;
            }
            else
                *d_ptr++ = xdata[i];
        }
        else
            *d_ptr++ = '.';
    }

    *d_ptr++ = '\0';

    return ret_val;
}

