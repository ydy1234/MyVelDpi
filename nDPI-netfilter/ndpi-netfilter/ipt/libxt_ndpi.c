/* 
 * libxt_ndpi.c
 * Copyright (C) 2010-2012 G. Elian Gidoni <geg@gnu.org>
 *               2012 Ed Wildgoose <lists@wildgooses.com>
 * 
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the PACE technology by ipoque GmbH
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <xtables.h>

#include <linux/version.h>

#define NDPI_IPTABLES_EXT
#include "xt_ndpi.h"
#include "ndpi_config.h"

/* copy from ndpi_main.c */

int NDPI_BITMASK_IS_EMPTY(NDPI_PROTOCOL_BITMASK a) {
  int i;

  for(i=0; i<NDPI_NUM_FDS_BITS; i++)
    if(a.fds_bits[i] != 0)
      return(0);

  return(1);
}

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#endif

#if NDPI_LAST_IMPLEMENTED_PROTOCOL != NDPI_PROTOCOL_MAXNUM
#error LAST_IMPLEMENTED_PROTOCOL != PROTOCOL_MAXNUM
#endif

static char *prot_short_str[] = { NDPI_PROTOCOL_SHORT_STRING,NULL };
static char  prot_disabled[NDPI_LAST_IMPLEMENTED_PROTOCOL+1] = { 0, };

#define NDPI_OPT_ERROR  (NDPI_LAST_IMPLEMENTED_PROTOCOL+1)
#define NDPI_OPT_PROTO  (NDPI_LAST_IMPLEMENTED_PROTOCOL+2)
#define NDPI_OPT_ALL    (NDPI_LAST_IMPLEMENTED_PROTOCOL+3)
#define NDPI_OPT_MASTER (NDPI_LAST_IMPLEMENTED_PROTOCOL+4)
#define NDPI_OPT_PROTOCOL  (NDPI_LAST_IMPLEMENTED_PROTOCOL+5)
#define NDPI_OPT_HMASTER   (NDPI_LAST_IMPLEMENTED_PROTOCOL+6)

static void 
ndpi_mt4_save(const void *entry, const struct xt_entry_match *match)
{
	const struct xt_ndpi_mtinfo *info = (const void *)match->data;
	const char *cinv = info->invert ? "! ":"";
        int i,c,l,t;

	if(info->error) {
		printf(" %s--error",cinv);
		return;
	}
	if(info->have_master) {
		printf(" %s--have-master",cinv);
		return;
	}

        for (t = l = c = i = 0; i <= NDPI_LAST_IMPLEMENTED_PROTOCOL; i++) {
		if (!strncmp(prot_short_str[i],"badproto_",9)) continue;
		if (!prot_disabled[i]) { 
		    t++;
		    if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, i) != 0) {
			l = i;
			c++;
		    }
		}
	}
	if(!c) return; // BUG?

	printf(" %s", cinv);
	if(info->m_proto && !info->p_proto)
		printf("--match-master");
	if(!info->m_proto && info->p_proto)
		printf("--match-proto");

	if( c == 1) {
		printf(" --%s ", prot_short_str[l]);
		return;
	}
	if( c == t-1 && 
	    !NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags,NDPI_PROTOCOL_UNKNOWN) ) { 
		printf(" --all ");
		return;
	}
	printf(" --proto " );
	if(c > t/2 + 1) {
	    printf("all");
	    for (i = 1; i <= NDPI_LAST_IMPLEMENTED_PROTOCOL; i++) {
                if (!prot_disabled[i] && NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, i) == 0)
			printf(",-%s", prot_short_str[i]);
	    }
	    return;
	}
        for (l = i = 0; i <= NDPI_LAST_IMPLEMENTED_PROTOCOL; i++) {
                if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, i) != 0)
			printf("%s%s",l++ ? ",":"", prot_short_str[i]);
        }
}


static void 
ndpi_mt4_print(const void *entry, const struct xt_entry_match *match,
                  int numeric)
{
	const struct xt_ndpi_mtinfo *info = (const void *)match->data;
	const char *cinv = info->invert ? "!":"";
        int i,c,l,t;

	if(info->error) {
		printf(" %sndpi error",cinv);
		return;
	}
	if(info->have_master) {
		printf(" %sndpi have-master",cinv);
		return;
	}

        for (t = c = i = 0; i <= NDPI_LAST_IMPLEMENTED_PROTOCOL; i++) {
		if (!strncmp(prot_short_str[i],"badproto_",9)) continue;
		if (!prot_disabled[i]) {
		    t++;
		    if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, i) != 0) c++;
		}
	}
	if(!c) return;
	printf(" %sndpi", cinv);
	if(info->m_proto && !info->p_proto)
		printf(" match-master");
	if(!info->m_proto && info->p_proto)
		printf(" match-proto");

	if( c == t-1 && 
	    !NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags,NDPI_PROTOCOL_UNKNOWN) ) {
		printf(" all protocols");
		return;
	}

	printf(" protocol%s ",c > 1 ? "s":"");
	if(c > t/2 + 1) {
	    printf("all");
	    for (i = 1; i <= NDPI_LAST_IMPLEMENTED_PROTOCOL; i++) {
                if (!prot_disabled[i] && NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, i) == 0)
			printf(",-%s", prot_short_str[i]);
	    }
	    return;
	}

        for (l = i = 0; i <= NDPI_LAST_IMPLEMENTED_PROTOCOL; i++) {
                if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, i) != 0)
                        printf("%s%s",l++ ? ",":"", prot_short_str[i]);
        }
}


static int 
ndpi_mt4_parse(int c, char **argv, int invert, unsigned int *flags,
                  const void *entry, struct xt_entry_match **match)
{
	struct xt_ndpi_mtinfo *info = (void *)(*match)->data;
        int i;

	info->invert = invert;

	if(c == NDPI_OPT_ERROR) {
		info->error = 1;
        	*flags |= 2;
		return true;
	}
	if(c == NDPI_OPT_HMASTER ) {
		info->have_master = 1;
        	*flags |= 4;
		return true;
	}
	if(c == NDPI_OPT_MASTER) {
		info->m_proto = 1;
        	*flags |= 8;
		return true;
	}
	if(c == NDPI_OPT_PROTOCOL) {
		info->p_proto = 1;
        	*flags |= 0x10;
		return true;
	}

	if(c == NDPI_OPT_PROTO) {
		char *np = optarg,*n;
		int num;
		int op;
		while((n = strtok(np,",")) != NULL) {
			num = -1;
			op = 1;
			if(*n == '-') {
				op = 0;
				n++;
			}
			for (i = 0; i <= NDPI_LAST_IMPLEMENTED_PROTOCOL; i++) {
			    if(!strcmp(prot_short_str[i],n)) {
				    num = i;
				    break; 
			    }
			}
			if(num < 0) {
			    if(strcmp(n,"all")) {
				printf("Unknown proto '%s'\n",n);
				return false;
			    }
			    for (i = 1; i <= NDPI_LAST_IMPLEMENTED_PROTOCOL; i++) {
				if(strncmp(prot_short_str[i],"badproto_",9) && !prot_disabled[i]) {
				    if(op)
					NDPI_ADD_PROTOCOL_TO_BITMASK(info->flags,i);
				     else
					NDPI_DEL_PROTOCOL_FROM_BITMASK(info->flags,i);
				}
			    }
			} else {
			    if(prot_disabled[num]) {
				printf("Disabled proto '%s'\n",n);
				return false;
			    }
			    if(op)
				NDPI_ADD_PROTOCOL_TO_BITMASK(info->flags,num);
			     else
				NDPI_DEL_PROTOCOL_FROM_BITMASK(info->flags,num);
			}
			*flags |= 1;
			np = NULL;
		}
		if(NDPI_BITMASK_IS_EMPTY(info->flags)) *flags &= ~1;
		return *flags != 0;
	}
	if(c == NDPI_OPT_ALL) {
		for (i = 1; i <= NDPI_LAST_IMPLEMENTED_PROTOCOL; i++) {
	    	    if(strncmp(prot_short_str[i],"badproto_",9) && !prot_disabled[i])
			NDPI_ADD_PROTOCOL_TO_BITMASK(info->flags,i);
		}
        	*flags |= 1;
		return true;
	}
	if(c > NDPI_OPT_ALL) {
		printf("BUG! c > NDPI_LAST_IMPLEMENTED_PROTOCOL+1\n");
		return false;
	}
	if(c >= 0 && c <= NDPI_LAST_IMPLEMENTED_PROTOCOL) {
        	NDPI_ADD_PROTOCOL_TO_BITMASK(info->flags, c);
		*flags |= 1;
		return true;
	}
	return false;
}

#ifndef xtables_error
#define xtables_error exit_error
#endif

static void
ndpi_mt_check (unsigned int flags)
{
	flags &= 7;
	if (flags == 1 || flags == 2 || flags == 4) return;
	if ((flags & 6) == 6) {
	    xtables_error(PARAMETER_PROBLEM, "xt_ndpi: cant check error and master protocol ");
	}
	if ((flags & 3) == 3)
	    xtables_error(PARAMETER_PROBLEM, "xt_ndpi: cant check error and protocol ");

	if (!(flags & 1))
	    xtables_error(PARAMETER_PROBLEM, "xt_ndpi: You need to "
                              "specify at least one protocol");

	xtables_error(PARAMETER_PROBLEM, "xt_ndpi: unknown error! ");
}

static int cmp_pname(const void *p1, const void *p2) {
	const char *a,*b;
	a = *(const char **)p1;
	b = *(const char **)p2;
	if(a && b) {
		return strcmp( a, b);
	}
	if(a)	return -1;
	if(b)	return 1;
	return 0;
}

static int ndpi_print_prot_list(int cond) {
        int i,c,d,l;
	char line[128];
	char *pn[NDPI_LAST_IMPLEMENTED_PROTOCOL+1];

	bzero((char *)&pn[0],sizeof(pn));

        for (i = 1,d = 0; i <= NDPI_LAST_IMPLEMENTED_PROTOCOL; i++) {
	    if(!strncmp(prot_short_str[i],"badproto_",9)) continue;
	    if(prot_disabled[i] != cond) { 
		    d++;
		    continue;
	    }
	    pn[i-1] = prot_short_str[i];
	}
	qsort(&pn[0],NDPI_LAST_IMPLEMENTED_PROTOCOL-1,sizeof(pn[0]),cmp_pname);
        for (i = 0,c = 0,l=0; i <= NDPI_LAST_IMPLEMENTED_PROTOCOL; i++) {
	    if(!pn[i]) break;
	    l += snprintf(&line[l],sizeof(line)-1-l,"%-20s ", pn[i]);
	    c++;
	    if(c == 4) {
		    printf("%s\n",line);
		    c = 0; l = 0;
	    }
	}
	if(c > 0) printf("%s\n",line);
	return d;
}

static void
ndpi_mt_help(void)
{
        int d;

	printf( "ndpi match options:\n"
		"  --error            Match error detecting process\n"
		"  --have-master      Match if master protocol detected\n"
		"  --match-master     Match master protocol only\n"
		"  --match-proto      Match protocol only\n"
		"Special protocol names:\n"
		"  --all              Match any known protocol\n"
		"  --unknown          Match unknown protocol packets\n");
	printf( "Enabled protocols: ( option form '--protoname' or --proto protoname[,protoname...])\n");
	d = ndpi_print_prot_list(0);
	if(!d) return;
	printf( "Disabled protocols:\n");
	ndpi_print_prot_list(1);
}

static struct option ndpi_mt_opts[NDPI_LAST_IMPLEMENTED_PROTOCOL+8];

static struct xtables_match
ndpi_mt4_reg = {
	.version = XTABLES_VERSION,
	.name = "ndpi",
	.revision = 0,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
	.family = AF_INET,
#else
	.family = NFPROTO_UNSPEC,
#endif
	.size = XT_ALIGN(sizeof(struct xt_ndpi_mtinfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_ndpi_mtinfo)),
	.help = ndpi_mt_help,
	.parse = ndpi_mt4_parse,
	.final_check = ndpi_mt_check,
	.print = ndpi_mt4_print,
	.save = ndpi_mt4_save,
	.extra_opts = ndpi_mt_opts,
};
/* target NDPIMARK */
enum {
        O_SET_VALUE=0,
        O_SET_NDPI,
        O_SET_NDPI_M,
        O_SET_NDPI_P,
        O_SET_MARK,
        O_SET_CLSF,
        O_ACCEPT,
        F_SET_VALUE  = 1 << O_SET_VALUE,
        F_SET_NDPI   = 1 << O_SET_NDPI,
        F_SET_NDPI_M = 1 << O_SET_NDPI_M,
        F_SET_NDPI_P = 1 << O_SET_NDPI_P,
        F_SET_MARK = 1 << O_SET_MARK,
        F_SET_CLSF = 1 << O_SET_CLSF,
        F_ACCEPT   = 1 << O_ACCEPT,
        F_ANY         = F_SET_VALUE | F_SET_NDPI | F_SET_NDPI_M |
			F_SET_NDPI_P |F_SET_MARK | F_SET_CLSF |
			F_ACCEPT,
};

static void NDPI_help(void)
{
        printf(
"NDPI target options:\n"
"  --value value/mask                  Set value = (value & ~mask) | value\n"
"  --ndpi-id                           Set value = (value & ~proto_mask) | proto_mark by any proto\n"
"  --ndpi-id-p                         Set value = (value & ~proto_mask) | proto_mark by proto\n"
"  --ndpi-id-m                         Set value = (value & ~proto_mask) | proto_mark by master protocol\n"
"  --set-mark                          Set nfmark = value\n"
"  --set-clsf                          Set priority = value\n"
"  --accept                            -j ACCEPT\n"
);
}

static const struct xt_option_entry NDPI_opts[] = {
        {.name = "value",    .id = O_SET_VALUE,.type = XTTYPE_MARKMASK32},
        {.name = "ndpi-id",  .id = O_SET_NDPI, .type = XTTYPE_NONE},
        {.name = "ndpi-id-m", .id = O_SET_NDPI_M, .type = XTTYPE_NONE},
        {.name = "ndpi-id-p", .id = O_SET_NDPI_P, .type = XTTYPE_NONE},
        {.name = "set-mark", .id = O_SET_MARK, .type = XTTYPE_NONE},
        {.name = "set-clsf", .id = O_SET_CLSF, .type = XTTYPE_NONE},
        {.name = "accept",   .id = O_ACCEPT,   .type = XTTYPE_NONE},
        XTOPT_TABLEEND,
};
static void NDPI_parse_v0(struct xt_option_call *cb)
{
        struct xt_ndpi_tginfo *markinfo = cb->data;

        xtables_option_parse(cb);
        switch (cb->entry->id) {
        case O_SET_VALUE:
                markinfo->mark = cb->val.mark;
                markinfo->mask = ~cb->val.mask;
                break;
	case O_SET_NDPI:
		markinfo->any_proto_id = 1;
		markinfo->m_proto_id = 0;
		markinfo->p_proto_id = 0;
		break;
	case O_SET_NDPI_M:
		markinfo->m_proto_id = 1;
		if(markinfo->p_proto_id) {
			markinfo->m_proto_id = 0;
			markinfo->p_proto_id = 0;
			markinfo->any_proto_id = 1;
		}
		break;
	case O_SET_NDPI_P:
		markinfo->p_proto_id = 1;
		if(markinfo->m_proto_id) {
			markinfo->m_proto_id = 0;
			markinfo->p_proto_id = 0;
			markinfo->any_proto_id = 1;
		}
		break;
	case O_SET_MARK:
		markinfo->t_mark = 1;
		break;
	case O_SET_CLSF:
		markinfo->t_clsf = 1;
		break;
	case O_ACCEPT:
		markinfo->t_accept = 1;
		break;
        default:
                xtables_error(PARAMETER_PROBLEM,
                           "NDPI target: unknown --%s",
                           cb->entry->name);
        }
}

static void NDPI_print_v0(const void *ip,
                          const struct xt_entry_target *target, int numeric)
{
        const struct xt_ndpi_tginfo *info =
                (const struct xt_ndpi_tginfo *)target->data;
char buf[128];
int l;
        l = snprintf(buf,sizeof(buf)-1," NDPI");
	if(info->t_mark)
	     l += snprintf(&buf[l],sizeof(buf)-l-1, " set MARK ");
	if(info->t_clsf)
	     l += snprintf(&buf[l],sizeof(buf)-l-1, " set CLSF ");
	if(info->mask || info->mark) {
	     if(info->mask)
		l += snprintf(&buf[l],sizeof(buf)-l-1," and 0x%x or 0x%x",
				info->mask,info->mark);
	     else
	        l += snprintf(&buf[l],sizeof(buf)-l-1," set 0x%x", info->mark);
	}
	if(info->any_proto_id)
	     l += snprintf(&buf[l],sizeof(buf)-l-1,
			     " by any ndpi-id");
	else {
		if(info->m_proto_id)
		     l += snprintf(&buf[l],sizeof(buf)-l-1,
			     " by master ndpi-id");
		if(info->p_proto_id)
		     l += snprintf(&buf[l],sizeof(buf)-l-1,
			     " by proto ndpi-id");
	}
	if(info->t_accept)
	     l += snprintf(&buf[l],sizeof(buf)-l-1," ACCEPT");
	printf(buf);
}

static void NDPI_save_v0(const void *ip, const struct xt_entry_target *target)
{
        const struct xt_ndpi_tginfo *info =
                (const struct xt_ndpi_tginfo *)target->data;
	char buf[128];
	int l = 0;
	if(info->mask || info->mark) {
	     l += snprintf(&buf[l],sizeof(buf)-l-1," --value 0x%x", info->mark);
	     if(info->mask)
		l += snprintf(&buf[l],sizeof(buf)-l-1,"/0x%x",~info->mask);
	}
	if(info->any_proto_id)
	     l += snprintf(&buf[l],sizeof(buf)-l-1, " --ndpi-id");
	else {
		if(info->m_proto_id)
		     l += snprintf(&buf[l],sizeof(buf)-l-1, " --ndpi-id-m");
		if(info->p_proto_id)
		     l += snprintf(&buf[l],sizeof(buf)-l-1, " --ndpi-id-p");
	}
	if(info->t_mark)
	     l += snprintf(&buf[l],sizeof(buf)-l-1, " --set-mark");
	if(info->t_clsf)
	     l += snprintf(&buf[l],sizeof(buf)-l-1, " --set-clsf");
	if(info->t_accept)
	     l += snprintf(&buf[l],sizeof(buf)-l-1," --accept");
	printf(buf);

}

static void NDPI_check(struct xt_fcheck_call *cb)
{
        if (!(cb->xflags & (F_SET_MARK|F_SET_CLSF))) 
                xtables_error(PARAMETER_PROBLEM,
                           "NDPI target: Parameter --set-mark or --set-clsf"
                           " is required");
        if (!(cb->xflags & (F_SET_VALUE|F_SET_NDPI|F_SET_NDPI_M|F_SET_NDPI_P)))
                xtables_error(PARAMETER_PROBLEM,
                           "NDPI target: Parameter --value or --ndpi-id[-[mp]]"
                           " is required");
}

static struct xtables_target ndpi_tg_reg[] = {
        {
                .family        = NFPROTO_UNSPEC,
                .name          = "NDPI",
                .version       = XTABLES_VERSION,
                .revision      = 0,
                .size          = XT_ALIGN(sizeof(struct xt_ndpi_tginfo)),
                .userspacesize = XT_ALIGN(sizeof(struct xt_ndpi_tginfo)),
                .help          = NDPI_help,
                .print         = NDPI_print_v0,
                .save          = NDPI_save_v0,
                .x6_parse      = NDPI_parse_v0,
                .x6_fcheck     = NDPI_check,
                .x6_options    = NDPI_opts,
        },
};

void _init(void)
{
        int i;
	char buf[128],*c,pname[32],mark[32];
	uint32_t index;

	FILE *f_proto = fopen("/proc/net/xt_ndpi/proto","r");

	if(!f_proto)
		xtables_error(PARAMETER_PROBLEM, "xt_ndpi: kernel module not load.");
	pname[0] = '\0';
	index = 0;
	while(!feof(f_proto)) {
		c = fgets(buf,sizeof(buf)-1,f_proto);
		if(!c) break;
		if(buf[0] == '#') {
			if(!strstr(buf,"#version") || !strstr(buf,NDPI_GIT_RELEASE)) break;
			pname[0] = ' ';
			continue;
		}
		if(!pname[0]) continue;
		if(sscanf(buf,"%x %s %s",&index,mark,pname) != 3) continue;
		if(index > NDPI_LAST_IMPLEMENTED_PROTOCOL) continue;
		prot_disabled[index] = strncmp(mark,"disable",7) == 0;
		prot_short_str[index] = strdup(pname);	
	}
	fclose(f_proto);
	if(index != NDPI_LAST_IMPLEMENTED_PROTOCOL)
	    xtables_error(PARAMETER_PROBLEM, "xt_ndpi: kernel module version missmatch.");

        for (i = 0; i <= NDPI_LAST_IMPLEMENTED_PROTOCOL; i++){
                ndpi_mt_opts[i].name = prot_short_str[i];
                ndpi_mt_opts[i].flag = NULL;
		ndpi_mt_opts[i].has_arg = 0;
                ndpi_mt_opts[i].val = i;
        }

	i=NDPI_OPT_ERROR;
	ndpi_mt_opts[i].name = "error";
	ndpi_mt_opts[i].flag = NULL;
	ndpi_mt_opts[i].has_arg = 0;
	ndpi_mt_opts[i].val = i;
	i=NDPI_OPT_PROTO;
	ndpi_mt_opts[i].name = "proto";
	ndpi_mt_opts[i].flag = NULL;
	ndpi_mt_opts[i].has_arg = 1;
	ndpi_mt_opts[i].val = i;
	i=NDPI_OPT_ALL;
	ndpi_mt_opts[i].name = "all";
	ndpi_mt_opts[i].flag = NULL;
	ndpi_mt_opts[i].has_arg = 0;
	ndpi_mt_opts[i].val = i;
	i=NDPI_OPT_MASTER;
	ndpi_mt_opts[i].name = "match-master";
	ndpi_mt_opts[i].flag = NULL;
	ndpi_mt_opts[i].has_arg = 0;
	ndpi_mt_opts[i].val = i;
	i=NDPI_OPT_PROTOCOL;
	ndpi_mt_opts[i].name = "match-proto";
	ndpi_mt_opts[i].flag = NULL;
	ndpi_mt_opts[i].has_arg = 0;
	ndpi_mt_opts[i].val = i;
	i=NDPI_OPT_HMASTER;
	ndpi_mt_opts[i].name = "have-master";
	ndpi_mt_opts[i].flag = NULL;
	ndpi_mt_opts[i].has_arg = 0;
	ndpi_mt_opts[i].val = i;
	i++;
	ndpi_mt_opts[i].name = NULL;
	ndpi_mt_opts[i].flag = NULL;
	ndpi_mt_opts[i].has_arg = 0;
	ndpi_mt_opts[i].val = 0;

	xtables_register_match(&ndpi_mt4_reg);
	xtables_register_targets(ndpi_tg_reg, ARRAY_SIZE(ndpi_tg_reg));
}
