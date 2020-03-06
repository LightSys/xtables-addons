/*
 *	"tarhash" match extension to iptables
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License; either
 *	version 2 of the License, or any later version, as published by the
 *	Free Software Foundation.
 */
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter/x_tables.h>
#include "xt_tarhash.h"
#include "compat_user.h"
#if defined(CONFIG_IP6_NF_IPTABLES) || defined(CONFIG_IP6_NF_IPTABLES_MODULE)
#	define WITH_IPV6 1
#endif

enum {
	F_KEY         = 1 << 1,
	F_RATIO       = 1 << 2,
	F_SRC_PREFIX4 = 1 << 3,
	F_SRC_PREFIX6 = 1 << 4,
};

static const struct option tarhash_mt_opts[] = {
	{.name = "key",         .has_arg = true,  .val = 'k'},
	{.name = "ratio",       .has_arg = true,  .val = 'o'},
	{.name = "src-prefix4", .has_arg = true,  .val = '4'},
	{.name = "src-prefix6", .has_arg = true,  .val = '6'},
	{NULL},
};

static void tarhash_mt_help(void)
{
	printf(
		"tarhash match options:\n"
		"  --key          Seed/salt value for the hashing function\n"
		"  --ratio        Inverse of the likelihood that a port is answered\n"
		"  --src-prefix4  Number of bits in the source IPv4 considered in the hash function\n"
		"  --src-prefix6  Number of bits in the source IPv6 considered in the hash function\n"
	);
}

static bool parse_unsigned_long(char* str, unsigned long* out) {
	char* end;
	unsigned long val;

	errno = 0;
	val = strtoul(str, &end, 10);

	if ((errno == ERANGE && val == ULONG_MAX) ||
	    (errno != 0 && val == 0)) {
		return false;
	}

	if (end == str || *end != '\0') {
		return false;
	}
	
	*out = val;
	return true;
}

static int tarhash_mt_parse(int c, char **argv, int invert, unsigned int *flags,
                           const void *entry, struct xt_entry_match **match)
{
	struct xt_tarhash_mtinfo *info = (void *)(*match)->data;

	switch (c) {
	case 'k':
		xtables_param_act(XTF_ONLY_ONCE, "tarhash", "--key", *flags & F_KEY);
		xtables_param_act(XTF_NO_INVERT, "tarhash", "--key", invert);
		*flags |= F_KEY;
		if (strlen(optarg) != 32) {
			xtables_param_act(XTF_BAD_VALUE, "tarhash", "--key", optarg);
		}
		memcpy(&info->key, optarg, 32);
		return true;
	case 'o':
		xtables_param_act(XTF_ONLY_ONCE, "tarhash", "--ratio", *flags & F_RATIO);
		xtables_param_act(XTF_NO_INVERT, "tarhash", "--ratio", invert);
		*flags |= F_RATIO;
		unsigned long parsed_ratio;
		if (!parse_unsigned_long(optarg, &parsed_ratio) || parsed_ratio > UINT32_MAX) {
			xtables_param_act(XTF_BAD_VALUE, "tarhash", "--ratio", optarg);
			return false;
		}
		info->ratio = (uint32_t) parsed_ratio;
		return true;
	case '4':
		xtables_param_act(XTF_ONLY_ONCE, "tarhash", "--src-prefix4", *flags & F_SRC_PREFIX4);
		xtables_param_act(XTF_NO_INVERT, "tarhash", "--src-prefix4", invert);
		*flags |= F_SRC_PREFIX4;
		unsigned long parsed_src_prefix4;
		if (!parse_unsigned_long(optarg, &parsed_src_prefix4) || parsed_src_prefix4 > 32) {
			xtables_param_act(XTF_BAD_VALUE, "tarhash", "--src-prefix4", optarg);
			return false;
		}
		info->src_prefix4 = parsed_src_prefix4;
		info->mask4 = (0x1 << 31) >> ((uint8_t)parsed_src_prefix4 - 1);
		return true;
	case '6':
		xtables_param_act(XTF_ONLY_ONCE, "tarhash", "--src-prefix6", *flags & F_SRC_PREFIX6);
		xtables_param_act(XTF_NO_INVERT, "tarhash", "--src-prefix6", invert);
		*flags |= F_SRC_PREFIX6;
		unsigned long parsed_src_prefix6;
		if (!parse_unsigned_long(optarg, &parsed_src_prefix6) || parsed_src_prefix6 > 128) {
			xtables_param_act(XTF_BAD_VALUE, "tarhash", "--src-prefix6", optarg);
			return false;
		}
		info->src_prefix6 = parsed_src_prefix6;
		bool zero_rest = false;
		for (int i = 1; i <= 16; i++) {
			if (zero_rest) info->mask6[i-1] = 0;
			else if (parsed_src_prefix6 > (8 * i)) {
				info->mask6[i - 1] = UINT8_MAX;
			}
			else {
				info->mask6[i - 1] = (0x1<<7)>>(parsed_src_prefix6 - (8 * (16 - i)));
				zero_rest = true;
			}
		}
		return true;
	}
	return false;
}

static void tarhash_mt_check(unsigned int flags)
{
	if (!(flags & F_KEY)) {
		xtables_error(PARAMETER_PROBLEM,
			"tarhash: key must be provided");
	}
	if (!(flags & F_RATIO)) {
		xtables_error(PARAMETER_PROBLEM,
			"tarhash: ratio must be provided");
	}
	if (!(flags & F_SRC_PREFIX4)) {
		xtables_error(PARAMETER_PROBLEM,
			"tarhash: src-prefix4 must be provided");
	}
	if (!(flags & F_SRC_PREFIX6)) {
		xtables_error(PARAMETER_PROBLEM,
			"tarhash: src-prefix6 must be provided");
	}
}

static void tarhash_mt_save(const void *ip,
    const struct xt_entry_match *match)
{
	const struct xt_tarhash_mtinfo *info = (const void *)match->data;
	printf(" --key %.32s --ratio %u --src-prefix4 %u --src-prefix6 %u",
			info->key,
			info->ratio,
			info->src_prefix4,
			info->src_prefix6);
	//TODO: What is this function for? Can it be deleted?
}

static void tarhash_mt_print(const void *ip,
    const struct xt_entry_match *match, int numeric)
{
	printf(" tarhash ");
	tarhash_mt_save(ip, match);
}

static struct xtables_match tarhash_mt_reg = {
	.version       = XTABLES_VERSION,
	.name          = "tarhash",
	.family        = NFPROTO_UNSPEC,
	.size          = XT_ALIGN(sizeof(struct xt_tarhash_mtinfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_tarhash_mtinfo)),
	.help          = tarhash_mt_help,
	.parse         = tarhash_mt_parse,
	.final_check   = tarhash_mt_check,
	.print         = tarhash_mt_print,
	.save          = tarhash_mt_save,
	.extra_opts    = tarhash_mt_opts,
};

static __attribute__((constructor)) void tarhash_mt_ldr(void)
{
	xtables_register_match(&tarhash_mt_reg);
}

