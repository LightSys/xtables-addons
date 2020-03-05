/*
 *	"TARHASH" target extension to iptables
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
#include "xt_TARHASH.h"
#include "compat_user.h"
#if defined(CONFIG_IP6_NF_IPTABLES) || defined(CONFIG_IP6_NF_IPTABLES_MODULE)
#	define WITH_IPV6 1
#endif

enum {
	F_KEY         = 1 << 1,
	F_RATIO       = 1 << 2,
	F_SRC_PREFIX4 = 1 << 3,
#ifdef WITH_IPV6
	F_SRC_PREFIX6 = 1 << 4,
#endif
};

static const struct option tarhash_mt_opts[] = {
	{.name = "key",         .has_arg = true,  .val = 'k'},
	{.name = "ratio",       .has_arg = true,  .val = 'o'},
#ifdef WITH_IPV6
	{.name = "src-prefix4", .has_arg = true,  .val = '4'},
	{.name = "src-prefix6", .has_arg = true,  .val = '6'},
#else
	{.name = "src-prefix",  .has_arg = true,  .val = 's'},
#endif
	{NULL},
};

static void tarhash_mt_help(void)
{
	printf(
		"TARHASH target options:\n"
		"  --key          Seed/salt value for the hashing function\n"
		"  --ratio        Inverse of the likelihood that a port is answered\n"
#ifdef WITH_IPV6
		"  --src-prefix4  Number of bits in the source IPv4 considered in the hash function\n"
		"  --src-prefix6  Number of bits in the source IPv6 considered in the hash function\n"
#else 
		"  --src-prefix   Number of bits in the source IP considered in the hash function\n"
#endif
	);
}

static bool parse_unsigned_long(char* str, unsigned long* out) {
	char* end;
	unsigned long val;

	errno = 0;
	val = strtoul(str, &end, 10);

	if (errno == ERANGE && val == ULONG_MAX ||
	    errno != 0 && val == 0) {
		return false;
	}

	if (end == str || *end != '\0') {
		return false;
	}
	
	*out = val;
	return true;
}

static int tarhash_mt_parse(int c, char **argv, int invert, unsigned int *flags,
                           const void *entry, struct xt_entry_target **target)
{
	struct xt_tarhash_mtinfo *info = (void *)(*target)->data;

	switch (c) {
	case 'k':
		xtables_param_act(XTF_ONLY_ONCE, "TARHASH", "--key", *flags & F_KEY);
		xtables_param_act(XTF_NO_INVERT, "TARHASH", "--key", invert);
		*flags |= F_KEY;
		if (strlen(optarg) != 32) {
			xtables_param_act(XTF_BAD_VALUE, "TARHASH", "--key", optarg);
		}
		memcpy(&info->key, optarg, 32);
		return true;
	case 'o':
		xtables_param_act(XTF_ONLY_ONCE, "TARHASH", "--ratio", *flags & F_RATIO);
		xtables_param_act(XTF_NO_INVERT, "TARHASH", "--ratio", invert);
		*flags |= F_RATIO;
		unsigned long parsed_ratio;
		if (!parse_unsigned_long(optarg, &parsed_ratio) || parsed_ratio > UINT32_MAX) {
			xtables_param_act(XTF_BAD_VALUE, "TARHASH", "--ratio", optarg);
			return false;
		}
		info->ratio = (uint32_t) parsed_ratio;
		return true;
#ifdef WITH_IPV6
	case '4':
		xtables_param_act(XTF_ONLY_ONCE, "TARHASH", "--src-prefix4", *flags & F_SRC_PREFIX4);
		xtables_param_act(XTF_NO_INVERT, "TARHASH", "--src-prefix4", invert);
		*flags |= F_SRC_PREFIX4;
		unsigned long parsed_src_prefix4;
		if (!parse_unsigned_long(optarg, &parsed_src_prefix4) || parsed_src_prefix4 > 32) {
			xtables_param_act(XTF_BAD_VALUE, "TARHASH", "--src-prefix4", optarg);
			return false;
		}
		info->src_prefix4 = (uint8_t) parsed_src_prefix4;
		info->mask4 = (0x1<<31)>>(uint8_t) parsed_src_prefix4;
		return true;
	case '6':
		xtables_param_act(XTF_ONLY_ONCE, "TARHASH", "--src-prefix6", *flags & F_SRC_PREFIX6);
		xtables_param_act(XTF_NO_INVERT, "TARHASH", "--src-prefix6", invert);
		*flags |= F_SRC_PREFIX6;
		unsigned long parsed_src_prefix6;
		if (!parse_unsigned_long(optarg, &parsed_src_prefix6) || parsed_src_prefix6 > 128) {
			xtables_param_act(XTF_BAD_VALUE, "TARHASH", "--src-prefix6", optarg);
			return false;
		}
		info->src_prefix6 = (uint8_t) parsed_src_prefix6;
		/* TODO: add conditional compilation for wider IPv6 address blocks */
		bool zeroRest = false;
		for (int i = 1; i <= 16; i++) {
			if (zeroRest) info->mask6.u_8[i-1] = 0;
			else if (parsed_src_prefix6 > (8 * i)) {
				info->mask6.u_8[i - 1] = UINT8_MAX;
			}
			else {
				info->mask6.u_8[i - 1] = (0x1<<7)>>(parsed_src_prefix6 - (8 * (16 - i)));
				zeroRest = true;
			}
		}
		return true;
#else	
	case 's':
		xtables_param_act(XTF_ONLY_ONCE, "TARHASH", "--src-prefix", *flags & F_SRC_PREFIX4);
		xtables_param_act(XTF_NO_INVERT, "TARHASH", "--src-prefix", invert);
		*flags |= F_SRC_PREFIX4;
		unsigned long parsed_src_prefix4;
		if (!parse_unsigned_long(optarg, &parsed_src_prefix4) || parsed_src_prefix4 > 32) {
			xtables_param_act(XTF_BAD_VALUE, "TARHASH", "--src-prefix", optarg);
			return false;
		}
		info->src_prefix4 = (uint8_t) parsed_src_prefix4;
		info->mask4 = (0x1<<31)>>(uint8_t) parsed_src_prefix4;
		return true;
#endif
	}
	return false;
}

static void tarhash_mt_check(unsigned int flags)
{
	if (!(flags & F_KEY)) {
		xtables_error(PARAMETER_PROBLEM,
			"TARHASH: key must be provided");
	}
	if (!(flags & F_RATIO)) {
		xtables_error(PARAMETER_PROBLEM,
			"TARHASH: ratio must be provided");
	}
#ifdef WITH_IPV6
	if (!(flags & F_SRC_PREFIX4)) {
		xtables_error(PARAMETER_PROBLEM,
			"TARHASH: src-prefix4 must be provided");
	}
	if (!(flags & F_SRC_PREFIX6)) {
		xtables_error(PARAMETER_PROBLEM,
			"TARHASH: src-prefix6 must be provided");
	}
#else
	if (!(flags & F_SRC_PREFIX4)) {
		xtables_error(PARAMETER_PROBLEM,
			"TARHASH: src-prefix must be provided");
	}
#endif

}

static void tarhash_mt_save(const void *ip,
    const struct xt_entry_target *target)
{
	//TODO: What is this function for? Can it be deleted?
}

static void tarhash_mt_print(const void *ip,
    const struct xt_entry_target *target, int numeric)
{
	printf(" -j TARHASH");
	tarhash_mt_save(ip, target);
}

static struct xtables_match tarhash_mt_reg = {
	.version       = XTABLES_VERSION,
	.name          = "TARHASH",
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
	xtables_register_target(&tarhash_mt_reg);
}

