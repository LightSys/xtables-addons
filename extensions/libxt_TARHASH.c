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

enum {
	F_TARPIT     = 1 << 0,
	F_HONEYPOT   = 1 << 1,
	F_RESET      = 1 << 2,
	F_KEY        = 1 << 3,
	F_RATIO      = 1 << 4,
	F_SRC_PREFIX = 1 << 5,
};

static const struct option tarhash_tg_opts[] = {
	{.name = "tarpit",     .has_arg = false, .val = 't'},
	{.name = "honeypot",   .has_arg = false, .val = 'h'},
	{.name = "reset",      .has_arg = false, .val = 'r'},
	{.name = "key",        .has_arg = true,  .val = 'k'},
	{.name = "ratio",      .has_arg = true,  .val = 'o'},
	// TODO perhaps use a separate parameter for IPv4 and IPv6 addresses.
	{.name = "src-prefix", .has_arg = true,  .val = 's'},
	{NULL},
};

static void tarhash_tg_help(void)
{
	printf(
		"TARHASH target options:\n"
		"  --tarpit      Enable classic 0-window tarpit (default)\n"
		"  --honeypot    Enable honeypot option\n"
		"  --reset       Enable inline resets\n"
		"  --key         Seed/salt value for the hashing function\n"
		"  --ratio       Inverse of the likelihood that a port is answered\n"
		"  --src-prefix  Number of bits in the source IP considered in the hash function\n");
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

static int tarhash_tg_parse(int c, char **argv, int invert, unsigned int *flags,
                           const void *entry, struct xt_entry_target **target)
{
	struct xt_tarhash_tginfo *info = (void *)(*target)->data;

	switch (c) {
	case 't':
		info->variant = XTTARHASH_TARPIT;
		*flags |= F_TARPIT;
		return true;
	case 'h':
		info->variant = XTTARHASH_HONEYPOT;
		*flags |= F_HONEYPOT;
		return true;
	case 'r':
		info->variant = XTTARHASH_RESET;
		*flags |= F_RESET;
		return true;
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
	case 's':
		xtables_param_act(XTF_ONLY_ONCE, "TARHASH", "--src-prefix", *flags & F_SRC_PREFIX);
		xtables_param_act(XTF_NO_INVERT, "TARHASH", "--src-prefix", invert);
		*flags |= F_SRC_PREFIX;
		unsigned long parsed_src_prefix;
		if (!parse_unsigned_long(optarg, &parsed_src_prefix) || parsed_src_prefix > 32) {
			xtables_param_act(XTF_BAD_VALUE, "TARHASH", "--src-prefix", optarg);
			return false;
		}
		info->src_prefix = (uint8_t) parsed_src_prefix;
		return true;
	}
	return false;
}

static void tarhash_tg_check(unsigned int flags)
{
	unsigned int tarpit_flags = flags & 7;
	if (tarpit_flags == (F_TARPIT   | F_HONEYPOT) ||
	    tarpit_flags == (F_TARPIT   | F_RESET) ||
	    tarpit_flags == (F_HONEYPOT | F_RESET) ||
	    tarpit_flags == (F_TARPIT   | F_HONEYPOT | F_RESET)) {
		xtables_error(PARAMETER_PROBLEM,
			"TARHASH: only one action can be used at a time");
	}
	if (!(flags & F_KEY)) {
		xtables_error(PARAMETER_PROBLEM,
			"TARHASH: key must be provided");
	}
	if (!(flags & F_RATIO)) {
		xtables_error(PARAMETER_PROBLEM,
			"TARHASH: ratio must be provided");
	}
	if (!(flags & F_SRC_PREFIX)) {
		xtables_error(PARAMETER_PROBLEM,
			"TARHASH: src-prefix must be provided");
	}

}

static void tarhash_tg_save(const void *ip,
    const struct xt_entry_target *target)
{
	const struct xt_tarhash_tginfo *info = (const void *)target->data;

	switch (info->variant) {
	case XTTARHASH_TARPIT:
		printf(" --tarpit ");
		break;
	case XTTARHASH_HONEYPOT:
		printf(" --honeypot ");
		break;
	case XTTARHASH_RESET:
		printf(" --reset ");
		break;
	}
}

static void tarhash_tg_print(const void *ip,
    const struct xt_entry_target *target, int numeric)
{
	printf(" -j TARHASH");
	tarhash_tg_save(ip, target);
}

static struct xtables_target tarhash_tg_reg = {
	.version       = XTABLES_VERSION,
	.name          = "TARHASH",
	.family        = NFPROTO_UNSPEC,
	.size          = XT_ALIGN(sizeof(struct xt_tarhash_tginfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_tarhash_tginfo)),
	.help          = tarhash_tg_help,
	.parse         = tarhash_tg_parse,
	.final_check   = tarhash_tg_check,
	.print         = tarhash_tg_print,
	.save          = tarhash_tg_save,
	.extra_opts    = tarhash_tg_opts,
};

static __attribute__((constructor)) void tarhash_tg_ldr(void)
{
	xtables_register_target(&tarhash_tg_reg);
}

