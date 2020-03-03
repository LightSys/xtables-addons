#ifndef _LINUX_NETFILTER_XT_TARHASH_H
#define _LINUX_NETFILTER_XT_TARHASH_H 1

enum xt_tarhash_target_variant {
	XTTARHASH_TARPIT,
	XTTARHASH_HONEYPOT,
	XTTARHASH_RESET,
};

struct xt_tarhash_tginfo {
	uint8_t variant;
};

#endif /* _LINUX_NETFILTER_XT_TARHASHH */
