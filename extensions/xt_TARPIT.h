#ifndef _LINUX_NETFILTER_XT_TARPIT_H
#define _LINUX_NETFILTER_XT_TARPIT_H 1

enum xt_tarpit_target_variant {
	XTTARHASH_TARHASH,
};

struct xt_tarhash_tginfo {
	uint8_t variant;
};

#endif /* _LINUX_NETFILTER_XT_TARHASH_H */
