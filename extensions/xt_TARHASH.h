#ifndef _LINUX_NETFILTER_XT_TARHASH_H
#define _LINUX_NETFILTER_XT_TARHASH_H 1

enum xt_tarhash_target_variant {
	XTTARHASH_TARPIT,
	XTTARHASH_HONEYPOT,
	XTTARHASH_RESET,
};

struct xt_tarhash_tginfo {
	uint8_t  variant;
	uint8_t  src_prefix4;
	uint32_t mask4;
#ifdef WITH_IPV6
	/* TODO: add conditional compilation for wider IPv6 blocks */
	uint8_t  src_prefix6;
	union {
		uint8_t  u_8[16];
#if __UAPI_DEF_IN6_ADDR_ALT
		uint16_t u_16[8];
		uint32_t u_32[4];
#endif
	} mask6;

#endif
	uint32_t ratio;
	char     key[32];
};

#endif /* _LINUX_NETFILTER_XT_TARHASH_H */
