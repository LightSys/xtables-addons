#ifndef _LINUX_NETFILTER_XT_TARHASH_H
#define _LINUX_NETFILTER_XT_TARHASH_H 1

struct xt_tarhash_tginfo {
	uint8_t  src_prefix4;
	uint32_t mask4;
#ifdef WITH_IPV6
	/* TODO: add conditional compilation for wider IPv6 blocks */
	uint8_t  src_prefix6;
	uint8_t  mask6[16];
#endif
	uint32_t ratio;
	char     key[32];
};

#endif /* _LINUX_NETFILTER_XT_TARHASH_H */
