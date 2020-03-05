#ifndef _LINUX_NETFILTER_XT_TARHASH_H
#define _LINUX_NETFILTER_XT_TARHASH_H 1
#if defined(CONFIG_IP6_NF_IPTABLES) || defined(CONFIG_IP6_NF_IPTABLES_MODULE)
#	define WITH_IPV6 1
#endif

struct xt_tarhash_sdesc;

struct xt_tarhash_mtinfo {
	uint8_t  src_prefix4;
	uint32_t mask4;
#ifdef WITH_IPV6
	/* TODO: add conditional compilation for wider IPv6 blocks */
	uint8_t  src_prefix6;
	uint8_t  mask6[16];
#endif
	uint32_t ratio;
	char     key[32];

	struct crypto_shash *hash_algorithm;
	struct xt_tarhash_sdesc *sdesc;
};

#endif /* _LINUX_NETFILTER_XT_TARHASH_H */
