#ifndef _LINUX_NETFILTER_XT_TARHASH_H
#define _LINUX_NETFILTER_XT_TARHASH_H 1

struct xt_tarhash_sdesc;

struct xt_tarhash_mtinfo {
	uint32_t mask4;
#if defined(CONFIG_IP6_NF_IPTABLES) || defined(CONFIG_IP6_NF_IPTABLES_MODULE)
	/* TODO: add conditional compilation for wider IPv6 blocks */
	uint8_t  mask6[16];
#endif
	uint32_t ratio;
	char     key[32];

	struct crypto_shash *hash_algorithm;
	struct xt_tarhash_sdesc *desc;
};

#endif /* _LINUX_NETFILTER_XT_TARHASH_H */
