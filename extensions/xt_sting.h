#ifndef _LINUX_NETFILTER_XT_STING_H
#define _LINUX_NETFILTER_XT_STING_H 1

/* Several of these constants are one more than what might be expected because
 * we are allowing room for an extra null character." */
#define IP4HSIZE                  21
#define IP6HSIZE                  69
#define MAX_HASHLEN               128
#define MAX_PRINTK_HEX_STRING_LEN 257
#define HASH_ALGORITHM            "hmac(sha256-avx2)"
#define STING                     "sting: "
#define DEBUG                     1     /* 1 for debug kernel logging, 0 for none
				           debug elements should probably be removed in final product */

struct xt_sting_sdesc;

struct xt_sting_mtinfo {
	uint32_t ratio;
	uint8_t  src_prefix4;
	uint8_t  src_prefix6;
	char     key[32];

	uint32_t mask4;
	uint8_t  mask6[16];

	unsigned int digest_length;
	struct crypto_shash     *hash_algorithm;
	struct xt_sting_sdesc *desc;
};

#endif /* _LINUX_NETFILTER_XT_STING_H */
