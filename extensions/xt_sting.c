/*
 *	"TARPIT" target extension to Xtables
 *	Kernel module to capture and hold incoming TCP connections using
 *	no local per-connection resources.
 *
 *	Copyright © Aaron Hopkins <tools [at] die net>, 2002
 *
 *	Based on ipt_REJECT.c and offering functionality similar to
 *	LaBrea <http://www.hackbusters.net/LaBrea/>.
 *
 *	<<<
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *	>>>
 *
 * Goal:
 * - Allow incoming TCP connections to be established.
 * - Passing data should result in the connection being switched to the
 *   persist state (0 byte window), in which the remote side stops sending
 *   data and asks to continue every 60 seconds.
 * - Attempts to shut down the connection should be ignored completely, so
 *   the remote side ends up having to time it out.
 *
 * This means:
 * - Reply to TCP SYN,!ACK,!RST,!FIN with SYN-ACK, window 5 bytes
 * - Reply to TCP SYN,ACK,!RST,!FIN with RST to prevent spoofing
 * - Reply to TCP !SYN,!RST,!FIN with ACK, window 0 bytes, rate-limited
 */

#include <linux/ip.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <net/addrconf.h>
#include <net/ip6_checksum.h>
#include <net/ip6_route.h>
#include <net/ipv6.h>
#include <net/route.h>
#include <net/tcp.h>
#include <crypto/hash.h>
#include "compat_xtables.h"
#include "xt_sting.h"
#if defined(CONFIG_IP6_NF_IPTABLES) || defined(CONFIG_IP6_NF_IPTABLES_MODULE)
#	define WITH_IPV6 1
#endif

struct xt_sting_sdesc
{
	struct shash_desc shash;
	char ctx[];
};

# ifdef DEBUG
static void printk_hex_string(const char *buf, const size_t buflen)
{
	size_t i;
	const char *hex;
	char output[MAX_PRINTK_HEX_STRING_LEN];

	if (buflen > MAX_PRINTK_HEX_STRING_LEN) {
		printk(KERN_ERR STING "Too long of a string to print\n");
		return;
	}
	hex = "0123456789abcdef";
	output[buflen * 2] = 0;
	i = 0;
	while (i < buflen) {
		output[i * 2] = (hex[(buf[i] >> 4) & 0xF]);
		output[i * 2 + 1] = (hex[buf[i] & 0xF]);
		i++;
	}
	printk(KERN_DEBUG STING "%s\n", output);
}

static void printkhash(const struct xt_sting_mtinfo *info, char *hash)
{
	unsigned int digest_length;
	digest_length = info->digest_length;
	printk_hex_string(hash, digest_length);
}
#endif

static bool xtsting_decision(const struct xt_sting_mtinfo* info, const char *data, unsigned char datalen) 
{
	unsigned char hash[MAX_HASHLEN];
	size_t i;
	unsigned int result;
	unsigned int digest_length;

	/* perform the actual hash calculation and check for error */
	int hash_result = crypto_shash_digest(&info->desc->shash, data, datalen, hash);
	if (hash_result != 0) {
		printk(KERN_ERR STING "failed to create hash digest\n");
		return false;
	}

#ifdef DEBUG	
	printkhash(info, hash);
#endif
	
	/* mod the hash by ratio to determine match */
	i = 0;
	result = 0;
	digest_length = info->digest_length;
	while (i < digest_length) {
		result = (result * 256 + hash[i]) % info->ratio;
		i++;
	}
	return (result == 0);
}

static bool xtsting_hashdecided4(const struct tcphdr *oth, const struct iphdr *iph, const struct xt_sting_mtinfo *info)
{
	uint32_t indexed_source_ip;
	char string_to_hash[IP4HSIZE];

        indexed_source_ip = be32_to_cpu(iph->saddr) & info->mask4;

#ifdef DEBUG
	/* For checking whether we can access all needed properties */
	printk(KERN_DEBUG STING "dest port: %u\n", be16_to_cpu(oth->dest));
	printk(KERN_DEBUG STING "source ip: %u\n", be32_to_cpu(iph->saddr));
	printk(KERN_DEBUG STING "  dest ip: %u\n", be32_to_cpu(iph->daddr));
	printk(KERN_DEBUG STING "    ratio: %u\n", info->ratio);
	printk(KERN_DEBUG STING "      key: %s\n", info->key);
	printk(KERN_DEBUG STING "     mask: %u\n", info->mask4);	
	printk(KERN_DEBUG STING "masked ip: %u\n", indexed_source_ip);
#endif        
	/* format the hash string */
	snprintf(string_to_hash, IP4HSIZE, "%08x%08x%04x", indexed_source_ip,
		 be32_to_cpu(iph->daddr), be16_to_cpu(oth->dest));

	return xtsting_decision(info, string_to_hash, IP4HSIZE - 1);
}

#ifdef WITH_IPV6
static bool xtsting_hashdecided6(const struct tcphdr *oth, const struct ipv6hdr *iph, const struct xt_sting_mtinfo *info) 
{
        char string_to_hash[IP6HSIZE];
	const __u8 *sa = iph->saddr.s6_addr;
	const __u8 *da = iph->daddr.in6_u.u6_addr8;
	char saddr[16];
	size_t i;
	const uint8_t *ma = info->mask6;
	
	/* mask the IP address */
	i = 0;
	while (i < 16) {
		saddr[i] = sa[i] && ma[i];
		i++;
	}

	/* format the hash string */
	snprintf(string_to_hash, IP6HSIZE, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%04x",
		 saddr[0],  saddr[1],  saddr[2],  saddr[3],
		 saddr[4],  saddr[5],  saddr[6],  saddr[7],
		 saddr[8],  saddr[9],  saddr[10], saddr[11],
		 saddr[12], saddr[13], saddr[14], saddr[15], 
		 da[0],  da[1],  da[2],  da[3],  da[4],  da[5], da[6], 
		 da[7],  da[8],  da[9],  da[10], da[11], da[12],
		 da[13], da[14], da[15], be16_to_cpu(oth->dest));
	

#ifdef DEBUG
	printk(KERN_INFO STING "ipv6 string to hash: %s\n", string_to_hash);
	printk_hex_string(ma, 16);
#endif

	return xtsting_decision(info, string_to_hash, IP6HSIZE - 1);
}
#endif

static bool sting_tcp4(struct net *net, const struct sk_buff *oldskb,
    unsigned int hook, const struct iphdr *iph, const struct xt_sting_mtinfo *info)
{
	struct tcphdr _otcph;
	const struct tcphdr *oth;
	
	/* A truncated TCP header is not going to be useful */
	if (oldskb->len < ip_hdrlen(oldskb) + sizeof(struct tcphdr))
		return false;

	oth = skb_header_pointer(oldskb, ip_hdrlen(oldskb),
	                         sizeof(_otcph), &_otcph);
	if (oth == NULL)
		return false;

	/* Check using hash function whether tarpit response should be sent */
	return xtsting_hashdecided4(oth, iph, info);
}

#ifdef WITH_IPV6
static bool sting_tcp6(struct net *net, const struct sk_buff *oldskb,
    unsigned int hook, const struct ipv6hdr *iph, const struct xt_sting_mtinfo *info)
{
	struct tcphdr oth;
	unsigned int otcplen;
	int tcphoff;
	const struct ipv6hdr *oip6h = ipv6_hdr(oldskb);
	uint8_t proto;
	__be16 frag_off;

	proto   = oip6h->nexthdr;
	tcphoff = ipv6_skip_exthdr(oldskb,
	          (uint8_t *)(oip6h + 1) - oldskb->data, &proto, &frag_off);

	if (tcphoff < 0 || tcphoff > oldskb->len) {
		pr_debug("Cannot get TCP header.\n");
		return false;
	}

	otcplen = oldskb->len - tcphoff;

	/* IP header checks: fragment, too short. */
	if (proto != IPPROTO_TCP || otcplen < sizeof(struct tcphdr)) {
		pr_debug("proto(%d) != IPPROTO_TCP, "
		         "or too short. otcplen = %d\n",
		         proto, otcplen);
		return false;
	}

	if (skb_copy_bits(oldskb, tcphoff, &oth, sizeof(struct tcphdr))) {
		WARN_ON(1);
		return false;
	}

	/* Check using hash function whether tarpit response should be sent */
	return xtsting_hashdecided6(&oth, iph, info);
}
#endif

static bool sting_mt4(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct rtable *rt = skb_rtable(skb);
	const struct iphdr *iph = ip_hdr(skb);
	const struct xt_sting_mtinfo *info = par->targinfo;

	/* Do we have an input route cache entry? (Not in PREROUTING.) */
	if (rt == NULL)
		return false;

	/* No replies to physical multicast/broadcast */
	/* skb != PACKET_OTHERHOST handled by ip_rcv() */
	if (skb->pkt_type != PACKET_HOST)
		return false;

	/* Now check at the protocol level */
	if (rt->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
		return false;

	/*
	 * Our naive response construction does not deal with IP
	 * options, and probably should not try.
	 */
	if (ip_hdrlen(skb) != sizeof(struct iphdr))
		return false;

	/* We are not interested in fragments */
	if (iph->frag_off & htons(IP_OFFSET))
		return false;

	/* Check using hash function whether packet should continue */
	return sting_tcp4(par_net(par), skb, par->state->hook, iph, info);
}

#ifdef WITH_IPV6
static bool sting_mt6(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct ipv6hdr *iph = ipv6_hdr(skb);
	const struct rt6_info *rt = (struct rt6_info *)skb_dst(skb);
	const struct xt_sting_mtinfo *info = par->targinfo;
	uint8_t proto;
	__be16 frag_off;

	/* Do we have an input route cache entry? (Not in PREROUTING.) */
	if (rt == NULL) {
		pr_debug("Dropping no input route cache entry\n");
		return false;
	}

	/* No replies to physical multicast/broadcast */
	/* skb != PACKET_OTHERHOST handled by ip_rcv() */
	if (skb->pkt_type != PACKET_HOST) {
		pr_debug("type != PACKET_HOST");
		return false;
	}

	/*
	 * Our naive response construction does not deal with IP
	 * options, and probably should not try.
	 */
	proto = iph->nexthdr;
	if (ipv6_skip_exthdr(skb, skb_network_header_len(skb), &proto,
	    &frag_off) != sizeof(struct ipv6hdr))
		return false;

	if ((!(ipv6_addr_type(&iph->saddr) & IPV6_ADDR_UNICAST)) ||
	    (!(ipv6_addr_type(&iph->daddr) & IPV6_ADDR_UNICAST))) {
		pr_debug("addr is not unicast.\n");
		return false;
	}
	return sting_tcp6(par_net(par), skb, par->state->hook, iph, info);
}
#endif

static int sting_mt_check(const struct xt_mtchk_param *par)
{
	struct xt_sting_mtinfo *info;
	unsigned int desc_size;
	unsigned int alloc_size;

	info = par->matchinfo;
	info->hash_algorithm = crypto_alloc_shash(HASH_ALGORITHM, CRYPTO_ALG_TYPE_SHASH, 0); 
	info->digest_length = crypto_shash_digestsize(info->hash_algorithm);
	if (info->digest_length > MAX_HASHLEN) {
		printk(KERN_ERR STING "digest length for hash algorithm is too long.\n");
		return -EINVAL;
	}
	crypto_shash_setkey(info->hash_algorithm, info->key, info->digest_length);
	desc_size = crypto_shash_descsize(info->hash_algorithm);
	alloc_size = sizeof(struct shash_desc) + desc_size;
	info->desc = kmalloc(alloc_size, GFP_KERNEL);
	if (!info->desc) {
		printk(KERN_ERR STING "allocation failed\n");
		return -EINVAL;	
	}
	info->desc->shash.tfm = info->hash_algorithm;
	info->desc->shash.flags = 0x0;
	return 0;
}

static void sting_mt_destroy(const struct xt_mtdtor_param *par)
{
	struct xt_sting_mtinfo *info = par->matchinfo;
	kfree(info->desc);
	crypto_free_shash(info->hash_algorithm);
}

static struct xt_match sting_mt_reg[] __read_mostly = {
	{
		.name       = "sting",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.match      = sting_mt4,
		.matchsize  = sizeof(struct xt_sting_mtinfo),
		.checkentry = sting_mt_check,
		.destroy    = sting_mt_destroy,
		.me         = THIS_MODULE,
	},
#ifdef WITH_IPV6
	{
		.name       = "sting",
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.match      = sting_mt6,
		.matchsize  = sizeof(struct xt_sting_mtinfo),
		.checkentry = sting_mt_check,
		.destroy    = sting_mt_destroy,
		.me         = THIS_MODULE,
	},
#endif
};

static int __init sting_mt_init(void)
{
	if (request_module(HASH_ALGORITHM) < 0) {
		printk(KERN_ERR STING "request_module('%s') error.\n", HASH_ALGORITHM);
		return -ENXIO;
	}
	return xt_register_matches(sting_mt_reg, ARRAY_SIZE(sting_mt_reg));
}

static void __exit sting_mt_exit(void)
{
	xt_unregister_matches(sting_mt_reg, ARRAY_SIZE(sting_mt_reg));
}

module_init(sting_mt_init);
module_exit(sting_mt_exit);
MODULE_DESCRIPTION("Xtables: \"sting\", capture and hold TCP connections");
MODULE_AUTHOR("Jan Engelhardt ");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_sting");
MODULE_ALIAS("ip6t_sting");
