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

//TODO Rename files to lowercase because this is a match instead of a target.
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter/x_tables.h>
#ifdef CONFIG_BRIDGE_NETFILTER
#	include <linux/netfilter_bridge.h>
#endif
#include <net/addrconf.h>
#include <net/ip6_checksum.h>
#include <net/ip6_route.h>
#include <net/ipv6.h>
#include <net/route.h>
#include <net/tcp.h>
#include <crypto/hash.h>
#include "compat_xtables.h"
#include "xt_TARHASH.h"
#if defined(CONFIG_IP6_NF_IPTABLES) || defined(CONFIG_IP6_NF_IPTABLES_MODULE)
#	define WITH_IPV6 1
#endif

struct xt_tarhash_sdesc {
	struct shash_desc shash;
	char ctx[];
};

static printkhash(char *hash) {
	size_t i = 0;
	const char *hex = "0123456789abcdef";
	char hex_string_hash[65];
	hex_string_hash[64] = 0;
	while (i < 32) {
		hex_string_hash[i * 2] = (hex[(hash[i] >> 4) & 0xF]);
		hex_string_hash[i * 2 + 1] = (hex[hash[i] & 0xF]);
		i++;
	}
	printk("hash: %s\n", hex_string_hash);
}

static bool xttarhash_decision(const struct xt_tarhash_mtinfo* info, const char *data, unsigned char datalen) {
	unsigned char hash[32];
	int hash_result = crypto_shash_digest(&info->desc->shash, data, datalen, hash);
	if (hash_result != 0) {
		printk("failed to create hash digest\n");
	}
	printkhash(hash);
	unsigned char i = 0;
	unsigned int result = 0;
	while (i < 32) {
		result = (result * 256 + hash[i]) % info->ratio;
		i++;
	}
	return result == 0;
}

static bool xttarhash_hashdecided(const struct tcphdr *oth, const struct iphdr *iph, const struct xt_tarhash_mtinfo *info)
{
	// Make hash of (masked) source, dest, port, key
	// Modulus by ratio
	// If mod is 0, return true
	// If mod is non-zero return false

	/* For checking whether we can access all needed properties */

	printk("dest: %u\n", oth->dest);
	printk("saddr: %u\n", iph->saddr);
	printk("daddr: %u\n", iph->daddr);
	printk("ratio: %u\n", info->ratio);
	printk("key: %s\n", info->key);

	int hash = 0;
        char string_to_hash[21];
        uint32_t indexed_source_ip = iph->saddr && info->mask4;

        snprintf(string_to_hash, 21, "%08x %08x %04x", indexed_source_ip,
		 iph->daddr, oth->dest);

	return xttarhash_decision(info, string_to_hash, strlen(string_to_hash));
}

static bool xttarhash_hashdecided6(const struct tcphdr *oth, const struct ipv6hdr *iph, const struct xt_tarhash_mtinfo *info) 
{
	int hash = 0;
        char string_to_hash[69];
	
	__u8 *sa = iph->saddr.s6_addr;
	__u8 *da = iph->daddr.in6_u.u6_addr8;

	uint8_t *ma = info->mask6;

	snprintf(string_to_hash, 69, "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %04x",
		 sa[0] && ma[0], sa[1] && ma[1], sa[2] && ma[2], sa[3] && ma[3],
		 sa[4] && ma[4], sa[5] && ma[5], sa[6] && ma[6], sa[7] && ma[7],
		 sa[8] && ma[8], sa[9] && ma[9], sa[10] && ma[10],
		 sa[11] && ma[11], sa[12] && ma[12], sa[13] && ma[13],
		 sa[14] && ma[14], sa[15] && ma[15], da[0], da[1], da[2], da[3],
		 da[4], da[5], da[6], da[7], da[8], da[9], da[10], da[11], da[12],
		 da[13], da[14], da[15], oth->dest);

	return xttarhash_decision(string_to_hash, strlen(string_to_hash));
}

static void tarhash_tcp4(struct net *net, struct sk_buff *oldskb,
    unsigned int hook, const struct iphdr *iph, const struct xt_tarhash_mtinfo *info)
{
	struct tcphdr _otcph, *tcph;
	const struct tcphdr *oth;
	unsigned int addr_type = RTN_UNSPEC;
	struct sk_buff *nskb;
	const struct iphdr *oldhdr;
	struct iphdr *niph;
	uint16_t tmp, payload;
	
	unsigned int mode;

	mode = info->variant;

	/* A truncated TCP header is not going to be useful */
	if (oldskb->len < ip_hdrlen(oldskb) + sizeof(struct tcphdr))
		return;

	oth = skb_header_pointer(oldskb, ip_hdrlen(oldskb),
	                         sizeof(_otcph), &_otcph);
	if (oth == NULL)
		return;

	/* Check using hash function whether tarpit response should be sent */
	if (!xttarhash_hashdecided(oth, iph, info)) 
		goto free_nskb;

	/* Check checksum. */
	if (nf_ip_checksum(oldskb, hook, ip_hdrlen(oldskb), IPPROTO_TCP))
		return;

	/*
	 * Copy skb (even if skb is about to be dropped, we cannot just
	 * clone it because there may be other things, such as tcpdump,
	 * interested in it)
	 */
	nskb = skb_copy_expand(oldskb, LL_MAX_HEADER,
	                       skb_tailroom(oldskb), GFP_ATOMIC);
	if (nskb == NULL)
		return;

	/* This packet will not be the same as the other: clear nf fields */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
	nf_reset_ct(nskb);
#else
	nf_reset(nskb);
#endif
	skb_nfmark(nskb) = 0;
	skb_init_secmark(nskb);
	skb_shinfo(nskb)->gso_size = 0;
	skb_shinfo(nskb)->gso_segs = 0;
	skb_shinfo(nskb)->gso_type = 0;
	oldhdr = ip_hdr(oldskb);
	tcph = (struct tcphdr *)(skb_network_header(nskb) + ip_hdrlen(nskb));

	/* Swap source and dest */
	niph         = ip_hdr(nskb);
	niph->daddr  = xchg(&niph->saddr, niph->daddr);
	tmp          = tcph->source;
	tcph->source = tcph->dest;
	tcph->dest   = tmp;

	/* Calculate payload size?? */
	payload = nskb->len - ip_hdrlen(nskb) - sizeof(struct tcphdr);

	/* Truncate to length (no data) */
	tcph->doff    = sizeof(struct tcphdr) / 4;
	skb_trim(nskb, ip_hdrlen(nskb) + sizeof(struct tcphdr));
	niph->tot_len = htons(nskb->len);
	tcph->urg_ptr = 0;
	/* Reset flags */
	((u_int8_t *)tcph)[13] = 0;

	/* Adjust TCP checksum */
	tcph->check = 0;
	tcph->check = tcp_v4_check(sizeof(struct tcphdr), niph->saddr,
	              niph->daddr, csum_partial((char *)tcph,
	              sizeof(struct tcphdr), 0));

	/* Set DF, id = 0 */
	niph->frag_off = htons(IP_DF);
	if (mode == XTTARHASH_TARPIT || mode == XTTARHASH_RESET)
		niph->id = 0;
	else if (mode == XTTARHASH_HONEYPOT)
		niph->id = ~oldhdr->id + 1;

#ifdef CONFIG_BRIDGE_NETFILTER
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
	if (hook != NF_INET_FORWARD || ((struct nf_bridge_info *)skb_ext_find(nskb, SKB_EXT_BRIDGE_NF) != NULL &&
	    ((struct nf_bridge_info *)skb_ext_find(nskb, SKB_EXT_BRIDGE_NF))->physoutdev))
#else
	if (hook != NF_INET_FORWARD || (nskb->nf_bridge != NULL &&
	    nskb->nf_bridge->physoutdev != NULL))
#endif
#else
	if (hook != NF_INET_FORWARD)
#endif
		addr_type = RTN_LOCAL;

	if (ip_route_me_harder(net, nskb, addr_type))
		goto free_nskb;
	else
		niph = ip_hdr(nskb);

	nskb->ip_summed = CHECKSUM_NONE;

	/* Adjust IP TTL */
	if (mode == XTTARHASH_HONEYPOT)
		niph->ttl = 128;
	else
		niph->ttl = ip4_dst_hoplimit(skb_dst(nskb));

	/* Adjust IP checksum */
	niph->check = 0;
	niph->check = ip_fast_csum(skb_network_header(nskb), niph->ihl);

	/* "Never happens" */
	if (nskb->len > dst_mtu(skb_dst(nskb)))
		goto free_nskb;

	nf_ct_attach(nskb, oldskb);
	NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_OUT, net, nskb->sk, nskb, NULL,
		skb_dst(nskb)->dev, dst_output);
	return;

 free_nskb:
	kfree_skb(nskb);
}

#ifdef WITH_IPV6
static void tarhash_tcp6(struct net *net, struct sk_buff *oldskb,
    unsigned int hook, const struct ipv6hdr *iph, const struct xt_tarhash_mtinfo *info)
{
	struct sk_buff *nskb;
	struct tcphdr *tcph, oth;
	unsigned int otcplen;
	int tcphoff;
	const struct ipv6hdr *oip6h = ipv6_hdr(oldskb);
	struct ipv6hdr *ip6h;
	const uint8_t tclass = 0;
	uint8_t proto;
	uint16_t payload;
	__be16 frag_off;
	unsigned int mode;

	mode = info->variant;

	proto   = oip6h->nexthdr;
	tcphoff = ipv6_skip_exthdr(oldskb,
	          (uint8_t *)(oip6h + 1) - oldskb->data, &proto, &frag_off);

	if (tcphoff < 0 || tcphoff > oldskb->len) {
		pr_debug("Cannot get TCP header.\n");
		return;
	}

	otcplen = oldskb->len - tcphoff;

	/* IP header checks: fragment, too short. */
	if (proto != IPPROTO_TCP || otcplen < sizeof(struct tcphdr)) {
		pr_debug("proto(%d) != IPPROTO_TCP, "
		         "or too short. otcplen = %d\n",
		         proto, otcplen);
		return;
	}

	if (skb_copy_bits(oldskb, tcphoff, &oth, sizeof(struct tcphdr))) {
		WARN_ON(1);
		return;
	}

	/* Check checksum. */
	if (csum_ipv6_magic(&oip6h->saddr, &oip6h->daddr, otcplen, IPPROTO_TCP,
	    skb_checksum(oldskb, tcphoff, otcplen, 0))) {
		pr_debug("TCP checksum is invalid\n");
		return;
	}

	/* Check using hash function whether tarpit response should be sent */
	if (!xttarhash_hashdecided6(&oth, iph, info)) 
		goto free_nskb;


	nskb = skb_copy_expand(oldskb, LL_MAX_HEADER,
	       skb_tailroom(oldskb), GFP_ATOMIC);
	if (nskb == NULL) {
		if (net_ratelimit())
			pr_debug("cannot alloc skb\n");
		return;
	}

	/* This packet will not be the same as the other: clear nf fields */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
	nf_reset_ct(nskb);
#else
	nf_reset(nskb);
#endif
	skb_nfmark(nskb) = 0;
	skb_init_secmark(nskb);
	skb_shinfo(nskb)->gso_size = 0;
	skb_shinfo(nskb)->gso_segs = 0;
	skb_shinfo(nskb)->gso_type = 0;
	skb_put(nskb, sizeof(struct ipv6hdr));
	ip6h = ipv6_hdr(nskb);
	*(__be32 *)ip6h =  htonl(0x60000000 | (tclass << 20));
	ip6h->nexthdr = IPPROTO_TCP;
	ip6h->saddr = oip6h->daddr;
	ip6h->daddr = oip6h->saddr;

	/* Adjust IP TTL */
	if (mode == XTTARHASH_HONEYPOT) {
		ip6h->hop_limit = 128;
	} else {
		ip6h->hop_limit = ip6_dst_hoplimit(skb_dst(nskb));
	}

	tcph = (struct tcphdr *)(skb_network_header(nskb) +
	       sizeof(struct ipv6hdr));

	/* Truncate to length (no data) */
	skb_trim(nskb, sizeof(struct ipv6hdr) + sizeof(struct tcphdr));
	tcph->doff    = sizeof(struct tcphdr)/4;
	tcph->source  = oth.dest;
	tcph->dest    = oth.source;
	tcph->urg_ptr = 0;
	/* Reset flags */
	((uint8_t *)tcph)[13] = 0;

	payload = nskb->len - sizeof(struct ipv6hdr) - sizeof(struct tcphdr);

	ip6h->payload_len = htons(sizeof(struct tcphdr));
	tcph->check = 0;

	/* Adjust TCP checksum */
	tcph->check = csum_ipv6_magic(&ipv6_hdr(nskb)->saddr,
	              &ipv6_hdr(nskb)->daddr, sizeof(struct tcphdr),
	              IPPROTO_TCP,
	              csum_partial(tcph, sizeof(struct tcphdr), 0));

	if (ip6_route_me_harder(net, nskb))
		goto free_nskb;

	nskb->ip_summed = CHECKSUM_NONE;

	nf_ct_attach(nskb, oldskb);
	NF_HOOK(NFPROTO_IPV6, NF_INET_LOCAL_OUT, net, nskb->sk, nskb, NULL,
	        skb_dst(nskb)->dev, dst_output);
	return;

 free_nskb:
	kfree_skb(nskb);
}
#endif

static bool tarhash_mt4(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct iphdr *iph = ip_hdr(skb);
	const struct rtable *rt = skb_rtable(skb);
	const struct xt_tarhash_mtinfo *info = par->targinfo;

	/* Do we have an input route cache entry? (Not in PREROUTING.) */
	if (rt == NULL)
		return NF_DROP;

	/* No replies to physical multicast/broadcast */
	/* skb != PACKET_OTHERHOST handled by ip_rcv() */
	if (skb->pkt_type != PACKET_HOST)
		return NF_DROP;

	/* Now check at the protocol level */
	if (rt->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
		return NF_DROP;

	/*
	 * Our naive response construction does not deal with IP
	 * options, and probably should not try.
	 */
	if (ip_hdrlen(skb) != sizeof(struct iphdr))
		return NF_DROP;

	/* We are not interested in fragments */
	if (iph->frag_off & htons(IP_OFFSET))
		return NF_DROP;
	tarhash_tcp4(par_net(par), skb, par->state->hook, iph, info);
	return NF_DROP;
}

#ifdef WITH_IPV6
static bool tarhash_mt6(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct ipv6hdr *iph = ipv6_hdr(skb);
	const struct rt6_info *rt = (struct rt6_info *)skb_dst(skb);
	const struct xt_tarhash_mtinfo *info = par->targinfo;
	uint8_t proto;
	__be16 frag_off;

	/* Do we have an input route cache entry? (Not in PREROUTING.) */
	if (rt == NULL) {
		pr_debug("Dropping no input route cache entry\n");
		return NF_DROP;
	}

	/* No replies to physical multicast/broadcast */
	/* skb != PACKET_OTHERHOST handled by ip_rcv() */
	if (skb->pkt_type != PACKET_HOST) {
		pr_debug("type != PACKET_HOST");
		return NF_DROP;
	}

	/*
	 * Our naive response construction does not deal with IP
	 * options, and probably should not try.
	 */
	proto = iph->nexthdr;
	if (ipv6_skip_exthdr(skb, skb_network_header_len(skb), &proto,
	    &frag_off) != sizeof(struct ipv6hdr))
		return NF_DROP;

	if ((!(ipv6_addr_type(&iph->saddr) & IPV6_ADDR_UNICAST)) ||
	    (!(ipv6_addr_type(&iph->daddr) & IPV6_ADDR_UNICAST))) {
		pr_debug("addr is not unicast.\n");
		return NF_DROP;
	}
	tarhash_tcp6(par_net(par), skb, par->state->hook, iph, info);
	return NF_DROP;
}
#endif

static int tarhash_mt_check(const struct xt_mtchk_param *par) {
	struct xt_tarhash_mtinfo *info = par->matchinfo;
	// TODO: allocate the algorithm once for the whole module and set the key per packet?
	info->hash_algorithm = crypto_alloc_shash("hmac(sha256)", CRYPTO_ALG_TYPE_SHASH, 0);
	crypto_shash_setkey(info->hash_algorithm, info->key, 32);
	unsigned int desc_size = crypto_shash_descsize(info->hash_algorithm);
	unsigned int alloc_size = sizeof(struct shash_desc) + desc_size;
	info->desc = kmalloc(alloc_size, GFP_KERNEL);
	if (!info->desc) {
		printk("allocation failed\n");
		// TODO: error out in this case.
	}
	info->desc->shash.tfm = info->hash_algorithm;
	info->desc->shash.flags = 0x0;
	return 0;
}

static void tarhash_mt_destroy(const struct xt_mtdtor_param *par) {
	struct xt_tarhash_mtinfo *info = par->matchinfo;
	kfree(info->desc);
	crypto_free_shash(info->hash_algorithm);
}

static struct xt_match tarhash_mt_reg[] __read_mostly = {
	{
		.name       = "TARHASH",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.match      = tarhash_mt4,
		.matchsize = sizeof(struct xt_tarhash_mtinfo),
		.checkentry = tarhash_mt_check,
		.destroy    = tarhash_mt_destroy,
		.me         = THIS_MODULE,
	},
#ifdef WITH_IPV6
	{
		.name       = "TARHASH",
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.match      = tarhash_mt6,
		.matchsize = sizeof(struct xt_tarhash_mtinfo),
		.checkentry = tarhash_mt_check,
		.destroy    = tarhash_mt_destroy,
		.me         = THIS_MODULE,
	},
#endif
};

static int __init tarhash_mt_init(void)
{
	// TODO: check that the desired algorithm is available.
	return xt_register_matches(tarhash_mt_reg, ARRAY_SIZE(tarhash_mt_reg));
}

static void __exit tarhash_mt_exit(void)
{
	xt_unregister_matches(tarhash_mt_reg, ARRAY_SIZE(tarhash_mt_reg));
}

module_init(tarhash_mt_init);
module_exit(tarhash_mt_exit);
MODULE_DESCRIPTION("Xtables: \"TARHASH\", capture and hold TCP connections");
MODULE_AUTHOR("Jan Engelhardt ");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_TARHASH");
MODULE_ALIAS("ip6t_TARHASH");
