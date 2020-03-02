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
#include "compat_xtables.h"
#include "xt_TARHASH.h"
#if defined(CONFIG_IP6_NF_IPTABLES) || defined(CONFIG_IP6_NF_IPTABLES_MODULE)
#	define WITH_IPV6 1
#endif

static void xttarhash_tarhash(struct tcphdr *tcph, const struct tcphdr *oth)
{

}

static bool tarhash_generic(struct tcphdr *tcph, const struct tcphdr *oth,
    uint16_t payload, unsigned int mode)
{
	// JEB: I deleted the rest of the options for now.  We may want to bring them back
	// at some point, but for now I removed them
	switch(mode) {
	case XTTARHASH_TARHASH:
		if (!xttarhash_tarhash(tcph, oth))
			return false;
		break;
	}

	return true;
}

static void tarhash_tcp4(struct net *net, struct sk_buff *oldskb,
    unsigned int hook, unsigned int mode)
{
	struct tcphdr _otcph, *tcph;
	const struct tcphdr *oth;
	unsigned int addr_type = RTN_UNSPEC;
	struct sk_buff *nskb;
	const struct iphdr *oldhdr;
	struct iphdr *niph;
	uint16_t tmp, payload;

	/* A truncated TCP header is not going to be useful */
	if (oldskb->len < ip_hdrlen(oldskb) + sizeof(struct tcphdr))
		return;

	oth = skb_header_pointer(oldskb, ip_hdrlen(oldskb),
	                         sizeof(_otcph), &_otcph);
	if (oth == NULL)
		return;

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

	if (!tarhash_generic(tcph, oth, payload, mode))
		goto free_nskb;

	/* Adjust TCP checksum */
	tcph->check = 0;
	tcph->check = tcp_v4_check(sizeof(struct tcphdr), niph->saddr,
	              niph->daddr, csum_partial((char *)tcph,
	              sizeof(struct tcphdr), 0));

	/* Set DF, id = 0 */
	niph->frag_off = htons(IP_DF);
	// JEB: we need to verify which of these options best fits our TARHASH usecase
	if (mode == XTTARPIT_TARPIT || mode == XTTARPIT_RESET)
		niph->id = 0;
	else if (mode == XTTARPIT_HONEYPOT)
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
	if (mode == XTTARPIT_HONEYPOT)
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
    unsigned int hook, unsigned int mode)
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
	if (mode == XTTARPIT_HONEYPOT) {
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
	if (!tarhash_generic(&oth, tcph, payload, mode))
		goto free_nskb;

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

static unsigned int
tarhash_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct iphdr *iph = ip_hdr(skb);
	const struct rtable *rt = skb_rtable(skb);
	const struct xt_tarhash_tginfo *info = par->targinfo;

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
	tarhash_tcp4(par_net(par), skb, par->state->hook, info->variant);
	return NF_DROP;
}

#ifdef WITH_IPV6
static unsigned int
tarhash_tg6(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct ipv6hdr *iph = ipv6_hdr(skb);
	const struct rt6_info *rt = (struct rt6_info *)skb_dst(skb);
	const struct xt_tarhash_tginfo *info = par->targinfo;
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
	tarhash_tcp6(par_net(par), skb, par->state->hook, info->variant);
	return NF_DROP;
}
#endif

static struct xt_target tarhash_tg_reg[] __read_mostly = {
	{
		.name       = "TARHASH",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.hooks      = (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_FORWARD),
		.proto      = IPPROTO_TCP,
		.target     = tarhash_tg4,
		.targetsize = sizeof(struct xt_tarhash_tginfo),
		.me         = THIS_MODULE,
	},
#ifdef WITH_IPV6
	{
		.name       = "TARHASH",
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.hooks      = (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_FORWARD),
		.proto      = IPPROTO_TCP,
		.target     = tarhash_tg6,
		.targetsize = sizeof(struct xt_tarhash_tginfo),
		.me         = THIS_MODULE,
	},
#endif
};

static int __init tarhash_tg_init(void)
{
	return xt_register_targets(tarhash_tg_reg, ARRAY_SIZE(tarhash_tg_reg));
}

static void __exit tarhash_tg_exit(void)
{
	xt_unregister_targets(tarhash_tg_reg, ARRAY_SIZE(tarhash_tg_reg));
}

module_init(tarhash_tg_init);
module_exit(tarhash_tg_exit);
MODULE_DESCRIPTION("Xtables: \"TARHASH\", capture and hold TCP connections");
MODULE_AUTHOR("Jan Engelhardt ");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_TARHASH");
MODULE_ALIAS("ip6t_TARHASH");
