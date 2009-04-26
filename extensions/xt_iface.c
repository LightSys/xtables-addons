/*
 *	xt_iface - kernel module to match interface state flags
 *
 *	Original author: Gáspár Lajos <gaspar.lajos@glsys.eu>
 */

#include <linux/if.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include "xt_iface.h"

MODULE_AUTHOR("Gáspár Lajos <gaspar.lajos@glsys.eu>");
MODULE_DESCRIPTION("Xtables: iface match module");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_iface");
MODULE_ALIAS("ip6t_iface");
//MODULE_ALIAS("arpt_iface");

static const struct xt_iface_flag_pairs xt_iface_lookup[] =
{
	{.iface_flag = XT_IFACE_UP,		.iff_flag = IFF_UP},
	{.iface_flag = XT_IFACE_BROADCAST,	.iff_flag = IFF_BROADCAST},
	{.iface_flag = XT_IFACE_LOOPBACK,	.iff_flag = IFF_LOOPBACK},
	{.iface_flag = XT_IFACE_POINTOPOINT,	.iff_flag = IFF_POINTOPOINT},
	{.iface_flag = XT_IFACE_RUNNING,	.iff_flag = IFF_RUNNING},
	{.iface_flag = XT_IFACE_NOARP,		.iff_flag = IFF_NOARP},
	{.iface_flag = XT_IFACE_PROMISC,	.iff_flag = IFF_PROMISC},
	{.iface_flag = XT_IFACE_MULTICAST,	.iff_flag = IFF_MULTICAST},
	{.iface_flag = XT_IFACE_DYNAMIC,	.iff_flag = IFF_DYNAMIC},
	{.iface_flag = XT_IFACE_LOWER_UP,	.iff_flag = IFF_LOWER_UP},
	{.iface_flag = XT_IFACE_DORMANT,	.iff_flag = IFF_DORMANT},
};

static bool xt_iface_mt(const struct sk_buff *skb,
    const struct xt_match_param *par)
{
	const struct xt_iface_mtinfo *info = par->matchinfo;
	struct net_device *dev;
	bool retval;
	int i;

	dev    = dev_get_by_name(&init_net, info->ifname);
	retval = dev != NULL;
	if (retval) {
		for (i = 0; i < ARRAY_SIZE(xt_iface_lookup) && retval; ++i) {
			if (info->flags & xt_iface_lookup[i].iface_flag)
				retval &= dev->flags & xt_iface_lookup[i].iff_flag;
			if (info->invflags & xt_iface_lookup[i].iface_flag)
				retval &= !(dev->flags & xt_iface_lookup[i].iff_flag);
		}
		dev_put(dev);
	}
	return retval;
}

static struct xt_match xt_iface_mt_reg[] __read_mostly = {
	{
		.name       = "iface",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.matchsize  = XT_ALIGN(sizeof(struct xt_iface_mtinfo)),
		.match      = xt_iface_mt,
		.data       = 0,
		.me         = THIS_MODULE,
	},
	{
		.name       = "iface",
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.matchsize  = XT_ALIGN(sizeof(struct xt_iface_mtinfo)),
		.match      = xt_iface_mt,
		.data       = 0,
		.me         = THIS_MODULE,
	},
};

static int __init xt_iface_match_init(void)
{
	return xt_register_matches(xt_iface_mt_reg,
		ARRAY_SIZE(xt_iface_mt_reg));
}

static void __exit xt_iface_match_exit(void)
{
	xt_unregister_matches(xt_iface_mt_reg, ARRAY_SIZE(xt_iface_mt_reg));
}

module_init(xt_iface_match_init);
module_exit(xt_iface_match_exit);
