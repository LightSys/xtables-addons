/* ipt_geoip.h header file for libipt_geoip.c and ipt_geoip.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Copyright (c) 2004, 2005, 2006, 2007, 2008
 *
 * Samuel Jean
 * Nicolas Bouliane
 */
#ifndef _LINUX_NETFILTER_XT_GEOIP_H
#define _LINUX_NETFILTER_XT_GEOIP_H 1

#define XT_GEOIP_SRC         0x01     /* Perform check on Source IP */
#define XT_GEOIP_DST         0x02     /* Perform check on Destination IP */
#define XT_GEOIP_INV         0x04     /* Negate the condition */

#define XT_GEOIP_MAX         15       /* Maximum of countries */

/* Yup, an address range will be passed in with host-order */
struct geoip_subnet {
	__u32 begin;
	__u32 end;
};

struct geoip_country_user {
	aligned_u64 subnets;
	__u32 count;
	__u16 cc;
};

struct geoip_country_kernel;

union geoip_country_group {
	aligned_u64 user;
	struct geoip_country_kernel *kernel;
};

struct xt_geoip_match_info {
	__u8 flags;
	__u8 count;
	__u16 cc[XT_GEOIP_MAX];

	/* Used internally by the kernel */
	union geoip_country_group mem[XT_GEOIP_MAX];
};

#define COUNTRY(cc) (cc >> 8), (cc & 0x00FF)

#endif /* _LINUX_NETFILTER_XT_GEOIP_H */
