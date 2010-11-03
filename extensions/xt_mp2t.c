/*
 * MPEG2 TS match extension "mp2t" for Xtables.
 *
 * This module analyses the contents of MPEG2 Transport Stream (TS)
 * packets, and can detect TS/CC packet drops.
 *
 * Copyright (c) Jesper Dangaard Brouer <jdb@comx.dk>, 2009+
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License; either
 * version 2 of the License, or any later version, as published by the
 * Free Software Foundation.
 *
 */

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <linux/netfilter/x_tables.h>

#include <linux/rculist.h>

#include "xt_mp2t.h"
#include "compat_xtables.h"

#include <linux/netdevice.h> /* msg levels */

/* Proc file related */
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

/* Timestamp related */
#include <linux/time.h>

MODULE_AUTHOR("Jesper Dangaard Brouer <jdb@comx.dk>");
MODULE_DESCRIPTION("Detecting packet drops in MPEG2 Transport Streams (TS)");
MODULE_LICENSE("GPL");
MODULE_VERSION(XT_MODULE_VERSION);
MODULE_ALIAS("ipt_mp2t");

/* Proc related */
static struct proc_dir_entry *mp2t_procdir;
static const struct file_operations dl_file_ops;

/* Message level instrumentation based upon the device driver message
 * levels see include/linux/netdevice.h.
 *
 * Note that "msg_level" is runtime adjustable via:
 *  /sys/module/xt_mp2t/parameters/msg_level
 *
 */
#define NETIF_MSG_DEBUG  0x10000

/* Performance tuning instrumentation that can be compiled out */
/* #define PERFTUNE 1 */
#define PERFTUNE 0

#if 1
#define MP2T_MSG_DEFAULT						\
	(NETIF_MSG_DRV   | NETIF_MSG_PROBE  | NETIF_MSG_LINK |		\
	 NETIF_MSG_IFUP  | NETIF_MSG_IFDOWN |				\
	 NETIF_MSG_DEBUG | NETIF_MSG_RX_ERR | NETIF_MSG_RX_STATUS	\
	)
#else
#define MP2T_MSG_DEFAULT						\
	(NETIF_MSG_DRV    | NETIF_MSG_PROBE  | NETIF_MSG_LINK |		\
	 NETIF_MSG_IFUP   | NETIF_MSG_IFDOWN |				\
	 NETIF_MSG_RX_ERR |						\
	)
#endif

static int debug  = -1;
static int msg_level;
module_param(debug, int, 0);
module_param(msg_level, int, 0664);
MODULE_PARM_DESC(debug, "Set low N bits of message level");
MODULE_PARM_DESC(msg_level, "Message level bit mask");

/* Possibility to compile out print statements, this was used when
 * profiling the code.
 */
/* #define NO_MSG_CODE 1 */
/* #undef DEBUG */
/* #define DEBUG 1 */

#ifdef NO_MSG_CODE
#undef DEBUG
#endif

#ifdef DEBUG
#define msg_dbg(TYPE, f, a...)						\
	do {	if (msg_level & NETIF_MSG_##TYPE)			\
			if (net_ratelimit())				\
				printk(KERN_DEBUG PFX f "\n", ## a);	\
	} while (0)
#else
#define msg_dbg(TYPE, f, a...)
#endif

#ifdef NO_MSG_CODE
#define msg_info(TYPE, f, a...)
#else
#define msg_info(TYPE, f, a...)						\
	do {	if (msg_level & NETIF_MSG_##TYPE)			\
			if (net_ratelimit())				\
				printk(KERN_INFO PFX f "\n", ## a);	\
	} while (0)
#endif

#ifdef NO_MSG_CODE
#define msg_notice(TYPE, f, a...)
#else
#define msg_notice(TYPE, f, a...)					\
	do {	if (msg_level & NETIF_MSG_##TYPE)			\
			if (net_ratelimit())				\
				printk(KERN_NOTICE PFX f "\n", ## a);	\
	} while (0)
#endif

#ifdef NO_MSG_CODE
#define msg_warn(TYPE, f, a...)
#else
#define msg_warn(TYPE, f, a...)						\
	do {	if (msg_level & NETIF_MSG_##TYPE)			\
			if (net_ratelimit())				\
				printk(KERN_WARNING PFX f "\n", ## a);	\
	} while (0)
#endif


#ifdef NO_MSG_CODE
#define msg_err(TYPE, f, a...)
#else
#define msg_err(TYPE, f, a...)						\
	do {	if (msg_level & NETIF_MSG_##TYPE)			\
			if (net_ratelimit())				\
				printk(KERN_ERR PFX f "\n", ## a);	\
	} while (0)
#endif


/*** Defines from Wireshark packet-mp2t.c ***/
#define MP2T_PACKET_SIZE 188
#define MP2T_SYNC_BYTE 0x47

#define MP2T_SYNC_BYTE_MASK	0xFF000000
#define MP2T_TEI_MASK		0x00800000
#define MP2T_PUSI_MASK		0x00400000
#define MP2T_TP_MASK		0x00200000
#define MP2T_PID_MASK		0x001FFF00
#define MP2T_TSC_MASK		0x000000C0
#define MP2T_AFC_MASK		0x00000030
#define MP2T_CC_MASK		0x0000000F

#define MP2T_SYNC_BYTE_SHIFT	24
#define MP2T_TEI_SHIFT		23
#define MP2T_PUSI_SHIFT		22
#define MP2T_TP_SHIFT		21
#define MP2T_PID_SHIFT		8
#define MP2T_TSC_SHIFT		6
#define MP2T_AFC_SHIFT		4
#define MP2T_CC_SHIFT		0

/** WIRESHARK CODE COPY-PASTE
 *
 * Wireshark value_string structures
 * typedef struct _value_string {
 *	u32	   value;
 *	const char *strptr;
 * } value_string;
 *
 * Adaption field values "doc" taken from Wireshark
 * static const value_string mp2t_afc_vals[] = {
 *	{ 0, "Reserved" },
 *	{ 1, "Payload only" },
 *	{ 2, "Adaptation Field only" },
 *	{ 3, "Adaptation Field and Payload" },
 *	{ 0, NULL }
 * };
 *
 * WIRESHARK Data structure used for detecting CC drops
 *
 *  conversation
 *    |
 *    +-> mp2t_analysis_data
 *          |
 *          +-> pid_table (RB tree)
 *          |     |
 *          |     +-> pid_analysis_data (per pid)
 *          |     +-> pid_analysis_data
 *          |     +-> pid_analysis_data
 *          |
 *          +-> frame_table (RB tree)
 *                |
 *                +-> frame_analysis_data (only created if drop detected)
 *                      |
 *                      +-> ts_table (RB tree)
 *                            |
 *                            +-> pid_analysis_data (per TS subframe)
 *                            +-> pid_analysis_data

 * Datastructures:
 * ---------------
 *
 * xt_rule_mp2t_conn_htable (per iptables rule)
 *    metadata
 *    locking: RCU
 *    hash[metadata.cfg.size]
 *          |
 *          +-> lists of type mp2t_stream elements
 *
 *
 * mp2t_stream (per multicast/mpeg2-ts stream)
 *     stats (about skips and discontinuities)
 *     locking: Spinlock
 *     pid_cc_table (normal list)
 *       |
 *       +-> list of type pid_data_t
 *           One per PID representing the last TS frames CC value
 *
 *
 **/

/*** Global defines ***/
static DEFINE_SPINLOCK(mp2t_lock); /* Protects conn_htables list */
static LIST_HEAD(conn_htables);    /* List of xt_rule_mp2t_conn_htable's */
static u_int32_t GLOBAL_ID;	   /* Used for assigning rule_id's */
/* TODO/FIXME: xt_hashlimit has this extra mutex, do I need it?
static DEFINE_MUTEX(mp2t_mutex);*/ /* Additional checkentry protection */


/* This is sort of the last TS frames info per pid */
struct pid_data_t {
	struct list_head list;
	int16_t pid;
	int16_t cc_prev;
};

#define MAX_PID 0x1FFF

/** Hash table stuff **/

/* Data to match a stream / connection */
struct mp2t_stream_match { /* Like xt_hashlimit: dsthash_dst */
	union {
		struct {
			__be32 dst; /* MC addr first */
			__be32 src;
		} ip;
	};
	__be16 dst_port;
	__be16 src_port;
};

/* Hash entry with info about the mp2t stream / connection */
struct mp2t_stream { /* Like xt_hashlimit: dsthash_ent */
	/* Place static / read-only parts in the beginning */
	struct hlist_node node;
	struct mp2t_stream_match match;

	/* Place modified structure members in the end */
	/* FIXME: Add spacing in struct for cache alignment */

	/* Per stream total skips and discontinuity */
	/* TODO: Explain difference between skips and discontinuity */
	u64 skips;
	u64 discontinuity;

	/* lock for writing/changing/updating */
	spinlock_t lock;

	/* Usage counter to protect against dealloc/kfree */
	atomic_t use;

	/* PID list with last CC value */
	struct list_head pid_list;
	int pid_list_len;

	/* For RCU-protected deletion */
	struct rcu_head rcu_head;
};


/* This is basically our "stream" connection tracking.
 *
 * Keeping track of the MPEG2 streams per iptables rule.
 * There is one hash-table per iptables rule.
 * (Based on xt_hashlimit).
 */
struct xt_rule_mp2t_conn_htable {

	/* Global list containing these elements are needed: (1) to
	 * avoid realloc of our data structures when other rules gets
	 * inserted. (2) to provide stats via /proc/ as data must not
	 * be deallocated while a process reads data from /proc.
	 */
	struct list_head list;		/* global list of all htables */
	atomic_t use;			/* reference counting  */
	u_int32_t id;			/* id corrosponding to rule_id */
	/* u_int8_t family; */ /* needed for IPv6 support */

	/* "cfg" is also defined here as the real hash array size might
	 * differ from the user defined size, and changing the
	 * userspace defined rule data is not allowed as userspace
	 * then cannot match the rule again for deletion */
	struct mp2t_cfg cfg;		/* config */

	/* Used internally */
	spinlock_t lock;		/* write lock for hlist_head */
	u_int32_t rnd;			/* random seed for hash */
	int rnd_initialized;
	unsigned int count;		/* number entries in table */
	u_int16_t warn_condition;	/* limiting warn printouts */

	/* Rule creation time can be used by userspace to 1) determine
	 * the running periode and 2) to detect if the rule has been
	 * flushed between two reads.
	 */
	struct timespec time_created;

	/*TODO: Implement timer GC cleanup, to detect streams disappearing
	  struct timer_list timer;*/	/* timer for gc */

	/* Instrumentation for perf tuning */
	int32_t max_list_search;	/* Longest search in a hash list */
	atomic_t concurrency_cnt;	/* Trying to detect concurrency */
	int32_t stream_not_found;	/* Number of stream created */

	/* Proc seq_file entry */
	struct proc_dir_entry *pde;

	struct hlist_head stream_hash[0];/* conn/stream hashtable
					  * struct mp2t_stream elements */
};

/* Inspired by xt_hashlimit.c : htable_create() */
static bool
mp2t_htable_create(struct xt_mp2t_mtinfo *minfo)
{
	struct xt_rule_mp2t_conn_htable *hinfo;
	unsigned int hash_buckets;
	unsigned int hash_struct_sz;
	char rule_name[IFNAMSIZ+5];
	unsigned int i;
	u_int32_t id;
	size_t size;

	/* Q: is lock with mp2t_lock necessary */
	spin_lock(&mp2t_lock);
	id = GLOBAL_ID++;
	spin_unlock(&mp2t_lock);

	if (minfo->cfg.size)
		hash_buckets = minfo->cfg.size;
	else
		hash_buckets = 100;

	hash_struct_sz = sizeof(*minfo->hinfo); /* metadata struct size */
	size = hash_struct_sz +	sizeof(struct list_head) * hash_buckets;

	msg_info(IFUP, "Alloc htable(%d) %d bytes elems:%d metadata:%d bytes",
		 id, (int)size, hash_buckets, hash_struct_sz);

	hinfo = kzalloc(size, GFP_ATOMIC);
	if (hinfo == NULL) {
		msg_err(DRV, "unable to create hashtable(%d), out of memory!",
			id);
		return false;
	}
	minfo->hinfo = hinfo;

	/* Copy match config into hashtable config */
	memcpy(&hinfo->cfg, &minfo->cfg, sizeof(hinfo->cfg));
	hinfo->cfg.size = hash_buckets;

	/* Max number of connection we want to track */
	/* TODO: REMOVE code
	if (minfo->cfg.max == 0)
		hinfo->cfg.max = 8 * hinfo->cfg.size;
	else if (hinfo->cfg.max < hinfo->cfg.size)
		hinfo->cfg.max = hinfo->cfg.size;
	*/

	if (hinfo->cfg.max_list == 0)
		hinfo->cfg.max_list = 20;

	/* Init the hash buckets */
	for (i = 0; i < hinfo->cfg.size; i++)
		INIT_HLIST_HEAD(&hinfo->stream_hash[i]);

	/* Refcnt to allow alloc data to survive between rule updates*/
	atomic_set(&hinfo->use, 1);
	hinfo->id = id;

	INIT_LIST_HEAD(&hinfo->list);
	/*
	spin_lock(&mp2t_lock);
	list_add_tail(&conn_htables, &hinfo->list);
	spin_unlock(&mp2t_lock);
	*/

	hinfo->count = 0;
	hinfo->rnd_initialized = 0;
	hinfo->max_list_search = 0;
	atomic_set(&hinfo->concurrency_cnt, 0);
	hinfo->stream_not_found = 0;

	getnstimeofday(&hinfo->time_created);

	/* Generate a rule_name for proc if none given */
	if (!minfo->rule_name || !strlen(minfo->rule_name))
		snprintf(rule_name, IFNAMSIZ+5, "rule_%d", hinfo->id);
	else
		/* FIXME: Check for duplicate names! */
		snprintf(rule_name, IFNAMSIZ+5, "rule_%s", minfo->rule_name);

	/* Create proc entry */
	hinfo->pde = proc_create_data(rule_name, 0, mp2t_procdir,
				      &dl_file_ops, hinfo);

#ifdef CONFIG_PROC_FS
	if (!hinfo->pde) {
		msg_err(PROBE, "Cannot create proc file named: %s",
			minfo->rule_name);
		kfree(hinfo);
		return false;
	}
#endif

	spin_lock_init(&hinfo->lock);

	return true;
}

static u_int32_t
hash_match(const struct xt_rule_mp2t_conn_htable *ht,
	   const struct mp2t_stream_match *match)
{
	u_int32_t hash = jhash2((const u32 *)match,
				sizeof(*match)/sizeof(u32),
				ht->rnd);
	/*
	 * Instead of returning hash % ht->cfg.size (implying a divide)
	 * we return the high 32 bits of the (hash * ht->cfg.size) that will
	 * give results between [0 and cfg.size-1] and same hash distribution,
	 * but using a multiply, less expensive than a divide
	 */
	return ((u64)hash * ht->cfg.size) >> 32;
}

static inline
bool match_cmp(const struct mp2t_stream *ent,
			     const struct mp2t_stream_match *b)
{
	return !memcmp(&ent->match, b, sizeof(ent->match));
}

static struct mp2t_stream *
mp2t_stream_find(struct xt_rule_mp2t_conn_htable *ht,
		 const struct mp2t_stream_match *match)
{
	struct mp2t_stream *entry;
	struct hlist_node  *pos;
	u_int32_t hash;
	int cnt = 0;

#if PERFTUNE
	int parallel = 0;
	static int limit;

	/* rcu_read_lock(); // Taken earlier */
	parallel = atomic_inc_return(&ht->concurrency_cnt);
#endif
	hash = hash_match(ht, match);

	if (!hlist_empty(&ht->stream_hash[hash])) {
		/* The hlist_for_each_entry_rcu macro uses the
		 * appropiate rcu_dereference() to access the
		 * mp2t_stream pointer */
		hlist_for_each_entry_rcu(entry, pos,
				     &ht->stream_hash[hash], node) {
			cnt++;
			if (match_cmp(entry, match))
				goto found;
		}
	}

	/* rcu_read_unlock(); // Released later */
#if PERFTUNE
	atomic_dec(&ht->concurrency_cnt);
#endif
	ht->stream_not_found++; /* This is racy, but its only a debug var */
	return NULL;

found:
	if (unlikely(cnt > ht->cfg.max_list) &&
	    unlikely(cnt > ht->max_list_search)) {
		ht->max_list_search = cnt;
		msg_warn(PROBE, "Perf: Long list search %d in stream_hash[%u]",
			 cnt, hash);
	}

#if PERFTUNE
	atomic_dec(&ht->concurrency_cnt);

	if (parallel > 2 && (limit++ % 100 == 0))
		msg_info(PROBE, "Did it in parallel, concurrency count:%d",
			 parallel);
#endif

	return entry;
}

static struct pid_data_t *
mp2t_pid_find(struct mp2t_stream *stream, const int16_t pid)
{
	struct pid_data_t *entry;

	list_for_each_entry(entry, &stream->pid_list, list) {
		if (entry->pid == pid)
			return entry;
	}
	return NULL;
}

static struct pid_data_t *
mp2t_pid_create(struct mp2t_stream *stream, const int16_t pid)
{
	struct pid_data_t *entry;

	entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		msg_err(DRV, "can't allocate new pid list entry");
		return NULL;
	}
	entry->pid     = pid;
	entry->cc_prev = -1;

	stream->pid_list_len++;

	list_add_tail(&entry->list, &stream->pid_list);

	return entry;
}

static int
mp2t_pid_destroy_list(struct mp2t_stream *stream)
{
	struct pid_data_t *entry, *n;

	msg_dbg(PROBE, "Cleanup up pid list with %d elements",
		stream->pid_list_len);

	list_for_each_entry_safe(entry, n, &stream->pid_list, list) {
		stream->pid_list_len--;
		kfree(entry);
	}
	WARN_ON(stream->pid_list_len != 0);
	return stream->pid_list_len;
}

static struct mp2t_stream *
mp2t_stream_alloc_init(struct xt_rule_mp2t_conn_htable *ht,
		       const struct mp2t_stream_match *match)
{
	struct mp2t_stream *entry; /* hashtable entry */
	unsigned int entry_sz;
	size_t size;
	u_int32_t hash;

	/* initialize hash with random val at the time we allocate
	 * the first hashtable entry */
	if (unlikely(!ht->rnd_initialized)) {
		spin_lock_bh(&ht->lock);
		if (unlikely(!ht->rnd_initialized)) {
			get_random_bytes(&ht->rnd, 4);
			ht->rnd_initialized = 1;
		}
		spin_unlock_bh(&ht->lock);
	}

	/* DoS protection / embedded feature, for protection the size
	 * of the hash table lists. Limit the number of streams the
	 * module are willing to track.  This limit is configurable
	 * from userspace.  Can also be useful on small CPU/memory
	 * systems. */
	if (ht->cfg.max && ht->count >= ht->cfg.max) {
		if (unlikely(ht->warn_condition < 10)) {
			ht->warn_condition++;
			msg_warn(RX_ERR,
			 "Rule[%d]: "
			 "Stopped tracking streams, max %u exceeded (%u) "
			 "(Max can be adjusted via --max-streams param)",
			 ht->id, ht->cfg.max, ht->count);
		}
		return NULL;
	}

	/* Calc the hash value */
	hash = hash_match(ht, match);

	/* Allocate new stream element */
	/* entry = kmem_cache_alloc(hashlimit_cachep, GFP_ATOMIC); */
	size = entry_sz = sizeof(*entry);
	/* msg_info(IFUP, "Alloc new stream entry (%d bytes)", entry_sz); */

	entry = kzalloc(entry_sz, GFP_ATOMIC);
	if (!entry) {
		msg_err(DRV, "can't allocate new stream elem");
		return NULL;
	}
	memcpy(&entry->match, match, sizeof(entry->match));

	spin_lock_init(&entry->lock);
	atomic_set(&entry->use, 1);

	/* Init the pid table list */
	INIT_LIST_HEAD(&entry->pid_list);
	entry->pid_list_len = 0;

	/* init the RCU callback structure needed by call_rcu() */
	INIT_RCU_HEAD(&entry->rcu_head);

	/* Q Locking: Adding and deleting elements from the
	 * stream_hash[] lists is protected by the spinlock ht->lock.
	 * Should we only use try lock and exit if we cannot get it???
	 * I'm worried about what happens if we are waiting for the
	 * lock held by xt_mp2t_mt_destroy() which will dealloc ht
	 */
	spin_lock_bh(&ht->lock);
	hlist_add_head_rcu(&entry->node, &ht->stream_hash[hash]);
	ht->count++; /* Convert to atomic? Its write protected by ht->lock */
	spin_unlock_bh(&ht->lock);

	return entry;
}

/*
 * The xt_mp2t_mt_check(), return type changed, which is quite
 *  confusing as the return logic gets turned around.
 *
 *  TODO: Think change happend in 2.6.35, need to check the exact
 *  kernel version this changed in!
 */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 34)
enum RETURNVALS { error = 0 /*false*/, success = 1 /*true*/, };
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)
enum RETURNVALS { error = -EINVAL, success = 0, };
#endif

static int
xt_mp2t_mt_check(const struct xt_mtchk_param *par)
{
	struct xt_mp2t_mtinfo *info = par->matchinfo;

	/*
	if (info->flags & ~XT_MP2T_DETECT_DROP)
		return false;
	*/

	/* Debugging, this should not be possible */
	if (!info) {
		msg_err(DRV, "ERROR info is NULL");
		return error;
	}

	/* Debugging, this should not be possible */
	if (IS_ERR_VALUE((unsigned long)(info->hinfo))) {
		msg_err(DRV, "ERROR info->hinfo is an invalid pointer!!!");
		return error;
	}

	/* TODO/FIXME: Add a check to NOT allow proc files with same
	 * name in /proc/net/xt_mp2t/rule_%s */


	/* TODO: Write about how, this preserves htable memory by
	 * reuse of hinfo pointer and incrementing 'use' refcounter
	 * assures that xt_mp2t_mt_destroy() will not call
	 * conn_htable_destroy() thus not deallocating our memory */
	if (info->hinfo != NULL) {
		atomic_inc(&info->hinfo->use);
		msg_info(DEBUG, "ReUsing info->hinfo ptr:[%p] htable id:%d",
			 info->hinfo, info->hinfo->id);
		return success;
	}

	if (mp2t_htable_create(info) == false) {
		msg_err(DRV, "Error creating hash table");
		return error;
	}

	return success;
}

static void
mp2t_stream_free(struct rcu_head *head)
{
	struct mp2t_stream *stream;

	stream = container_of(head, struct mp2t_stream, rcu_head);

	/* Debugging check */
	if (unlikely(!stream))
		printk(KERN_CRIT PFX
		       "Free BUG: Stream ptr is NULL (tell:jdb@comx.dk)\n");

	/* Deallocate the PID list */
	spin_lock_bh(&stream->lock);
	mp2t_pid_destroy_list(stream);
	spin_unlock_bh(&stream->lock);

	/* Before free, check the 'use' reference counter */
	if (atomic_dec_and_test(&stream->use)) {
		kfree(stream);
	} else {
		/* If this can occur, we should schedule something
		 * that can clean up */
		printk(KERN_CRIT PFX
		       "Free BUG: Stream still in use! (tell:jdb@comx.dk)\n");
	}
}

static void
conn_htable_destroy(struct xt_rule_mp2t_conn_htable *ht)
{
	unsigned int i;

	/* Remove proc entry */
	remove_proc_entry(ht->pde->name, mp2t_procdir);

	msg_info(IFDOWN, "Destroy stream elements (%d count) in htable(%d)",
		 ht->count, ht->id);
	msg_dbg(IFDOWN, "Find stream, not found %d times",
		ht->stream_not_found);

	/* lock hash table and iterate over it to release all elements */
	spin_lock(&ht->lock);
	for (i = 0; i < ht->cfg.size; i++) {
		struct mp2t_stream *stream;
		struct hlist_node *pos, *n;
		hlist_for_each_entry_safe(stream, pos, n,
					  &ht->stream_hash[i], node) {

			hlist_del_rcu(&stream->node);
			ht->count--;

			/* Have to use call_rcu(), because we cannot
			   use synchronize_rcu() here, because we are
			   holding a spinlock, or else we will get a
			   "scheduling while atomic" bug.
			*/
			call_rcu_bh(&stream->rcu_head, mp2t_stream_free);
		}
	}
	spin_unlock(&ht->lock);

	msg_info(IFDOWN,
		 "Free htable(%d) (%d buckets) longest list search %d",
		 ht->id, ht->cfg.size, ht->max_list_search);

	if (ht->count != 0)
		printk(KERN_CRIT PFX
		       "Free BUG: ht->count != 0 (tell:jdb@comx.dk)\n");

	kfree(ht);
}


/*
 * Keeping dynamic allocated memory when the rulesets are swapped.
 *
 * Iptables rule updates works by replacing the entire ruleset.  Our
 * dynamic allocated data (per rule) needs to survive this update, BUT
 * only if our rule has not been removed.  This is achieved by having
 * a reference counter.  The reason it works, is that during swapping
 * of rulesets, the checkentry function (xt_mp2t_mt_check) is called
 * on the new ruleset _before_ calling the destroy function
 * (xt_mp2t_mt_destroy) on the old ruleset.  During checkentry, we
 * increment the reference counter on data if we can find the data
 * associated with this rule.
 *
 * Functions used to achieve this is:
 *   conn_htable_get() - Find data and increment refcnt
 *   conn_htable_put() - Finished usind data, delete if last user
 *   conn_htable_add() - Add data to the global searchable list
 */

static struct xt_rule_mp2t_conn_htable*
conn_htable_get(u32 rule_id)
{
	struct xt_rule_mp2t_conn_htable *hinfo;

	spin_lock_bh(&mp2t_lock);
	list_for_each_entry(hinfo, &conn_htables, list) {
		if (hinfo->id == rule_id) {
			atomic_inc(&hinfo->use);
			spin_unlock_bh(&mp2t_lock);
			return hinfo;
		}
	}
	spin_unlock_bh(&mp2t_lock);
	return NULL;
}

static void
conn_htable_put(struct xt_rule_mp2t_conn_htable *hinfo)
{
	/* Finished using element, delete if last user */
	if (atomic_dec_and_test(&hinfo->use)) {
		spin_lock_bh(&mp2t_lock);
		list_del(&hinfo->list);
		spin_unlock_bh(&mp2t_lock);
		conn_htable_destroy(hinfo);
	}
}

static void
conn_htable_add(struct xt_rule_mp2t_conn_htable *hinfo)
{
	spin_lock_bh(&mp2t_lock);
	list_add_tail(&conn_htables, &hinfo->list);
	spin_unlock_bh(&mp2t_lock);
}

static void
xt_mp2t_mt_destroy(const struct xt_mtdtor_param *par)
{
	const struct xt_mp2t_mtinfo *info = par->matchinfo;
	struct xt_rule_mp2t_conn_htable *hinfo;
	hinfo = info->hinfo;

	/* Calls only destroy if refcnt is zero */
	if (atomic_dec_and_test(&hinfo->use))
		conn_htable_destroy(hinfo);
}


/* Calc the number of skipped CC numbers. Note that this can easy
 * overflow, and a value above 7 indicate several network packets
 * could be lost.
 */
static inline unsigned int
calc_skips(unsigned int curr, unsigned int prev)
{
	int res = 0;

	/* Only count the missing TS frames in between prev and curr.
	 * The "prev" frame CC number seen is confirmed received, its
	 * the next frames CC counter which is the first known missing
	 * TS frame
	 */
	prev += 1;

	/* Calc missing TS frame 'skips' */
	res = curr - prev;

	/* Handle wrap around */
	if (res < 0)
		res += 16;

	return res;
}

/* Return the number of skipped CC numbers */
static int
detect_cc_drops(struct pid_data_t *pid_data, int8_t cc_curr,
		const struct sk_buff *skb)
{
	int8_t cc_prev;
	int skips = 0;

	cc_prev           = pid_data->cc_prev;
	pid_data->cc_prev = cc_curr;

	/* Null packet always have a CC value equal 0 */
	if (pid_data->pid == 0x1fff)
		return 0;

	/* FIXME: Handle adaptation fields and Remove this code */
	/* Its allowed that (cc_prev == cc_curr) if its an adaptation
	 * field.
	 */
	if (cc_prev == cc_curr)
		return 0;

	/* Have not seen this pid before */
	if (cc_prev == -1)
		return 0;

	/* Detect if CC is not increasing by one all the time */
	if (cc_curr != ((cc_prev+1) & MP2T_CC_MASK)) {
		skips = calc_skips(cc_curr, cc_prev);

		msg_info(RX_STATUS,
			 "Detected drop pid:%d CC curr:%d prev:%d skips:%d",
			 pid_data->pid, cc_curr, cc_prev, skips);

		/* TODO: Do accounting per PID ?
		pid_data->cc_skips += skips;
		pid_data->cc_err++;
		*/
	}

	return skips;
}


static int
dissect_tsp(unsigned char *payload_ptr, u16 payload_len,
	    const struct sk_buff *skb, struct mp2t_stream *stream)
{
	__be32 header;
	u16 pid;
	u8 afc;
	int8_t cc_curr;
	int skips = 0;
	struct pid_data_t *pid_data;

	/* Process header*/
	header  = ntohl(*(u32 *)payload_ptr);
	pid     = (header & MP2T_PID_MASK) >> MP2T_PID_SHIFT;
	afc     = (header & MP2T_AFC_MASK) >> MP2T_AFC_SHIFT;
	cc_curr = (header & MP2T_CC_MASK)  >> MP2T_CC_SHIFT;

	msg_dbg(PKTDATA, "TS header:0x%X pid:%d cc:%d afc:%d",
		header, pid, cc_curr, afc);

	/* Adaption Field Control header */
	if (unlikely(afc == 2)) {
		/* An 'adaptation field only' packet will have the
		 * same CC value as the previous payload packet. */
		return 0;
		/* TODO: Add parsing of Adaption headers. The PCR
		 * counter is hidden here...*/
	}

	pid_data = mp2t_pid_find(stream, pid);
	if (!pid_data) {
		pid_data = mp2t_pid_create(stream, pid);
		if (!pid_data)
			return 0;
	}


	skips = detect_cc_drops(pid_data, cc_curr, skb);

	return skips;
}


static int
dissect_mp2t(unsigned char *payload_ptr, u16 payload_len,
	     const struct sk_buff *skb, const struct udphdr *uh,
	     const struct xt_mp2t_mtinfo *info)
{
	u16 offset = 0;
	int skips  = 0;
	int skips_total = 0;
	int discontinuity = 0;
	const struct iphdr *iph = ip_hdr(skb);

	struct mp2t_stream     *stream; /* "Connection" */
	struct mp2t_stream_match match;

	struct xt_rule_mp2t_conn_htable *hinfo;
	hinfo = info->hinfo;

	/** Lookup stream data structures **/

	/* Fill in the match struct */
	memset(&match, 0, sizeof(match)); /* Worried about struct padding */
	match.ip.src = iph->saddr;
	match.ip.dst = iph->daddr;
	match.src_port = uh->source;
	match.dst_port = uh->dest;

	/* spin_lock_bh(&hinfo->lock); // Replaced by RCU */
	rcu_read_lock_bh();

	stream = mp2t_stream_find(hinfo, &match);
	if (!stream) {
		stream = mp2t_stream_alloc_init(hinfo, &match);
		if (!stream) {
			/* spin_unlock_bh(&hinfo->lock); // Replaced by RCU */
			rcu_read_unlock_bh();
			return 0;
		}
		/* msg_info(RX_STATUS, */
		printk(KERN_INFO
		       "Rule:%d New stream (%pI4 -> %pI4)\n",
		       hinfo->id, &iph->saddr, &iph->daddr);
	}

	/** Process payload **/

	spin_lock_bh(&stream->lock); /* Update lock for the stream */

	/* Protect against dealloc (via atomic counter stream->use) */
	if (!atomic_inc_not_zero(&stream->use)) {
		/* If "use" is zero, then we about to be free'd */
		spin_unlock_bh(&stream->lock); /* Update lock for the stream */
		rcu_read_unlock_bh();
		printk(KERN_CRIT PFX "Error atomic stream->use is zero\n");
		return 0;
	}

	while ((payload_len - offset) >= MP2T_PACKET_SIZE) {

		skips = dissect_tsp(payload_ptr, payload_len, skb, stream);

		if (skips > 0)
			discontinuity++;
		/* TODO: if (skips > 7) signal_loss++; */
		skips_total += skips;

		offset +=  MP2T_PACKET_SIZE;
		payload_ptr += MP2T_PACKET_SIZE;
	}

	if (discontinuity > 0) {
		stream->skips         += skips_total;
		stream->discontinuity += discontinuity;
	}

	atomic_dec(&stream->use); /* Protect agains dealloc */
	spin_unlock_bh(&stream->lock); /* Update lock for the stream */
	rcu_read_unlock_bh();
	/* spin_unlock_bh(&hinfo->lock); // Replaced by RCU */

	/* Place print statement after the unlock section */
	if (discontinuity > 0) {
		msg_notice(RX_STATUS,
			   "Detected discontinuity "
			   "%pI4 -> %pI4 (CCerr:%d skips:%d)",
			   &ip_hdr(skb)->saddr, &ip_hdr(skb)->daddr,
			   discontinuity, skips_total);
	}

	return skips_total;
}


static bool
is_mp2t_packet(unsigned char *payload_ptr, u16 payload_len)
{
	u16 offset = 0;

	/* IDEA/TODO: Detect wrong/changing TS mappings */

	/* Basic payload Transport Stream check */
	if (payload_len % MP2T_PACKET_SIZE > 0) {
		msg_dbg(PKTDATA, "Not a MPEG2 TS packet, wrong size");
		return false;
	}

	/* Check for a sync byte in all TS frames */
	while ((payload_len - offset) >= MP2T_PACKET_SIZE) {

		if (payload_ptr[0] != MP2T_SYNC_BYTE) {
			msg_dbg(PKTDATA, "Invalid MP2T packet skip!");
			return false;
		}
		offset +=  MP2T_PACKET_SIZE;
		payload_ptr += MP2T_PACKET_SIZE;
	}
	/* msg_dbg(PKTDATA, "True MP2T packet"); */

	return true;
}


static bool
xt_mp2t_match(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_mp2t_mtinfo *info = par->matchinfo;
	const struct iphdr *iph = ip_hdr(skb);
	const struct udphdr *uh;
	struct udphdr _udph;
	__be32 saddr, daddr;
	u16 ulen;
	u16 hdr_size;
	u16 payload_len;
	unsigned char *payload_ptr;

	bool res = false;
	int skips = 0;

	if (!(info->flags & XT_MP2T_DETECT_DROP)) {
		msg_err(RX_ERR, "You told me to do nothing...?!");
		return false;
	}

	/*
	if (!pskb_may_pull((struct sk_buff *)skb, sizeof(struct udphdr)))
		return false;
	*/

	saddr = iph->saddr;
	daddr = iph->daddr;

	/* Must not be a fragment. */
	if (par->fragoff != 0) {
		msg_warn(RX_ERR, "Skip cannot handle fragments "
			 "(pkt from:%pI4 to:%pI4) len:%u datalen:%u"
			 , &saddr, &daddr, skb->len, skb->data_len);
		return false;
	}

	/* We need to walk through the payload data, and I don't want
	 * to handle fragmented SKBs, the SKB has to be linearized */
	if (skb_is_nonlinear(skb)) {
		if (skb_linearize((struct sk_buff *)skb) != 0) {
			msg_err(RX_ERR, "SKB linearization failed"
				"(pkt from:%pI4 to:%pI4) len:%u datalen:%u",
				&saddr, &daddr, skb->len, skb->data_len);
			/* TODO: Should we just hotdrop it?
			   *par->hotdrop = true;
			*/
			return false;
		}
	}

	uh = skb_header_pointer(skb, par->thoff, sizeof(_udph), &_udph);
	if (unlikely(uh == NULL)) {
		/* Something is wrong, cannot even access the UDP
		 * header, no choice but to drop. */
		msg_err(RX_ERR, "Dropping evil UDP tinygram "
			"(pkt from:%pI4 to:%pI4)", &saddr, &daddr);
		par->hotdrop = true;
		return false;
	}
	ulen = ntohs(uh->len);

	/* How much do we need to skip to access payload data */
	hdr_size    = par->thoff + sizeof(struct udphdr);
	payload_ptr = skb_network_header(skb) + hdr_size;
	/* payload_ptr = skb->data + hdr_size; */
	BUG_ON(payload_ptr != (skb->data + hdr_size));

	/* Different ways to determine the payload_len.  Think the
	 * safest is to use the skb->len, as we really cannot trust
	 * the contents of the packet.
	  payload_len = ntohs(iph->tot_len)- hdr_size;
	  payload_len = ulen - sizeof(struct udphdr);
	*/
	payload_len = skb->len - hdr_size;

/* Not sure if we need to clone packets
	if (skb_shared(skb))
		msg_dbg(RX_STATUS, "skb(0x%p) shared", skb);

	if (!skb_cloned(skb))
		msg_dbg(RX_STATUS, "skb(0x%p) NOT cloned", skb);
*/

	if (is_mp2t_packet(payload_ptr, payload_len)) {
		msg_dbg(PKTDATA, "Jubii - its a MP2T packet");
		skips = dissect_mp2t(payload_ptr, payload_len, skb, uh, info);
	} else {
		msg_dbg(PKTDATA, "Not a MPEG2 TS packet "
			"(pkt from:%pI4 to:%pI4)", &saddr, &daddr);
		return false;
	}

	if (info->flags & XT_MP2T_DETECT_DROP)
		res = !!(skips); /* Convert to a bool */

	return res;
}

static struct xt_match mp2t_mt_reg[] __read_mostly = {
	{
		.name           = "mp2t",
		.revision       = 0,
		.family         = NFPROTO_IPV4,
		.match          = xt_mp2t_match,
		.checkentry     = xt_mp2t_mt_check,
		.destroy        = xt_mp2t_mt_destroy,
		.proto		= IPPROTO_UDP,
		.matchsize      = sizeof(struct xt_mp2t_mtinfo),
		.me             = THIS_MODULE,
	},
};


/*** Proc seq_file functionality ***/

static void *mp2t_seq_start(struct seq_file *s, loff_t *pos)
{
	struct proc_dir_entry *pde = s->private;
	struct xt_rule_mp2t_conn_htable *htable = pde->data;
	unsigned int *bucket;

	if (*pos >= htable->cfg.size)
		return NULL;

	if (!*pos)
		return SEQ_START_TOKEN;

	bucket = kmalloc(sizeof(unsigned int), GFP_ATOMIC);
	if (!bucket)
		return ERR_PTR(-ENOMEM);

	*bucket = *pos;
	return bucket;
}

static void *mp2t_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct proc_dir_entry *pde = s->private;
	struct xt_rule_mp2t_conn_htable *htable = pde->data;
	unsigned int *bucket = (unsigned int *)v;

	if (v == SEQ_START_TOKEN) {
		bucket = kmalloc(sizeof(unsigned int), GFP_ATOMIC);
		if (!bucket)
			return ERR_PTR(-ENOMEM);
		*bucket = 0;
		*pos    = 0;
		v = bucket;
		return bucket;
	}

	*pos = ++(*bucket);
	if (*pos >= htable->cfg.size) {
		kfree(v);
		return NULL;
	}
	return bucket;
}

static void mp2t_seq_stop(struct seq_file *s, void *v)
{
	unsigned int *bucket = (unsigned int *)v;
	kfree(bucket);
}

static int mp2t_seq_show_real(struct mp2t_stream *stream, struct seq_file *s,
			      unsigned int bucket)
{
	int res;

	if (!atomic_inc_not_zero(&stream->use)) {
		/* If "use" is zero, then we about to be free'd */
		return 0;
	}

	res = seq_printf(s, "bucket:%d dst:%pI4 src:%pI4 dport:%u sport:%u "
			    "pids:%d skips:%llu discontinuity:%llu\n",
			 bucket,
			 &stream->match.ip.dst,
			 &stream->match.ip.src,
			 ntohs(stream->match.dst_port),
			 ntohs(stream->match.src_port),
			 stream->pid_list_len,
			 stream->skips,
			 stream->discontinuity
		);

	atomic_dec(&stream->use);

	return res;
}

static int mp2t_seq_show(struct seq_file *s, void *v)
{
	struct proc_dir_entry *pde = s->private;
	struct xt_rule_mp2t_conn_htable *htable = pde->data;
	unsigned int *bucket = (unsigned int *)v;
	struct mp2t_stream *stream;
	struct hlist_node *pos;
	struct timespec delta;
	struct timespec now;

	/*
	  The syntax for the proc output is "key:value" constructs,
	  seperated by a space.  This is done to ease machine/script
	  parsing and still keeping it human readable.
	*/

	if (v == SEQ_START_TOKEN) {
		getnstimeofday(&now);
		delta = timespec_sub(now, htable->time_created);

		/* version info */
		seq_printf(s, "# info:version module:%s version:%s\n",
			   XT_MODULE_NAME, XT_MODULE_VERSION);

		/* time info */
		seq_printf(s, "# info:time created:%ld.%09lu"
			      " now:%ld.%09lu delta:%ld.%09lu\n",
			   (long)htable->time_created.tv_sec,
			   htable->time_created.tv_nsec,
			   (long)now.tv_sec, now.tv_nsec,
			   (long)delta.tv_sec, delta.tv_nsec);

		/* dynamic info */
		seq_puts(s, "# info:dynamic");
		seq_printf(s, " rule_id:%d", htable->id);
		seq_printf(s, " streams:%d", htable->count);
		seq_printf(s, " streams_check:%d", htable->stream_not_found);
		seq_printf(s, " max_list_search:%d",  htable->max_list_search);
		seq_printf(s, " rnd:%u", htable->rnd);
		seq_puts(s, "\n");

		/* config info */
		seq_puts(s, "# info:config");
		seq_printf(s, " htable_size:%u", htable->cfg.size);
		seq_printf(s, " max-streams:%u", htable->cfg.max);
		seq_printf(s, " list_search_warn_level:%d",
			   htable->cfg.max_list);
		seq_puts(s, "\n");

	} else {
		rcu_read_lock();
		if (!hlist_empty(&htable->stream_hash[*bucket])) {
			hlist_for_each_entry_rcu(stream, pos,
						 &htable->stream_hash[*bucket],
						 node) {
				if (mp2t_seq_show_real(stream, s, *bucket)) {
					rcu_read_unlock();
					return -1;
				}
			}
		}
		rcu_read_unlock();
	}
	return 0;
}

static const struct seq_operations dl_seq_ops = {
	.start = mp2t_seq_start,
	.next  = mp2t_seq_next,
	.stop  = mp2t_seq_stop,
	.show  = mp2t_seq_show
};

static int mp2t_proc_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &dl_seq_ops);

	if (!ret) {
		struct seq_file *sf = file->private_data;
		sf->private = PDE(inode);
	}
	return ret;
}

static const struct file_operations dl_file_ops = {
	.owner   = THIS_MODULE,
	.open    = mp2t_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};

/*** Module init & exit ***/

static int __init mp2t_mt_init(void)
{
	int err;
	GLOBAL_ID = 1; /* Module counter for rule_id assignments */

	/* The list conn_htables contain references to dynamic
	 * allocated memory (via xt_rule_mp2t_conn_htable ptr) that
	 * needes to survive between rule updates.
	 */
	INIT_LIST_HEAD(&conn_htables);

	msg_level = netif_msg_init(debug, MP2T_MSG_DEFAULT);
	msg_info(DRV, "Loading: %s", version);
	msg_dbg(DRV, "Message level (msg_level): 0x%X", msg_level);

	/* Register the mp2t matches */
	err = xt_register_matches(mp2t_mt_reg, ARRAY_SIZE(mp2t_mt_reg));
	if (err) {
		msg_err(DRV, "unable to register matches");
		return err;
	}

#ifdef CONFIG_PROC_FS
	/* Create proc directory shared by all rules */
	mp2t_procdir = proc_mkdir(XT_MODULE_NAME, init_net.proc_net);
	if (!mp2t_procdir) {
		msg_err(DRV, "unable to create proc dir entry");
		/* In case of error unregister the mp2t matches */
		xt_unregister_matches(mp2t_mt_reg, ARRAY_SIZE(mp2t_mt_reg));
		err = -ENOMEM;
	}
#endif

	return err;
}

static void __exit mp2t_mt_exit(void)
{
	msg_info(DRV, "Unloading: %s", version);

	remove_proc_entry(XT_MODULE_NAME, init_net.proc_net);

	xt_unregister_matches(mp2t_mt_reg, ARRAY_SIZE(mp2t_mt_reg));

	/* Its important to wait for all call_rcu_bh() callbacks to
	 * finish before this module is deallocated as the code
	 * mp2t_stream_free() is used by these callbacks.
	 *
	 * Notice doing a synchronize_rcu() is NOT enough. Need to
	 * invoke rcu_barrier_bh() to enforce wait for completion of
	 * call_rcu_bh() callbacks on all CPUs.
	 */
	rcu_barrier_bh();
}

module_init(mp2t_mt_init);
module_exit(mp2t_mt_exit);
