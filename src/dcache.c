// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
/*
 * HymoFS LKM - dcache fallback implementations.
 * Provides fallback implementations for dentry_path_raw and d_absolute_path
 * when these kernel symbols are not exported (e.g., on some GKI kernels).
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/rcupdate.h>
#include "dcache.h"

/*
 * Prepend a name to the buffer, moving the pointer backwards.
 * Returns new pointer position or NULL if buffer overflow.
 */
static inline char *prepend_name(char *buffer, int *buflen, const struct qstr *name)
{
	const char *str = name->name;
	int len = name->len;

	if (*buflen < len + 1)
		return NULL;

	*buflen -= len;
	memcpy(buffer + *buflen, str, len);
	(*buflen)--;
	buffer[*buflen] = '/';

	return buffer + *buflen;
}

/*
 * Walk up the dentry tree from dentry to root, building the path.
 * This is similar to kernel's __dentry_path.
 *
 * @dentry: starting dentry
 * @buf: buffer to write path into
 * @buflen: length of buffer
 *
 * Returns pointer to start of path within buf, or ERR_PTR on error.
 */
static char *__hymo_dentry_path(const struct dentry *dentry, char *buf, int buflen)
{
	const struct dentry *d = dentry;
	char *p;
	int error = 0;

	if (buflen < 2)
		return ERR_PTR(-ENAMETOOLONG);

	/* Start at end of buffer, working backwards */
	buflen--;
	p = buf + buflen;
	*p = '/';

	/* Walk up the dentry tree */
	while (d && d->d_parent != d) {
		const struct qstr *name = &d->d_name;

		/* Prepend name with separator */
		p = prepend_name(buf, &buflen, name);
		if (!p) {
			error = -ENAMETOOLONG;
			break;
		}

		d = d->d_parent;
	}

	if (error)
		return ERR_PTR(error);

	/* Ensure path starts with '/' */
	if (buflen > 0) {
		buflen--;
		p = buf + buflen;
		*p = '/';
	}

	return p;
}

char *hymo_dentry_path_raw_fallback(const struct dentry *dentry, char *buf, int buflen)
{
	char *res;

	if (!dentry || !buf || buflen < 2)
		return ERR_PTR(-EINVAL);

	/* Use rcu_read_lock for safe traversal */
	rcu_read_lock();
	res = __hymo_dentry_path(dentry, buf, buflen);
	rcu_read_unlock();

	return res;
}

/*
 * For d_absolute_path, we need to handle mount traversal.
 * Since real_mount() is not exported, we use a simplified approach
 * that works with the vfsmount structure directly.
 *
 * Note: This implementation traverses dentries within a single mount.
 * For most use cases in this module (inject/merge listing), this is sufficient.
 */
char *hymo_d_absolute_path_fallback(const struct path *path, char *buf, int buflen)
{
	const struct dentry *dentry;
	char *res;

	if (!path || !buf || buflen < 2)
		return ERR_PTR(-EINVAL);

	if (!path->dentry || !path->mnt)
		return ERR_PTR(-EINVAL);

	dentry = path->dentry;

	rcu_read_lock();

	/*
	 * Use __hymo_dentry_path for the dentry traversal.
	 * This gives us the path within the mount point.
	 * For full absolute path, we rely on the fact that
	 * our use cases typically involve paths within /system or similar.
	 */
	res = __hymo_dentry_path(dentry, buf, buflen);

	rcu_read_unlock();

	return res;
}

/*
 * We need d_lookup for the fallback. This function pointer is set
 * via hymo_dcache_fallback_init() from hymofs_lkm.c which has access
 * to the symbol resolution mechanism.
 */
static struct dentry *(*hymo_d_lookup_func)(struct dentry *, struct qstr *);

/*
 * hymo_d_hash_and_lookup_fallback - Lookup a dentry by name
 * @dir: parent directory dentry
 * @name: qstr containing the name to lookup
 *
 * This is a fallback when kernel's d_hash_and_lookup is not exported.
 *
 * Returns the found dentry or NULL if not found or if d_lookup is unavailable.
 */
struct dentry *hymo_d_hash_and_lookup_fallback(struct dentry *dir, struct qstr *name)
{
	struct dentry *dentry;

	if (!dir || !name || !name->name)
		return NULL;

	/*
	 * If d_lookup is not available, we can't perform the lookup.
	 * Return NULL safely - this just disables the optimization.
	 */
	if (!hymo_d_lookup_func)
		return NULL;

	/*
	 * Compute hash if not already set.
	 * full_name_hash is typically exported and safe to use.
	 */
	if (!name->hash)
		name->hash = full_name_hash(dir, name->name, name->len);

	rcu_read_lock();
	dentry = hymo_d_lookup_func(dir, name);
	rcu_read_unlock();

	return dentry;
}

/*
 * hymo_dcache_fallback_init - Initialize fallback function pointers
 * @lookup_fn: d_lookup function pointer (or NULL if unavailable)
 *
 * Called from hymofs_lkm_init after symbol resolution.
 */
void hymo_dcache_fallback_init(void *lookup_fn)
{
	hymo_d_lookup_func = lookup_fn;
	if (!hymo_d_lookup_func)
		pr_warn("hymofs: d_lookup not found, d_hash_and_lookup fallback will return NULL\n");
}
