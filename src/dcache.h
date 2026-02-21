/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
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
#ifndef _HYMOFS_DCACHE_H
#define _HYMOFS_DCACHE_H

#include <linux/dcache.h>
#include <linux/path.h>

/*
 * hymo_dentry_path_raw_fallback - Get the path of a dentry as a string
 * @dentry: dentry to get path for
 * @buf: buffer to write path into
 * @buflen: length of buffer
 *
 * Fallback implementation when kernel's dentry_path_raw is not available.
 * Returns pointer to the start of the path string within buf, or ERR_PTR on error.
 *
 * Note: RCU read lock is acquired internally for safe dentry traversal.
 */
char *hymo_dentry_path_raw_fallback(const struct dentry *dentry, char *buf, int buflen);

/*
 * hymo_d_absolute_path_fallback - Get the absolute path from a struct path
 * @path: path to get absolute path for
 * @buf: buffer to write path into
 * @buflen: length of buffer
 *
 * Fallback implementation when kernel's d_absolute_path is not available.
 * Returns pointer to the start of the path string within buf, or ERR_PTR on error.
 *
 * Note: This implementation handles single-mount traversal. For most use cases
 * in this module (inject/merge listing within /system), this is sufficient.
 * RCU read lock is acquired internally for safe traversal.
 */
char *hymo_d_absolute_path_fallback(const struct path *path, char *buf, int buflen);

/*
 * hymo_d_hash_and_lookup_fallback - Lookup a dentry by name in parent directory
 * @dir: parent directory dentry
 * @name: qstr containing the name to lookup
 *
 * Fallback implementation when kernel's d_hash_and_lookup is not available.
 * Returns the found dentry or NULL if not found.
 *
 * Note: This searches the dcache for an existing dentry. It does not perform
 * an actual filesystem lookup. Caller must call dput() on the returned dentry.
 */
struct dentry *hymo_d_hash_and_lookup_fallback(struct dentry *dir, struct qstr *name);

/*
 * hymo_dcache_fallback_init - Initialize fallback function pointers
 * @lookup_fn: d_lookup function pointer from hymofs_lookup_name (or NULL)
 *
 * Must be called from hymofs_lkm_init after symbol resolution is available.
 */
void hymo_dcache_fallback_init(void *lookup_fn);

#endif /* _HYMOFS_DCACHE_H */
