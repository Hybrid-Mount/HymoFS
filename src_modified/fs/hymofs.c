#include <linux/string.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fsnotify.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/namei.h>
#include <linux/backing-dev.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <linux/security.h>
#include <linux/mount.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/time.h>
#include <linux/dirent.h>

#include "hymofs.h"

#ifdef CONFIG_HYMOFS

/* HymoFS God Mode - Advanced Path Manipulation */
#define HYMO_HASH_BITS 10

struct hymo_entry {
    char *src;
    char *target;
    unsigned char type;
    struct hlist_node node;
};
struct hymo_hide_entry {
    char *path;
    struct hlist_node node;
};

struct hymo_inject_entry {
    char *dir;
    struct hlist_node node;
};

static DEFINE_HASHTABLE(hymo_paths, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_hide_paths, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_inject_dirs, HYMO_HASH_BITS);
static DEFINE_SPINLOCK(hymo_lock);
atomic_t hymo_version = ATOMIC_INIT(0);
EXPORT_SYMBOL(hymo_version);

static void hymo_cleanup(void) {
    struct hymo_entry *entry;
    struct hymo_hide_entry *hide_entry;
    struct hymo_inject_entry *inject_entry;
    struct hlist_node *tmp;
    int bkt;
    hash_for_each_safe(hymo_paths, bkt, tmp, entry, node) {
        hash_del(&entry->node);
        kfree(entry->src);
        kfree(entry->target);
        kfree(entry);
    }
    hash_for_each_safe(hymo_hide_paths, bkt, tmp, hide_entry, node) {
        hash_del(&hide_entry->node);
        kfree(hide_entry->path);
        kfree(hide_entry);
    }
    hash_for_each_safe(hymo_inject_dirs, bkt, tmp, inject_entry, node) {
        hash_del(&inject_entry->node);
        kfree(inject_entry->dir);
        kfree(inject_entry);
    }
}

static ssize_t hymo_ctl_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
    char *kbuf, *orig_kbuf, *cmd, *arg1, *arg2, *arg3;
    struct hymo_entry *entry;
    struct hymo_hide_entry *hide_entry;
    struct hymo_inject_entry *inject_entry;
    u32 hash;
    unsigned long flags;
    bool found = false;
    int bkt;
    struct hlist_node *tmp;

    if (count == 0 || count > PAGE_SIZE) return -EINVAL;
    orig_kbuf = kmalloc(count + 1, GFP_KERNEL);
    if (!orig_kbuf) return -ENOMEM;
    if (copy_from_user(orig_kbuf, buf, count)) {
        kfree(orig_kbuf);
        return -EFAULT;
    }
    orig_kbuf[count] = 0;
    if (count > 0 && orig_kbuf[count - 1] == '\n') orig_kbuf[count - 1] = 0;

    kbuf = orig_kbuf;
    cmd = strsep(&kbuf, " ");
    
    if (!cmd) {
        kfree(orig_kbuf);
        return -EINVAL;
    }

    if (strcmp(cmd, "add") == 0) {
        arg1 = strsep(&kbuf, " "); // src
        arg2 = strsep(&kbuf, " "); // target
        arg3 = strsep(&kbuf, " "); // type (optional)
        if (!arg1 || !arg2) {
            kfree(orig_kbuf);
            return -EINVAL;
        }
        hash = full_name_hash(NULL, arg1, strlen(arg1));
        spin_lock_irqsave(&hymo_lock, flags);
        hash_for_each_possible(hymo_paths, entry, node, hash) {
            if (strcmp(entry->src, arg1) == 0) {
                kfree(entry->target);
                entry->target = kstrdup(arg2, GFP_ATOMIC);
                if (arg3) kstrtou8(arg3, 10, &entry->type);
                else entry->type = 0;
                found = true;
                break;
            }
        }
        if (!found) {
            entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
            if (entry) {
                entry->src = kstrdup(arg1, GFP_ATOMIC);
                entry->target = kstrdup(arg2, GFP_ATOMIC);
                if (arg3) kstrtou8(arg3, 10, &entry->type);
                else entry->type = 0;
                if (entry->src && entry->target)
                    hash_add(hymo_paths, &entry->node, hash);
                else {
                    kfree(entry->src);
                    kfree(entry->target);
                    kfree(entry);
                }
            }
        }
        atomic_inc(&hymo_version);
        spin_unlock_irqrestore(&hymo_lock, flags);
    } else if (strcmp(cmd, "hide") == 0) {
        arg1 = strsep(&kbuf, " ");
        if (!arg1) {
            kfree(orig_kbuf);
            return -EINVAL;
        }
        hash = full_name_hash(NULL, arg1, strlen(arg1));
        spin_lock_irqsave(&hymo_lock, flags);
        hash_for_each_possible(hymo_hide_paths, hide_entry, node, hash) {
            if (strcmp(hide_entry->path, arg1) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            hide_entry = kmalloc(sizeof(*hide_entry), GFP_ATOMIC);
            if (hide_entry) {
                hide_entry->path = kstrdup(arg1, GFP_ATOMIC);
                if (hide_entry->path)
                    hash_add(hymo_hide_paths, &hide_entry->node, hash);
                else
                    kfree(hide_entry);
            }
        }
        atomic_inc(&hymo_version);
        spin_unlock_irqrestore(&hymo_lock, flags);
    } else if (strcmp(cmd, "inject") == 0) {
        arg1 = strsep(&kbuf, " ");
        if (!arg1) {
            kfree(orig_kbuf);
            return -EINVAL;
        }
        hash = full_name_hash(NULL, arg1, strlen(arg1));
        spin_lock_irqsave(&hymo_lock, flags);
        hash_for_each_possible(hymo_inject_dirs, inject_entry, node, hash) {
            if (strcmp(inject_entry->dir, arg1) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            inject_entry = kmalloc(sizeof(*inject_entry), GFP_ATOMIC);
            if (inject_entry) {
                inject_entry->dir = kstrdup(arg1, GFP_ATOMIC);
                if (inject_entry->dir)
                    hash_add(hymo_inject_dirs, &inject_entry->node, hash);
                else
                    kfree(inject_entry);
            }
        }
        atomic_inc(&hymo_version);
        spin_unlock_irqrestore(&hymo_lock, flags);
    } else if (strcmp(cmd, "delete") == 0) {
        arg1 = strsep(&kbuf, " ");
        if (!arg1) {
            kfree(orig_kbuf);
            return -EINVAL;
        }
        hash = full_name_hash(NULL, arg1, strlen(arg1));
        spin_lock_irqsave(&hymo_lock, flags);
        
        hash_for_each_possible(hymo_paths, entry, node, hash) {
            if (strcmp(entry->src, arg1) == 0) {
                hash_del(&entry->node);
                kfree(entry->src);
                kfree(entry->target);
                kfree(entry);
                goto out_delete;
            }
        }
        hash_for_each_possible(hymo_hide_paths, hide_entry, node, hash) {
            if (strcmp(hide_entry->path, arg1) == 0) {
                hash_del(&hide_entry->node);
                kfree(hide_entry->path);
                kfree(hide_entry);
                goto out_delete;
            }
        }
        hash_for_each_possible(hymo_inject_dirs, inject_entry, node, hash) {
            if (strcmp(inject_entry->dir, arg1) == 0) {
                hash_del(&inject_entry->node);
                kfree(inject_entry->dir);
                kfree(inject_entry);
                goto out_delete;
            }
        }
out_delete:
        atomic_inc(&hymo_version);
        spin_unlock_irqrestore(&hymo_lock, flags);
    } else if (strcmp(cmd, "clear") == 0) {
        spin_lock_irqsave(&hymo_lock, flags);
        hymo_cleanup();
        atomic_inc(&hymo_version);
        spin_unlock_irqrestore(&hymo_lock, flags);
    }

    kfree(orig_kbuf);
    return count;
}

static int hymo_ctl_show(struct seq_file *m, void *v) {
    struct hymo_entry *entry;
    struct hymo_hide_entry *hide_entry;
    struct hymo_inject_entry *inject_entry;
    int bkt;
    unsigned long flags;

    seq_printf(m, "HymoFS Protocol: 3\n");
    seq_printf(m, "HymoFS Config Version: %d\n", atomic_read(&hymo_version));

    spin_lock_irqsave(&hymo_lock, flags);
    hash_for_each(hymo_paths, bkt, entry, node) {
        seq_printf(m, "add %s %s %d\n", entry->src, entry->target, entry->type);
    }
    hash_for_each(hymo_hide_paths, bkt, hide_entry, node) {
        seq_printf(m, "hide %s\n", hide_entry->path);
    }
    hash_for_each(hymo_inject_dirs, bkt, inject_entry, node) {
        seq_printf(m, "inject %s\n", inject_entry->dir);
    }
    spin_unlock_irqrestore(&hymo_lock, flags);
    return 0;
}

static int hymo_ctl_open(struct inode *inode, struct file *file) {
    return single_open(file, hymo_ctl_show, NULL);
}

static const struct proc_ops hymo_ctl_ops = {
    .proc_open = hymo_ctl_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
    .proc_write = hymo_ctl_write,
};

static int __init hymofs_init(void)
{
    spin_lock_init(&hymo_lock);
    hash_init(hymo_paths);
    hash_init(hymo_hide_paths);
    hash_init(hymo_inject_dirs);
    
    proc_create("hymo_ctl", 0660, NULL, &hymo_ctl_ops);
    
    pr_info("HymoFS: initialized (Procfs Mode)\n");
    return 0;
}
fs_initcall(hymofs_init);

/* Returns kstrdup'd target if found, NULL otherwise. Caller must kfree. */
char *__hymofs_resolve_target(const char *pathname)
{
    unsigned long flags;
    struct hymo_entry *entry;
    u32 hash;
    char *target = NULL;

    if (atomic_read(&hymo_version) == 0) return NULL;
    if (!pathname) return NULL;
    hash = full_name_hash(NULL, pathname, strlen(pathname));

    spin_lock_irqsave(&hymo_lock, flags);
    hash_for_each_possible(hymo_paths, entry, node, hash) {
        if (strcmp(entry->src, pathname) == 0) {
            target = kstrdup(entry->target, GFP_ATOMIC);
            break;
        }
    }
    spin_unlock_irqrestore(&hymo_lock, flags);
    return target;
}
EXPORT_SYMBOL(__hymofs_resolve_target);

bool __hymofs_should_hide(const char *pathname)
{
    unsigned long flags;
    struct hymo_hide_entry *entry;
    u32 hash;
    bool found = false;
    if (atomic_read(&hymo_version) == 0) return false;
    if (!pathname) return false;

    hash = full_name_hash(NULL, pathname, strlen(pathname));
    spin_lock_irqsave(&hymo_lock, flags);
    hash_for_each_possible(hymo_hide_paths, entry, node, hash) {
        if (strcmp(entry->path, pathname) == 0) {
            found = true;
            break;
        }
    }
    spin_unlock_irqrestore(&hymo_lock, flags);
    return found;
}
EXPORT_SYMBOL(__hymofs_should_hide);

bool __hymofs_should_spoof_mtime(const char *pathname)
{
    unsigned long flags;
    struct hymo_inject_entry *entry;
    u32 hash;
    bool found = false;

    if (atomic_read(&hymo_version) == 0) return false;
    if (!pathname) return false;

    hash = full_name_hash(NULL, pathname, strlen(pathname));

    spin_lock_irqsave(&hymo_lock, flags);
    hash_for_each_possible(hymo_inject_dirs, entry, node, hash) {
        if (strcmp(entry->dir, pathname) == 0) {
            found = true;
            break;
        }
    }
    spin_unlock_irqrestore(&hymo_lock, flags);
    return found;
}
EXPORT_SYMBOL(__hymofs_should_spoof_mtime);

static bool __hymofs_should_replace(const char *pathname)
{
    unsigned long flags;
    struct hymo_entry *entry;
    u32 hash;
    bool found = false;

    if (atomic_read(&hymo_version) == 0) return false;
    if (!pathname) return false;

    hash = full_name_hash(NULL, pathname, strlen(pathname));

    spin_lock_irqsave(&hymo_lock, flags);
    hash_for_each_possible(hymo_paths, entry, node, hash) {
        if (strcmp(entry->src, pathname) == 0) {
            found = true;
            break;
        }
    }
    spin_unlock_irqrestore(&hymo_lock, flags);
    return found;
}

int hymofs_populate_injected_list(const char *dir_path, struct dentry *parent, struct list_head *head)
{
    unsigned long flags;
    struct hymo_entry *entry;
    struct hymo_inject_entry *inject_entry;
    struct hymo_name_list *item;
    u32 hash;
    int bkt;
    bool should_inject = false;
    size_t dir_len;
    if (atomic_read(&hymo_version) == 0) return 0;
    if (!dir_path) return 0;

    dir_len = strlen(dir_path);
    hash = full_name_hash(NULL, dir_path, dir_len);

    spin_lock_irqsave(&hymo_lock, flags);
    
    hash_for_each_possible(hymo_inject_dirs, inject_entry, node, hash) {
        if (strcmp(inject_entry->dir, dir_path) == 0) {
            should_inject = true;
            break;
        }
    }
    if (should_inject) {
        hash_for_each(hymo_paths, bkt, entry, node) {
            if (strncmp(entry->src, dir_path, dir_len) == 0) {
                char *name = NULL;
                if (dir_len == 1 && dir_path[0] == '/') {
                    name = entry->src + 1;
                } else if (entry->src[dir_len] == '/') {
                    name = entry->src + dir_len + 1;
                }

                if (name && *name && strchr(name, '/') == NULL) {
                    item = kmalloc(sizeof(*item), GFP_ATOMIC);
                    if (item) {
                        item->name = kstrdup(name, GFP_ATOMIC);
                        item->type = entry->type;
                        if (item->name) list_add(&item->list, head);
                        else kfree(item);
                    }
                }
            }
        }
    }

    spin_unlock_irqrestore(&hymo_lock, flags);
    return 0;
}
EXPORT_SYMBOL(hymofs_populate_injected_list);

struct filename *hymofs_handle_getname(struct filename *result)
{
    char *target;

    if (IS_ERR(result)) return result;

    /* HymoFS God Mode Hook */
    if (hymofs_should_hide(result->name)) {
        putname(result);
        /* Return ENOENT directly */
        return ERR_PTR(-ENOENT);
    } else {
        target = hymofs_resolve_target(result->name);
        if (target) {
            putname(result);
            result = getname_kernel(target);
            kfree(target);
        }
    }
    return result;
}
EXPORT_SYMBOL(hymofs_handle_getname);

void __hymofs_prepare_readdir(struct hymo_readdir_context *ctx, struct file *file)
{
    ctx->file = file;
    ctx->path_buf = NULL;
    ctx->dir_path = NULL;
    ctx->dir_path_len = 0;

    ctx->path_buf = (char *)__get_free_page(GFP_KERNEL);
    if (ctx->path_buf && file && file->f_path.dentry) {
        char *p = d_path(&file->f_path, ctx->path_buf, PAGE_SIZE);
        if (!IS_ERR(p)) {
            int len = strlen(p);
            memmove(ctx->path_buf, p, len + 1);
            ctx->dir_path = ctx->path_buf;
            ctx->dir_path_len = len;
        } else {
            free_page((unsigned long)ctx->path_buf);
            ctx->path_buf = NULL;
        }
    }
}
EXPORT_SYMBOL(__hymofs_prepare_readdir);

void __hymofs_cleanup_readdir(struct hymo_readdir_context *ctx)
{
    if (ctx->path_buf) free_page((unsigned long)ctx->path_buf);
}
EXPORT_SYMBOL(__hymofs_cleanup_readdir);

bool __hymofs_check_filldir(struct hymo_readdir_context *ctx, const char *name, int namlen)
{
    if (ctx->dir_path) {
        if (ctx->dir_path_len + 1 + namlen < PAGE_SIZE) {
            char *p = ctx->path_buf + ctx->dir_path_len;
            if (p > ctx->path_buf && p[-1] != '/') *p++ = '/';
            memcpy(p, name, namlen);
            p[namlen] = '\0';
            if (hymofs_should_hide(ctx->path_buf)) return true;
            if (__hymofs_should_replace(ctx->path_buf)) return true;
        }
    }
    return false;
}
EXPORT_SYMBOL(__hymofs_check_filldir);

struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[];
};

int hymofs_inject_entries(struct hymo_readdir_context *ctx, void __user **dir_ptr, int *count, loff_t *pos)
{
    struct linux_dirent __user *current_dir = *dir_ptr;
    struct list_head head;
    struct hymo_name_list *item, *tmp;
    loff_t current_idx = 0;
    loff_t start_idx;
    int injected = 0;
    int error = 0;
    int initial_count = *count;
    bool is_transition = (*pos < HYMO_MAGIC_POS);
    struct dentry *parent;

    if (!ctx->file) return 0;
    parent = ctx->file->f_path.dentry;

    if (is_transition) {
        start_idx = 0;
    } else {
        start_idx = *pos - HYMO_MAGIC_POS;
    }

    INIT_LIST_HEAD(&head);
    hymofs_populate_injected_list(ctx->dir_path, parent, &head);

    list_for_each_entry_safe(item, tmp, &head, list) {
        if (current_idx >= start_idx) {
            int name_len = strlen(item->name);
            int reclen = ALIGN(offsetof(struct linux_dirent, d_name) + name_len + 2, sizeof(long));
            if (*count >= reclen) {
                struct linux_dirent d;
                d.d_ino = 1;
                d.d_off = HYMO_MAGIC_POS + current_idx + 1;
                d.d_reclen = reclen;
                if (copy_to_user(current_dir, &d, offsetof(struct linux_dirent, d_name)) ||
                    copy_to_user(current_dir->d_name, item->name, name_len) ||
                    put_user(0, current_dir->d_name + name_len) ||
                    put_user(item->type, (char __user *)current_dir + reclen - 1)) {
                        error = -EFAULT;
                        break;
                }
                current_dir = (struct linux_dirent __user *)((char __user *)current_dir + reclen);
                *count -= reclen;
                injected++;
            } else {
                break;
            }
        }
        current_idx++;
        list_del(&item->list);
        kfree(item->name);
        kfree(item);
    }
    
    list_for_each_entry_safe(item, tmp, &head, list) {
        list_del(&item->list);
        kfree(item->name);
        kfree(item);
    }

    if (error == 0) {
        if (injected > 0) {
            if (is_transition) {
                *pos = HYMO_MAGIC_POS + injected;
            } else {
                *pos += injected;
            }
        }
        error = initial_count - *count;
    }
    
    *dir_ptr = current_dir;
    return error;
}
EXPORT_SYMBOL(hymofs_inject_entries);

int hymofs_inject_entries64(struct hymo_readdir_context *ctx, void __user **dir_ptr, int *count, loff_t *pos)
{
    struct linux_dirent64 __user *current_dir = *dir_ptr;
    struct list_head head;
    struct hymo_name_list *item, *tmp;
    loff_t current_idx = 0;
    loff_t start_idx;
    int injected = 0;
    int error = 0;
    int initial_count = *count;
    bool is_transition = (*pos < HYMO_MAGIC_POS);
    struct dentry *parent;

    if (!ctx->file) return 0;
    parent = ctx->file->f_path.dentry;

    if (is_transition) {
        start_idx = 0;
    } else {
        start_idx = *pos - HYMO_MAGIC_POS;
    }

    INIT_LIST_HEAD(&head);
    hymofs_populate_injected_list(ctx->dir_path, parent, &head);

    list_for_each_entry_safe(item, tmp, &head, list) {
        if (current_idx >= start_idx) {
            int name_len = strlen(item->name);
            int reclen = ALIGN(offsetof(struct linux_dirent64, d_name) + name_len + 1, sizeof(u64));
            if (*count >= reclen) {
                struct linux_dirent64 d;
                d.d_ino = 1;
                d.d_off = HYMO_MAGIC_POS + current_idx + 1;
                d.d_reclen = reclen;
                d.d_type = item->type;
                if (copy_to_user(current_dir, &d, offsetof(struct linux_dirent64, d_name)) ||
                    copy_to_user(current_dir->d_name, item->name, name_len) ||
                    put_user(0, current_dir->d_name + name_len)) {
                        error = -EFAULT;
                        break;
                }
                current_dir = (struct linux_dirent64 __user *)((char __user *)current_dir + reclen);
                *count -= reclen;
                injected++;
            } else {
                break;
            }
        }
        current_idx++;
        list_del(&item->list);
        kfree(item->name);
        kfree(item);
    }
    
    list_for_each_entry_safe(item, tmp, &head, list) {
        list_del(&item->list);
        kfree(item->name);
        kfree(item);
    }

    if (error == 0) {
        if (injected > 0) {
            if (is_transition) {
                *pos = HYMO_MAGIC_POS + injected;
            } else {
                *pos += injected;
            }
        }
        error = initial_count - *count;
    }
    
    *dir_ptr = current_dir;
    return error;
}
EXPORT_SYMBOL(hymofs_inject_entries64);

void hymofs_spoof_stat(const struct path *path, struct kstat *stat)
{
    char *buf = (char *)__get_free_page(GFP_KERNEL);
    if (buf && path && path->dentry) {
        char *p = d_path(path, buf, PAGE_SIZE);
        if (!IS_ERR(p)) {
            if (hymofs_should_spoof_mtime(p)) {
                ktime_get_real_ts64(&stat->mtime);
                stat->ctime = stat->mtime;
            }
        }
        free_page((unsigned long)buf);
    }
}
EXPORT_SYMBOL(hymofs_spoof_stat);

#endif /* CONFIG_HYMOFS */
