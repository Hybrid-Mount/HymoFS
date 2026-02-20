/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS - userspace/kernel shared definitions (ioctl, protocol, constants).
 *
 * License: Author's work under Apache-2.0; when used with the kernel or LKM,
 * GPL-2.0 applies for kernel compatibility.
 */
#ifndef _LINUX_HYMO_MAGIC_H
#define _LINUX_HYMO_MAGIC_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/bits.h>
#else
#include <sys/ioctl.h>
#include <stddef.h>
#include <stdint.h>
#endif

#define HYMO_MAGIC1 0x48594D4F
#define HYMO_MAGIC2 0x524F4F54
#define HYMO_PROTOCOL_VERSION 12

#define HYMO_MAX_LEN_PATHNAME 256
#define HYMO_FAKE_CMDLINE_SIZE 4096

#ifdef __KERNEL__
#define AS_FLAGS_HYMO_HIDE 40
#define BIT_HYMO_HIDE BIT(40)
#define AS_FLAGS_HYMO_DIR_HAS_HIDDEN 41
#define BIT_HYMO_DIR_HAS_HIDDEN BIT(41)
#define AS_FLAGS_HYMO_SPOOF_KSTAT 42
#define BIT_HYMO_SPOOF_KSTAT BIT(42)
#endif

#define HYMO_SYSCALL_NR 142

#define HYMO_CMD_GET_FD 0x48021

#define HYMO_PRCTL_GET_FD 0x48021

struct hymo_syscall_arg {
    const char *src;
    const char *target;
    int type;
};

struct hymo_syscall_list_arg {
    char *buf;
    size_t size;
};

struct hymo_uid_list_arg {
    __u32 count;
    __u32 reserved;
    __aligned_u64 uids;
};

struct hymo_spoof_kstat {
    unsigned long target_ino;
    char target_pathname[HYMO_MAX_LEN_PATHNAME];
    unsigned long spoofed_ino;
    unsigned long spoofed_dev;
    unsigned int spoofed_nlink;
    long long spoofed_size;
    long spoofed_atime_sec;
    long spoofed_atime_nsec;
    long spoofed_mtime_sec;
    long spoofed_mtime_nsec;
    long spoofed_ctime_sec;
    long spoofed_ctime_nsec;
    unsigned long spoofed_blksize;
    unsigned long long spoofed_blocks;
    int is_static;
    int err;
};

#define HYMO_UNAME_LEN 65
struct hymo_spoof_uname {
    char sysname[HYMO_UNAME_LEN];                       
    char nodename[HYMO_UNAME_LEN];                      
    char release[HYMO_UNAME_LEN];
    char version[HYMO_UNAME_LEN];
    char machine[HYMO_UNAME_LEN];                       
    char domainname[HYMO_UNAME_LEN];                    
    int err;
};

struct hymo_spoof_cmdline {
    char cmdline[HYMO_FAKE_CMDLINE_SIZE];
    int err;
};

#define HYMO_FEATURE_KSTAT_SPOOF    (1 << 0)
#define HYMO_FEATURE_UNAME_SPOOF    (1 << 1)
#define HYMO_FEATURE_CMDLINE_SPOOF  (1 << 2)
#define HYMO_FEATURE_SELINUX_BYPASS (1 << 4)
#define HYMO_FEATURE_MERGE_DIR      (1 << 5)

#define HYMO_IOC_MAGIC 'H'
#define HYMO_IOC_ADD_RULE           _IOW(HYMO_IOC_MAGIC, 1, struct hymo_syscall_arg)
#define HYMO_IOC_DEL_RULE           _IOW(HYMO_IOC_MAGIC, 2, struct hymo_syscall_arg)
#define HYMO_IOC_HIDE_RULE          _IOW(HYMO_IOC_MAGIC, 3, struct hymo_syscall_arg)
#define HYMO_IOC_CLEAR_ALL          _IO(HYMO_IOC_MAGIC, 5)
#define HYMO_IOC_GET_VERSION        _IOR(HYMO_IOC_MAGIC, 6, int)
#define HYMO_IOC_LIST_RULES         _IOWR(HYMO_IOC_MAGIC, 7, struct hymo_syscall_list_arg)
#define HYMO_IOC_SET_DEBUG          _IOW(HYMO_IOC_MAGIC, 8, int)
#define HYMO_IOC_REORDER_MNT_ID     _IO(HYMO_IOC_MAGIC, 9)
#define HYMO_IOC_SET_STEALTH        _IOW(HYMO_IOC_MAGIC, 10, int)
#define HYMO_IOC_HIDE_OVERLAY_XATTRS _IOW(HYMO_IOC_MAGIC, 11, struct hymo_syscall_arg)
#define HYMO_IOC_ADD_MERGE_RULE     _IOW(HYMO_IOC_MAGIC, 12, struct hymo_syscall_arg)
#define HYMO_IOC_SET_MIRROR_PATH    _IOW(HYMO_IOC_MAGIC, 14, struct hymo_syscall_arg)
#define HYMO_IOC_ADD_SPOOF_KSTAT    _IOW(HYMO_IOC_MAGIC, 15, struct hymo_spoof_kstat)
#define HYMO_IOC_UPDATE_SPOOF_KSTAT _IOW(HYMO_IOC_MAGIC, 16, struct hymo_spoof_kstat)
#define HYMO_IOC_SET_UNAME          _IOW(HYMO_IOC_MAGIC, 17, struct hymo_spoof_uname)
#define HYMO_IOC_SET_CMDLINE        _IOW(HYMO_IOC_MAGIC, 18, struct hymo_spoof_cmdline)
#define HYMO_IOC_GET_FEATURES       _IOR(HYMO_IOC_MAGIC, 19, int)
#define HYMO_IOC_SET_ENABLED        _IOW(HYMO_IOC_MAGIC, 20, int)
#define HYMO_IOC_SET_HIDE_UIDS      _IOW(HYMO_IOC_MAGIC, 21, struct hymo_uid_list_arg)

#endif