// lockwrite: run a shell command so that it, and everything it starts, can only write to a set
// of directories, cannot change chosen files inside them, and cannot reach chosen local
// sockets. No root needed:
//   1. a private user + mount namespace, in which
//        AUTOMODE_RO paths (e.g. .git/hooks, .git/config) are bind-mounted read-only and
//        AUTOMODE_HIDE paths (local sockets, socket directories) are covered up;
//   2. Landlock (Linux >= 5.13) confining every filesystem write to AUTOMODE_RW, and on
//      ABI >= 6 (Linux >= 6.12) also blocking abstract unix sockets and signals to processes
//      outside the sandbox. A Landlock-restricted process cannot mount or unmount, so the
//      read-only binds cannot be undone, and cannot ptrace or reach /proc/<pid>/root of
//      processes outside it.
// Reads, execution and the network are not restricted.
//
// It stands in for the shell: opencode runs it through a link named like the real shell
// (sandbox/bin/bash, .../zsh, .../sh) with the arguments it would give that shell, so the
// command itself is never rewritten. lockwrite sets up the sandbox, then runs
//   $AUTOMODE_SHELL <its own arguments>
// Environment:
//   AUTOMODE_SHELL  the real shell, e.g. /bin/bash
//   AUTOMODE_RW     ':'-separated directories where writes are allowed
//   AUTOMODE_RO     ':'-separated paths made read-only (optional)
//   AUTOMODE_HIDE   ':'-separated sockets, files or directories to cover (optional)
//   AUTOMODE_PIN    ':'-separated directories bound onto themselves, so that they cannot be
//                   renamed or replaced (optional)
//   AUTOMODE_TMPFS  ':'-separated directories that get a private writable tmpfs (optional)
// AUTOMODE_RW entries may also be single files (device files), which get file write rights.
// All AUTOMODE_* variables are removed before the shell starts. Paths containing ':' cannot
// be expressed and are left out by the caller.
//
// `lockwrite --selftest` sets everything up around /tmp and exits 0, or fails like a run would.
// Fails closed: if any step fails, the command does not run (exit 126).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif
#ifndef LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
#define LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET (1ULL << 0)
#define LANDLOCK_SCOPE_SIGNAL (1ULL << 1)
#endif

// The ABI 6 layout of the ruleset attribute, declared here so older headers still build.
struct ruleset_attr_v6 {
  __u64 handled_access_fs;
  __u64 handled_access_net;
  __u64 scoped;
};

static int ll_create(const void *a, size_t s, __u32 f) { return syscall(__NR_landlock_create_ruleset, a, s, f); }
static int ll_add(int fd, enum landlock_rule_type t, const void *a, __u32 f) { return syscall(__NR_landlock_add_rule, fd, t, a, f); }
static int ll_restrict(int fd, __u32 f) { return syscall(__NR_landlock_restrict_self, fd, f); }

static void die(const char *what) {
  fprintf(stderr, "lockwrite: %s: %s (command not run)\n", what, strerror(errno));
  exit(126);
}

static void write_file(const char *path, const char *text) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0 || write(fd, text, strlen(text)) != (ssize_t)strlen(text)) die(path);
  close(fd);
}

// Mount flags that must be kept on a remount inside a user namespace (they are locked).
static unsigned long locked_flags(const char *path) {
  struct statvfs sv;
  if (statvfs(path, &sv)) die(path);
  unsigned long f = 0;
  if (sv.f_flag & ST_NOSUID) f |= MS_NOSUID;
  if (sv.f_flag & ST_NODEV) f |= MS_NODEV;
  if (sv.f_flag & ST_NOEXEC) f |= MS_NOEXEC;
  if (sv.f_flag & ST_NOATIME) f |= MS_NOATIME;
  if (sv.f_flag & ST_NODIRATIME) f |= MS_NODIRATIME;
  if (sv.f_flag & ST_RELATIME) f |= MS_RELATIME;
  return f;
}

static void make_readonly(const char *path) {
  struct stat st;
  if (lstat(path, &st)) {
    if (errno == ENOENT) return;  // nothing there to protect; the caller creates what must exist
    die(path);
  }
  if (S_ISLNK(st.st_mode)) {  // binding would follow it somewhere else
    errno = ELOOP;
    die(path);
  }
  if (mount(path, path, NULL, MS_BIND | MS_REC, NULL)) die(path);
  if (mount(NULL, path, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | locked_flags(path), NULL)) die(path);
}

static void hide(const char *path) {
  struct stat st;
  if (lstat(path, &st)) {
    if (errno == ENOENT) return;
    die(path);
  }
  if (S_ISLNK(st.st_mode)) return;  // the target, if listed, is covered by its own entry
  if (S_ISDIR(st.st_mode)) {
    if (mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k,mode=0700")) die(path);
  } else {
    if (mount("/dev/null", path, NULL, MS_BIND, NULL)) die(path);
  }
}

static void pin(const char *path) {
  struct stat st;
  if (lstat(path, &st)) {
    if (errno == ENOENT) return;
    die(path);
  }
  if (!S_ISDIR(st.st_mode)) return;
  if (mount(path, path, NULL, MS_BIND | MS_REC, NULL)) die(path);
}

static void private_tmpfs(const char *path) {
  struct stat st;
  if (stat(path, &st) || !S_ISDIR(st.st_mode)) return;
  if (mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_NODEV, "size=256m,mode=1777")) die(path);
}

static void each(char *list, void (*fn)(const char *)) {
  for (char *save = NULL, *p = strtok_r(list, ":", &save); p; p = strtok_r(NULL, ":", &save))
    if (*p) fn(p);
}

static int ruleset_fd = -1;
static __u64 write_rights;

static void allow_writes(const char *path) {
  int fd = open(path, O_PATH | O_CLOEXEC);
  if (fd < 0) {
    if (errno == ENOENT) return;  // cannot be written to anyway
    die(path);
  }
  struct stat st;
  if (fstat(fd, &st)) die(path);
  // A single file (a device) can only be granted rights that apply to files.
  __u64 rights = S_ISDIR(st.st_mode) ? write_rights : write_rights & (LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE);
  struct landlock_path_beneath_attr pb = {.allowed_access = rights, .parent_fd = fd};
  if (ll_add(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0)) die(path);
  close(fd);
}

int main(int argc, char **argv) {
  const char *shell = getenv("AUTOMODE_SHELL");
  int selftest = !shell && argc == 2 && strcmp(argv[1], "--selftest") == 0;
  if (selftest) shell = "/bin/sh";
  const char *rw = selftest ? "/tmp" : getenv("AUTOMODE_RW");
  const char *ro = getenv("AUTOMODE_RO");
  const char *hidden = getenv("AUTOMODE_HIDE");
  const char *pinned = getenv("AUTOMODE_PIN");
  const char *tmpfs = getenv("AUTOMODE_TMPFS");
  if (!shell || !rw || shell[0] != '/') {
    fprintf(stderr, "lockwrite: AUTOMODE_SHELL (absolute) and AUTOMODE_RW must be set (command not run)\n");
    return 126;
  }
  char *shell_c = strdup(shell), *rw_c = strdup(rw);
  char *ro_c = strdup(selftest || !ro ? "" : ro), *hide_c = strdup(selftest || !hidden ? "" : hidden);
  char *pin_c = strdup(selftest || !pinned ? "" : pinned), *tmpfs_c = strdup(selftest || !tmpfs ? "" : tmpfs);
  if (!shell_c || !rw_c || !ro_c || !hide_c || !pin_c || !tmpfs_c) die("strdup");
  unsetenv("AUTOMODE_SHELL");
  unsetenv("AUTOMODE_RW");
  unsetenv("AUTOMODE_RO");
  unsetenv("AUTOMODE_HIDE");
  unsetenv("AUTOMODE_PIN");
  unsetenv("AUTOMODE_TMPFS");

  // 1. Private user + mount namespace. The uid stays the same, so files keep their owner and a
  //    non-root exec drops every capability the namespace granted.
  uid_t uid = getuid();
  gid_t gid = getgid();
  if (unshare(CLONE_NEWUSER | CLONE_NEWNS)) die("unshare(user, mount namespace)");
  char map[64];
  write_file("/proc/self/setgroups", "deny");
  snprintf(map, sizeof map, "%u %u 1", uid, uid);
  write_file("/proc/self/uid_map", map);
  snprintf(map, sizeof map, "%u %u 1", gid, gid);
  write_file("/proc/self/gid_map", map);
  if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) die("make mounts private");
  each(pin_c, pin);  // first, so later read-only binds inside them stack on top
  each(ro_c, make_readonly);
  each(hide_c, hide);
  each(tmpfs_c, private_tmpfs);
  // The working directory still refers to the directory as it was before the mounts above. Re-enter
  // it by path, so relative paths go through the new mounts instead of around them.
  char *cwd = getcwd(NULL, 0);
  if (!cwd || chdir(cwd)) die("re-enter working directory");
  free(cwd);

  // 2. Landlock.
  int abi = ll_create(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
  if (abi < 1) die("Landlock is not available");
  write_rights = LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                 LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
                 LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                 LANDLOCK_ACCESS_FS_MAKE_SYM;
  if (abi >= 2) write_rights |= LANDLOCK_ACCESS_FS_REFER;
  if (abi >= 3) write_rights |= LANDLOCK_ACCESS_FS_TRUNCATE;
  struct ruleset_attr_v6 attr = {.handled_access_fs = write_rights};
  size_t attr_size = 8;  // ABI 1-3 only know handled_access_fs
  if (abi >= 4) attr_size = 16;
  if (abi >= 6) {
    attr.scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL;
    attr_size = sizeof attr;
  }
  ruleset_fd = ll_create(&attr, attr_size, 0);
  if (ruleset_fd < 0) die("landlock_create_ruleset");
  each(rw_c, allow_writes);
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) die("prctl(NO_NEW_PRIVS)");
  if (ll_restrict(ruleset_fd, 0)) die("landlock_restrict_self");
  close(ruleset_fd);

  if (selftest) {
    printf("lockwrite: ok (Landlock ABI %d%s)\n", abi, abi >= 6 ? ", sockets and signals scoped" : "");
    return 0;
  }
  // Inherited descriptors above stderr could hold a directory opened before the mounts above, a
  // way around them like the old working directory. Close them (Linux >= 5.9; older: best effort).
  if (syscall(SYS_close_range, 3, ~0U, 0) && errno == ENOSYS)
    for (int fd = 3; fd < 1024; fd++) close(fd);
  argv[0] = shell_c;  // the real shell, with exactly the arguments opencode passed
  execv(shell_c, argv);
  die(shell_c);
}
