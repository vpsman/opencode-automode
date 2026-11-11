// lockwrite: run a shell command so that it, and everything it starts, can only write to a set
// of directories, cannot change chosen files inside them, cannot reach chosen local sockets,
// and does not outlive the tool call. No root needed:
//   1. a private user + mount + PID namespace, in which
//        every mount outside the writable directories is remounted read-only (so chmod, utime
//        and setxattr fail there too, which Landlock does not mediate),
//        AUTOMODE_RO paths (e.g. .git/hooks, .git/config) are bind-mounted read-only and
//        AUTOMODE_HIDE paths (local sockets, credential files) are covered up;
//   2. Landlock ABI >= 5 (Linux >= 6.10) confining every filesystem write, truncate and rename
//      to AUTOMODE_RW and denying ioctl on device files (no TIOCSTI), and on ABI >= 6
//      (Linux >= 6.12) also blocking abstract unix sockets and signals to processes outside the
//      sandbox. A Landlock-restricted process cannot mount or unmount, so the read-only binds
//      cannot be undone, and cannot ptrace or reach /proc/<pid>/root of processes outside it.
//   3. the shell runs as a child of the namespace's init process, which exits when the shell
//      does: the kernel then kills whatever the command left running in the background.
// Reads of files that are not hidden, execution and the network are not restricted.
//
// It stands in for the shell: opencode runs it through a link named like the real shell
// (sandbox/bin/bash, .../zsh, .../sh) with the arguments it would give that shell, so the
// command itself is never rewritten. lockwrite sets up the sandbox, then runs
//   $AUTOMODE_SHELL <its own arguments>
// Environment (lists are newline-separated, so a ':' in a path is fine):
//   AUTOMODE_SHELL     the real shell, e.g. /bin/bash
//   AUTOMODE_RW        directories where writes are allowed
//   AUTOMODE_RO        paths made read-only (optional)
//   AUTOMODE_HIDE      sockets, files or directories to cover (optional)
//   AUTOMODE_PIN       directories bound onto themselves, so that they cannot be renamed or
//                      replaced (optional)
//   AUTOMODE_COVER     an empty regular file bound over hidden files (default /dev/null)
//   AUTOMODE_TMPFS     directories that get a private writable tmpfs (optional)
//   AUTOMODE_ENV_KEEP  when set: the only environment variables the command may see (optional)
//   AUTOMODE_FAKE_ABI  tests only: pretend the kernel has this Landlock ABI. It can only lower
//                      the real one, so it can only make lockwrite refuse to run.
// AUTOMODE_RW entries may also be single files (device files), which get file write rights.
// All AUTOMODE_* variables are removed before the shell starts.
//
// `lockwrite --selftest` sets everything up around /tmp and exits 0, or fails like a run would.
// Fails closed: if any step fails, the command does not run (exit 126).
//
// Written in Rust for the string handling: the path lists, the environment filter and the
// mountinfo parser see names an earlier command could have chosen, before the sandbox is up.
// The system calls themselves are `unsafe` either way; each block below is one call whose
// arguments are NUL-terminated strings or plain integers owned by this function.

use std::ffi::{CString, OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::{env, fs, io, mem, process, ptr};

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;
const FS_WRITE_FILE: u64 = 1 << 1;
const FS_REMOVE_DIR: u64 = 1 << 4;
const FS_REMOVE_FILE: u64 = 1 << 5;
const FS_MAKE_CHAR: u64 = 1 << 6;
const FS_MAKE_DIR: u64 = 1 << 7;
const FS_MAKE_REG: u64 = 1 << 8;
const FS_MAKE_SOCK: u64 = 1 << 9;
const FS_MAKE_FIFO: u64 = 1 << 10;
const FS_MAKE_BLOCK: u64 = 1 << 11;
const FS_MAKE_SYM: u64 = 1 << 12;
const FS_REFER: u64 = 1 << 13;
const FS_TRUNCATE: u64 = 1 << 14;
const FS_IOCTL_DEV: u64 = 1 << 15;
const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
const SCOPE_SIGNAL: u64 = 1 << 1;
const WRITE_RIGHTS: u64 = FS_WRITE_FILE | FS_REMOVE_DIR | FS_REMOVE_FILE | FS_MAKE_CHAR | FS_MAKE_DIR | FS_MAKE_REG | FS_MAKE_SOCK | FS_MAKE_FIFO | FS_MAKE_BLOCK | FS_MAKE_SYM | FS_REFER | FS_TRUNCATE;

// Below this ABI truncate(2) (ABI < 3) and device ioctls (ABI < 5) are not confined.
const MIN_ABI: i64 = 5;

// The ABI 6 layout of the ruleset attribute.
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

fn fail(message: &str) -> ! {
    eprintln!("lockwrite: {message} (command not run)");
    process::exit(126)
}

// For a failed system call: `what` and the error it left in errno.
fn die(what: &[u8]) -> ! {
    let error = io::Error::last_os_error();
    fail(&format!("{}: {}", String::from_utf8_lossy(what), error))
}

fn die_with(what: &[u8], error: io::Error) -> ! {
    fail(&format!("{}: {}", String::from_utf8_lossy(what), error))
}

fn cstr(bytes: &[u8]) -> CString {
    CString::new(bytes).unwrap_or_else(|_| fail("a path contains a NUL byte"))
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn sys_mount(source: Option<&[u8]>, target: &[u8], fstype: Option<&[u8]>, flags: libc::c_ulong, data: Option<&[u8]>) -> bool {
    let source = source.map(cstr);
    let target = cstr(target);
    let fstype = fstype.map(cstr);
    let data = data.map(cstr);
    let p = |s: &Option<CString>| s.as_ref().map_or(ptr::null(), |c| c.as_ptr());
    // SAFETY: every pointer is null or a NUL-terminated string that lives until the call returns.
    unsafe { libc::mount(p(&source), target.as_ptr(), p(&fstype), flags, p(&data) as *const libc::c_void) == 0 }
}

// A newline-separated list from the environment, without empty entries.
fn list(value: Option<OsString>) -> Vec<Vec<u8>> {
    value.map(OsString::into_vec).unwrap_or_default().split(|&b| b == b'\n').filter(|p| !p.is_empty()).map(<[u8]>::to_vec).collect()
}

fn path(bytes: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(bytes))
}

// The file's type without following a final symlink; None when nothing is there.
fn kind(target: &[u8]) -> Option<fs::FileType> {
    match fs::symlink_metadata(path(target)) {
        Ok(meta) => Some(meta.file_type()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => die_with(target, e),
    }
}

// Mount flags that must be kept on a remount inside a user namespace (they are locked).
fn locked_flags(target: &[u8]) -> Option<libc::c_ulong> {
    let c = cstr(target);
    // SAFETY: `sv` is a plain struct of integers that statvfs fills; `c` is NUL-terminated.
    let sv = unsafe {
        let mut sv: libc::statvfs = mem::zeroed();
        if libc::statvfs(c.as_ptr(), &mut sv) != 0 {
            return None;
        }
        sv
    };
    let mut flags = 0;
    for (st, ms) in [
        (libc::ST_NOSUID, libc::MS_NOSUID),
        (libc::ST_NODEV, libc::MS_NODEV),
        (libc::ST_NOEXEC, libc::MS_NOEXEC),
        (libc::ST_NOATIME, libc::MS_NOATIME),
        (libc::ST_NODIRATIME, libc::MS_NODIRATIME),
        (libc::ST_RELATIME, libc::MS_RELATIME),
    ] {
        if sv.f_flag & st != 0 {
            flags |= ms;
        }
    }
    Some(flags)
}

fn remount_readonly(target: &[u8]) {
    let flags = locked_flags(target).unwrap_or_else(|| die(target));
    if !sys_mount(None, target, None, libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | flags, None) {
        die(target);
    }
}

fn make_readonly(target: &[u8]) {
    let Some(kind) = kind(target) else { return }; // nothing there to protect; the caller creates what must exist
    if kind.is_symlink() {
        // Binding would follow it somewhere else.
        fail(&format!("{}: is a symbolic link", String::from_utf8_lossy(target)));
    }
    if !sys_mount(Some(target), target, None, libc::MS_BIND | libc::MS_REC, None) {
        die(target);
    }
    remount_readonly(target);
}

fn hide(target: &[u8], cover: &[u8]) {
    let Some(kind) = kind(target) else { return };
    if kind.is_symlink() {
        return; // the target, if listed, is covered by its own entry
    }
    if kind.is_dir() {
        if !sys_mount(Some(b"tmpfs"), target, Some(b"tmpfs"), libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_RDONLY, Some(b"size=4k,mode=0700")) {
            die(target);
        }
    } else {
        // An empty read-only file where the caller supplies one, so that a write to a hidden file
        // fails instead of vanishing into /dev/null.
        if !sys_mount(Some(cover), target, None, libc::MS_BIND, None) {
            die(target);
        }
        if cover != b"/dev/null" {
            remount_readonly(target);
        }
    }
}

// Binds a directory onto itself: it cannot be renamed or replaced, and as a mount of its own it
// stays writable when the mount it lives on is remounted read-only.
fn pin(target: &[u8]) {
    if kind(target).is_some_and(|k| k.is_dir()) && !sys_mount(Some(target), target, None, libc::MS_BIND | libc::MS_REC, None) {
        die(target);
    }
}

fn private_tmpfs(target: &[u8]) {
    if fs::metadata(path(target)).is_ok_and(|m| m.is_dir()) && !sys_mount(Some(b"tmpfs"), target, Some(b"tmpfs"), libc::MS_NOSUID | libc::MS_NODEV, Some(b"size=256m,mode=1777")) {
        die(target);
    }
}

fn under(target: &[u8], roots: &[Vec<u8>]) -> bool {
    roots.iter().any(|root| root.len() > 1 && target.starts_with(root) && (target.len() == root.len() || target[root.len()] == b'/'))
}

// mountinfo writes space, tab, newline and backslash in a mount point as \ooo.
fn unescape(field: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(field.len());
    let mut i = 0;
    while i < field.len() {
        let octal = |b: u8, max: u8| (b'0'..=max).contains(&b);
        if field[i] == b'\\' && i + 3 < field.len() && octal(field[i + 1], b'3') && octal(field[i + 2], b'7') && octal(field[i + 3], b'7') {
            out.push(((field[i + 1] - b'0') << 6) | ((field[i + 2] - b'0') << 3) | (field[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(field[i]);
            i += 1;
        }
    }
    out
}

fn is_mount_root(target: &[u8]) -> bool {
    let c = cstr(target);
    // SAFETY: `sx` is a plain struct that statx fills; `c` is NUL-terminated.
    unsafe {
        let mut sx: libc::statx = mem::zeroed();
        if libc::statx(libc::AT_FDCWD, c.as_ptr(), libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT, 0, &mut sx) != 0 {
            return true; // unknown: treat as one
        }
        let root = libc::STATX_ATTR_MOUNT_ROOT as u64;
        sx.stx_attributes_mask & root == 0 || sx.stx_attributes & root != 0
    }
}

// Everything outside the writable directories becomes read-only.
fn readonly_outside(writable: &[Vec<u8>]) {
    let info = fs::read("/proc/self/mountinfo").unwrap_or_else(|e| die_with(b"/proc/self/mountinfo", e));
    for line in info.split(|&b| b == b'\n') {
        // "<id> <parent> <major:minor> <root> <mount point> ..."
        let Some(field) = line.split(|&b| b == b' ').nth(4) else { continue };
        let target = unescape(field);
        if under(&target, writable) {
            continue;
        }
        // A mount this user cannot even look into cannot be changed by the command either. One
        // that is gone or covered by another mount is reached through that other mount's own line.
        let Some(flags) = locked_flags(&target) else {
            if [libc::EACCES, libc::ENOENT, libc::ENOTCONN, libc::ESTALE].contains(&errno()) {
                continue;
            }
            die(&target)
        };
        if !sys_mount(None, &target, None, libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | flags, None) {
            let e = errno();
            // EINVAL for a path that is no longer a mount root: the mount is covered by a later
            // one (the old /proc submounts under the new /proc) and cannot be reached at all.
            if e == libc::EACCES || e == libc::ENOENT || (e == libc::EINVAL && !is_mount_root(&target)) {
                continue;
            }
            die_with(&target, io::Error::from_raw_os_error(e));
        }
    }
}

fn landlock_abi() -> i64 {
    // SAFETY: the version query takes a null attribute and size 0.
    unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, ptr::null::<libc::c_void>(), 0usize, LANDLOCK_CREATE_RULESET_VERSION) as i64 }
}

fn allow_writes(ruleset: libc::c_int, target: &[u8]) {
    let file = match fs::OpenOptions::new().read(true).custom_flags_path().open(path(target)) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return, // cannot be written to anyway
        Err(e) => die_with(target, e),
    };
    let meta = file.metadata().unwrap_or_else(|e| die_with(target, e));
    // A single file (a device) can only be granted rights that apply to files. No path gets the
    // device-ioctl right.
    let rights = if meta.is_dir() { WRITE_RIGHTS } else { FS_WRITE_FILE | FS_TRUNCATE };
    let attr = PathBeneathAttr { allowed_access: rights, parent_fd: std::os::fd::AsRawFd::as_raw_fd(&file) };
    // SAFETY: `attr` is the kernel's packed path_beneath layout and outlives the call.
    if unsafe { libc::syscall(libc::SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH, &attr as *const PathBeneathAttr, 0u32) } != 0 {
        die(target);
    }
}

// Opens with O_PATH: no read permission is needed to name a directory in a rule.
trait OpenPath {
    fn custom_flags_path(&mut self) -> &mut Self;
}
impl OpenPath for fs::OpenOptions {
    fn custom_flags_path(&mut self) -> &mut Self {
        std::os::unix::fs::OpenOptionsExt::custom_flags(self, libc::O_PATH | libc::O_CLOEXEC)
    }
}

fn exit_code(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        128 + libc::WTERMSIG(status)
    }
}

extern "C" fn noop(_signal: libc::c_int) {}

fn write_file(target: &str, text: &str) {
    fs::write(target, text).unwrap_or_else(|e| die_with(target.as_bytes(), e));
}

fn main() {
    let args: Vec<OsString> = env::args_os().collect();
    let selftest = env::var_os("AUTOMODE_SHELL").is_none() && args.len() == 2 && args[1] == "--selftest";
    let shell = if selftest { Some(OsString::from("/bin/sh")) } else { env::var_os("AUTOMODE_SHELL") };
    let writable = if selftest { vec![b"/tmp".to_vec()] } else { list(env::var_os("AUTOMODE_RW")) };
    let optional = |name: &str| if selftest { Vec::new() } else { list(env::var_os(name)) };
    let (readonly, hidden, pinned, tmpfs) = (optional("AUTOMODE_RO"), optional("AUTOMODE_HIDE"), optional("AUTOMODE_PIN"), optional("AUTOMODE_TMPFS"));
    let keep = if selftest { None } else { env::var_os("AUTOMODE_ENV_KEEP").map(|v| list(Some(v))) };
    let cover_file = if selftest { None } else { env::var_os("AUTOMODE_COVER") };
    let abi_cap = env::var("AUTOMODE_FAKE_ABI").ok().map(|v| v.trim().parse::<i64>().unwrap_or(0));
    let shell = match shell {
        Some(shell) if shell.as_bytes().first() == Some(&b'/') && (selftest || env::var_os("AUTOMODE_RW").is_some()) => shell,
        _ => fail("AUTOMODE_SHELL (absolute) and AUTOMODE_RW must be set"),
    };
    if let Some(cover) = &cover_file {
        let ok = cover.as_bytes().first() == Some(&b'/') && fs::metadata(cover).is_ok_and(|m| m.is_file() && m.size() == 0);
        if !ok {
            fail("AUTOMODE_COVER must be an empty regular file");
        }
    }

    // The environment: every AUTOMODE_* variable goes, and with a keep list everything not on it.
    let names: Vec<OsString> = env::vars_os().map(|(name, _)| name).collect();
    for name in names {
        let bytes = name.as_bytes();
        if bytes.starts_with(b"AUTOMODE_") || keep.as_ref().is_some_and(|keep| !keep.iter().any(|k| k == bytes)) {
            env::remove_var(&name);
        }
    }

    // 1. Private user + mount + PID namespace. The uid stays the same, so files keep their owner
    //    and a non-root exec drops every capability the namespace granted.
    // SAFETY: getuid and getgid cannot fail; unshare takes flags only.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWPID) } != 0 {
        die(b"unshare(user, mount, pid namespace)");
    }
    write_file("/proc/self/setgroups", "deny");
    write_file("/proc/self/uid_map", &format!("{uid} {uid} 1"));
    write_file("/proc/self/gid_map", &format!("{gid} {gid} 1"));

    // The first child is the new PID namespace's init. This process only waits for it, and stays
    // alive through the signals opencode sends the process group so the exit status gets back.
    // SAFETY: the process has one thread, so the child may go on using the allocator and std.
    let init = unsafe { libc::fork() };
    if init < 0 {
        die(b"fork");
    }
    if init > 0 {
        // SAFETY: `action` is zeroed and then given a handler that does nothing.
        unsafe {
            let mut action: libc::sigaction = mem::zeroed();
            action.sa_sigaction = noop as extern "C" fn(libc::c_int) as usize;
            for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT] {
                libc::sigaction(signal, &action, ptr::null_mut());
            }
        }
        let mut status = 0;
        // SAFETY: `status` is a valid place for the exit status.
        while unsafe { libc::waitpid(init, &mut status, 0) } < 0 {
            if errno() != libc::EINTR {
                die(b"waitpid");
            }
        }
        process::exit(exit_code(status));
    }
    // If the process above is killed, init dies, and the kernel kills the rest of the namespace.
    // SAFETY: prctl with integer arguments.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong, 0, 0, 0) } != 0 {
        die(b"prctl(PDEATHSIG)");
    }

    if !sys_mount(None, b"/", None, libc::MS_REC | libc::MS_PRIVATE, None) {
        die(b"make mounts private");
    }
    // A /proc for the new PID namespace: `ps` and `kill` see only the sandbox. Where the kernel
    // refuses (a /proc that is partly covered, as in some containers) the old one stays; processes
    // outside are still out of reach of signals and ptrace.
    if !sys_mount(Some(b"proc"), b"/proc", Some(b"proc"), libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, None) && ![libc::EPERM, libc::EBUSY].contains(&errno()) {
        die(b"mount /proc");
    }
    // The cover file is opened inside the new mount namespace (a descriptor from the old one
    // cannot be bound here) and bound through /proc/self/fd, so it still works once its
    // directory is hidden. It stays open until the mounts are made.
    let cover_handle = cover_file.as_ref().map(|cover| fs::OpenOptions::new().read(true).custom_flags_path().open(cover).unwrap_or_else(|e| die_with(cover.as_bytes(), e)));
    let cover: Vec<u8> = match &cover_handle {
        Some(file) => format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(file)).into_bytes(),
        None => b"/dev/null".to_vec(),
    };
    for target in writable.iter().chain(&pinned) {
        pin(target); // before the read-only binds, so those stack on top
    }
    for target in &readonly {
        make_readonly(target);
    }
    for target in &hidden {
        hide(target, &cover);
    }
    for target in &tmpfs {
        private_tmpfs(target);
    }
    readonly_outside(&writable);
    drop(cover_handle);
    // The working directory still refers to the directory as it was before the mounts above.
    // Re-enter it by path, so relative paths go through the new mounts instead of around them.
    let cwd = env::current_dir().unwrap_or_else(|e| die_with(b"re-enter working directory", e));
    env::set_current_dir(&cwd).unwrap_or_else(|e| die_with(b"re-enter working directory", e));

    // 2. Landlock.
    let mut abi = landlock_abi();
    if abi < 1 {
        die(b"Landlock is not available");
    }
    if let Some(cap) = abi_cap {
        abi = abi.min(cap);
    }
    if abi < MIN_ABI {
        fail(&format!("Landlock ABI {abi} is too old, ABI {MIN_ABI} (Linux 6.10) is needed"));
    }
    let attr = RulesetAttr { handled_access_fs: WRITE_RIGHTS | FS_IOCTL_DEV, handled_access_net: 0, scoped: if abi >= 6 { SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL } else { 0 } };
    // ABI 4 and 5 know handled_access_fs and handled_access_net; ABI 6 adds scoped.
    let attr_size: usize = if abi >= 6 { mem::size_of::<RulesetAttr>() } else { 16 };
    // SAFETY: `attr` has the kernel's layout and `attr_size` bytes of it are valid.
    let ruleset = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, &attr as *const RulesetAttr, attr_size, 0u32) } as libc::c_int;
    if ruleset < 0 {
        die(b"landlock_create_ruleset");
    }
    for target in &writable {
        allow_writes(ruleset, target);
    }
    // SAFETY: integer arguments only; `ruleset` is the descriptor made above.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0, 0, 0) != 0 {
            die(b"prctl(NO_NEW_PRIVS)");
        }
        if libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0u32) != 0 {
            die(b"landlock_restrict_self");
        }
        libc::close(ruleset);
    }

    if selftest {
        println!("lockwrite: ok (Landlock ABI {abi}{})", if abi >= 6 { ", sockets and signals scoped" } else { "" });
        return;
    }

    // 3. The shell. Init waits for it and then exits, which ends everything else in the namespace.
    // SAFETY: single-threaded, as above.
    let child = unsafe { libc::fork() };
    if child < 0 {
        die(b"fork");
    }
    if child == 0 {
        // Inherited descriptors above stderr could hold a directory opened before the mounts
        // above, a way around them like the old working directory.
        // SAFETY: integer arguments only.
        if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) } != 0 {
            die(b"close_range");
        }
        // The real shell, with exactly the arguments opencode passed.
        let error = process::Command::new(&shell).arg0(&shell).args(&args[1..]).exec();
        die_with(shell.as_bytes(), error);
    }
    loop {
        let mut status = 0;
        // SAFETY: `status` is a valid place for the exit status.
        let done = unsafe { libc::wait(&mut status) };
        if done == child {
            process::exit(exit_code(status));
        }
        if done < 0 && errno() != libc::EINTR {
            die(b"wait");
        }
    }
}
