use anyhow::{anyhow, bail, Context, Result};
use clap::{ArgAction, Parser};
use landlock::{
    make_bitflags, Access, AccessFs, BitFlags, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, ABI,
};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "locked-run-as-user",
    about = "Run a command as another user with a Landlock filesystem allowlist",
    trailing_var_arg = true
)]
struct Args {
    /// User name or numeric UID. If given, look up UID, GID, and supplemental groups and apply them.
    #[arg(long)]
    user: Option<String>,

    /// Read-only paths (repeatable).
    #[arg(long, value_name = "PATH", action = ArgAction::Append)]
    ro: Vec<PathBuf>,

    /// Read + execute paths (repeatable).
    #[arg(long, value_name = "PATH", action = ArgAction::Append)]
    rox: Vec<PathBuf>,

    /// Read + write paths (repeatable).
    #[arg(long, value_name = "PATH", action = ArgAction::Append)]
    rw: Vec<PathBuf>,

    /// Read + write + execute paths (repeatable).
    #[arg(long, value_name = "PATH", action = ArgAction::Append)]
    rwx: Vec<PathBuf>,

    /// Add a small set of common runtime paths for dynamically linked executables.
    #[arg(long)]
    libs: bool,

    /// Resolve actually used shared libraries (ldd-style) and allowlist them explicitly.
    #[arg(long)]
    resolve_libs: bool,

    /// Print the final allowlist (paths + rights) before enforcing Landlock.
    #[arg(long)]
    debug: bool,

    /// Command to execute (use `--` to separate it from launcher options).
    #[arg(value_name = "CMD", required = true)]
    cmd: Vec<OsString>,
}

#[derive(Debug)]
struct UserInfo {
    name: CString,
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Resolve --user (do NSS lookups before Landlock is enforced).
    let user_info = match &args.user {
        Some(u) => Some(resolve_user(u).context("failed to resolve --user")?),
        None => None,
    };

    // Resolve the command path (and rewrite argv[0] to an absolute/canonical path when possible).
    let (cmd_path, cmd_argv) = resolve_command(&args.cmd)
        .with_context(|| format!("failed to resolve command {:?}", args.cmd.get(0)))?;

    // Choose an ABI "ceiling". Best-effort will degrade on older kernels by default.
    let abi = ABI::V6;

    // Access sets implementing your CLI semantics (note: AccessFs::from_write contains a broad set
    // of "write-ish" operations like create/remove/rename/truncate depending on ABI). 
    let access_ro: BitFlags<AccessFs> = make_bitflags!(AccessFs::{ ReadFile | ReadDir });
    let access_rox: BitFlags<AccessFs> = access_ro | AccessFs::Execute;
    let access_rw: BitFlags<AccessFs> = access_ro | AccessFs::from_write(abi);
    let access_rwx: BitFlags<AccessFs> = access_rw | AccessFs::Execute;

    // Collect and merge rules by (path -> union of requested rights).
    // BTreeMap gives deterministic ordering.
    let mut allow: BTreeMap<PathBuf, BitFlags<AccessFs>> = BTreeMap::new();

    // User-specified rules must exist.
    for p in args.ro {
        add_allow_path(&mut allow, p, access_ro, true)?;
    }
    for p in args.rox {
        add_allow_path(&mut allow, p, access_rox, true)?;
    }
    for p in args.rw {
        add_allow_path(&mut allow, p, access_rw, true)?;
    }
    for p in args.rwx {
        add_allow_path(&mut allow, p, access_rwx, true)?;
    }

    // Always allow executing the command itself (file rule).
    add_allow_path(
        &mut allow,
        cmd_path.clone(),
        make_bitflags!(AccessFs::{ Execute | ReadFile }),
        true,
    )?;

    // If it's a script with #! shebang, allow executing the interpreter too.
    if let Some(interp) = shebang_interpreter(&cmd_path)? {
        add_allow_path(
            &mut allow,
            interp,
            make_bitflags!(AccessFs::{ Execute | ReadFile }),
            true,
        )?;
    }

    // --libs: add a minimal set of common glibc/ld.so locations.
    // These are "best effort": missing paths are ignored.
    if args.libs {
        // Common library roots (also covers the dynamic loader on most distros).
        // Use RO+X so the loader can be executed even if it lives under these trees.
        for p in [
            "/lib",
            "/lib64",
            "/usr/lib",
            "/usr/lib64",
            "/usr/local/lib",
            "/usr/local/lib64",
        ] {
            add_allow_path(&mut allow, PathBuf::from(p), access_rox, false)?;
        }

        // ld.so configuration files/directories are read by the loader.
        for p in ["/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d"] {
            add_allow_path(&mut allow, PathBuf::from(p), access_ro, false)?;
        }
    }

    if args.resolve_libs {
        let (trace_prog, trace_argv) = build_trace_command(&cmd_path, &cmd_argv)?;

        // 1) Allow the ELF interpreter for the traced program (dynamic loader), if any.
        if let Some(interp) = elf_interpreter(&trace_prog)? {
            add_allow_path(
                &mut allow,
                interp,
                make_bitflags!(AccessFs::{ Execute | ReadFile }),
                true,
            )?;
        }

        // 2) Resolve actual libs and allow them read-only.
        let used = resolve_used_shared_objects(&trace_prog, &trace_argv)
            .context("failed to resolve used shared libraries")?;

        for p in ["/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d"] {
            add_allow_path(&mut allow, PathBuf::from(p), access_ro, false)?;
        }

        for so in used {
            add_allow_path(
                &mut allow,
                so,
                make_bitflags!(AccessFs::{ ReadFile }),
                true,
            )?;
        }
    }

    if args.debug {
        debug_dump_allowlist(&allow);
    }

    // Build + enforce the Landlock ruleset.
    let status = enforce_landlock(abi, &allow).context("failed to enforce Landlock")?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => {}
        RulesetStatus::PartiallyEnforced => {
            eprintln!(
                "warning: Landlock is only partially enforced (best-effort fallback): {:?}",
                status
            );
        }
        RulesetStatus::NotEnforced => {
            bail!("Landlock is not enforced on this system: {:?}", status);
        }
    }

    // Drop privileges (if requested) AFTER Landlock is enforced.
    if let Some(info) = user_info {
        drop_privileges(&info).context("failed to drop privileges")?;
    }

    // Exec the target.
    execv(&cmd_path, &cmd_argv)
}

fn build_trace_command(cmd_path: &Path, cmd_argv: &[OsString]) -> Result<(PathBuf, Vec<OsString>)> {
    // If cmd is a script with shebang, the kernel actually executes the interpreter.
    // To match runtime behavior, trace the interpreter with argv = [interp, script, args...].
    if let Some(interp) = shebang_interpreter(cmd_path)? {
        let mut argv: Vec<OsString> = Vec::with_capacity(cmd_argv.len() + 1);
        argv.push(interp.as_os_str().to_os_string()); // argv[0] = interpreter
        argv.push(cmd_path.as_os_str().to_os_string()); // argv[1] = script path
        argv.extend_from_slice(&cmd_argv[1..]); // rest
        Ok((interp, argv))
    } else {
        Ok((cmd_path.to_path_buf(), cmd_argv.to_vec()))
    }
}

fn elf_interpreter(path: &Path) -> Result<Option<PathBuf>> {
    use goblin::elf::Elf;
    use std::fs;

    let data = fs::read(path)?;
    match Elf::parse(&data) {
        Ok(elf) => Ok(elf.interpreter.map(PathBuf::from)),
        Err(_) => Ok(None), // not an ELF (might be script), ignore
    }
}

fn resolve_used_shared_objects(prog: &Path, argv: &[OsString]) -> Result<Vec<PathBuf>> {
    // This is essentially what ldd does: run the dynamic loader in trace mode.
    // Safe enough here because you only run trusted executables.
    let mut cmd = std::process::Command::new(prog);
    cmd.args(&argv[1..]);
    cmd.env("LD_TRACE_LOADED_OBJECTS", "1");
    // Optional but often useful to avoid surprises:
    // cmd.env("LD_BIND_NOW", "1");

    let out = cmd.output().with_context(|| format!("failed to execute trace for {}", prog.display()))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        bail!(
            "library trace failed (exit {}):\nstdout:\n{}\nstderr:\n{}",
            out.status, stdout, stderr
        );
    }

    let mut paths: Vec<PathBuf> = Vec::new();
    let text = {
        let mut t = String::new();
        t.push_str(&String::from_utf8_lossy(&out.stdout));
        t.push('\n');
        t.push_str(&String::from_utf8_lossy(&out.stderr));
        t
    };

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Common ldd/trace formats:
        //   libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x...)
        //   /lib64/ld-linux-x86-64.so.2 (0x...)
        //   linux-vdso.so.1 (0x...)   [ignore: not a real filesystem path]
        if let Some(idx) = line.find("=>") {
            let rhs = line[idx + 2..].trim();
            if rhs.starts_with("not found") {
                continue;
            }
            // Take the first whitespace-delimited token after =>
            if let Some(tok) = rhs.split_whitespace().next() {
                if tok.starts_with('/') {
                    paths.push(PathBuf::from(tok));
                }
            }
        } else {
            // Take the first token; if it’s an absolute path, keep it.
            if let Some(tok) = line.split_whitespace().next() {
                if tok.starts_with('/') {
                    paths.push(PathBuf::from(tok));
                }
            }
        }
    }

    // Canonicalize + dedup (best effort).
    let mut canon: Vec<PathBuf> = Vec::new();
    for p in paths {
        let p = std::fs::canonicalize(&p).unwrap_or(p);
        if std::fs::metadata(&p).is_ok() {
            canon.push(p);
        }
    }
    canon.sort();
    canon.dedup();
    Ok(canon)
}

fn add_allow_path(
    map: &mut BTreeMap<PathBuf, BitFlags<AccessFs>>,
    path: PathBuf,
    access: BitFlags<AccessFs>,
    must_exist: bool,
) -> Result<()> {
    if must_exist {
        std::fs::metadata(&path)
            .with_context(|| format!("path does not exist: {}", path.display()))?;
    } else if std::fs::metadata(&path).is_err() {
        // best-effort: ignore missing paths for --libs
        return Ok(());
    }

    map.entry(path)
        .and_modify(|a| *a |= access)
        .or_insert(access);
    Ok(())
}

fn debug_dump_allowlist(allow: &BTreeMap<PathBuf, BitFlags<AccessFs>>) {
    eprintln!("locked-run-as-user: allowed paths ({} entries):", allow.len());
    for (p, a) in allow.iter() {
        eprintln!("  {:?}  {}", a, p.display());
    }
}

fn enforce_landlock(abi: ABI, allow: &BTreeMap<PathBuf, BitFlags<AccessFs>>) -> Result<landlock::RestrictionStatus> {
    // Handle all filesystem rights defined by the chosen ABI ceiling.
    // Anything not explicitly allowed by rules will be denied for handled rights.
    let handled = AccessFs::from_all(abi);

    let ruleset = Ruleset::default()
        .handle_access(handled)
        .context("handle_access failed")?
        .create()
        .context("ruleset create failed")?;

    let ruleset = ruleset.add_rules(allow.iter().map(|(p, a)| {
        build_path_rule(p, *a, abi).with_context(|| format!("failed to build rule for {}", p.display()))
    }))?;

    let status = ruleset.restrict_self().context("restrict_self failed")?;
    Ok(status)
}

fn build_path_rule(path: &Path, access: BitFlags<AccessFs>, abi: ABI) -> Result<PathBeneath<PathFd>> {
    let meta = std::fs::metadata(path)?;

    // If the path is not a directory, keep only file-legal rights.
    // AccessFs::from_file() is designed exactly for this. 
    let mut allowed = access;
    if !meta.is_dir() {
        allowed &= AccessFs::from_file(abi);
    }

    if allowed.is_empty() {
        bail!("no applicable Landlock rights for {}", path.display());
    }

    // PathFd opens with O_PATH | O_CLOEXEC. 
    let fd = PathFd::new(path)?;
    Ok(PathBeneath::new(fd, allowed))
}

fn resolve_command(cmd: &[OsString]) -> Result<(PathBuf, Vec<OsString>)> {
    let arg0 = cmd
        .get(0)
        .ok_or_else(|| anyhow!("missing command"))?
        .clone();

    let has_slash = arg0.as_os_str().as_bytes().contains(&b'/');
    let resolved = if has_slash {
        let p = PathBuf::from(&arg0);
        // Canonicalize when possible (absolute, resolves symlinks).
        std::fs::canonicalize(&p).unwrap_or(p)
    } else {
        which_in_path(&arg0)?
    };

    let mut argv = cmd.to_vec();
    argv[0] = resolved.as_os_str().to_os_string();
    Ok((resolved, argv))
}

fn which_in_path(cmd: &OsString) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let path = std::env::var_os("PATH").ok_or_else(|| anyhow!("PATH is not set"))?;
    for dir in std::env::split_paths(&path) {
        let cand = dir.join(cmd);
        if let Ok(md) = std::fs::metadata(&cand) {
            if md.is_file() && (md.permissions().mode() & 0o111) != 0 {
                return Ok(std::fs::canonicalize(&cand).unwrap_or(cand));
            }
        }
    }
    bail!("command {:?} not found in PATH", cmd)
}

fn shebang_interpreter(path: &Path) -> Result<Option<PathBuf>> {
    use std::io::Read;

    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Ok(None),
    };

    let mut buf = [0u8; 4096];
    let n = f.read(&mut buf).unwrap_or(0);
    if n < 2 || &buf[..2] != b"#!" {
        return Ok(None);
    }

    let line_end = buf[..n]
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(n);

    let mut line = &buf[2..line_end];
    while !line.is_empty() && line[0].is_ascii_whitespace() {
        line = &line[1..];
    }
    if line.is_empty() {
        return Ok(None);
    }

    let interp = line
        .split(|b| b.is_ascii_whitespace())
        .next()
        .unwrap_or(&[]);

    if interp.is_empty() {
        return Ok(None);
    }

    let interp_os = OsString::from_vec(interp.to_vec());
    let interp_path = PathBuf::from(interp_os);
    if interp_path.is_absolute() {
        Ok(Some(interp_path))
    } else {
        Ok(None)
    }
}

fn resolve_user(spec: &str) -> Result<UserInfo> {
    // Require root if we want to change identity to someone else.
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        bail!("--user requires running as root (current euid = {})", euid);
    }

    if let Ok(uid) = spec.parse::<u32>() {
        let (name, gid) = passwd_by_uid(uid as libc::uid_t)?;
        let groups = supplementary_groups(&name, gid)?;
        Ok(UserInfo {
            name,
            uid: uid as libc::uid_t,
            gid,
            groups,
        })
    } else {
        let name = CString::new(spec).context("username contains NUL byte")?;
        let (uid, gid) = passwd_by_name(&name)?;
        let groups = supplementary_groups(&name, gid)?;
        Ok(UserInfo { name, uid, gid, groups })
    }
}

fn pw_buf_size() -> usize {
    // Fallback if sysconf returns indeterminate.
    let n = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    if n <= 0 {
        16384
    } else {
        n as usize
    }
}

fn passwd_by_name(name: &CString) -> Result<(libc::uid_t, libc::gid_t)> {
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0u8; pw_buf_size()];

    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };

    if rc != 0 {
        return Err(std::io::Error::from_raw_os_error(rc)).context("getpwnam_r failed");
    }
    if result.is_null() {
        bail!("no such user: {:?}", name);
    }

    Ok((pwd.pw_uid, pwd.pw_gid))
}

fn passwd_by_uid(uid: libc::uid_t) -> Result<(CString, libc::gid_t)> {
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0u8; pw_buf_size()];

    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };

    if rc != 0 {
        return Err(std::io::Error::from_raw_os_error(rc)).context("getpwuid_r failed");
    }
    if result.is_null() {
        bail!("no passwd entry for uid {}", uid);
    }

    let pw_name = unsafe { CStr::from_ptr(pwd.pw_name) };
    let name = CString::new(pw_name.to_bytes()).context("pw_name contains NUL?")?;
    Ok((name, pwd.pw_gid))
}

fn supplementary_groups(user: &CString, primary_gid: libc::gid_t) -> Result<Vec<libc::gid_t>> {
    // Start with a reasonable buffer and grow if needed. (getgrouplist returns -1 if too small.) 
    let mut ngroups: libc::c_int = 16;
    let mut groups: Vec<libc::gid_t> = vec![0; ngroups as usize];

    loop {
        let mut n = ngroups;
        let rc = unsafe {
            libc::getgrouplist(
                user.as_ptr(),
                primary_gid,
                groups.as_mut_ptr(),
                &mut n,
            )
        };

        if rc >= 0 {
            groups.truncate(n as usize);
            groups.sort_unstable();
            groups.dedup();
            return Ok(groups);
        }

        if n <= 0 {
            bail!("getgrouplist failed for user {:?}", user);
        }

        ngroups = n;
        groups.resize(ngroups as usize, 0);
    }
}

fn drop_privileges(info: &UserInfo) -> Result<()> {
    // Apply supplementary groups before dropping uid.
    let rc = unsafe { libc::setgroups(info.groups.len(), info.groups.as_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("setgroups failed");
    }

    // Set real/effective/saved IDs to prevent regaining privilege.
    if unsafe { libc::setresgid(info.gid, info.gid, info.gid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("setresgid failed");
    }
    if unsafe { libc::setresuid(info.uid, info.uid, info.uid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("setresuid failed");
    }

    Ok(())
}

fn execv(cmd: &Path, argv: &[OsString]) -> Result<()> {
    let cmd_c = CString::new(cmd.as_os_str().as_bytes())
        .with_context(|| format!("command path contains NUL: {}", cmd.display()))?;

    let mut c_argv: Vec<CString> = Vec::with_capacity(argv.len());
    for a in argv {
        let c = CString::new(a.as_os_str().as_bytes())
            .context("argument contains NUL byte")?;
        c_argv.push(c);
    }

    // execv expects *const *const c_char
    let mut ptrs: Vec<*const libc::c_char> = c_argv
        .iter()
        .map(|s| s.as_ptr() as *const libc::c_char)
        .collect();
    ptrs.push(std::ptr::null());

    unsafe {
        libc::execv(cmd_c.as_ptr(), ptrs.as_ptr());
    }

    Err(std::io::Error::last_os_error()).context("execv failed")
}

