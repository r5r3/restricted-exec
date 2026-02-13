# restricted-exec

A secure command execution wrapper that applies multiple security restrictions to launched executables using Linux security features including Landlock, seccomp, capabilities, and user namespace isolation.

---

⚠️ **EARLY DEVELOPMENT WARNING** ⚠️

This tool is in an **early development stage** and is **not ready for production use**. The API, behavior, security guarantees, and all aspects of the implementation may change significantly in future versions. Use only for testing and development purposes.

## Features

- **Landlock filesystem sandboxing**: Restrict filesystem access to explicitly allowed paths
- **Network restrictions**: Control TCP connect/bind operations by port
- **Seccomp syscall filtering**: Block dangerous syscalls
- **Capability dropping**: Remove Linux capabilities
- **User privilege dropping**: Run as different user with proper group membership
- **Automatic library resolution**: Detect and allowlist required shared libraries
- **Abstract UNIX socket scoping**: Restrict abstract socket access (Landlock ABI v6+)

## Installation

### From Source

```bash
git clone https://github.com/r5r3/restricted-exec.git
cd restricted-exec
cargo build --release
sudo cp target/release/restricted-exec /usr/local/bin/
```

### Requirements

- Linux kernel ≥ 5.13 (for full Landlock ABI v6 features)
- Root privileges for user switching and capability operations
- Landlock-enabled kernel (CONFIG_SECURITY_LANDLOCK=y)
- Seccomp support

## Usage

```bash
restricted-exec [OPTIONS] -- COMMAND [ARGS]...
```

## Options

### Basic Restrictions

- `--user USER`: Run as specified user (name or UID). When this option is used, restricted-exec performs NSS lookups to resolve the user's UID, GID, and supplementary groups, then drops privileges to that user after applying all security restrictions. Requires root privileges.

- `--ro PATH`: Allow read-only access to PATH. This grants Landlock ReadFile and ReadDir access rights, permitting the process to read file contents and directory listings but not modify anything.

- `--rox PATH`: Allow read+execute access to PATH. Grants ReadFile, ReadDir, and Execute access rights. Suitable for directories containing executables or libraries that need to be both read and executed.

- `--rw PATH`: Allow read+write access to PATH. Grants read access plus write permissions (WriteFile access right). Allows modifying files and creating new files in directories.

- `--rwx PATH`: Allow read+write+execute access to PATH. Grants all filesystem access rights: ReadFile, ReadDir, WriteFile, and Execute. Provides full access to the specified path.

### Library Handling

- `--default-libs`: Allow access to common system library directories (/lib, /lib64, /usr/lib, /usr/lib64, etc.) and LD configuration files (/etc/ld.so.cache, /etc/ld.so.conf). This provides basic support for dynamically linked executables without explicit library resolution.

- `--resolve-libs`: Automatically detect and allowlist required shared libraries by running the command with LD_TRACE_LOADED_OBJECTS=1. This parses the dynamic loader output to identify all .so files needed by the executable and its dependencies, then adds them to the filesystem allowlist with read access.

- `--allow-nss`: Allow access to NSS (Name Service Switch) configuration files and modules. This includes /etc/nsswitch.conf, /etc/passwd, /etc/group, and other NSS-related files. Also allows libnss_* modules found in common library directories, enabling username/group lookups and other NSS operations.

### Network Restrictions (Landlock ABI v4+)

- `--net-allow-port PORT`: Allow outgoing TCP connections to the specified destination PORT. Repeatable to allow multiple ports. This creates Landlock rules that permit connect() syscalls to the specified ports while denying all others.

- `--net-allow-bind PORT`: Allow binding TCP sockets to the specified local PORT. Repeatable to allow multiple ports. Port 0 allows binding to the ephemeral port range (ip_local_port_range). This controls bind() syscall access.

- `--net-deny-connect`: Deny all outgoing TCP connections by handling the ConnectTcp Landlock access right without adding any allow rules. This provides a complete network egress blockade.

- `--net-deny-bind`: Deny all TCP binding operations by handling the BindTcp Landlock access right without adding any allow rules. Prevents the process from creating listening sockets.

- `--scope-abstract-unix-socket`: Scope abstract UNIX sockets to prevent connecting to abstract UNIX domain sockets created outside the Landlock domain. Requires Landlock ABI v6+. This restricts IPC communication to sockets created within the same sandbox.

### Security Features

- `--drop-caps`: Drop all Linux capabilities from the process. This removes ambient, effective, permitted, and inheritable capabilities, and drops bounding set capabilities if CAP_SETPCAP is available. This prevents the process from performing privileged operations even if it later gains root privileges.

- `--allow-new-privs`: Allow gaining new privileges via exec (disables no_new_privs). By default, restricted-exec sets no_new_privs=1 to prevent privilege escalation through setuid/setgid executables and file capabilities. Use this flag only when necessary for helpers like fusermount3 or sshfs.

- `--log-level LEVEL`: Set log level (warn, info, debug). Controls the verbosity of restricted-exec's own logging. For more detailed control, you can also set the RUST_LOG environment variable.

### Seccomp Filtering

- `--seccomp-filter ITEM`: Block syscalls by name or use predefined lists (prefixed with @). This adds syscalls to the seccomp blocklist, causing them to return EPERM when called. Supports both individual syscall names (e.g., "mount") and predefined lists (e.g., "@default").

- `--seccomp-allow ITEM`: Remove syscalls from the effective blocklist. This can be used to allow specific syscalls that would otherwise be blocked by a predefined list. For example, `--seccomp-filter @mount --seccomp-allow mount` would block all mount-related syscalls except the basic mount syscall.

**Predefined syscall lists:**
- `@default`: Docker-style "significant blocked syscalls" including dangerous operations like module loading, kernel symbol access, mount operations, ptrace, reboot, and other privileged operations. Also includes conditional rules for clone (namespace flags) and personality syscalls.

- `@mount`: Mount-related syscalls including mount, umount, pivot_root, and the new mount API syscalls (open_tree, move_mount, etc.), plus namespace helpers like unshare and setns.

## Examples

### Basic Filesystem Restriction

```bash
# Allow only /tmp read-write and execute a command
restricted-exec --rw /tmp -- ls /tmp
```

### Run as Different User

```bash
# Run as user 'nobody' with restricted filesystem access
sudo restricted-exec --user nobody --ro /etc --rox /usr/bin -- ls /etc
```

### Automatic Library Resolution

```bash
# Automatically detect required libraries for the command
restricted-exec --resolve-libs -- /usr/bin/python3 -c "import sys; print(sys.version)"
```

### Network Restrictions

```bash
# Allow only HTTPS connections and specific bind port
restricted-exec --net-allow-port 443 --net-allow-bind 8080 -- ./my_server
```

### Seccomp Filtering

```bash
# Block mount-related syscalls
restricted-exec --seccomp-filter @mount -- bash -c "mount /dev/sda1 /mnt"
```

## Implementation Details

### Library Resolution

When `--resolve-libs` is used:
1. The command is executed with `LD_TRACE_LOADED_OBJECTS=1`
2. Output is parsed to extract shared library paths
3. Libraries are added to the allowlist with read access
4. Common library directories are also allowed

### Shebang Handling

Script interpreters are automatically detected and allowed when:
1. The command is a script with `#!` shebang
2. The interpreter path is absolute
3. The interpreter is added to the allowlist

### Path Normalization

All paths are normalized:
- Existing paths: canonicalized (symlinks resolved)
- Non-existing paths: lexically cleaned (`.`, `..` removed)

## Logging

Use `--log-level` or set `RUST_LOG` environment variable:

```bash
# Debug logging
RUST_LOG=debug restricted-exec --ro /tmp -- ls /tmp

# Or use the flag
restricted-exec --log-level debug --ro /tmp -- ls /tmp
```

## Limitations

- Requires Linux kernel ≥ 5.13 for full feature set
- Landlock ABI v6 required for abstract UNIX socket scoping
- Some features require root privileges
- Seccomp rules may vary by architecture
- Library resolution requires executable to support `LD_TRACE_LOADED_OBJECTS`

## Building

```bash
cargo build --release
```

## License

Apache-2.0

## Security Considerations

- Always test restrictions thoroughly before production use
- Combine multiple security mechanisms for defense in depth
- Monitor logs for partial enforcement warnings
- Be aware that Landlock is a sandboxing mechanism, not a complete security solution

## Related Projects

- [Landrun](https://github.com/Zouuup/landrun): Very similar tool with focus only on landlock.
- [Landlock LSM](https://landlock.io/)
- [libseccomp](https://github.com/seccomp/libseccomp)
- [Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
