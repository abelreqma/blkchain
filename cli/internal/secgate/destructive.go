package secgate

import (
	"fmt"
	"strings"
)

// DestructiveViolation reports a deny error when a command performs a
// destructive action: it deletes or overwrites data, damages a filesystem or
// disk, stops or kills processes or the machine, changes accounts or
// credentials, changes attributes or ownership recursively on a system path,
// removes packages, or truncates logs. It is the destructive-action denylist of
// the LOCAL gate profile and is never called for the external profile.
//
// This is a best-effort denylist. A denylist cannot be proven complete: a
// destructive binary or flag it does not know passes. It stays enforceable
// because the command is structured argv (Task 1 keeps shells, interpreters,
// exec-wrappers, find exec predicates, and raw shell metacharacters out, so the
// binary and flags are always inspectable) and it is backstopped by the /safe
// human confirmation of every command. Known residual gaps: mv, cp, ln, tee, and
// install can overwrite a file, and chmod, chown, and chgrp on a single absolute
// path (not recursive) are allowed.
//
// Two strategies keep it consistent across spellings:
//   - a binary that is destructive in every form (rm, dd, mkfs.*, kill,
//     passwd, ...) is denied by base name, case-insensitively, whatever its args;
//   - a dual-use binary (chmod, systemctl, service, apt, rpm, ...) is denied
//     only for its destructive form, and its safe forms (systemctl status, apt
//     list, chmod 644 file, rpm -qa) stay allowed. Subcommands match on any
//     argument token, not only the first non-flag one, so a flag value between
//     the binary and the subcommand (apt -o X=Y remove) cannot hide it. Flags
//     match in the separate, glued, bundled, abbreviated, and =value spellings.
func DestructiveViolation(c Command) error {
	name := strings.ToLower(baseName(strings.TrimSpace(c.Binary)))
	if name == "" {
		return nil
	}
	args := c.Args
	deny := func(why string) error {
		return fmt.Errorf("%s %s (destructive action not permitted in the local profile)", name, why)
	}

	if alwaysDestructive[name] || hasDestructivePrefix(name) {
		return deny("is a destructive command")
	}
	if words, ok := destructiveWords[name]; ok {
		if w, bad := anyWord(args, words); bad {
			return deny("with " + w + " is destructive")
		}
	}
	switch name {
	case "chmod", "chown", "chgrp":
		if p, bad := recursiveSystemPath(args); bad {
			return deny("recursive on " + p + " is destructive")
		}
	case "dscl":
		for _, a := range args {
			if dsclWrite[strings.ToLower(strings.TrimLeft(a, "-"))] {
				return deny("with " + a + " modifies the directory")
			}
		}
	case "diskutil":
		for _, a := range args {
			l := strings.ToLower(a)
			for _, p := range diskutilPrefixes {
				if strings.HasPrefix(l, p) {
					return deny(a + " is destructive")
				}
			}
		}
	case "apt", "apt-get", "aptitude":
		if hasLong(args, "purge", 2) || hasLong(args, "auto-remove", 3) || hasLong(args, "autoremove", 3) {
			return deny("with a purge or auto-remove flag is destructive")
		}
		// `install pkg-` removes pkg, `install pkg_` purges it.
		for _, a := range args {
			if len(a) > 1 && a[0] != '-' && (strings.HasSuffix(a, "-") || strings.HasSuffix(a, "_")) {
				return deny("with " + a + " removes a package")
			}
		}
	case "pacman":
		if hasShort(args, "R") || hasLong(args, "remove", 3) {
			return deny("removes packages")
		}
	case "rpm":
		if hasShort(args, "e") || hasLong(args, "erase", 2) {
			return deny("erases packages")
		}
	case "dpkg":
		if hasShort(args, "rP") || hasLong(args, "remove", 3) || hasLong(args, "purge", 2) {
			return deny("removes packages")
		}
	case "logrotate":
		if hasShort(args, "f") || hasLong(args, "force", 2) {
			return deny("-f forces log rotation")
		}
	case "journalctl":
		if hasLong(args, "vacuum", 3) || hasLong(args, "rotate", 3) {
			return deny("deletes or rotates journal files")
		}
	case "dmesg":
		if hasShort(args, "cC") || hasLong(args, "clear", 3) || hasLong(args, "read-clear", 3) {
			return deny("clears the kernel log")
		}
	case "crontab":
		if hasShort(args, "r") || hasLong(args, "remove", 3) {
			return deny("-r deletes the crontab")
		}
	case "sed", "gsed":
		if hasShort(args, "i") || hasLong(args, "in-place", 2) {
			return deny("-i edits files in place")
		}
	case "rsync":
		if hasLong(args, "delete", 3) || hasLong(args, "remove-source-files", 3) || hasLong(args, "remove-sent-files", 3) {
			return deny("deletes files")
		}
	case "iptables", "ip6tables", "iptables-legacy", "ip6tables-legacy":
		if hasShort(args, "FXDPRAIENZ") ||
			hasLong(args, "flush", 2) || hasLong(args, "delete-chain", 3) || hasLong(args, "delete", 3) ||
			hasLong(args, "policy", 2) || hasLong(args, "append", 2) || hasLong(args, "insert", 2) ||
			hasLong(args, "replace", 3) || hasLong(args, "new-chain", 3) || hasLong(args, "rename-chain", 3) ||
			hasLong(args, "zero", 2) {
			return deny("changes the firewall rules")
		}
	}
	return nil
}

// alwaysDestructive are binaries denied whatever their arguments. dd is denied
// outright: of= to a device or file is destructive and the argument is hard to
// bound safely. kill is denied even for -l or -0 for simplicity.
var alwaysDestructive = set(
	// file and data destruction
	"rm", "rmdir", "unlink", "shred", "truncate", "dd", "wipe", "srm",
	// filesystems and disks
	"mke2fs", "mkswap", "mkdosfs", "mkntfs", "wipefs", "fdisk", "cfdisk", "sfdisk",
	"parted", "gdisk", "sgdisk", "blkdiscard", "format", "umount", "swapoff",
	"lvremove", "vgremove", "pvremove", "lvreduce", "vgreduce",
	// process and system control
	"kill", "pkill", "killall", "killall5", "skill", "xkill",
	"shutdown", "reboot", "halt", "poweroff", "telinit",
	// accounts and credentials
	"passwd", "chpasswd", "userdel", "usermod", "deluser", "groupdel", "gpasswd",
	"useradd", "adduser", "groupadd", "addgroup", "groupmod", "newusers",
	"chsh", "chfn", "vipw", "vigr", "sysadminctl",
	// attributes
	"chattr",
	// firewall restore replaces every rule
	"iptables-restore", "ip6tables-restore",
)

// hasDestructivePrefix matches the families mkfs, mkfs.<type>, and newfs*.
func hasDestructivePrefix(name string) bool {
	return strings.HasPrefix(name, "mkfs") || strings.HasPrefix(name, "newfs")
}

// destructiveWords maps a dual-use binary to the subcommand words that make it
// destructive. A word matches any argument token, case-insensitively.
var destructiveWords = map[string]map[string]bool{
	"init": set("0", "1", "6", "s"),
	"systemctl": set("stop", "disable", "mask", "kill", "poweroff", "reboot", "halt",
		"kexec", "suspend", "hibernate", "hybrid-sleep", "emergency", "rescue",
		"isolate", "set-default"),
	"service":    set("stop", "force-stop", "kill"),
	"rc-service": set("stop", "force-stop", "kill"),
	"initctl":    set("stop", "force-stop", "kill"),
	"launchctl":  set("unload", "bootout", "remove", "kill", "disable", "stop"),
	"apt":        set("remove", "purge", "autoremove", "autopurge", "erase"),
	"apt-get":    set("remove", "purge", "autoremove", "autopurge", "erase"),
	"aptitude":   set("remove", "purge", "autoremove", "forget-new"),
	"yum":        set("remove", "erase", "autoremove", "swap", "rollback"),
	"dnf":        set("remove", "rm", "erase", "autoremove", "swap", "rollback"),
	"dnf5":       set("remove", "rm", "erase", "autoremove", "swap", "rollback"),
	"microdnf":   set("remove", "erase"),
	"apk":        set("del", "delete"),
	"zypper":     set("remove", "rm", "purge-kernels"),
	"brew":       set("uninstall", "remove", "rm", "autoremove", "cleanup", "untap", "zap"),
	"snap":       set("remove"),
	"flatpak":    set("uninstall", "remove"),
	"pip":        set("uninstall"),
	"pip3":       set("uninstall"),
	"npm":        set("uninstall", "remove", "rm", "un", "unlink", "prune"),
	"gem":        set("uninstall"),
	"cryptsetup": set("luksformat", "erase", "lukserase", "luksremovekey", "lukskillslot", "reencrypt"),
	"zpool":      set("destroy", "labelclear"),
	"zfs":        set("destroy"),
	"nft":        set("flush", "delete", "destroy", "add", "insert", "replace", "create", "rename"),
	"ufw": set("disable", "reset", "delete", "enable", "allow", "deny", "reject", "limit",
		"insert", "route", "default", "reload"),
}

// dsclWrite are the dscl commands that change the directory (accounts,
// groups, passwords). dscl accepts them with or without a leading dash.
var dsclWrite = set("delete", "create", "change", "append", "merge", "passwd")

// diskutilPrefixes are the lowercase prefixes of diskutil verbs that erase,
// repartition, or delete.
var diskutilPrefixes = []string{
	"erase", "secureerase", "zerodisk", "randomdisk", "partition", "repartition",
	"reformat", "merge", "split", "resize", "delete",
}

func set(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

// anyWord reports the first argument token that is one of words, compared
// case-insensitively. A token that starts with '-' is a flag and never matches.
func anyWord(args []string, words map[string]bool) (string, bool) {
	for _, a := range args {
		if a != "" && a[0] != '-' && words[strings.ToLower(a)] {
			return a, true
		}
	}
	return "", false
}

// hasShort reports whether any single-dash argument (not a --long option)
// contains one of letters, so a bundled (-Rf, -fR) or glued spelling matches.
// It errs toward denial: a letter inside a glued value also matches.
func hasShort(args []string, letters string) bool {
	for _, a := range args {
		if len(a) >= 2 && a[0] == '-' && a[1] != '-' && strings.ContainsAny(a[1:], letters) {
			return true
		}
	}
	return false
}

// hasLong reports whether any --long argument names the option: an exact
// match, an abbreviation of at least min characters (getopt_long accepts an
// unambiguous prefix), a longer option that starts with name (--delete-after
// for delete), or any of these with =value. It errs toward denial.
func hasLong(args []string, name string, min int) bool {
	for _, a := range args {
		if len(a) < 3 || !strings.HasPrefix(a, "--") {
			continue
		}
		fname, _, _ := strings.Cut(a[2:], "=")
		if fname == "" {
			continue
		}
		if strings.HasPrefix(fname, name) || (len(fname) >= min && strings.HasPrefix(name, fname)) {
			return true
		}
	}
	return false
}

// recursiveSystemPath reports the first operand of a recursive chmod, chown,
// or chgrp that is an absolute path or has a ".." segment (the same bound
// pathEscapesScratch applies to file-access flags). A recursive change on a
// relative path stays inside the scratch working directory and is allowed, as
// is any non-recursive change. Tokens after "--" are operands, never flags.
func recursiveSystemPath(args []string) (string, bool) {
	var flags []string
	var operands []string
	endOpts := false
	for _, a := range args {
		switch {
		case endOpts:
			operands = append(operands, a)
		case a == "--":
			endOpts = true
		case len(a) >= 2 && a[0] == '-':
			flags = append(flags, a)
		default:
			operands = append(operands, a)
		}
	}
	// -R, and -r (a chmod mode or a mistaken recursive flag), --recursive and
	// its abbreviations.
	if !hasShort(flags, "Rr") && !hasLong(flags, "recursive", 2) {
		return "", false
	}
	for _, p := range operands {
		if pathEscapesScratch(p) {
			return p, true
		}
	}
	return "", false
}
