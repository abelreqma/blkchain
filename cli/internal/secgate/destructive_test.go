package secgate

import (
	"context"
	"strings"
	"testing"
)

func cmd(bin string, args ...string) Command { return Command{Binary: bin, Args: args} }

// Every command here is destructive and must be denied in local mode, both by
// DestructiveViolation directly and through the full Authorize pipeline.
func TestDestructiveDeniedEverySpelling(t *testing.T) {
	denied := []Command{
		// file and data destruction
		cmd("rm", "file"),
		cmd("rm", "-rf", "/"),
		cmd("/bin/rm", "-f", "x"),
		cmd("RM", "x"),
		cmd("rmdir", "d"),
		cmd("unlink", "f"),
		cmd("shred", "-u", "f"),
		cmd("shred", "-n3", "f"),
		cmd("truncate", "-s", "0", "f"),
		cmd("truncate", "-s0", "f"),
		cmd("dd", "if=/dev/zero", "of=/dev/sda"),
		cmd("dd", "if=/dev/sda", "of=out.img"),
		cmd("dd", "if=x"),
		cmd("wipe", "f"),
		cmd("srm", "f"),
		// filesystem and disk
		cmd("mkfs", "/dev/sda1"),
		cmd("mkfs.ext4", "/dev/sda1"),
		cmd("/sbin/mkfs.xfs", "-f", "/dev/sda1"),
		cmd("mke2fs", "/dev/sda1"),
		cmd("mkswap", "/dev/sda2"),
		cmd("wipefs", "-a", "/dev/sda"),
		cmd("fdisk", "/dev/sda"),
		cmd("parted", "/dev/sda", "mklabel", "gpt"),
		cmd("sgdisk", "--zap-all", "/dev/sda"),
		cmd("blkdiscard", "/dev/sda"),
		cmd("format", "c:"),
		cmd("newfs_apfs", "/dev/disk2"),
		cmd("diskutil", "eraseDisk", "APFS", "x", "disk2"),
		cmd("diskutil", "secureErase", "0", "disk2"),
		cmd("diskutil", "-v", "eraseVolume", "APFS", "x", "disk3s1"),
		cmd("diskutil", "partitionDisk", "disk2", "GPT", "APFS", "x", "100%"),
		cmd("diskutil", "zeroDisk", "disk2"),
		cmd("diskutil", "apfs", "deleteVolume", "disk3s1"),
		cmd("umount", "/mnt"),
		cmd("swapoff", "-a"),
		cmd("lvremove", "vg/lv"),
		cmd("vgremove", "vg"),
		cmd("pvremove", "/dev/sda1"),
		cmd("cryptsetup", "luksFormat", "/dev/sda1"),
		cmd("cryptsetup", "luksErase", "/dev/sda1"),
		cmd("zpool", "destroy", "tank"),
		cmd("zfs", "destroy", "tank/x"),
		// process and system control
		cmd("kill", "1"),
		cmd("kill", "-9", "1234"),
		cmd("kill", "-KILL", "1234"),
		cmd("pkill", "sshd"),
		cmd("pkill", "-f", "x"),
		cmd("killall", "nginx"),
		cmd("killall5", "-9"),
		cmd("skill", "-KILL", "user"),
		cmd("xkill"),
		cmd("shutdown", "-h", "now"),
		cmd("reboot"),
		cmd("halt"),
		cmd("poweroff"),
		cmd("telinit", "0"),
		cmd("telinit", "q"),
		cmd("init", "0"),
		cmd("init", "6"),
		cmd("init", "1"),
		cmd("systemctl", "stop", "sshd"),
		cmd("systemctl", "disable", "sshd"),
		cmd("systemctl", "disable", "--now", "sshd"),
		cmd("systemctl", "--now", "disable", "sshd"),
		cmd("systemctl", "mask", "sshd"),
		cmd("systemctl", "kill", "sshd"),
		cmd("systemctl", "poweroff"),
		cmd("systemctl", "reboot"),
		cmd("systemctl", "halt"),
		cmd("systemctl", "-H", "host", "stop", "x"),
		cmd("systemctl", "STOP", "x"),
		cmd("service", "sshd", "stop"),
		cmd("service", "sshd", "force-stop"),
		cmd("service", "sshd", "kill"),
		cmd("rc-service", "sshd", "stop"),
		cmd("launchctl", "unload", "x.plist"),
		cmd("launchctl", "bootout", "system/x"),
		cmd("launchctl", "remove", "x"),
		cmd("launchctl", "kill", "9", "x"),
		cmd("launchctl", "disable", "system/x"),
		cmd("initctl", "stop", "x"),
		// accounts and credentials
		cmd("passwd"),
		cmd("passwd", "root"),
		cmd("chpasswd"),
		cmd("userdel", "-r", "bob"),
		cmd("usermod", "-L", "bob"),
		cmd("deluser", "bob"),
		cmd("groupdel", "g"),
		cmd("gpasswd", "-d", "bob", "g"),
		cmd("useradd", "eve"),
		cmd("adduser", "eve"),
		cmd("groupadd", "g"),
		cmd("groupmod", "-n", "h", "g"),
		cmd("chsh", "-s", "/bin/x", "bob"),
		cmd("vipw"),
		cmd("sysadminctl", "-deleteUser", "bob"),
		cmd("dscl", ".", "-delete", "/Users/bob"),
		cmd("dscl", ".", "delete", "/Users/bob"),
		cmd("dscl", ".", "-create", "/Users/eve"),
		cmd("dscl", ".", "-passwd", "/Users/bob", "x"),
		// attributes and recursive ownership/permission changes
		cmd("chattr", "+i", "f"),
		cmd("chattr", "-i", "f"),
		cmd("chmod", "-R", "777", "/etc"),
		cmd("chmod", "-R", "777", "/"),
		cmd("chmod", "-r", "000", "/etc"),
		cmd("chmod", "-Rf", "777", "/etc"),
		cmd("chmod", "-fR", "777", "/etc"),
		cmd("chmod", "-vR", "777", "/etc"),
		cmd("chmod", "--recursive", "777", "/etc"),
		cmd("chmod", "--recur", "777", "/etc"),
		cmd("chmod", "--recursive=x", "777", "/etc"),
		cmd("chmod", "777", "/etc", "-R"),
		cmd("chmod", "-R", "777", "../../etc"),
		cmd("chmod", "-R", "777", "a/../../etc"),
		cmd("chmod", "-R", "u+w", "ok", "/etc"),
		cmd("chmod", "-R", "--", "777", "/etc"),
		cmd("chown", "-R", "bob", "/etc"),
		cmd("chown", "-R", "bob:bob", "/home"),
		cmd("chown", "--recursive", "bob", "/var"),
		cmd("chown", "-hR", "bob", "/var"),
		cmd("chgrp", "-R", "staff", "/usr"),
		cmd("/bin/chmod", "-R", "777", "/etc"),
		// package removal
		cmd("apt", "remove", "x"),
		cmd("apt", "purge", "x"),
		cmd("apt", "autoremove"),
		cmd("apt", "autopurge"),
		cmd("apt", "-y", "remove", "x"),
		cmd("apt", "-o", "Dpkg::Options=x", "remove", "x"),
		cmd("apt", "install", "--purge", "x"),
		cmd("apt", "install", "--auto-remove", "x"),
		cmd("apt", "install", "curl", "sudo-"),
		cmd("apt-get", "remove", "x"),
		cmd("apt-get", "purge", "x"),
		cmd("apt-get", "autoremove", "-y"),
		cmd("aptitude", "purge", "x"),
		cmd("yum", "remove", "x"),
		cmd("yum", "erase", "x"),
		cmd("yum", "autoremove"),
		cmd("dnf", "remove", "x"),
		cmd("dnf", "rm", "x"),
		cmd("dnf", "erase", "x"),
		cmd("dnf", "-y", "autoremove"),
		cmd("apk", "del", "x"),
		cmd("apk", "-v", "del", "x"),
		cmd("pacman", "-R", "x"),
		cmd("pacman", "-Rs", "x"),
		cmd("pacman", "-Rns", "x"),
		cmd("pacman", "-Rdd", "x"),
		cmd("pacman", "--remove", "x"),
		cmd("zypper", "remove", "x"),
		cmd("zypper", "rm", "x"),
		cmd("rpm", "-e", "x"),
		cmd("rpm", "-ev", "x"),
		cmd("rpm", "-evh", "x"),
		cmd("rpm", "--erase", "x"),
		cmd("rpm", "--erase=x"),
		cmd("dpkg", "-r", "x"),
		cmd("dpkg", "-P", "x"),
		cmd("dpkg", "--remove", "x"),
		cmd("dpkg", "--purge", "x"),
		cmd("brew", "uninstall", "x"),
		cmd("brew", "remove", "x"),
		cmd("snap", "remove", "x"),
		cmd("flatpak", "uninstall", "x"),
		cmd("pip", "uninstall", "x"),
		cmd("pip3", "uninstall", "-y", "x"),
		cmd("npm", "uninstall", "x"),
		cmd("gem", "uninstall", "x"),
		// log and history truncation, in-place edits, mass deletion
		cmd("logrotate", "-f", "/etc/logrotate.conf"),
		cmd("logrotate", "-fv", "/etc/logrotate.conf"),
		cmd("logrotate", "--force", "/etc/logrotate.conf"),
		cmd("journalctl", "--vacuum-size=1M"),
		cmd("journalctl", "--vacuum-time", "1s"),
		cmd("journalctl", "--rotate"),
		cmd("dmesg", "-C"),
		cmd("dmesg", "-c"),
		cmd("dmesg", "--clear"),
		cmd("dmesg", "--read-clear"),
		cmd("crontab", "-r"),
		cmd("crontab", "-ir"),
		cmd("sed", "-i", "s/a/b/", "f"),
		cmd("sed", "-i.bak", "s/a/b/", "f"),
		cmd("sed", "-ni", "p", "f"),
		cmd("sed", "-Ei", "s/a/b/", "f"),
		cmd("sed", "--in-place", "s/a/b/", "f"),
		cmd("sed", "--in-place=.bak", "s/a/b/", "f"),
		cmd("sed", "--in", "s/a/b/", "f"),
		cmd("rsync", "-a", "--delete", "a/", "b/"),
		cmd("rsync", "-a", "--delete-after", "a/", "b/"),
		cmd("rsync", "-a", "--remove-source-files", "a/", "b/"),
		// firewall flush
		cmd("iptables", "-F"),
		cmd("iptables", "-t", "nat", "-F"),
		cmd("iptables", "--flush"),
		cmd("iptables", "-X"),
		cmd("iptables", "-P", "INPUT", "DROP"),
		cmd("ip6tables", "-F"),
		cmd("nft", "flush", "ruleset"),
		cmd("ufw", "disable"),
		cmd("ufw", "reset"),
	}
	for _, c := range denied {
		if err := DestructiveViolation(c); err == nil {
			t.Errorf("DestructiveViolation must deny %v", c)
		}
		// A fresh gate per command keeps the episode command cap out of the result.
		g := localGate(t, "local\n")
		var actions []string
		g.Audit = func(a, d string) { actions = append(actions, a) }
		if d := g.Authorize(context.Background(), c); d.Allowed {
			t.Errorf("Authorize must deny %v in local mode", c)
		} else if len(actions) != 1 || actions[0] != "deny:destructive" {
			t.Errorf("%v must be denied by the destructive layer, audit = %v (%q)", c, actions, d.Reason)
		}
	}
}

// The safe forms of dual-use binaries stay allowed in local mode.
func TestDestructiveAllowsSafeForms(t *testing.T) {
	allowed := []Command{
		cmd("chmod", "644", "file"),
		cmd("chmod", "u+x", "script.sh"),
		cmd("chmod", "-x", "file"),
		cmd("chmod", "-v", "644", "a/b"),
		cmd("chown", "bob", "file"),
		cmd("chgrp", "staff", "file"),
		cmd("chmod", "-R", "755", "."),
		cmd("chmod", "-R", "755", "sub/dir"),
		cmd("systemctl", "status", "sshd"),
		cmd("systemctl", "show", "sshd"),
		cmd("systemctl", "list-units"),
		cmd("systemctl", "list-unit-files", "--type=service"),
		cmd("systemctl", "is-active", "sshd"),
		cmd("systemctl", "cat", "sshd"),
		cmd("service", "sshd", "status"),
		cmd("service", "--status-all"),
		cmd("apt", "list", "--installed"),
		cmd("apt", "show", "curl"),
		cmd("apt", "search", "curl"),
		cmd("apt-get", "install", "curl"),
		cmd("apt-cache", "policy", "curl"),
		cmd("dpkg", "-l"),
		cmd("dpkg", "-L", "curl"),
		cmd("dpkg", "-s", "curl"),
		cmd("dpkg", "--list"),
		cmd("rpm", "-qa"),
		cmd("rpm", "-qi", "curl"),
		cmd("rpm", "-ql", "curl"),
		cmd("yum", "list", "installed"),
		cmd("dnf", "info", "curl"),
		cmd("apk", "info"),
		cmd("pacman", "-Q"),
		cmd("pacman", "-Qi", "curl"),
		cmd("pacman", "-Ss", "curl"),
		cmd("zypper", "search", "curl"),
		cmd("brew", "list"),
		cmd("pip", "list"),
		cmd("launchctl", "list"),
		cmd("diskutil", "list"),
		cmd("diskutil", "info", "disk0"),
		cmd("dscl", ".", "-list", "/Users"),
		cmd("dscl", ".", "-read", "/Users/bob"),
		cmd("iptables", "-L", "-n"),
		cmd("iptables", "-S"),
		cmd("nft", "list", "ruleset"),
		cmd("ufw", "status"),
		cmd("journalctl", "-u", "sshd"),
		cmd("dmesg"),
		cmd("crontab", "-l"),
		cmd("logrotate", "-d", "/etc/logrotate.conf"),
		cmd("sed", "-n", "p", "file"),
		cmd("sed", "-e", "s/a/b/", "file"),
		cmd("sed", "-E", "s/a/b/", "file"),
		cmd("rsync", "-a", "a/", "b/"),
		cmd("iptables-save"),
		cmd("lvs"),
		cmd("ls", "-la", "/etc"),
		cmd("cat", "/etc/passwd"),
		cmd("id"),
		cmd("ps", "aux"),
		cmd("uname", "-a"),
		cmd("cp", "a", "b"),
	}
	for _, c := range allowed {
		if err := DestructiveViolation(c); err != nil {
			t.Errorf("DestructiveViolation must allow %v: %v", c, err)
		}
		g := localGate(t, "local\n")
		if d := g.Authorize(context.Background(), c); !d.Allowed {
			t.Errorf("Authorize must allow %v in local mode: %q", c, d.Reason)
		}
	}
}

func TestDestructiveViolationTrickyCases(t *testing.T) {
	cases := []struct {
		c    Command
		deny bool
	}{
		{cmd("chmod", "-R", "777", "/etc"), true},
		{cmd("chmod", "644", "file"), false},
		{cmd("chmod", "-R", "644", "rel/dir"), false},
		{cmd("dd", "if=/dev/sda", "of=out.img"), true},
		{cmd("systemctl", "stop", "x"), true},
		{cmd("systemctl", "status", "x"), false},
		{cmd("apt", "remove", "x"), true},
		{cmd("apt", "list"), false},
		{cmd("init", "6"), true},
		{cmd("init", "3"), false},
		{cmd("mkfs.btrfs", "/dev/x"), true},
		{cmd("  rm  ", "x"), true},
		{cmd("", "x"), false},
	}
	for _, tc := range cases {
		err := DestructiveViolation(tc.c)
		if tc.deny && err == nil {
			t.Errorf("must deny %v", tc.c)
		}
		if !tc.deny && err != nil {
			t.Errorf("must allow %v: %v", tc.c, err)
		}
	}
}

// The denial is audited as deny:destructive and names the binary.
func TestDestructiveDenialIsAudited(t *testing.T) {
	var actions, details []string
	g := localGate(t, "local\n")
	g.Audit = func(a, d string) { actions = append(actions, a); details = append(details, d) }
	d := g.Authorize(context.Background(), cmd("rm", "-rf", "x"))
	if d.Allowed {
		t.Fatal("rm must be denied")
	}
	if len(actions) != 1 || actions[0] != "deny:destructive" {
		t.Fatalf("audit actions = %v, want [deny:destructive]", actions)
	}
	if !strings.Contains(d.Reason, "rm") {
		t.Errorf("reason %q must name the binary", d.Reason)
	}
}

// The destructive denylist runs only in the local profile. The external
// profile is unchanged: a destructive binary that an operator put on the
// allowlist is not denied by this layer.
func TestDestructiveNotAppliedInExternalProfile(t *testing.T) {
	var actions []string
	g := &Gate{
		Mode:  Auto,
		Scope: okScope(t),
		Allow: NewAllowlist("rm", "kill", "apt", "chmod"),
		Audit: func(a, d string) { actions = append(actions, a) },
	}
	for _, c := range []Command{
		cmd("rm", "10.0.0.5"),
		cmd("kill", "10.0.0.5"),
		cmd("apt", "remove", "10.0.0.5"),
		cmd("chmod", "-R", "777", "/etc"),
	} {
		g.Authorize(context.Background(), c)
	}
	for _, a := range actions {
		if a == "deny:destructive" {
			t.Fatalf("external profile must not run the destructive denylist: %v", actions)
		}
	}
}
