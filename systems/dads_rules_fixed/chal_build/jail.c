// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2022 Google LLC.
 */

#define _GNU_SOURCE

#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/mount.h>
#include <linux/securebits.h>

static pid_t child_pid;
static int sockpair[2];

static void perror_exit(char *msg)
{
	perror(msg);
	exit(1);
}

static void wait_pid_terminate(pid_t pid)
{
	while (true) {
		int wstatus;
		pid_t w = waitpid(pid, &wstatus, WUNTRACED | WCONTINUED);

		if (w < 0) {
			if (errno == ERESTART || errno == EINTR)
				continue;
			perror_exit("waitpid");
		}

		if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus))
		 	break;
	}
}

static void parent(void)
{
	int child_pidfd, tmpfd;
	pid_t grandchild_pid;
	char c = 'c';

	if (unshare(CLONE_NEWNS))
		perror_exit("unshare");

	if (mount("tmpfs", "/run", "tmpfs", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL))
		perror_exit("mount");

	if (mkdir("/run/netns", 0755) && errno != EEXIST)
		perror_exit("mkdir");

	tmpfd = open("/run/netns/jail", O_RDONLY|O_CREAT|O_EXCL|O_CLOEXEC, 000);
	if (tmpfd < 0)
		perror_exit("open");
	close(tmpfd);

	child_pidfd = syscall(SYS_pidfd_open, child_pid, 0);
	if (child_pidfd < 0)
		perror_exit("pidfd_open");

	if (recv(sockpair[0], &c, 1, 0) < 0)
		perror_exit("recv");

	grandchild_pid = fork();
	if (grandchild_pid < 0)
		perror_exit("fork");
	if (!grandchild_pid) {
		if (setns(child_pidfd, CLONE_NEWNET))
			perror_exit("setns");
		if (mount("/proc/self/ns/net", "/run/netns/jail", NULL, MS_BIND, NULL))
			perror_exit("mount");

		// Writing to /proc/self/* requires we have CAP_SYS_ADMIN in the
		// target userns, but we only get CAP_SYS_ADMIN in a child
		// userns if we have that capability ourselves.
		if (prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS | SECBIT_NO_SETUID_FIXUP))
			perror_exit("prctl");

		// Writing to /proc/self/* requires we are on the same EUID/EGID
		// as the process that created the userns.
		if (setresgid(1000, 1000, 1000))
			perror_exit("setresgid");
		if (setgroups(0, NULL))
			perror_exit("setgroups");
		if (setresuid(1000, 1000, 1000))
			perror_exit("setresuid");

		// setresuid/gid sets this to 0, in which case we won't be able
		// to write to /proc/self/*
		if (prctl(PR_SET_DUMPABLE, 1))
			perror_exit("prctl");

		if (setns(child_pidfd, CLONE_NEWUSER))
			perror_exit("setns");

#define WRITEFILE(path, data) do {					\
	int fd = open(path, O_WRONLY|O_CLOEXEC);			\
	if (fd < 0)							\
		perror_exit(path);					\
	if (write(fd, data, sizeof(data) - 1) != sizeof(data) - 1)	\
		perror_exit("write");					\
	close(fd);							\
} while (0)

		WRITEFILE("/proc/self/uid_map", "0 1000 1");
		WRITEFILE("/proc/self/setgroups", "deny");
		WRITEFILE("/proc/self/gid_map", "0 1000 1");

		if (send(sockpair[0], &c, 1, 0) < 0)
			perror_exit("send");

		_exit(0);
	}
	wait_pid_terminate(grandchild_pid);

	grandchild_pid = fork();
	if (grandchild_pid < 0)
		perror_exit("fork");
	if (!grandchild_pid) {
		execl("/bin/bash", "bash", "/home/user/setup.sh", NULL);
		perror_exit("execl");
	}
	wait_pid_terminate(grandchild_pid);

	if (send(sockpair[0], &c, 1, 0) < 0)
		perror_exit("send");
	wait_pid_terminate(child_pid);
}

static void child(void)
{
	pid_t grandchild_pid;
	int procfs_fd, sysfs_fd;
	char c = 'c';

	// Mount tables changed here are locked by the child userns
	if (unshare(CLONE_NEWNS))
		perror_exit("unshare");

	// We dont want the jail to see the global /proc and /sys, so we could
	// either unmount it or overmount it. We cannot unmunt after
	// CLONE_NEWUSER because the mount becomes locked, and doing an
	// overmount after CLONE_NEWUSER is moot because that's reversible.
	// We'd do it before. However, doing either causes what's known as
	// "overmount protection". See explanation at:
	// https://bugs.chromium.org/p/chromium/issues/detail?id=1087937#c14
	// The relevant code is mount_too_revealing in fs/namespace.c
	// This will make it impossible to mount a new namespaced sysfs / procfs.
	// So instead of doing that, we do a weird dance here where we save
	// an fd for this mount. and use that to calm the kernel down.
	procfs_fd = syscall(SYS_open_tree, AT_FDCWD, "/proc", OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC);
	if (procfs_fd < 0)
		perror_exit("open_tree");
	if (umount2("/proc", MNT_DETACH))
		perror_exit("umount2");

	sysfs_fd = syscall(SYS_open_tree, AT_FDCWD, "/sys", OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC);
	if (sysfs_fd < 0)
		perror_exit("open_tree");
	if (umount2("/sys", MNT_DETACH))
		perror_exit("umount2");

	if (umount2("/mnt", MNT_DETACH))
		perror_exit("umount2");

	if (setresgid(1000, 1000, 1000))
		perror_exit("setresgid");
	if (setgroups(0, NULL))
		perror_exit("setgroups");
	if (setresuid(1000, 1000, 1000))
		perror_exit("setresuid");

	if (unshare(CLONE_NEWNS|CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET))
		perror_exit("unshare");

	if (send(sockpair[1], &c, 1, 0) < 0)
		perror_exit("send");

	grandchild_pid = fork();
	if (grandchild_pid < 0)
		perror_exit("fork");
	if (grandchild_pid) {
		wait_pid_terminate(grandchild_pid);
		return;
	}

	if (recv(sockpair[1], &c, 1, 0) < 0)
		perror_exit("recv");

	if (syscall(SYS_move_mount, procfs_fd, "", AT_FDCWD, "/mnt", MOVE_MOUNT_F_EMPTY_PATH))
		perror_exit("move_mount");
	if (mount("proc", "/proc", "proc", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL))
		perror_exit("mount");
	if (umount2("/mnt", MNT_DETACH))
		perror_exit("umount2");

	if (syscall(SYS_move_mount, sysfs_fd, "", AT_FDCWD, "/mnt", MOVE_MOUNT_F_EMPTY_PATH))
		perror_exit("move_mount");
	if (mount("sysfs", "/sys", "sysfs", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL))
		perror_exit("mount");
	if (umount2("/mnt", MNT_DETACH))
		perror_exit("umount2");

	if (recv(sockpair[1], &c, 1, 0) < 0)
		perror_exit("recv");

	puts("Entering jail...");
	execl("/bin/bash", "-bash", "-i", NULL);
	perror_exit("execl");
}

static void ttyhack(void)
{
	int tty_fd;

	// Just so we own the controlling terminal, and we need to do this
	// before the jail is truly entered, in which case access to the tty
	// device is already lost.

	// Normally I'd do
	//   exec setsid cttyhack /home/user/jail 0<>"/dev/ttyS0" 1>&0 2>&0
	// but for some reason alpine's busybox doesn't have cttyhack...

	if (setsid() < 0)
		return;
	tty_fd = open("/dev/ttyS0", O_RDWR|O_CLOEXEC);
	if (tty_fd < 0)
		return;

	dup2(tty_fd, 0);
	dup2(tty_fd, 1);
	dup2(tty_fd, 2);
}

int main(int argc, char *argv[])
{
	ttyhack();

	if (mount("", "/", NULL, MS_REC|MS_PRIVATE, NULL))
		perror_exit("mount");
	if (mount("", "/proc", NULL, MS_REMOUNT|MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL))
		perror_exit("mount");

	if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, sockpair))
		perror_exit("socketpair");

	child_pid = fork();
	if (child_pid < 0)
		perror_exit("fork");
	if (child_pid)
		parent();
	else
		child();

	return 0;
}
