#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ftrace.h> // kallsyms_lookup_name()
#include <linux/uaccess.h> // copy_to_user()
#include <linux/slab.h>

#include <linux/nls.h>
#include "util.h"

MODULE_AUTHOR("codetronik");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("Anti Android Root Detector");

#define ENABLE_TARGET_PROCESS

u64 *sys_call_table;
char* selinux_enforcing;
char fakesu[] = "/system/bin/fakesu";
char sh[] = "/system/bin/sh";
char dummy_path[] = "/8suza/sumalco";

////// The prototype of these is defined in include/linux/syscall.h
typedef asmlinkage int (*_original_openat)(int dfd, const char __user *filename, int flags, umode_t mode);
_original_openat org_openat;

typedef asmlinkage int (*_original_faccessat)(int dfd, const char __user *filename, int mode);
_original_faccessat org_faccessat;

typedef asmlinkage int (*_original_fstatat)(int dfd, const char __user *filename, struct stat64 __user *statbuf, int flag);
_original_fstatat org_fstatat;

typedef asmlinkage int (*_original_fchmodat)(int dfd, const char __user * filename, umode_t mode);
_original_fchmodat org_fchmodat;

typedef asmlinkage int (*_original_fchownat)(int dfd, const char __user *filename, uid_t user, gid_t group, int flag);
_original_fchownat org_fchownat;

typedef asmlinkage ssize_t (*_original_read)(unsigned int fd, char __user *buf, size_t count);
_original_read org_read;

typedef asmlinkage int (*_original_execve)(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp);
_original_execve org_execve;

typedef asmlinkage long (*_original_write)(unsigned int fd, const char __user *buf, size_t count);
_original_write org_write;
////// end of prototype

bool is_target_process(void)
{
#ifdef ENABLE_TARGET_PROCESS	
	int i = 0;

	// set your apps
	char* targetlist[] = {
		"go.minwon", // kr.go.minwon.m
		"sbanking", // com.shinhan.sbanking
		"fel", // me.iofel.packagelist
		"aaaa", // test
	};

	for (i=0; i < sizeof(targetlist) / sizeof(targetlist[0]); i++)
	{
		if (strstr(current->comm, targetlist[i]))
		{
			return true;
	
		}
	}
#else
	if (!strstr(current->comm, "swapper"))
	{
		return true;
	}	
#endif
	return false;

}

bool is_need_hook(const char *pathname)
{
	char* blacklist[] = {
		"magisk",
		"/system/bin/su",
		"riru",
		"termux",
	};
	int i = 0;
	
	for (i=0; i < sizeof(blacklist) / sizeof(blacklist[0]); i++)
	{
		if (strstr(pathname, blacklist[i]))
		{
			return true;
		}
	}
	return false;

}

asmlinkage int hook_execve(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp)
{
	char copystr[255] = {0, };
	char user_msg[] = "please type at your shell \"setenforce 0\"";
	struct cred *cred;
	struct pt_regs *regs;
	regs = task_pt_regs(current);
	
	strncpy_from_user(copystr, filename, sizeof(copystr));			
	
	// Use when su is not installed.
	if (strstr(copystr, fakesu))
	{		
		pr_info("[execve hook] fakesu");
		cred = (struct cred *)__task_cred(current);
		memset(&cred->uid, 0, sizeof(cred->uid));
		memset(&cred->gid, 0, sizeof(cred->gid));
		memset(&cred->suid, 0, sizeof(cred->suid));
		memset(&cred->euid, 0, sizeof(cred->euid));
		memset(&cred->egid, 0, sizeof(cred->egid));
		memset(&cred->fsuid, 0, sizeof(cred->fsuid));
		memset(&cred->fsgid, 0, sizeof(cred->fsgid));
		memset(&cred->cap_inheritable, 0xff, sizeof(cred->cap_inheritable));
		memset(&cred->cap_permitted, 0xff, sizeof(cred->cap_permitted));
		memset(&cred->cap_effective, 0xff, sizeof(cred->cap_effective));
		memset(&cred->cap_bset, 0xff, sizeof(cred->cap_bset));
		memset(&cred->cap_ambient, 0xff, sizeof(cred->cap_ambient));
		if (selinux_enforcing)
		{
			*selinux_enforcing = 0; // same as "setenforce 0"	
		}
		else // 수동으로 setenforce 0 입력 필요
		{
			org_write(2, convert_to_user_string(user_msg, sizeof(user_msg)), sizeof(user_msg) - 1);
		}
		return org_execve(convert_to_user_string(sh, sizeof(sh)), argv, envp);
	}

	if (is_target_process() == false)
	{
		return org_execve(filename, argv, envp);
	}

	pr_info("[execve hook] %s(%d) %016lx %016lx %s", current->comm, task_tgid_vnr(current), regs->regs[30], regs->pc, copystr);
	
	return org_execve(filename, argv, envp);
}

asmlinkage ssize_t hook_read(unsigned int fd, char __user *buf, size_t count)
{
	char* copybuf;

	if (is_target_process() == false)
	{
		return org_read(fd, buf, count);
	}
	
	copybuf = (char*)kmalloc(count, GFP_KERNEL);	
	copy_from_user(copybuf, buf, count);
	
	// your hook code
	
	kfree(copybuf);


	return org_read(fd, buf, count);
}

asmlinkage int hook_fchownat(int dfd, const char __user *filename, uid_t user, gid_t group, int flag)
{
	return org_fchownat(dfd, filename, user, group, flag);
}


asmlinkage int hook_fchmodat(int dfd, const char __user * filename, umode_t modes)
{
	return org_fchmodat(dfd, filename, modes);
}

asmlinkage int hook_fstatat(int dfd, const char __user *filename, struct stat64 __user *statbuf, int flag)
{
	char copystr[255] = {0, };

	struct pt_regs *regs;
	regs = task_pt_regs(current);
	
	strncpy_from_user(copystr, filename, sizeof(copystr));		
	
	
	if (strstr(copystr, fakesu))
	{		
		pr_info("[fstatat hook] fakesu");
		return org_fstatat(dfd, convert_to_user_string(sh, sizeof(sh)), statbuf, flag);
	}

	if (is_target_process() == false)
	{
		return org_fstatat(dfd, filename, statbuf, flag);
	}

	if (is_need_hook(copystr) == true)
	{		
		pr_info("[fstatat hook] %s(%d) %016lx %016lx %s -> hook", current->comm, task_tgid_vnr(current), regs->regs[30], regs->pc, copystr);

		return org_fstatat(dfd, convert_to_user_string(dummy_path, sizeof(dummy_path)), statbuf, flag);		
	}
	else
	{
		pr_info("[fstatat hook] %s(%d) %016lx %016lx %s", current->comm, task_tgid_vnr(current), regs->regs[30], regs->pc, copystr);

	}

	return org_fstatat(dfd, filename, statbuf, flag);
}
asmlinkage int hook_faccessat(int dfd, const char __user *filename, int mode)
{
	char copystr[255] = {0, };

	struct pt_regs *regs;
	regs = task_pt_regs(current);

	strncpy_from_user(copystr, filename, sizeof(copystr));			
	
	if (strstr(copystr, fakesu))
	{		
		
		pr_info("[faccessat hook] fakesu");
		return org_faccessat(dfd, convert_to_user_string(sh, sizeof(sh)), mode);
	}

	if (is_target_process() == false)
	{
		return org_faccessat(dfd, filename, mode);
	}

	if (is_need_hook(copystr) == true)
	{
		
		pr_info("[faccessat hook] %s(%d) %016lx %016lx %s -> hook", current->comm, task_tgid_vnr(current), regs->regs[30], regs->pc, copystr);

		return org_faccessat(dfd, convert_to_user_string(dummy_path, sizeof(dummy_path)), mode);		
	}
	else
	{
		pr_info("[faccessat hook] %s(%d) %016lx %016lx %s", current->comm, task_tgid_vnr(current), regs->regs[30], regs->pc, copystr);

	}

	return org_faccessat(dfd, filename, mode);

}

asmlinkage int hook_openat(int dfd, const char __user *filename, int flags, umode_t mode)
{
	char copystr[255] = {0, };
	struct pt_regs *regs;
	regs = task_pt_regs(current);

	if (is_target_process() == false)
	{
		return org_openat(dfd, filename, flags, mode);
	}

	
	strncpy_from_user(copystr, filename, sizeof(copystr));		
	
	if (is_need_hook(copystr) == true)
	{
		
		pr_info("[openat hook] %s(%d) %016lx %016lx %s -> hook", current->comm, task_tgid_vnr(current), regs->regs[30], regs->pc, copystr);

		return org_openat(dfd, convert_to_user_string(dummy_path, sizeof(dummy_path)), flags, mode);		
	}
	else if (strstr(copystr, "/proc/self/mounts"))
	{
		/*
			/proc/self/mounts 에서 아래의 로그가 남으므로 우회할 필요가 있음
			/dev/Nmtq/.magisk/block/system_root /system/bin/dmctl ext4 ro,seclabel,relatime,errors=remount-ro 0 0
			reference: https://github.com/darvincisec/DetectMagiskHide/blob/master/app/src/main/c/native-lib.c
		*/
		//char replace_mount[] = "/data/local/tmp/0.txt";
		pr_info("[openat hook] %s(%d) %016lx %016lx %s -> need hook", current->comm, task_tgid_vnr(current), regs->regs[30], regs->pc, copystr);

		//return org_openat(dirfd, convert_to_user_string(replace_mount, sizeof(replace_mount)), flags, mode);		
	}
	else
	{
		pr_info("[openat hook] %s(%d) %016lx %016lx %s", current->comm, task_tgid_vnr(current), regs->regs[30], regs->pc, copystr);
	}

	return org_openat(dfd, filename, flags, mode);
}



void syscall_hook(void)
{
	sys_call_table = (u64*)kallsyms_lookup_name("sys_call_table");	
	pr_info("[CODETRONIK] syscall table %016lx", sys_call_table);

	enable_memory_rw((unsigned long)sys_call_table, 0x4000);
	
	org_openat = (_original_openat)sys_call_table[__NR_openat];
	org_faccessat = (_original_faccessat)sys_call_table[__NR_faccessat];
	org_fstatat = (_original_fstatat)sys_call_table[__NR3264_fstatat];
	org_fchmodat = (_original_fchmodat)sys_call_table[__NR_fchmodat];
	org_fchownat = (_original_fchownat)sys_call_table[__NR_fchownat];
	org_read = (_original_read)sys_call_table[__NR_read];
	org_execve = (_original_execve)sys_call_table[__NR_execve];

	sys_call_table[__NR_faccessat] = (u64)hook_faccessat;
	sys_call_table[__NR_openat] = (u64)hook_openat;
	sys_call_table[__NR3264_fstatat] = (u64)hook_fstatat;
	sys_call_table[__NR_fchmodat] = (u64)hook_fchmodat;	
	sys_call_table[__NR_fchownat] = (u64)hook_fchownat;  
	sys_call_table[__NR_execve] = (u64)hook_execve;  
	sys_call_table[__NR_read] = (u64)hook_read;

}

int init_module(void)
{
	
	org_write = (_original_write)kallsyms_lookup_name("sys_write");
	selinux_enforcing = (char*)kallsyms_lookup_name("selinux_enforcing");
	pr_info("[CODETRONIK] selinux_enforcing %016lx value %c", selinux_enforcing, selinux_enforcing[0]);

	syscall_hook();

	return 0;
}

void cleanup_module(void)
{
	/*
		At the moment of exit, api functions still continue to be called, resulting in a fault.
		I checked the log below in /proc/last_kmsg
		[2:          rmmod: 7927] Accessing user space memory(8) outside uaccess.h routines
		[2:          rmmod: 7927] sec_debug_set_extra_info_fault = PAGE / 0x8
		[2:          rmmod: 7927] Internal error: Accessing user space memory outside uaccess.h routines: 96000005 [#1] PREEMPT SMP
	*/
	sys_call_table[__NR_faccessat] = (u64)org_faccessat;
	sys_call_table[__NR_openat] = (u64)org_openat;
	sys_call_table[__NR3264_fstatat] = (u64)org_fstatat;
	sys_call_table[__NR_fchmodat] = (u64)org_fchmodat;	
	sys_call_table[__NR_fchownat] = (u64)org_fchownat;  
	sys_call_table[__NR_execve] = (u64)org_execve;  
	sys_call_table[__NR_read] = (u64)org_read;


}