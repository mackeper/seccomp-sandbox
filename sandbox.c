/**
 * Sandbox created using the libseccomp-dev
 *
 * Authors: Lars Lundin, Carl Dath, Marcus Östling	
 */

#include <stdio.h> // printf
#include <sys/ptrace.h> //ptrace, trace syscalls
#include <sys/prctl.h> 
#include <seccomp.h> //seccomp
#include <unistd.h> // execve, getpid
#include <sys/types.h> // pid_t

int main(int argc, char** argv) {
	if(argc < 2) {
		printf("Usage: ./sandbox <executable>\n");
		return 0;
	}
	printf("Run \"%s\" in safe mode\n\n", argv[1]);

	// Init the filter
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_KILL);

	// Setup basic whitelist
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);

	// Setup rules for execve
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0); 
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0); 
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0); 
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0); 
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0); 
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0); 
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0); 
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0); 
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0); 
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0); 
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0); 
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0); 

	seccomp_load(ctx);

	//Exec program
	char* newargv[] = {NULL, NULL};
	char* newenv[] = {NULL};
	execve(argv[1], newargv, newenv);

	printf("ERROR: Could not run program.\n");
	return 0;
}
