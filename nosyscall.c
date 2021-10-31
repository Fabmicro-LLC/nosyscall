/*
 * nosyscall is a simple tool to skip or block selected syscalls which is sometimes 
 * needed when running Linux apps on FreeBSD with the linuxulator Linux emulation.
 *
 * For instance, there's a flock() compatiblity problem: in FreeBSD, flock() syscall
 * is same as fcntl(F_SETLK), but in Linux 2.0 and higher flock() and fcntl(F_SETLK)
 * are two independent system calls. This makes Linux programmers to use both to obtain
 * a tightlock on a file, while FreeBSD programmer has to use only one of these.
 * If both syscalls are used in an Linux app running on FreeBSD it gets to a deadlock or
 * to undesired error code which may not be handled in the app. To work-around this
 * one of the syscalls has to be skipped.
 *
 * Note: this is for X86_AMD64 architecture only. You have to modify register names
 * to get it working on some other architecture.
 *
 * Copyright(C) Fabmicro, LLC., 2021, Tyumen, Russia.
 *
 * Written by "Ruslan Zalata" <rz@fabmicro.ru>.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <machine/reg.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>

#define	FREEBSD_SYS_nanosleep	240
#define LINUX_SYS_nanosleep	35

#define	MODE_NONE		0
#define	MODE_SKIP		1
#define	MODE_REJECT		2
#define	MODE_BLOCK		3
#define	MODE_TRACE		4

#define	BLOCK_LIST_SIZE		256

char* modes[] = { "none", "skip", "reject", "block", "trace" };

struct block_syscall {
	int syscall_number;
	int sysarg_number;
	long sysarg_value;
	int mode;
};


struct block_syscall* block_syscall_list = NULL;

int sys_nanosleep = 0;	// nanosleep() syscall number, depends on ABI 


int addsyscall(char* str, int mode)
{
	int idx;

	for(idx = 0; idx < BLOCK_LIST_SIZE; idx++)
		if(block_syscall_list[idx].syscall_number == 0)
			break;

	if(idx == BLOCK_LIST_SIZE) {
		fprintf(stderr, "No more room in block list!\n");
		exit(EXIT_FAILURE);
	} 

	block_syscall_list[idx].mode = mode;

	char* str_arg = index(str, ':');

	if(str_arg == NULL) {
		// Just a syscall, no argument provided
		block_syscall_list[idx].syscall_number = strtol(str, NULL, 0); 
		block_syscall_list[idx].sysarg_number = -1; // do not match arguments
		return idx;
	}

	*str_arg++ = 0;

	char* str_val = index(str_arg, '=');

	if(str_val == NULL) {
		// No value provided, use zero
		block_syscall_list[idx].syscall_number = strtol(str, NULL, 0); 
		block_syscall_list[idx].sysarg_number = strtol(str_arg, NULL, 0) % 4; // only four args supported 
		block_syscall_list[idx].sysarg_value = 0;
		return idx;
	}

	*str_val++ = 0;

	// All three provided: syscall number, argument number and argumen value

	block_syscall_list[idx].syscall_number = strtol(str, NULL, 0); 
	block_syscall_list[idx].sysarg_number = strtol(str_arg, NULL, 0); 
	block_syscall_list[idx].sysarg_value = strtol(str_val, NULL, 0);

	return idx;
}



int getdata(int pid, long addr, long* data)
{
	int status;

	if(data == NULL)
		return -1;

	if(pid <= 0)
		return -1;

	errno = 0;

	*data = ptrace(PT_READ_D, pid, (caddr_t) addr, 0);

	return -errno;
}


int getregs(int pid, struct reg* registers)
{
	int status;

	if(registers == NULL)
		return -1;

	if(pid <= 0)
		return -1;

	status = ptrace(PT_GETREGS, pid, (caddr_t) registers, 0);

	if(status != 0)
		return -1;

	return registers->r_rax;
}


int setregs(int pid, struct reg* registers)
{
	int status;

	if(registers == NULL)
		return -1;

	if(pid <= 0)
		return -1;

	return ptrace(PT_SETREGS, pid, (caddr_t) registers, 0);
}


void run(char** argv)
{
	int status;

	status = ptrace(PT_TRACE_ME, 0, 0, 0);

	if(status != 0)
		exit(EXIT_FAILURE);

	execv(argv[0], argv);
}


void usage(char* prog)
{
	fprintf(stderr, "Usage:\n"
		"\t%s [-srb] syscall_num:arg_num=arg_val /path/to/program_to_be_traced\n"
		"\t%s [-srb] syscall_number /path/to/program_to_be_traced\n\n"
		"\t-s - to skip given syscall, will return 0 to tracee\n"
		"\t-r - to reject given syscall, will return -1 to tracee\n"
		"\t-b - to block given syscall, will stop execution and quit\n"
		"\t-t - don't do anything, just trace (print info when syscall is met).\n\n"
		"\tA syscall can identified by 'syscall_num' number and one of its parameters\n"
		"\tset by 'arg_num' and value 'arg_val'. There can be no more that 256 blocks set at once.\n\n"
		"Copyright (C) 2021, Fabmicro, LLC., Tyumen, Russia. Written by Ruslan Zalata <rz@fabmicro.ru>\n\n",
		prog, prog);

	exit(EXIT_FAILURE);
}


int main(int argc, char** argv)
{
	int verbose = 0;
	int max_syscall_idx = -1;
	struct reg registers;
	int pid;
	int ch;

	if(argc < 3) 
		usage(argv[0]);
	

	block_syscall_list = (struct block_syscall*) malloc(sizeof(struct block_syscall) * BLOCK_LIST_SIZE);

	if(block_syscall_list == NULL) {
		fprintf(stderr, "Cannot allocate memory for block list: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	memset((void*) block_syscall_list, 0, sizeof(struct block_syscall) * BLOCK_LIST_SIZE);

	while ((ch = getopt(argc, argv, "vs:r:b:t:?h")) != -1) {
		switch(ch) {
			case 's': {
				max_syscall_idx = addsyscall(optarg, MODE_SKIP);
			} break;

			case 'r': {
				max_syscall_idx = addsyscall(optarg, MODE_REJECT);
			} break;

			case 'b': {
				max_syscall_idx = addsyscall(optarg, MODE_BLOCK);
			} break;

			case 't': {
				max_syscall_idx = addsyscall(optarg, MODE_TRACE);
			} break;

			case 'v': {
				verbose++;
			} break;

			default:
				usage(argv[0]);
		}
	}
	argc -= optind;
	argv += optind;


	fprintf(stderr, "Syscalls to handle: ");

	for(int i = 0; i < max_syscall_idx+1; i++)
		if(block_syscall_list[i].syscall_number != 0) 
			fprintf(stderr, "syscall=%d,argn=%d,argv=%p,mode=%s ",
				block_syscall_list[i].syscall_number, 
				block_syscall_list[i].sysarg_number, 
				(void*)block_syscall_list[i].sysarg_value,
				modes[block_syscall_list[i].mode]
			);

	fprintf(stderr, "\n\n");


	pid = fork();
	if(pid == -1) {
		fprintf(stderr, "Fork failed: %s\n", strerror (errno));
		exit(EXIT_FAILURE);
	}
	else if(pid == 0) {
		run(argv);
	}
	else {
		int count = 0;
		int skipped = 0;
		int rejected = 0;

		if(wait (0) == -1) {
			fprintf(stderr, "Wait failed.\n");
			exit(EXIT_FAILURE);
		}

		// Get ABI type

		int mib[4];
		char abi[32];
		size_t len = sizeof(abi);
		mib[0] = CTL_KERN;
		mib[1] = KERN_PROC;
		mib[2] = KERN_PROC_SV_NAME;
		mib[3] = pid;

		if(sysctl(mib, 4, abi, &len, NULL, 0) < 0) {
			fprintf(stderr, "Failed to get ABI type: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		if(verbose)
			fprintf(stderr, "PID: %d, ABI: %s\n", pid, abi);

		if(strncmp(abi, "Linux", 5) == 0)
			sys_nanosleep = LINUX_SYS_nanosleep;
		else
			sys_nanosleep = FREEBSD_SYS_nanosleep;

		// Trace till syscall entry

		while(ptrace (PT_TO_SCE, pid, (caddr_t) 1, 0) == 0) {
			int call;
			int retval;
			int mode = MODE_NONE;
			long sysargs[4];

			if(wait (0) == -1)
				break;

			call = getregs(pid, &registers);

			if(call == -1)
				break;
		
			// Ontain syscall args

			ptrace(PT_GET_SC_ARGS, pid, (caddr_t) &sysargs, sizeof(sysargs)); 
			

			// Check if this syscall has to be skipped

			for(int i = 0; i < max_syscall_idx+1; i++) {
				if(block_syscall_list[i].syscall_number == 0)
					continue;

				if(block_syscall_list[i].sysarg_number == -1) {
					if(block_syscall_list[i].syscall_number == call) {
						mode = block_syscall_list[i].mode;
						break;
					}
				} else {
					if(block_syscall_list[i].syscall_number == call &&
					   sysargs[block_syscall_list[i].sysarg_number] == block_syscall_list[i].sysarg_value) {
						mode = block_syscall_list[i].mode;
						break;
					}
				}
			}

			if(verbose > 1 || (mode && verbose)) {

				fprintf(stderr, "Count: %05d syscall %3d entry\n\trax: 0x%016lx, rbx: 0x%016lx, rcx: 0x%016lx, rsp: 0x%016lx\n"
					"\trdi: 0x%016lx, rsi: 0x%016lx, rdx: 0x%016lx, r10: 0x%016lx\n"
					"\tstack: ", count, call, registers.r_rax, registers.r_rbx, registers.r_rcx, registers.r_rsp, registers.r_rdi, registers.r_rsi, registers.r_rdx, registers.r_r10);


				for(int i = 0; i < 4; i++) {
					long data;
					if(getdata(pid, registers.r_rsp + i*8, &data) < 0)
						break;

					fprintf(stderr, "0x%016lx, ", data);
				}

				fprintf(stderr, "\n\targs: ");

				for(int i = 0; i < sizeof(sysargs) / sizeof(*sysargs); i++) 
					fprintf(stderr, "0x%016lx, ", sysargs[i]);

				fprintf(stderr, "\n");
			}


			switch(mode) {
				default:
				case MODE_NONE:
				case MODE_TRACE:
					break;

				case MODE_SKIP: {
					// To skip a syscall we have to call some other harmless syscall like nanosleep() 
					registers.r_rax = sys_nanosleep;
					registers.r_rdi = 0;
					registers.r_rsi = 0;
					setregs(pid, &registers);

					if(verbose)
						fprintf(stderr, "\tSyscall is to be skipped!\n");

					skipped++;
				} break;

				case MODE_REJECT: {
					// Same as to skip
					registers.r_rax = sys_nanosleep;
					registers.r_rdi = 0;
					registers.r_rsi = 0;
					setregs(pid, &registers);

					if(verbose)
						fprintf(stderr, "\tSyscall is to be rejected!\n");
	
					rejected++;
				} break;

				case MODE_BLOCK: {
					if(verbose)
						fprintf(stderr, "\tBlocking this syscall!\n");
					exit(2);
				};
			}

			ptrace(PT_TO_SCX, pid, (caddr_t) 1, 0); // trace till syscall exit 

			if(wait(0) == -1)
				break;
		
			retval = getregs(pid, &registers);

			if(verbose > 1 || (mode && verbose))
				fprintf(stderr, "Count: %05d syscall %3d exit, ret_val = %d\n", count, call, retval);

			switch(mode) {
				default:
				case MODE_NONE:
				case MODE_TRACE:
					break;

				case MODE_SKIP: {
					// indicate no error to tracee
					registers.r_rax = 0;
					setregs(pid, &registers);

					if(verbose)
						fprintf(stderr, "\tSyscall skipped!\n\n");
				} break;

				case MODE_REJECT: {
					// indicate some error to tracee
					registers.r_rax = -1;
					setregs(pid, &registers);

					if(verbose)
						fprintf(stderr, "\tSyscall rejected!\n\n");
				} break;

				case MODE_BLOCK: {
					if(verbose)
						fprintf(stderr, "\tSyscall blocked (we should not get to this!)\n\n");
					exit(2);
				};
			}


			count++;
		}

		if(verbose)
			fprintf(stderr, "%d system calls processed, %d skipped and %d rejected.\n", count, skipped, rejected);
	}

	return 0;
}
