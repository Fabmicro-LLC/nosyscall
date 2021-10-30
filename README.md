## Nosyscall 

nosyscall is a simple tool to skip or block selected syscalls which is sometimes
needed when running Linux apps on FreeBSD with the linuxulator Linux emulation.

For instance, there's a flock() compatiblity problem: in FreeBSD, flock() syscall
is same as fcntl(F_SETLK), but in Linux 2.0 and higher flock() and fcntl(F_SETLK)
are two independent file locking mechanisms implemented as syscalls. 
This makes Linux programmers to use both to obtain a tight lock on a file, while 
FreeBSD programmer has to use only one of these. If both syscalls are used in a 
Linux app running on FreeBSD it gets to a deadlock or to undesired error code which 
may not be handled in the app. To work-around this issue one of the syscalls has to 
be ignored (skipped).

Note: this tool was made for X86_AMD64 architecture. To make it run on some other 
architecture, you have to modify register names.

Copyright(C) 2021, Fabmicro, LLC., Tyumen, Russia.

Written by "Ruslan Zalata" <rz@fabmicro.ru>.

SPDX-License-Identifier: BSD-2-Clause


