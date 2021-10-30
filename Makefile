default: nosyscall.c 
	cc -o nosyscall nosyscall.c

clean:
	rm nosyscall
