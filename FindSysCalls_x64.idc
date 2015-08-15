//Created by: Sec-Mini-Projects (2014) under the MIT License - See "LICENSE" for Details. 
//Description: Scans for x86-64 64-bit syscall operands and renames the function that the syscall is located within and adds a comment to the syscall instruction line.
//			   All found syscalls have a comment added to the IDA Output window and if a ptrace call exists, is noted at the end of the log output.
//			   This script traces the disassembly should the syscall value be declared prior to the syscall.
//Usage: Click within the section you want to scan and run this IDC file
//Limitations or Future Improvements:Does not include all opcodes and the op codes should be read from a file instead of hard-coded into the script.


#include <idc.idc>

extern ptrace_found;
extern start;
extern end;

static main()
{
	start = GetSegmentAttr(ScreenEA(),SEGATTR_START);
	end  = GetSegmentAttr(ScreenEA(),SEGATTR_END);
	ptrace_found = 0;
	while (start < end)
	{
		if(GetMnem(start) == "syscall")
		{
			FindAndPrintSysName(start,"Rabbit");
		}
		start++;
	}
	if (ptrace_found == 1)
	{
		Message("WARNING - PTRACE FOUND!!! \n");
	}
}

static FindAndPrintSysName(new_addr,new_operand)
{
	auto found = 0;
	while(found == 0)
	{
		auto op1 = GetOpnd(PrevAddr(new_addr),0);
		auto op2 = GetOpnd(PrevAddr(new_addr),1);
		auto mnem = GetMnem(PrevAddr(new_addr));
		auto type = GetOpType(PrevAddr(new_addr),1);
		if(mnem == "mov" && (op1 == "eax" || op1 == "rax" || op1 == "ax" || op1 == "al" || op1 == new_operand))
		{
			if(type == 5)
			{				
				if(op2 == "3")	
				{
					op2 = "sys_close";
				}
				else if(op2 == "0")
				{
					op2 = "sys_read";
				}
				else if(op2 == "1")
				{
					op2 = "sys_write";
				}
				else if(op2 == "2")
				{
					op2 = "sys_open";
				}
				else if(op2 == "4")
				{
					op2 = "sys_stat";
				}
				else if(op2 == "5")
				{
					op2 = "sys_fstat";
				}
				else if(op2 == "6")
				{
					op2 = "sys_lstat";
				}
				else if(op2 == "8")
				{
					op2 = "sys_lseek";
				}
				else if(op2 == "9")
				{
					op2 = "sys_mmap";
				}
				else if(op2 == "0Dh")	
				{
					op2 = "sys_rt_sigactiont";
				}
				else if(op2 == "0Ah")	
				{
					op2 = "sys_mprotect";
				}
				else if(op2 == "0Bh")	
				{
					op2 = "sys_munmap";
				}
				else if(op2 == "0Ch")	
				{
					op2 = "sys_brk";
				}
				else if(op2 == "0Eh")
				{
					op2 = "sys_rt_sigprocmask";
				}
				else if(op2 == "0Fh")
				{
					op2 = "sys_rt_sigreturn";
				}
				else if(op2 == "10h")		
				{
					op2 = "sys_mprotect";
				}
				else if(op2 == "14h")	
				{
					op2 = "sys_writev";
				}
				else if(op2 == "15h")
				{
					op2 = "sys_access";
				}
				else if(op2 == "18h")		
				{
					op2 = "sys_sched_yield";
				}
				else if(op2 == "19h")	
				{
					op2 = "sys_mremap";
				}
				else if(op2 == "1Ch")	
				{
					op2 = "sys_madvise";
				}
				else if(op2 == "23h")		
				{
					op2 = "sys_nanosleep";
				}
				else if(op2 == "26h")	
				{
					op2 = "sys_msync";
				}
				else if(op2 == "27h")	
				{
					op2 = "sys_getpid";
				}
				else if(op2 == "29h")	
				{
					op2 = "sys_socket";
				}
				else if(op2 == "2Ah")
				{
					op2 = "sys_connect";
				}
				else if(op2 == "2Ch")	
				{
					op2 = "sys_sendto";
				}
				else if(op2 == "3Ch")
				{
					op2 = "sys_exit";
				}
				else if(op2 == "3Fh")
				{
					op2 = "sys_uname";
				}
				else if(op2 == "48h")
				{
					op2 = "sys_fcntl";
				}
				else if(op2 == "4Eh")
				{
					op2 = "sys_getdents";
				}
				else if(op2 == "4Fh")
				{
					op2 = "sys_getcwd";
				}
				else if(op2 == "59h")
				{
					op2 = "sys_readlink";
				}
				else if(op2 == "61h")
				{
					op2 = "sys_getrlimit";
				}
				else if(op2 == "66h")	
				{
					op2 = "sys_getuid";
				}
				else if(op2 == "65h")
				{
					op2 = "sys_ptrace";
					ptrace_found = 1;
				}
				else if(op2 == "68h")	
				{
					op2 = "sys_getgid";
				}
				else if(op2 == "6Bh")
				{
					op2 = "sys_setgid";
				}
				else if(op2 == "6Ch")
				{
					op2 = "sys_getegid";
				}
				else if(op2 == "9Eh")
				{
					op2 = "sys_arch_prctl";
				}
				else if(op2 == "065h")
				{
					op2 = "sys_ptrace";
				}
				else if(op2 == "0BAh")
				{
					op2 = "sys_gettid";
				}
				else if(op2 == "0C9h")
				{
					op2 = "sys_time";
				}
				else if(op2 == "0CAh")
				{
					op2 = "sys_futex";
				}
				else if(op2 == "106h")
				{
					op2 = "sys_newfstatat";
				}
				else if(op2 == "0E5h")
				{
					op2 = "sys_clock_getres";
				}
				else if(op2 == "0EAh")
				{
					op2 = "sys_tgkill";
				}
				else if(op2 == "101h")
				{
					op2 = "sys_openat";
				}
				MakeComm(start, op2);
				if(strstr(GetFunctionName(GetFunctionAttr(start, FUNCATTR_START)), "APICALL_") == -1)
				{
					MakeNameEx(GetFunctionAttr(start, FUNCATTR_START), "APICALL_" + ltoa(start,16) + "_" +op2, SN_PUBLIC);
				}
				Message("Found Syscall at %x - %s\n",start,op2);
			}
			else
			{
				new_addr--;
				FindAndPrintSysName(new_addr,op2);
			}
			found = 1;
		}
		new_addr--;
	}
}


