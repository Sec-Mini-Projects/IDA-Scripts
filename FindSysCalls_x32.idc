//Created by: Sec-Mini-Projects (2014) under the MIT License - See "LICENSE" for Details. 
//Description: Scans for x86 32-bit syscall operands and renames the function that the syscall is located within and adds a comment to the syscall instruction line.
//			   All found syscalls have a comment added to the IDA Output window and if a ptrace call exists, is noted at the end of the log output.
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
				if(op2 == "6")	
				{
					op2 = "sys_close";
				}
				else if(op2 == "3")
				{
					op2 = "sys_read";
				}
				else if(op2 == "4")
				{
					op2 = "sys_write";
				}
				else if(op2 == "5")
				{
					op2 = "sys_open";
				}
				else if(op2 == "12h")
				{
					op2 = "sys_stat";
				}
				else if(op2 == "1Ch")
				{
					op2 = "sys_fstat";
				}
				else if(op2 == "54h")
				{
					op2 = "sys_lstat";
				}
				else if(op2 == "13h")
				{
					op2 = "sys_lseek";
				}
				else if(op2 == "5Ah")
				{
					op2 = "old_mmap";
				}
				else if(op2 == "07Dh")	
				{
					op2 = "sys_mprotect";
				}
				else if(op2 == "05Bh")	
				{
					op2 = "sys_munmap";
				}
				else if(op2 == "02Dh")	
				{
					op2 = "sys_brk";
				}
				else if(op2 == "07Eh")
				{
					op2 = "sys_rt_sigprocmask";
				}
				else if(op2 == "0ADh")
				{
					op2 = "sys_rt_sigreturn";
				}
				else if(op2 == "07Dh")		
				{
					op2 = "sys_mprotect";
				}
				else if(op2 == "092h")	
				{
					op2 = "sys_writev";
				}
				else if(op2 == "021h")
				{
					op2 = "sys_access";
				}
				else if(op2 == "09Eh")		
				{
					op2 = "sys_sched_yield";
				}
				else if(op2 == "0A3h")	
				{
					op2 = "sys_mremap";
				}
				else if(op2 == "0A2h")		
				{
					op2 = "sys_nanosleep";
				}
				else if(op2 == "90h")	
				{
					op2 = "sys_msync";
				}
				else if(op2 == "014h")	
				{
					op2 = "sys_getpid";
				}
				else if(op2 == "066h")	
				{
					op2 = "sys_socketcall";
				}
				else if(op2 == "1")
				{
					op2 = "sys_exit";
				}
				else if(op2 == "06Dh")
				{
					op2 = "sys_uname";
				}
				else if(op2 == "037h")
				{
					op2 = "sys_fcntl";
				}
				else if(op2 == "8Dh")
				{
					op2 = "sys_getdents";
				}
				else if(op2 == "0B7h")
				{
					op2 = "sys_getcwd";
				}
				else if(op2 == "055h")
				{
					op2 = "sys_readlink";
				}
				else if(op2 == "04Ch")
				{
					op2 = "sys_getrlimit";
				}
				else if(op2 == "018h")	
				{
					op2 = "sys_getuid";
				}
				else if(op2 == "01Ah")
				{
					op2 = "sys_ptrace";
					ptrace_found = 1;
				}
				else if(op2 == "02Fh")	
				{
					op2 = "sys_getgid";
				}
				else if(op2 == "02Eh")
				{
					op2 = "sys_setgid";
				}
				else if(op2 == "32h")
				{
					op2 = "sys_getegid";
				}
				else if(op2 == "0ACh")
				{
					op2 = "sys_prctl";
				}
				else if(op2 == "01Ah")
				{
					op2 = "sys_ptrace";
				}
				else if(op2 == "0Dh")
				{
					op2 = "sys_time";
				}
				else if(op2 == "06Ch")
				{
					op2 = "sys_newfstat";
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


