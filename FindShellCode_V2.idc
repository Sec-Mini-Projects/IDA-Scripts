//Created by: Sec-Mini-Projects (2014) under the MIT License - See "LICENSE" for Details. 
//Description: Finds and stops execution once shellcode has been found.
//Usage: Start the vulnerable program, add breakpoints to important Windows API's BEFORE the malicious file is being read in, then run this script.
//Usage: Change the doXtimes if you want the script to check for shellcode multiple layers up the call chain.
//Limitations: This script uses generic shellcode detection techniques and may result in false positives.  Manual user intervention and/or modification of this script will be required.


auto found = 0;
auto cnter = 1;
auto exitme = 0;
GetDebuggerEvent(WFNE_CONT,-1);
while (found == 0 && exitme == 0)
{
	auto evt = GetDebuggerEvent(WFNE_ANY,-1);
	if(evt == BREAKPOINT)
	{
		auto doXtimes = 2;
		while (doXtimes > 0 && found == 0)
		{
			StepUntilRet();
			GetDebuggerEvent(WFNE_SUSP,-1);
			Message("IP IS %x ",ScreenEA());
			if(strstr(SegName(ScreenEA()),"Stack") != -1 || strstr(SegName(ScreenEA()),"debug") != -1)
			{
				Message("Found exploit");
				found = 1;
				PauseProcess();
			}
			doXtimes--;
		}
		if(found == 0)
		{
		   GetDebuggerEvent(WFNE_CONT,-1); 
		   Message("Nothing at %x ",ScreenEA());
		}
		if (cnter % 350 == 0)
		{
			if(AskYN(1,"Continue Executing?") < 1)
			{
				exitme = 1;
			}
		}
	}
	else if(evt == EXCEPTION)
	{
		Message("Please step-over the exception, configure the exception to be passed to the application and do not suspend, re-run this script. \n");
		exitme = 1;
	}
    cnter++;
}
