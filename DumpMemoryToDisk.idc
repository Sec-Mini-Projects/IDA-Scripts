//Created by: Sec-Mini-Projects (2015) under the MIT License - See "LICENSE" for Details. 
//Description: Dumps out data that exists between the cursor location and the entered end address, an even number of bytes will be written to the "idaout,bin" file.
//Usage: Make sure the cursor is set to the start of the data to be dumped, run this IDC script via IDA and enter the end address.  An even number of bytes will be output regardless of end address.
//Important: The output file is called "idaout.bin".


auto file = fopen("idaout.bin", "wb");
if (file != 0)
{
	auto start = ScreenEA();
	auto end = AskLong(0,"Give me the address in memory to stop at - total size of output will be an even number");
	if(start < end)
	{
		while (start < end)
		{
			writeshort(file,DbgWord(start),0);
			start = start + 2;	
		}
	}
	else
	{
		Warning("The start address is greater than or equal to the end address, please enter a valid address.");
	}
	fclose(file);
}