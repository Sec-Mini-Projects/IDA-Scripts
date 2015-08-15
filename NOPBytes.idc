//Created by: Sec-Mini-Projects (2013) under the MIT License - See "LICENSE" for Details.  
//Description: NOPs out a sequence of bytes
//Usage: Make sure the cursor is set to the start of the sequence of bytes, run this script and then enter how many bytes to NOP out.


auto x = AskLong(10,"How many times to patch 1 byte with NOP?");
auto y = 0;
auto start = ScreenEA();
while (y < x)
{
	PatchByte(start + y,0x90);
	y++;
}
