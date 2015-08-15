//Created by: Sec-Mini-Projects (2014) under the MIT License - See "LICENSE" for Details. 
//Description: XORs a sequence of bytes with a provided one byte key.
//Usage: Make sure the cursor is pointing to the start of the sequence of bytes, run this script, enter how many bytes to XOR, enter a value to XOR the sequence of bytes with.
auto x = AskLong(10,"How many times apply XOR?");
auto xorstuff = AskLong(0,"Value to XOR");
auto y = 0;
auto curloc = ScreenEA();
while (y < x)
{
	PatchByte(curloc+y,xorstuff ^ Byte(curloc+y));
	y++;
}