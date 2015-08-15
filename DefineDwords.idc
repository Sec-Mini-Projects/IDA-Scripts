//Created by: Sec-Mini-Projects (2014) under the MIT License - See "LICENSE" for Details. 
//Description: Repeatedly defines a sequence of bytes as a DWORD as many times as the user tells the script.
//Usage: Make sure the cursor is set to the start of the sequence of bytes, run this script and then enter how many times 4 bytes should be defined.


auto x = AskLong(20,"How many times to define 4 bytes?");
auto y = 0;
auto start = ScreenEA();
while (y < x)
{
	if(y == 0)
	{
		MakeDword(start);
	}
	else
	{
		MakeDword(start + (y*4));
    }
	y++;
}