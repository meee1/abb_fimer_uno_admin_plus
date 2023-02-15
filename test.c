#include <stdio.h>
#include <string.h>
#include <time.h>


unsigned int encipherDecimal(unsigned char a1,unsigned char a2)

{
  bool v2; // cf@1
  bool v3; // zf@1
  signed int v4; // r3@4
  unsigned int result; // r0@7

  v2 = (unsigned int)a1 >= 9;
  v3 = a1 == 9;
  if ( (unsigned int)a1 <= 9 )
  {
    v2 = (unsigned int)a2 >= 9;
    v3 = a2 == 9;
  }
  if ( !v3 && v2 )
    v4 = 0;
  else
    v4 = 1;
  if ( !v3 && v2 )
    result = v4;
  else
    result = (unsigned char)(a1 + a2) % 0xAu & 0xFF;
  return result;
}
char decipherDecimal(unsigned char a1,unsigned char a2)

{
 bool v2; // cf@1
  bool v3; // zf@1
  signed int v4; // r3@4
  signed int result; // r0@9

  v2 = (unsigned int)a1 >= 9;
  v3 = a1 == 9;
  if ( (unsigned int)a1 <= 9 )
  {
    v2 = (unsigned int)a2 >= 9;
    v3 = a2 == 9;
  }
  if ( !v3 && v2 )
    v4 = 0;
  else
    v4 = 1;
  if ( !v3 && v2 )
  {
    result = v4;
  }
  else
  {
    if ( a2 > (unsigned int)a1 )
      a1 = a1 + 10;
    result = (unsigned char)(a1 - a2);
  }
  return result;
}


int encipherDecimalArray(unsigned char *a1,unsigned char *a2)

{
  unsigned char *param1; // r6@1
  unsigned char *param2minus1; // r5@1
  int counter; // r4@1
  int temp; // t1@2
  int result; // r0@2

  param1 = a1;
  param2minus1 = a2 - 1;
  counter = 0;
  do
  {
    temp = (param2minus1++)[1];
    result = encipherDecimal(param1[counter], temp);
    param1[counter] = result;
    if ( (unsigned char)counter != 5 )
    {
      result = encipherDecimal(param2minus1[1], result);
      param2minus1[1] = result;
    }
    ++counter;
  }
  while ( counter != 6 );
  return result;
}
int decipherDecimalArray(unsigned char *a1,unsigned char *a2)

{
  unsigned char *param1; // r6@1
  unsigned char *param2minus1; // r5@1
  int counter; // r4@1
  unsigned char v5; // t1@4
  int result; // r0@4

  param1 = a1;
  param2minus1 = a2 - 1;
  counter = 0;
  do
  {
    if ( (unsigned char)counter != 5 )
      param2minus1[2] = encipherDecimal(param2minus1[2], param1[counter]);
    v5 = (param2minus1++)[1];
    result = decipherDecimal(param1[counter], v5);
    param1[counter++] = result;
  }
  while ( counter != 6 );
  return result;
}

int SMLABB(short val1,
             short val2,
             int val3){
				 
				 return val1 * val2 + val3;
			 }


int getValidityStartEpochTime(unsigned char *param_1,unsigned char *param_2)

{
  unsigned char *adminkey;
  unsigned char *devid;
  unsigned char *pcVar1;
  int counter;
  unsigned char outputdatetime [6];
  unsigned char local_4c [6];
  struct tm tStack68;
  
  memset(&tStack68,0,0x2c);
  devid = param_2;
  if (1/*0xf < *(uint *)(devid + -0xc)*/) {
    counter = 0;
    do {
      outputdatetime[counter] = devid[counter] - 0x30;
      counter = counter + 1;
    } while (counter != 6);
    pcVar1 = devid + 11;
    counter = 0;
    do {
      pcVar1 = pcVar1 + 1;
      local_4c[counter] = *pcVar1 -0x30;
      counter = counter + 1;
    } while (counter != 4);
    local_4c[4] = 2;
    local_4c[5] = 0;
    encipherDecimalArray(outputdatetime,local_4c);
    counter = 0;
    do {
		//printf("%c vs %c \n", local_4c[counter] + 0x30, outputdatetime[counter] + 0x30);
      local_4c[counter] = outputdatetime[counter];
      counter = counter + 1;
    } while (counter != 6);
	//printf("\n");
	//490883
	//printf("0x%x%x%x%x%x%x\n",local_4c[0],local_4c[1],local_4c[2],local_4c[3],local_4c[4],local_4c[5]);
	
    adminkey = param_1;
    counter = 0;
    do {
      outputdatetime[counter] = adminkey[counter] -0x30;
      counter = counter + 1;
    } while (counter != 6);
    decipherDecimalArray(outputdatetime,local_4c);
    tStack68.tm_year = (short)(unsigned short)outputdatetime[0] * 10 + (unsigned int)outputdatetime[1] + 100;
    tStack68.tm_mon = (short)(unsigned short)outputdatetime[2] * 10 + (unsigned int)outputdatetime[3] + -1;
    tStack68.tm_mday = (short)(unsigned short)outputdatetime[4] * 10 + (unsigned int)outputdatetime[5];
    

    tStack68.tm_isdst = -1;
	
	/*
	char _R1 = (unsigned char)almostadate[0];
	char _R2 = (unsigned char)almostadate[1];
    char _R3 = 10;
    __asm { SMLABB          R2, R3, R1, R2 }
    _R1 = (unsigned char )almostadate[2];
    s.tm_year = _R2 + 100;
    __asm { SMLABB          R2, R3, R1, R2 }
    _R1 = (unsigned char )almostadate[4];
    s.tm_mon = _R2 - 1;
    __asm { SMLABB          R3, R3, R1, R2 }
    s.tm_mday = _R3;
    s.tm_isdst = -1;
	*/
  }
  int ans = mktime(&tStack68);
  
  time_t t = time(0) - 60*60*24*3;
  
  if(ans > t && ans < t + 0x127500 && tStack68.tm_year <= 123 && outputdatetime[4] <= 3 && outputdatetime[2] <= 1) {
	//  if(tStack68.tm_year+1900 == 2023) {
  printf("%i %i %i %s %s %i %i %i %i %i %i %i  %i\n", tStack68.tm_year+1900, tStack68.tm_mon+1, tStack68.tm_mday, param_1, param_2, ans, outputdatetime[0], outputdatetime[1], outputdatetime[2], outputdatetime[3], outputdatetime[4], outputdatetime[5], t);
  

  }
  return ans;
}



//0x16310

//110085
//3418
//688779
//2023-02-12



int main(int argc, char *argv[]) {
	{
		unsigned char t1 [6] = "\x2\x3\x0\x2\x0\x1";
		unsigned char t2 [6] = "\x4\x9\x0\x8\x8\x3";
		
		encipherDecimalArray(t1,t2);
		
		printf("0x%x%x%x%x%x%x\n",t1[0],t1[1],t1[2],t1[3],t1[4],t1[5]);
		printf("0x%x%x%x%x%x%x\n",t2[0],t2[1],t2[2],t2[3],t2[4],t2[5]);
	}
	
	{
		unsigned char t2 [6] = "\x3\x4\x1\x8\x2\x0";
		unsigned char t1 [6] = "\x1\x1\x0\x0\x8\x5";
		
			printf("0x%x%x%x%x%x%x\n",t1[0],t1[1],t1[2],t1[3],t1[4],t1[5]);
		printf("0x%x%x%x%x%x%x\n",t2[0],t2[1],t2[2],t2[3],t2[4],t2[5]);
		
		encipherDecimalArray(t1,t2);
		
		printf("0x%x%x%x%x%x%x\n",t1[0],t1[1],t1[2],t1[3],t1[4],t1[5]);
		printf("0x%x%x%x%x%x%x\n",t2[0],t2[1],t2[2],t2[3],t2[4],t2[5]);
		
		unsigned char  t3[6] = "\x2\x3\x0\x2\x0\x1";
		
			printf("0x%x%x%x%x%x%x\n",t1[0],t1[1],t1[2],t1[3],t1[4],t1[5]);
		printf("0x%x%x%x%x%x%x\n",t2[0],t2[1],t2[2],t2[3],t2[4],t2[5]);
		
		encipherDecimalArray(t1,t3);
		
		printf("0x%x%x%x%x%x%x\n",t1[0],t1[1],t1[2],t1[3],t1[4],t1[5]);
		printf("0x%x%x%x%x%x%x\n",t2[0],t2[1],t2[2],t2[3],t2[4],t2[5]);
	}
	
	for(int a = 0; a <= 999999; a++) {
		
		unsigned char local_1 [8] = "\x0";
		unsigned char local_2 [18] = fixme;   eg "999089-3P25-1422";
		
		sprintf((char*)local_1, "%06i", a);
		getValidityStartEpochTime(local_1, local_2);
		
		
	}
}