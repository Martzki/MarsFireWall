# MarsFireWall
> Linux Kernel FireWall based on Linux Netfilter
## Features
> * Stateful firewall
> * Dynamic NAT
> * Filter log 
## Environment
> Ubuntu 12.04  
> Linux 3.5.0
## Data structure define
### Filter rule
```C++
typedef struct Rule{
  unsigned int sip;
  unsigned int dip;
  unsigned short sport;
  unsigned short dport;
  unsigned short protocol;
  unsigned short sMask;
  unsigned short dMask;
  bool accept;
  bool log;
  struct Rule *next;
}Rule;
```
### Host info
> Host info is used to define inner net.
> Usually the ip is the interface to inner net and most time it equals firewall's ip.
> Usually the mask is the mask of the interface to inner net and most time it equals firewall's mask.
```C++
typedef struct HostInfo{
    __be32 ip;
    __be16 mask;
}HostInfo;
```
### NAT rule
```C++
typedef struct NATRule {
        unsigned int ip;
	unsigned int natip;
        unsigned short port;
	unsigned short natport;
	struct NATRule *next;
}NATRule;
```
### Time
```C++
typedef struct mtime{
    int year;
    int month;
    int day;
    int hour;
    int min;
    int sec;
}mtime;
```
### Active link
```C++
typedef struct ActiveLink {
    __be32 sip;
    __be32 dip;
    __be16 sport;
    __be16 dport;
    __u8 protocol;
    mtime createtime;
    __u8 lifetime;
    bool log;
    struct ActiveLink *next;
}ActiveLink;
```
### Log
```C++
typedef struct Log{
    __be32 sip;
    __be32 dip;
    __be16 sport;
    __be16 dport;
    __u8 protocol;
    mtime time;
    bool accept;
    struct Log *next;
}Log;
```
## User Mode API
> Using ioctl through a char device to communicate with kernel in user mode.
### Write filter rule to kernel
```C++
Rule rule;
/*You need to consummate rule*/
ioctl(fd,FW_ADD_RULE,&rule);
```
### Remove filter rule in kernel
```C++
Rule rule;
/*You need to consummate rule*/
ioctl(fd,FW_REMOVE_RULE,&rule);
```
### Clear filter rule in kernel
```C++
ioctl(fd,FW_CLEAR_RULE,NULL);
```
### Set host info in kernel and start NAT transformation
```C++
HostInfo hostInfo;
/*You need to consummate hostInfo*/
ioctl(fd,FW_START_NAT_TRANSFORM,&hostInfo);
```
### Stop NAT transformation
```C++
ioctl(fd,FW_STOP_NAT_TRANSFORM,NULL);
```
### Get sum of NAT rules in kernel
```C++
int NATLen;
ioctl(fd,FW_GET_NAT_LEN,&NATLen);
```
### Get NAT rules from kernel
```C++
NATRule *NATRules = new NATRule[NATLen];
ioctl(fd,FW_REFRESH_NAT_RULE,NATRules);
```
### Get sum of active links in kernel
```C++
int linkLen;
ioctl(fd,FW_GET_ACTIVELINK_LEN,&linkLen);
```
### Get active links from kernel
```C++
ActiveLink *activeLinks = new ActiveLink[linkLen];
ioctl(fd,FW_REFRESH_ACTIVELINK,activeLinks);
```
### Get sum of logs from kernel
```C++
int logLen;
ioctl(fd,FW_GET_LOG_LEN,&logLen);
```
### Get logs from kernel
```C++
Log *logs;
ioctl(fd,FW_WRITE_LOG,logs);
```
## Technical details
Coming soon
## Contact me
mars@hust.edu.cn
