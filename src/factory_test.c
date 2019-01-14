#define _GNU_SOURCE     /* To get defns of NI_MAXSERV and NI_MAXHOST */
#include <arpa/inet.h>
#include <assert.h>
#include <error.h>
#include <fcntl.h>
#include <getopt.h>
#include <ifaddrs.h>
//#include <linux/if.h>
//#include <linux/mii.h>
#include <linux/types.h>
#include <linux/if_link.h>
#include <linux/sockios.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ethtool.h>
//#include <linux/netdevice.h>
#include <netdb.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sched.h>
#include <time.h>
#include "factory_test.h"
#ifdef MTK
#include "rdm.h"
#include "ra_ioctl.h"
#endif

unsigned int gdma_count[24];
const char GDMA[25][20] = {"GDMA1_RX_GBCNT  : ",\
						 "GDMA1_RX_GPCNT  : ",\
						 "GDMA1_RX_OERCNT : ",\
						 "GDMA1_RX_FERCNT : ",\
						 "GDMA1_RX_SERCNT : ",\
						 "GDMA1_RX_LERCNT : ",\
						 "GDMA1_RX_CERCNT : ",\
						 "GDMA1_RX_FCCNT  : ",\
						 "GDMA1_TX_SKIPCNT: ",\
						 "GDMA1_TX_COLCNT : ",\
						 "GDMA1_TX_GBCNT  : ",\
						 "GDMA1_TX_GPCNT  : ",\
						 "\0"
};
char *TXCRC    = "Tx CRC Error        :";
char *RXCRC    = "Rx CRC Error        :";
char *TXGDPKT = "Tx Unicast Packet   :";
char *RXGDPKT = "Rx Unicast Packet   :";

unsigned int len[17] = {0};


int if_num,flag;
int default_link_value;
int link_value;
int default_speed_duplex[2];
int speed_duplex[2];

int sd[16],frame_length;
unsigned char  mac[16][ETH_ALEN];
unsigned char  *ether_frame[16];
struct sockaddr_ll *port[16];
unsigned char tx_macaddr[ETH_ALEN] = {0,0xc,0x29,0x27,0xd4,0xf8};

time_t tNow , tStart;
#define  pthread_num  1
pthread_t send_thread[10],check_thread;
//int network_down[17];
//int network_error;
struct rtnl_link_stats *if_statistics[16];
//struct rtnl_link_stats64 *if_statistics64[16];
int  statistics_label;
int  txrx_zone;
#define handle_error(msg) \
           do { perror(msg);} while (0)

/*
*   get interface link status
*/
typedef enum {
	IFSTATUS_UP,
	IFSTATUS_DOWN,
	IFSTATUS_ERR
} interface_status_t;

interface_status_t interface_detect_beat_ethtool(int fd, const char *iface)
{
    struct ifreq ifr;
    struct ethtool_value edata;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name)-1);

    edata.cmd = ETHTOOL_GLINK;
    ifr.ifr_data = (caddr_t) &edata;

    if (ioctl(fd, SIOCETHTOOL, &ifr) == -1)
    {
        perror("ETHTOOL_GLINK failed ");
        return IFSTATUS_ERR;
    }

    return edata.data ? IFSTATUS_UP : IFSTATUS_DOWN;
}

static int init_board(void)
{
	int i;
	if(!strcmp(board_name,"NM01")){
		if_num = 5;
	}
	else if(!strcmp(board_name,"NA20")){
		if_num = 5;
	}

	else{
		printf("The board name error\n");
		return -1;
	}

	default_link_value = 0;
	default_speed_duplex[0] = 0;
	default_speed_duplex[1] = 0;
	for(i=0;i<if_num;i++){
		default_link_value += 1 <<  i;
	}
	for(i=0;i<if_num;i++){
		if(i < 8){
			default_speed_duplex[0] += 6 <<  4*i;
		}
		else{
			default_speed_duplex[1] += 6 <<  4*(i-8);
		}
	}

	return 0;
}

static int is_file_exist(char *file_path)
{
	if(file_path == NULL){
		//printf("The file_path is NULL !\n");
		return -1;
	}
	if(access(file_path ,F_OK) == 0)
	{
		return 0;
	}
	else
	{
		//printf("The file of %s is not exist.\n",file_path);
		return -1;
	}
}


static int get_if_link_status(void)
{
	int sk = 0,ret = 0,i;
	int method = 0;
	struct ifreq ifr;
	ra_mii_ioctl_data mii;
	if ((sk = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
      {
	        printf("Open socket failed\n");
	        return -1;
       }
	strncpy(ifr.ifr_name, "eth0", 5);
      ifr.ifr_data = &mii;
	method = RAETH_MII_READ;
	mii.phy_id = 31;
	link_value = 0;
	speed_duplex[0] = 0;
	for(i = 0;i<5;i++){
		mii.reg_num = 0x3008 + i*0x100;
		ret = ioctl(sk, method, &ifr);
		if (ret < 0){
			printf("mii_mgr: ioctl error\n");
			return -1;
		}
		link_value |= (mii.val_out & 0x1) << i;
		speed_duplex[0] |= (((mii.val_out & 0xc) >> 2) + ((mii.val_out & 0x2) << 1)) << 4*i;
	}
	#if 0
	mii.phy_id = 5;
	mii.reg_num = 17;
	ret = ioctl(sk, method, &ifr);
	if (ret < 0){
		printf("mii_mgr: ioctl error\n");
		return -1;
	}

	ret = 0;
	link_value += ((mii.val_out >> 15) & 0x1) << 5;
	ret += 2 << ((mii.val_out >> 12) & 0x1);
	ret += (mii.val_out >> 13) & 0x3;

	speed_duplex[0] |= (ret & 0xf) << 4*5;
	#endif
	close(sk);
	return link_value;
}


/*
*   get interface mac
*/

static int get_if_mac(unsigned char * mac,const char * iface)
{
	   const char *device = iface;

	   struct ifreq req;
	   int err,i;

	   int s=socket(AF_INET,SOCK_DGRAM,0);
	   strcpy(req.ifr_name,device);
	   err=ioctl(s,SIOCGIFHWADDR,&req);
	   close(s);

	  if(err) {
	   	 printf("Get %s MAC Fail\n",iface);
		 return -1;
   	   }
	   else{
		 memcpy(mac,req.ifr_hwaddr.sa_data,ETH_ALEN);
		 //for(i=0;i<ETH_ALEN;i++)printf("%02x",mac[i]);
		return 0;
         }

	  return 0;
}


/*
*   get interface link mode(speed and duplex)
*/
/*
bit3:default 0
bit2
	1��b0: Half Duplex.
	1��b1: Full Duplex.
bit1:bit0
	Port n Speed [1:0] Status
	Current speed of port n after PHY links up.
	2��b00: 10 Mbps
	2��b01: 100 Mbps
	2��b10: 1000 Mbps
	2��b11: Invalid
e.g:1000M Full .value = 6;
*/
static int get_if_speed_duplex(int bug,int *pret)
{
	struct ifreq ifr;
	struct ethtool_cmd ecmd;
	int fd,i;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0){
		   printf("%s: socket error\n",__func__);
		   return -1;
	}

	for(i=0;i<if_num;i++){
		/* Setup our control structures. */
		memset(&ifr, 0, sizeof(ifr));
		strcpy(ifr.ifr_name, if_name[i]);

		ecmd.cmd = 1;
		ifr.ifr_data = (caddr_t)&ecmd;
		if(ioctl(fd, SIOCETHTOOL, &ifr)){
		   close(fd);
		   perror("SIOCETHTOOL");
		   return -1;
		}
		if(i < 8){
			pret[0]  |= (ecmd.duplex ? DUPLEX_FULL : DUPLEX_HALF) << (4*i + 2);
			switch(ecmd.speed){
				case SPEED_1000:
					pret[0]  |= 2 << 4*i;
					break;
				case SPEED_100:
					pret[0]  |= 1 << 4*i;
					break;
				case SPEED_10:
					pret[0]  |= 0 << 4*i;
					break;
				default:
					printf("%s:Get invalid speed\n",if_name[i]);
					close(fd);
					 return -1;
			  }
		}
		else{
			pret[1]  |= (ecmd.duplex ? DUPLEX_FULL: DUPLEX_HALF) << (4*(i -8) + 2);
			switch(ecmd.speed){
				case SPEED_1000:
					pret[1]  |= 2 << 4*(i-8);
					break;
				case SPEED_100:
					pret[1]  |= 1 << 4*(i-8);
					break;
				case SPEED_10:
					pret[1]  |= 0 << 4*(i-8);
					break;
				default:
					printf("%s:Get invalid speed\n",if_name[i]);
					close(fd);
					 return -1;
			  }
		}
		if(bug)printf( "%s: speed:%d, duplex:%s\n", if_name[i], ecmd.speed,ecmd.duplex ? "full" : "half");
	}
	close(fd);
	return 0;
}

/*
*   get interface statistics
*/
int get_if_statistics(void)
{
	#if 0
	    struct ifaddrs *ifaddr, *ifa;
           int i,n, ret = -1;
           if (getifaddrs(&ifaddr) == -1) {
               perror("getifaddrs");
			return -1;
           }
         for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
               if (ifa->ifa_addr == NULL)
                   continue;
			   //printf("%d:ifa->ifa_name = %s\n",n,ifa->ifa_name);
			   ret = strcmp(ifa->ifa_name,if_name[5]);
			   if(ret == 0){
				   if(ifa->ifa_data != NULL){
					if_statistics[5] = ifa->ifa_data;
				   }
			   }
		}
           freeifaddrs(ifaddr);
           return 0;
	#endif
}

static int  get_port_statistics(int bug)
{
		const char *filepath = "/proc/mt7621/esw_cnt";
		int filelen = 5*1024-1;

		char *p = NULL;
		int fd = NULL;

		//unsigned int len[17] = {0};
		int i,ret;
		char buff[11] = {'\0'};

		if((fd = open(filepath,O_RDONLY)) ==  -1){
			printf("open %s failed\n",filepath);
			return 	-1;
		}

		char *pRead  = malloc(filelen + 1);
		memset(pRead,0,filelen+1);
		if(read(fd,pRead,filelen)  == 0){
			printf("read %s failed\n",filepath);
			free(pRead);
			return 	-1;
		}
		else{
			close(fd);
		}

		for(i=0;i<12;i++){
			if(p = strstr(pRead,GDMA[i])){
				p += strlen(GDMA[i]);
				memset(buff,0,sizeof(buff));
				memcpy(buff,p,10);
				gdma_count[i] += atoi(buff);
			}
				//printf("%s%010d\n",GDMA[i],gdma_count[i]);
		}

		if(!bug){
			len[0] = gdma_count[3];
			len[1] = gdma_count[6];
			if(p = strstr(pRead,TXCRC)){
				p += strlen(TXCRC);

				memset(buff,0,sizeof(buff));
				memcpy(buff,p,10);
				len[2] = atoi(buff);
				for(i=3;i<7;i++){
					p += 11;
					memset(buff,0,sizeof(buff));
					memcpy(buff,p,10);
					len[i] = atoi(buff);
				}
			}

			if(p = strstr(pRead,RXCRC)){
				p += strlen(RXCRC);
				memset(buff,0,sizeof(buff));
				memcpy(buff,p,10);
				len[7] = atoi(buff);
				for(i=8;i<12;i++){
					p += 11;
					memset(buff,0,sizeof(buff));
					memcpy(buff,p,10);
					len[i] = atoi(buff);
				}
			}
			#if 0
			get_if_statistics();
			len[14] = if_statistics[5]->tx_errors;
			len[15] = if_statistics[5]->rx_errors;
			len[16] = if_statistics[5]->rx_crc_errors;
			ret = 0;
			#endif
			for(i=0;i<12;i++){
				//printf("len[%d] = %d\n",i,len[i]);
				if(default_err_count <  len[i]){
					statistics_label = -1;
					break;
					//ret = -1;
				}
			}
		}
		else{
			int len[17] = {0};
			len[0] = gdma_count[1];
			len[1] = gdma_count[11];
			if(p = strstr(pRead,TXGDPKT)){
				p += strlen(TXGDPKT);

				memset(buff,0,sizeof(buff));
				memcpy(buff,p,10);
				len[2] = atoi(buff);
				for(i=3;i<7;i++){
					p += 11;
					memset(buff,0,sizeof(buff));
					memcpy(buff,p,10);
					len[i] = atoi(buff);
				}
			}

			if(p = strstr(pRead,RXGDPKT)){
				p += strlen(RXGDPKT);
				memset(buff,0,sizeof(buff));
				memcpy(buff,p,10);
				len[7] = atoi(buff);
				for(i=8;i<12;i++){
					p += 11;
					memset(buff,0,sizeof(buff));
					memcpy(buff,p,10);
					len[i] = atoi(buff);
				}
			}

			for(i=0;i<12;i++){
				if(len[i] == 0){
					txrx_zone += 1;;
					//break;
				}
			}
		}
		free(pRead);
		return 0;
}

static int get_link_speed_duplex(int bug)
{
	get_if_link_status();
	if(link_value != default_link_value){
		if(bug){
			printf("Please ensure all RJ45 have been connected.\n");
			return -1;
		}
	}
	else{
		if( (default_speed_duplex[0]  != speed_duplex[0]) || (default_speed_duplex[1]  != speed_duplex[1]) ){
			printf("speed and duplex aren't 1000Mb/s Full.\n");
			return -1;
		}
	}
	return 0;
}
static int mtk7621_clear_statistics(void)
{
	int sk = 0,ret = 0;
	int method = 0;
	struct ifreq ifr;
	ra_mii_ioctl_data mii;
	if ((sk = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        printf("Open socket failed\n");
        return -1;
    }
     strncpy(ifr.ifr_name, "eth0", 5);
     ifr.ifr_data = &mii;
	method = RAETH_MII_WRITE;
	mii.phy_id = 31;
	mii.reg_num = 0x4fe0;
	mii.val_in  = 0;
	ret = ioctl(sk, method, &ifr);
	if (ret < 0){
		printf("mii_mgr: ioctl error\n");
		exit(-1);
	}
	//printf("Set: phy[%d].reg[%d] = %04x\n",mii.phy_id, mii.reg_num, mii.val_in);
	mii.val_in  = 0x80000000;
	ret = ioctl(sk, method, &ifr);
	if (ret < 0){
		printf("mii_mgr: ioctl error\n");
		exit(-1);
	}
	//printf("Set: phy[%d].reg[%d] = %04x\n",mii.phy_id, mii.reg_num, mii.val_in);
	close(sk);
	return 0;
}
static int init_network_sock(void)
{
	int i;
	struct ifreq ifr;
	unsigned char  *data;
	data = (unsigned char  *)malloc(MAX_DATA);
	memset(data,0xaa,MAX_DATA);

	frame_length = 14+MAX_DATA;

	for(i=0;i<if_num;i++){
		if ((sd[i]= socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL ))) < 0) {
		    		handle_error("socket  failed ");
		    		exit (-1);
		  }
		/*  set interface promisc mode */
		strncpy(ifr.ifr_name,if_name[i],IFNAMSIZ);
		if(-1 == ioctl(sd[i],SIOCGIFFLAGS,&ifr)){
		     perror("ioctl");
		     close(sd[i]);
		     exit(-1);
		}
		ifr.ifr_flags |=IFF_PROMISC;
		if(-1 == ioctl(sd[i],SIOCSIFFLAGS,&ifr)){
		     perror("ioctl");
		     close(sd[i]);
		     exit(-1);
		}
		if(get_if_mac(mac[i],if_name[i]))
			exit(-1);
	}

	for(i=0;i<if_num;i++){
		port[i] =(struct sockaddr_ll *)malloc(sizeof(struct sockaddr_ll));
		if(NULL ==  port[i]){
			printf("%s:Allocate %d'th port space failed\n",__func__,i);
			exit(-1);
		}
		ether_frame[i] = (unsigned char  *)malloc(frame_length);
		if(NULL ==  ether_frame[i]){
			printf("%s:Allocate %d'th ether_frame space failed\n",__func__,i);
			exit(-1);
		}
		memset(port[i],0,sizeof(struct sockaddr_ll));
		memset(ether_frame[i],0,frame_length);

		if ((port[i]->sll_ifindex = if_nametoindex(if_name[i])) == 0) {
		    	perror ("if_nametoindex() failed to obtain interface index ");
		   	 exit (-1);
         	}
		port[i]->sll_family = AF_PACKET;
	  	memcpy (port[i]->sll_addr, tx_macaddr, 6);
	 	 port[i]->sll_halen = htons (6);

	  	memcpy (ether_frame[i], tx_macaddr, 6);
	       memcpy (ether_frame[i] +6, mac[i], 6);
	  	ether_frame[i][12] = ETH_P_DEAN / 256;
	  	ether_frame[i][13] = ETH_P_DEAN % 256;
		memcpy (ether_frame[i] +14 , data, MAX_DATA);
	}

	free(data);
	return 0;
}

static int set_start_time(void)
{
	tStart = time(NULL);
	time(&tStart);
	if (tStart < 0)
	{
		perror("time");
		return -1;
	}
	tNow = time(NULL);
	system("gpio l 0 2 2 4000 0 4000");
	printf("Aging test time is %02d:%02d:%02d\n",default_age_time/(60*60),(default_age_time%(60*60))/60,(default_age_time%(60*60))%60);

	return 0;
}

void *send_0_package(void *arg)
{
	int i = 0;
	while(flag){
		for(i=0;i<if_num;i++){
			  if (( sendto (sd[i], ether_frame[i], frame_length, 0, (struct sockaddr *) port[i], sizeof (struct sockaddr_ll))) <= 0) {
			  	//printf("port%d send_package failed",i);
	       		handle_error("sendto");
				flag = 0;
			  	get_link_speed_duplex(0);
				break;
	     		 }
		}
	}
	 pthread_exit(NULL);
}
/*
void *send_1_package(void *arg)
{
	int i = 0;
	while(flag){
		for(i=0;i<if_num;i++){
			  if (( sendto (sd[i], ether_frame[i], frame_length, 0, (struct sockaddr *) port[i], sizeof (struct sockaddr_ll))) <= 0) {
			  	printf("port%d send_package failed",i);
	       		handle_error("sendto");
				flag = 0;
	     		 }
		}
	}
	 pthread_exit(NULL);
}
*/

void *check_result(void *arg)
{
	long int tmp;
	int i;
	 while(flag){
		time(&tNow);
		if (tNow < 0){
			flag = 0;
			perror("checktime");
		}

		get_link_speed_duplex(0);
		get_port_statistics(0);
		if(((tNow - tStart) <= 120) && (70 <= (tNow - tStart))){
			get_port_statistics(1);
		}
		if((link_value !=  default_link_value) || (default_speed_duplex[0] != speed_duplex[0]) || (default_speed_duplex[1] != speed_duplex[1]) ||
			((tNow - tStart) > (default_age_time)) || (statistics_label == -1)  || (txrx_zone != 0) ){
			flag=0;
			break;
		}
		else{
			tmp = (long int)(default_age_time-(tNow - tStart));
			printf("\rRemainder aging testing time %02ld:%02ld:%02ld",tmp/3600, tmp%3600/60, tmp%3600%60);
			fflush(stdout);
			sleep(10);
		}
	 }
       pthread_exit(NULL);
}

void thread_create(void)
{
       int temp,i;

	for(i=0;i<pthread_num;i++){
		memset(&send_thread[i], 0, sizeof(pthread_t));
	}
	if((temp = pthread_create(&send_thread[0], NULL, send_0_package, NULL)) != 0){
		handle_error("pthread create send_thread failed ");
		exit(-1);
	}
	/*
	if((temp = pthread_create(&send_thread[1], NULL, send_1_package, NULL)) != 0){
		handle_error("pthread create send_thread failed ");
		exit(-1);
	}
	*/
	memset(&check_thread, 0, sizeof(pthread_t));
	if((temp = pthread_create(&check_thread, NULL, check_result, NULL)) != 0){
		handle_error("pthread create check_thread failed ");
		exit(-1);
	}
	printf("************************All OK,start Aging testing********************************\n");
}

void thread_wait(void)
{
	int i;
	for(i=0;i<pthread_num;i++){
		pthread_join(send_thread[i],NULL);
	}
	pthread_join(check_thread,NULL);
}

static int transformation_result_buf(FILE *fp)
{
	system("cat /proc/mt7621/esw_cnt  > /natest_result.log");
	const char *filepath = "/natest_result.log";
	struct stat status;
	stat(filepath,&status);
	int filelen = (int )status.st_size;

	char *p = NULL;
	FILE *fd = NULL;

	unsigned int len[17] = {0};
	int i,j,ret,val;
	char buff[11] = {'\0'};

	if((fd = fopen(filepath,"r+")) == NULL){
		printf("open %s failed\n",filepath);
		return 	-1;
	}

	char *pRead  = malloc(filelen + 1);
	memset(pRead,0,filelen+1);
	if(fread(pRead,filelen,1,fd) == 0){
		printf("read %s failed\n",filepath);
		free(pRead);
		fclose(fp);
		return 	-1;
	}
	else{
		pRead[filelen] = '\0';
		fclose(fd);
	}
	system("rm -rf /natest_result.log");
	for(i=0;i<24;i++){
		if(p = strstr(pRead,GDMA[i])){
		p += strlen(GDMA[i]);
		memset(buff,0,sizeof(buff));
		snprintf(buff,11,"%010u",gdma_count[i]);
		memcpy(p,buff,10);
		}
	}
	fprintf(fp,"%s",pRead);
	free(pRead);
	return 0;
}

int storage_test_result(char *sourfilepath,char *dest)
{
    char *filepath = sourfilepath;
	char *destination = dest;
	struct stat status;
	stat(filepath,&status);
	int filelen = (int )status.st_size + 2;
	int clearlen = 16*1024 -1;
	int len = 0;
	FILE *fd = NULL;
	char *pClear  = malloc(clearlen);
	char *pRead  = malloc(filelen);
	//printf("filelen = %d\n",filelen);
	memset(pClear,0,clearlen);
	memset(pRead,0,filelen);
	pRead[0] = '\n';
	pRead[filelen -1] = '\n';

	if(filelen > clearlen){
		printf("error:write file too big\n");
		free(pRead);
		free(pClear);
		return -1;
	}


	if((fd = fopen(filepath,"r")) == NULL){
		printf("open %s failed\n",filepath);
		free(pRead);
		free(pClear);
		return -1;
	}

	if(fread(&pRead[1],filelen-2,1,fd) == 0){
		printf("read %s failed\n",filepath);
		free(pRead);
		free(pClear);
		return -1;
	}
	else{
		fclose(fd);
		fd = NULL;
	}

	//printf("%s\n len = %d\n",pRead,strlen(pRead));

	fd = fopen(destination, "r+");
	if(NULL == fd)
      {
	    	perror("fopen");
		free(pRead);
		free(pClear);
		return -1;
	 }
	fseek(fd,48*1024, SEEK_SET);
      fwrite(pClear, clearlen, 1, fd);

	fseek(fd,48*1024, SEEK_SET);
      fwrite(pRead, filelen, 1, fd);
	free(pRead);
	free(pClear);
	return 0;
}

/*
* parameter value:1:Failed,0:Ok
*/
static int record_result(int value)
{
	int fo,i,mode,val,pkt_cnt = 0;
	char  *writeaddr = "/dev/mtdblock3";
	FILE *fp;
	char filename[18];
	snprintf(filename,13,"%02x%02x%02x%02x%02x%02x",mac[0][0],mac[0][1],mac[0][2],mac[0][3],mac[0][4],mac[0][5]);
	filename[12] = '\0';
	//printf("macadd = %s",filename);
	if(value){
		strcat(filename,"_Fail");
	}

	if((fo= open(filename,O_WRONLY | O_APPEND  | O_CREAT | O_TRUNC,S_IRUSR | S_IWUSR)) == -1){
		perror("open");
		return -1;
	}
       close(fo);

	if((fp = fopen(filename,"r+")) == NULL){
		printf("open %s failed\n",filename);
		return 	-1;
	}
	transformation_result_buf(fp);

	fprintf(fp,"                Aging Test Result\n");
	fprintf(fp," 		 <%s>\n",filename);
	fprintf(fp,"************************************************\n");
	fprintf(fp,"Start Time : %s\n",ctime(&tStart));
	fprintf(fp,"Stop  Time : %s\n",ctime(&tNow));
	fprintf(fp,"Test Result: %s\n",value?"Fail":"Ok");



	if(value){
		get_port_statistics(0);
		fprintf(fp,"-----------------------------------------------\n");
		if(((tNow - tStart) < default_age_time)){
			long int tmp;
			tmp = (long int)(tNow - tStart);
			fprintf(fp,"Aging time %02ld:%02ld:%02ld\n",tmp/3600, tmp%3600/60, tmp%3600%60);
		}
		if(statistics_label == -1){
					if(default_err_count<len[0])fprintf(fp,"GMAC1 RX FCS      error:%010u\n",len[0]);
					if(default_err_count<len[1])fprintf(fp,"GMAC1 RX checksum error:%010u\n",len[1]);
					for(i=2;i<7;i++){
						if(default_err_count<len[i])fprintf(fp,"Port%d TX CRC   error:%010u\n",i-2,len[i]);
					}
					for(i=7;i<12;i++){
						if(default_err_count<len[i])fprintf(fp,"Port%d RX CRC   error:%010\n",i-7,len[i]);
					}
					#if 0
					if(if_statistics[5]->tx_errors > default_err_count)      fprintf(fp,"Port5 TX     error:%010u\n",if_statistics[5]->tx_errors);
					if(if_statistics[5]->rx_errors > default_err_count)      fprintf(fp,"Port5 RX     error:%010u\n",if_statistics[5]->rx_errors);
					if(if_statistics[5]->rx_crc_errors >default_err_count)fprintf(fp,"Port5 RX CRC error:%010u\n",if_statistics[5]->rx_crc_errors);
					#endif
		}

		if(txrx_zone != 0){
			switch(txrx_zone){
						case 1:
							fprintf(fp,"GDMA1_RX_GPCNT  : 0000000000 (Rx Good Pkts)\n");
							break;
						case 2:
							fprintf(fp,"GDMA1_TX_GPCNT  : 0000000000 (Tx Good Pkts)\n");
							break;
						case 3:
							fprintf(fp,"GDMA2_RX_GPCNT  : 0000000000 (Rx Good Pkts)\n");
							break;
						case 4:
							fprintf(fp,"GDMA2_TX_GPCNT  : 0000000000 (Tx Good Pkts)\n");
							break;
						case 5:
							fprintf(fp,"Port0  Tx Unicast Packet   :       0\n");
							break;
						case 6:
							fprintf(fp,"Port1  Tx Unicast Packet   :       0\n");
							break;
						case 7:
							fprintf(fp,"Port2  Tx Unicast Packet   :       0\n");
							break;
						case 8:
							fprintf(fp,"Port3  Tx Unicast Packet   :       0\n");
							break;
						case 9:
							fprintf(fp,"Port4  Tx Unicast Packet   :       0\n");
							break;
						case 10:
							fprintf(fp,"Port0  Rx Unicast Packet   :       0\n");
							break;
						case 11:
							fprintf(fp,"Port1  Rx Unicast Packet   :       0\n");
							break;
						case 12:
							fprintf(fp,"Port2  Rx Unicast Packet   :       0\n");
							break;
						case 13:
							fprintf(fp,"Port3  Rx Unicast Packet   :       0\n");
							break;
						case 14:
							fprintf(fp,"Port4  Rx Unicast Packet   :       0\n");
							break;
						default:
							fprintf(fp,"There is one port with zero data\n");
							break;
					}
		}

		if(link_value !=  default_link_value){
				for(i=0;i<if_num;i++){
					if(!(0x1 & (link_value >> i))){
						fprintf(fp,"%s: link down\n",if_name[i]);
					}
				}
		}
		else{
			if((default_speed_duplex[0] != speed_duplex[0]) ||   (default_speed_duplex[1] != speed_duplex[1])){
					for(i=0;i<if_num;i++){
							if(i < 8)
								mode = 0xf & (speed_duplex[0] >> 4*i);
							else
								mode = 0xf & (speed_duplex[1] >> 4*(i-8));
							if(mode != 0x6){
								switch(mode & 0x3){
									case 0x10:
											val = 1000;
											break;
									case 0x01:
											val = 100;
											break;
									case 0:
											val = 10;
											break;
									default:
											val =0;
											break;
								}
								fprintf(fp,"%s: Speed: %dMb/s Duplex: %s\n",if_name[i],val,((mode >> 2) & 0x1)?"Full":"Half");
							}
					}
			}
		}
	}
	fprintf(fp,"************************************************\n");
	//fprintf(fp,"=====================");

	#if 0
	fprintf(fp,"Port5\n");
			fprintf(fp,"+-----------------------------------------------------------------+\n");
			fprintf(fp,"tx_packets         :%10u          rx_packets      :%10u\n"
		               "tx_bytes           :%10u          rx_bytes        :%10u\n"
					   "tx_errors          :%10u          rx_errors       :%10u\n"
					   "tx_dropped         :%10u          rx_dropped      :%10u\n"
		               "collisions         :%10u          multicast       :%10u\n"
					   "tx_aborted_errors  :%10u          rx_over_errors  :%10u\n"
		               "tx_carrier_errors  :%10u          rx_crc_errors   :%10u\n"
					   "tx_fifo_errors     :%10u          rx_frame_errors :%10u\n"
					   "tx_heartbeat_errors:%10u          rx_fifo_errors  :%10u\n"
		               "tx_window_errors   :%10u          rx_missed_errors:%10u\n",
		                          if_statistics[5]->tx_packets,if_statistics[5]->rx_packets,
		                         if_statistics[5]->tx_bytes, if_statistics[5]->rx_bytes,
						  if_statistics[5]->tx_errors, if_statistics[5]->rx_errors,
						if_statistics[5]->tx_dropped, if_statistics[5]->rx_dropped,
						if_statistics[5]->collisions, if_statistics[5]->multicast,
		                          if_statistics[5]->tx_aborted_errors, if_statistics[5]->rx_over_errors,
						  if_statistics[5]->tx_carrier_errors,if_statistics[5]->rx_crc_errors,
						  if_statistics[5]->tx_fifo_errors, if_statistics[5]->rx_frame_errors,
					  if_statistics[5]->tx_heartbeat_errors, if_statistics[5]->rx_fifo_errors,
					  if_statistics[5]->tx_window_errors, if_statistics[5]->rx_missed_errors);
			fprintf(fp,"+-----------------------------------------------------------------+\n");
			fclose(fp);
	#endif
	fclose(fp);
	if(storage_test_result(filename,writeaddr))
		printf("storage test  result error \n");
	else
		printf("storage test  result ok \n");



	return 0;
}

static int handle_result(void)
{
	if((link_value !=  default_link_value) || (default_speed_duplex[0] != speed_duplex[0]) ||
	   (default_speed_duplex[1] != speed_duplex[1])  || (statistics_label == -1)  || (txrx_zone != 0) || ((tNow - tStart) < default_age_time) ){

			record_result(1);
			system("gpio l 0 4000 0 1 0 4000");
			return -1;
	}
	else{
			record_result(0);
			system("/etc/init.d/factory disable");
			system("gpio l 0 0 4000 1 0 4000");
			return 0;
	}

	return 0;
}

static void free_resources(void)
{
	int i;
	for(i=0;i<if_num;i++){
		close(sd[i]);
		free(port[i]);
		free(ether_frame[i]);
		//free(if_statistics[i]);
	}
}

int  lte_test(void)
{
	FILE *fp = NULL;
	char *filepath = "/uci.log";
	char *p = NULL;
	char  sim[]        = "network.modem.simcard=insterd";
	char  lteproto[] = "network.modem.lteproto=";
	char rssi[]         = "network.modem.rssi=";
	//char reversion[] = "network.modem.Reversion=";
	char reversion[] = "network.modem.lteversion=";
	char lteversion[]=  "network.modem.ltemodel=";
	int filelen = 0, i=0,ret=0,rssi_result = 0,err_result1 ,err_result2;
	char *pRead  = NULL;
	struct stat status;
	char buf[25] = {'\0'};
	char key;
	int two_antenna = 1;


while(two_antenna--){
	err_result1 = 0;
	err_result2 = 0;
	ret = 0;
	rssi_result  = 0;
	system("uci show network.modem > /uci.log");
	stat(filepath,&status);
	filelen = (int )status.st_size;
	pRead  = malloc(filelen);
	memset(pRead,0,filelen);
	if((fp = fopen(filepath,"r")) == NULL){
		printf("Get uci show network.modem file Fail\n");
		free(pRead);
		return 	-1;
	}

	if(fread(pRead,filelen,1,fp) == 0){
		printf("Open uci show network.modem file Fail\n");
		free(pRead);
		fclose(fp);
		return 	-1;
	}
	else{
		fclose(fp);
	}
	system("rm -rf  /uci.log");
	printf("\n****************************************************\n");
	//lte Manufacturer
	if(p = strstr(pRead,lteversion)){
		p += strlen(lteversion);
		i = 0;
		while(p[i] != '\n')i++;
		memset(buf,'\0',sizeof(buf));
		memcpy(buf,p,i);
		printf("LTE Manufacturer   :  %s\n",buf);
	}
	else{
		printf("LTE Manufacturer   :  isn't  detected\n");
	}

	//lte software
	if(p = strstr(pRead,reversion)){
		p += strlen(reversion);
		i = 0;
		while(p[i] != '\n')i++;
		memset(buf,'\0',sizeof(buf));
		memcpy(buf,p,i);
		//printf("buf = %s\n",buf);
		if(memcmp(buf,REVERSION,i)){
			printf("LTE Reversion      :  %s\r\t\t\t\t\t\tError\n",buf);
			//free(pRead);
			printf("\n****************************************************\n");
			//return -1;
		}
		else{
			printf("LTE Reversion      :  %s\r\t\t\t\t\t\tOK\n",buf);
		}
	}
	else{
		printf("LTE Reversion      :  isn't  detected\n");
		free(pRead);
		printf("\n****************************************************\n");
		return -1;
	}

	//network type
	if(p = strstr(pRead,lteproto)){
		p += strlen(lteproto);
		i = 0;
		while(p[i] != '\n')i++;
		memset(buf,'\0',sizeof(buf));
		memcpy(buf,p,i);
		if(  buf[0] == '4' ){
			ret = 1;
			printf("LTE Network type   :  %s\r\t\t\t\t\t\tOK\n",buf);
		}
		else{
			ret = 0;
			printf("LTE Network type   :  %s\r\t\t\t\t\t\tError\n",buf);
		}
	}
	else{
		err_result1 = -1;
		printf("LTE Network type   :  isn't  detected\n");
	}

	// rssi
	if(p = strstr(pRead,rssi)){
		p += strlen(rssi);
		i = 0;
		while(p[i] != '\n')i++;
		memset(buf,'\0',sizeof(buf));
		memcpy(buf,p,i);
		rssi_result = atoi(buf);
		if( rssi_result > -75){
			ret =  (ret << 1) + 1;
			printf("LTE Signal strength:  %d\r\t\t\t\t\t\tOK\n",rssi_result);
		}
		else {
			ret =  (ret << 1) + 0;
			printf("LTE Signal strength:  %d\r\t\t\t\t\t\tError\n",rssi_result);
		}
	}
	else{
		err_result2 = -1;
		printf("LTE Signal strength:  isn't  detected\n");
	}
	printf("****************************************************\n");
	//sim card
	if((err_result1 ==  -1) ||(err_result2 ==  -1))
	{
		two_antenna = 0;
		 if(p = strstr(pRead,sim)){
		 	printf("SIM card           :  is  detected\n");
		 }
		 else{
			printf("SIM card           :  isn't  detected\n");
		 }
		 	printf("\n\t\t--------------------------\n");
			printf("\t\t|                        |\n");
			printf("\t\t| LTE  Modem  is  FAIL!  |\n") ;
			printf("\t\t|                        |\n");
			printf("\t\t--------------------------\n");
	}
	else {
		if(ret == 3){
			printf("\n\t\t--------------------------\n");
			printf("\t\t|                        |\n");
			printf("\t\t| LTE  Modem  is  OK     |\n") ;
			printf("\t\t|                        |\n");
			printf("\t\t--------------------------\n");


		}
		else{
			two_antenna = 0;
			printf("\n\t\t--------------------------\n");
			printf("\t\t|                        |\n");
			printf("\t\t| LTE  Modem  is  FAIL!  |\n") ;
			printf("\t\t|                        |\n");
			printf("\t\t--------------------------\n");
		}
	}
	free(pRead);
	#if 0
	if(1 == two_antenna){
		printf("\nPlease Enter any key ,switch the antenna to continue the test\n");
		key = getchar();
		while(key == '\n')
		{
			key = getchar();
		}
		//sleep(5);
	}
	#endif
}
	return 0;
}


static int do_aging_test(void)
{
	flag = 1;
	statistics_label = 0;
	txrx_zone = 0;

	if(get_link_speed_duplex(1))
		return -1;

	init_network_sock();
	set_start_time();
	if(!strcmp(board_name,"NA07")){
		mtk7621_clear_statistics();
	}
	thread_create();
	//send_0_package(NULL);
	thread_wait();
	//get_port_statistics();
	handle_result();
	//free_resources();
	return 0;
}

static int  show_aging_result(void)
 {
        char filename[18] = {'\0'};
        char ok_name[13];
        char fail_name[18];
        char *result_aging = "aging.log";
        get_if_mac(mac[0],if_name[0]);
        snprintf(ok_name,13,"%02x%02x%02x%02x%02x%02x",mac[0][0],mac[0][1],mac[0][2],mac[0][3],mac[0][4],mac[0][5]);
        ok_name[12] = '\0';
        strcpy(fail_name,ok_name);
        strcat(fail_name,"_Fail");
        if(0 == is_file_exist(fail_name)){
               strcpy(filename,fail_name);
               goto cat;
        }
	  else  if(0 == is_file_exist(ok_name)){
               strcpy(filename,ok_name);
               goto cat;
        }
        else{
              printf("There isn't  result of aging testing \n");
              return -1;
        }

 cat:
        rename(filename,result_aging);
        system("cat  aging.log");
        rename(result_aging,filename);
	  return 0;
 }


static int show_user_option(const char *board_type)
{
	printf("\n");
	printf("            ======================================\n");
	printf("            |     %s Testing(%s)    |\n",board_type,version);
	printf("            |  1. LTE                            |\n");
	printf("            |  2. Aging Test                     |\n");
	printf("            |  3. Show Aging Test  Result        |\n");
	printf("            |  0. Exit                           |\n");
	printf("            ======================================\n");
}

int main(int argc, char *argv[])
{
	char key = -1;
	int val = -1;

	if(init_board())
		return -1;

	if(argc > 1){
		default_age_time = atoi(argv[1]);
		if(default_age_time < 1){
			printf("Please input right aging time[dec],unit sec.\n");
			return -1;
		}
	}

	if(argc > 2){
		default_err_count = atoi(argv[2]);
		if(default_err_count < 1){
			printf("Please input right error count[dec].\n");
			return -1;
		}
	}

	if(argc > 3){
		do_aging_test();
		return 0;
	}

	while(1){
		show_user_option(board_name);
		printf("Please input your choice[0-3]:");
getchoose:
		scanf("%c", &key);
		//printf("%c\n",key);
		switch (key){
			case '1':
					lte_test();
					break;
			case '2':
					do_aging_test();
					break;
			case '3':
					show_aging_result();
					break;
			case '0':
					return 0;
			default	:
				goto getchoose;
		}
	}
    return 0;



}
