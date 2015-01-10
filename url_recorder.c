#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

#define PROMISC 1
#define SNAPLEN 1600

static char log_file[] = "/var/log/url_record.txt";
static char pidfile[] = "/var/run/url_recorder";
static FILE* log_fp;
static pthread_mutex_t log_mutex;
static char nic_bitmap[20];
static char nic[10];

int log_init()
{
	int ret;
	
	pthread_mutex_init(&log_mutex,NULL);
	log_fp = fopen(log_file,"a+");
	if (log_fp == NULL){
		printf("open log file failed\n");
	}
	
	return 0;
}

int logging(char *data,int len)
{
	time_t timet;
	struct tm *p;
	char str_time[100];

	timet = time(NULL);
	p = localtime(&timet);
	
	pthread_mutex_lock(&log_mutex);

	strftime(str_time,sizeof(str_time),"<--%m-%d %H:%M:%S-->  ",p);
	fwrite(str_time,strlen(str_time),1,log_fp);
	fwrite(data,len,1,log_fp);
	fputc('\n',log_fp);
	fflush(log_fp);

	pthread_mutex_unlock(&log_mutex);	

	return 0;
}

int create_pidfile()
{
	return 0;
}


int is_http_request(const unsigned char* buf, int len)
{
    if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T'){
        return 1;
    }

    if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T'){
        return 2;
    }

    return 0;
}

int http_hdr_len(const unsigned char* buf, int len)
{
    int i = 0;
    int hdr_len = 0;

    for (i = 0; i < len - 3; i++){
        if (buf[i] == '\r' && buf[i + 1] == '\n'
            && buf[i + 2] == '\r' && buf[i + 3] == '\n'){
            hdr_len = i;
            break;
        }
    }

    return hdr_len;

}

int get_url(unsigned char* buf, int *url_len, const unsigned char *pkt_data, int hdr_len)
{
   const  unsigned char* cur;
    int host_len;
    int uri_len;

    memcpy(buf, "http://", 7);
    buf += 7;
    *url_len = 7;

    cur = strstr(pkt_data, "Host:");
    if (cur == NULL)
        return -1;
    cur += 6;
    host_len = field_len(cur, hdr_len - (cur - pkt_data));

    if (host_len && (*url_len +host_len<1200)){
        memcpy(buf, cur, host_len);
        buf += host_len;
	*url_len += host_len;
    }
    else
    {
        return -1;
    }

    cur = pkt_data;
    if (pkt_data[0] == 'G')
        cur += 4;
    else if (pkt_data[0] == 'P'){
        cur += 5;
    }

    uri_len = field_len(cur, hdr_len - (cur - pkt_data));
    uri_len -= 9;

    if((*url_len + uri_len) < 1200){
	memcpy(buf, cur, uri_len);
    	*url_len += uri_len;
    }
    
    return 0;
    
}

int field_len(const unsigned char* buf, int len)
{
    int i = 0;
    int field_len = 0;
    
    for (i = 0; i < len-1; i++){
        if (buf[i] == '\r' && buf[i + 1] == '\n'){
            field_len = i;
            break;
        }
    }

    return field_len;
}

int is_tcp(const unsigned char* buf, int len)
{
    if (len < 54)
        return 0;
	
	//l2proto = Linux cooked capture
    //if (buf[12] != 0x08 || buf[13] != 0x00){
    if (buf[14] != 0x08 || buf[15] != 0x00){
        return 0;
    }
    
    //if (buf[23] != 0x06){//tcp flag
    if (buf[25] != 0x06){//tcp flag
        return 0;
    }

    return 1;
}

void callback(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *bytes)
{
    int len;
    const unsigned char *buf;
    const unsigned char *cur;
    unsigned char url[1024];
    int url_len = 0;
    char data[1400];
    int is_req;
    int hdr_len;
    int ret;

    buf = bytes;
    len = h->caplen;
    cur = buf;

    if (!is_tcp(buf, len)){
        return;
    }

    //cur += 54;
    //len -= 54;//tcp hdr ip hdr
    cur += 56;
    len += 56;

    is_req = is_http_request(cur, len);
    hdr_len = http_hdr_len(cur, len);

    switch (is_req){
    case 0:
        break;
    case 1:
        ret = get_url(url,&url_len, cur, hdr_len);
        if (ret == 0){
		logging(url,url_len);
	//printf("url_len:%d\n",url_len);
        }
        break;
    case 2:
        ret = get_url(url,&url_len, cur, hdr_len);
        if (ret == 0){
		logging(url,url_len);
        }
        //get_data(data, curl, len);
        break;
    default:
        break;
    }
}


void *capture_thread(void* arg)
{

	char dev[10];
	pcap_t *pt;
	char errbuf[PCAP_ERRBUF_SIZE];

	strcpy(dev,(char*)arg);
    	dev[9] = 0;

	
	pt = pcap_open_live(dev, SNAPLEN, PROMISC, -1, errbuf);
    	if (pt == NULL){
        	printf("open dev failed\n");
        	return;
    	}

	pcap_loop(pt, -1, callback,NULL);
//	pthread_detach(pthread_self());
	printf("capture thread create\n");

}

int start_capture(char *dev)
{

	char dev_vpath[30] = "/sys/class/net/";
	pthread_t thread;
	pthread_attr_t attr;

	strcpy(nic,dev);
	sleep(1);
	strcat(dev_vpath,nic);
	if(access(dev_vpath,0) == 0){
		int ret;
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
		pthread_create(&thread,&attr,capture_thread,nic);
		pthread_attr_destroy(&attr);
	}

	return 0;	
}


void parseBinaryNetLinkMessage(struct nlmsghdr *nlh)
{
	int len = nlh->nlmsg_len - sizeof(*nlh);
	struct ifinfomsg *ifi;

	if(sizeof(*ifi) > (size_t)len){
		printf("Got a short message\n");
		return ;
	}

	ifi = (struct  ifinfomsg*)NLMSG_DATA(nlh);
	if((ifi->ifi_flags & IFF_LOOPBACK) != 0){
		return ;
	}

	struct rtattr *rta = (struct rtattr*)
		((char*)ifi + NLMSG_ALIGN(sizeof(*ifi)));
	len = NLMSG_PAYLOAD(nlh,sizeof(*ifi));

	while(RTA_OK(rta,len)){
		switch(rta->rta_type){
			case IFLA_IFNAME:
			{
				char ifname[IFNAMSIZ];
				int  up;
				char id;
				snprintf(ifname,sizeof(ifname),"%s",
					(char*)RTA_DATA(rta));
				up = (ifi->ifi_flags & IFF_RUNNING)? 1 : 0;
				if (up && ((ifname[0] == 'p')&&(ifname[1] == 'p')&&
					(ifname[2] == 'p'))){
					printf("msg from:%s",ifname);
					sscanf(ifname+3,"%d",(int*)&id);
					if(nic_bitmap[id])
						break;
					start_capture(ifname);
					nic_bitmap[id] = 1;	
					printf("%s  %d\n",ifname,up);
				} 
				if (!up && ((ifname[0] == 'p')&&(ifname[1] == 'p')&&
                                        (ifname[2] == 'p'))){
					sscanf(ifname+3,"%d",(int*)&id);
					nic_bitmap[id] = 0;
					printf("%s %d\n",ifname,up);
				}
			}
		}

		rta = RTA_NEXT(rta,len);
	}

}


int main(int argc,char** argv)
{

	struct sockaddr_nl addr;
	struct nlmsghdr *nlh;
	char buffer[4096];
	int sock,len;


	//daemon(0,0);
	create_pidfile();
	log_init();

	
	if((sock = socket(AF_NETLINK,SOCK_RAW,NETLINK_ROUTE)) == -1){
		printf("open NETLINK_ROUTE socket failed\n");
		goto exit;
	}

	memset(&addr,0,sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = RTMGRP_LINK |RTMGRP_IPV4_IFADDR;
	
	if(bind(sock,(struct sockaddr*)&addr,sizeof(addr)) == -1){
		printf("bind failed\n");
		goto exit;
	}

	while((len = recv(sock,buffer,4096,0)) > 0){
		nlh = (struct nlmsghdr*)buffer;
		while((NLMSG_OK(nlh,len)) && (nlh->nlmsg_type != NLMSG_DONE)){
			if(nlh->nlmsg_type == RTM_NEWLINK){
				parseBinaryNetLinkMessage(nlh);
			}
			nlh = NLMSG_NEXT(nlh,len);
		}
	}

	close(sock);
	
exit:
		exit(0);
}

