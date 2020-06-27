#include "skel.h"
#include <iostream>
#include <algorithm>
#include <fstream>
#include <vector>
#define n_route 700001
#define n_arp 1001

using namespace std;

struct route_table_entry* rtable;
struct arp_entry* arp_table;
int rtable_size;
int arp_table_len;

// bool function for stl sort criteria
// sorting ascendent after prefix
// in case of "=", sorting ascendent after mask
bool cmp(const route_table_entry& rte1, const route_table_entry& rte2)
{
    if (rte1.prefix == rte2.prefix)
        return rte1.mask < rte2.mask;
    return rte1.prefix < rte2.prefix;
}
int binarySearch(int l, int r, __u32 dest_ip)
{
    if (r >= l) {
        int mid = l + (r - l) / 2;
        if (rtable[mid].prefix == (dest_ip & rtable[mid].mask)) {
            while (1) {
                mid++;
                if (rtable[mid].prefix != (dest_ip & rtable[mid].mask)) {
                    return --mid;
                }
            }
        }
        if (rtable[mid].prefix < (dest_ip & rtable[mid].mask))
        	return binarySearch(mid + 1, r, dest_ip);
        return binarySearch(l, mid - 1, dest_ip);
    }
    return -1;
}

// function for getting a match in rtable
// Recursive Binary seatch is used in order to have O(log n)
// if no route is found, null returned
struct route_table_entry* get_best_route(__u32 dest_ip)
{

    int pos = binarySearch(0, rtable_size, dest_ip);
    if (pos == -1) {
        return NULL;
    }
    return &rtable[pos];
}

// function for getting a match in arp_table
struct arp_entry* get_arp_entry(__u32 ip)
{

    for (int i = 0; i < arp_table_len; ++i) {
        if (arp_table[i].ip == ip) {
            return &arp_table[i];
        }
    }
    return NULL;
}

// function for parsing rtable.txt
// memorizing size of rtable
void parse_route_table()
{
    ifstream fin("rtable.txt");
    if (fin.eof()) {
        cout << "Coulldn't open rtable.txt " << '\n';
    }
    std::string string1, string2, string3, string4;
    char prefix[50], next_hop[50], mask[50], interface[50];
    int k = 0;
    while (!fin.eof()) {
        fin >> string1 >> string2 >> string3 >> string4;
        strcpy(prefix, string1.c_str());
        strcpy(next_hop, string2.c_str());
        strcpy(mask, string3.c_str());
        strcpy(interface, string4.c_str());
        rtable[k].prefix = inet_addr(prefix);
        rtable[k].next_hop = inet_addr(next_hop);
        rtable[k].mask = inet_addr(mask);
        rtable[k++].interface = atoi(interface);
    }

    fin.close();
    rtable_size = k;
}

// function for parsing arp_table.txt
// memorizing size of arp_table
void parse_arp_table()
{
    ifstream fin("arp_table.txt");
    if (fin.eof()) {
        cout << "Coulldn't open arp_table.txt " << '\n';
    }
    char ip_str[50], mac_str[50];
    int i = 0;
    while (!fin.eof()) {
        fin >> ip_str >> mac_str;
        arp_table[i].ip = inet_addr(ip_str);
        int rc = hwaddr_aton(mac_str, arp_table[i++].mac);
        DIE(rc < 0, "invalid MAC");
    }
    arp_table_len = i;
    fin.close();
}

// handling icmp packet for the 2 cases presented in main
void custom_icmp_packet(struct iphdr* ip_hdr, struct ether_header* eth_hdr, int interface, char key[])
{
    packet pkt;
    struct ether_header* eth_hdrr = (struct ether_header*)pkt.payload;
    struct iphdr* ip_hdrr = (struct iphdr*)(pkt.payload + sizeof(struct ether_header));
    struct icmphdr* icmp_hdrr = (struct icmphdr*)(pkt.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

    pkt.len = sizeof(struct ether_header) + sizeof(struct iphdr)
        + sizeof(struct icmphdr);
    pkt.interface = interface;

    // IP_HDRR
    ip_hdrr->version = 4;
    ip_hdrr->ihl = 5;
    ip_hdrr->tos = 0;
    ip_hdrr->protocol = IPPROTO_ICMP;
    ip_hdrr->frag_off = 0;
    ip_hdrr->ttl = 64;
    memcpy(&ip_hdrr->daddr, &ip_hdr->saddr, sizeof(ip_hdr->saddr));
    ip_hdrr->id = htons(getpid());
    ip_hdrr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    ip_hdrr->check = 0;
    ip_hdrr->check = ip_checksum(ip_hdrr, sizeof(struct iphdr));

    // ICMP_HDRR
    icmp_hdrr->code = 0;
    if (strcmp(key, "ttl") == 0) {
        icmp_hdrr->type = 11;
    }
    if (strcmp(key, "no_route") == 0) {
        icmp_hdrr->type = 3;
    }
    icmp_hdrr->un.echo.id = htons(getpid());
    icmp_hdrr->un.echo.sequence = htons(1);
    icmp_hdrr->checksum = 0;
    icmp_hdrr->checksum = ip_checksum(icmp_hdrr, sizeof(struct icmphdr));

    // ETH_HDRR
    memcpy(eth_hdrr->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_dhost));
    memcpy(eth_hdrr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
    eth_hdrr->ether_type = htons(ETHERTYPE_IP);

    // sending ICMP packet
    send_packet(interface, &pkt);
}

int main(int argc, char* argv[])
{
    packet m;
    int rc;

    init();
    rtable = new route_table_entry[n_route];
    arp_table = new arp_entry[n_arp];
    DIE(rtable == NULL, "memory");

    parse_route_table();
    parse_arp_table();

    // sorting route_table in order to find best route
    sort(rtable, rtable + rtable_size, cmp);

    while (1) {
    	// receiving packet
        rc = get_packet(&m);
        DIE(rc < 0, "get_message");
        struct ether_header* eth_hdr = (struct ether_header*)m.payload;
        struct iphdr* ip_hdr = (struct iphdr*)(m.payload + sizeof(struct ether_header));
        struct icmphdr* icmp_original = (struct icmphdr*)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
        
        // handling IP packet
        uint16_t oldChecksum = ip_hdr->check;
        ip_hdr->check = 0;

        // if IP packet(for router) -> type ICMP ECHO request
        // swapping addresses(destination <--> source)
        // icmp_hdrr->type is 0;
        if (icmp_original->type == 8 && ip_hdr->daddr == inet_addr(get_interface_ip(m.interface))) {
            __u32 change_addr;
            memcpy(&change_addr, &ip_hdr->daddr, sizeof(ip_hdr->saddr));
            memcpy(&ip_hdr->daddr, &ip_hdr->saddr, sizeof(ip_hdr->saddr));
            memcpy(&ip_hdr->saddr, &change_addr, sizeof(change_addr));
            icmp_original->type = 0;
            send_packet(m.interface, &m);
            continue;
        }

        // if new_checksum is wrong, packet is thrown
        if (oldChecksum != ip_checksum(ip_hdr, sizeof(struct iphdr))) {
            continue;
        }
        // if IP packet and TTL is <= 1
        // handling and overriding packet fields for sending
        // custom_icmp_packet with icmp_hdrr->type = 11
        // packet is thrown
        if (ip_hdr->ttl <= 1) {
            char key[] = "ttl";
            custom_icmp_packet(ip_hdr, eth_hdr, m.interface, key);

            continue;
        }
        struct route_table_entry* best_route = get_best_route(ip_hdr->daddr);
        // if route is inexistent, sending ICMP packet
        // with icmp_hdrr->type = 3
        // packet is thrown
        if (best_route == NULL) {
            char key[] = "no_route";
            custom_icmp_packet(ip_hdr, eth_hdr, m.interface, key);
            continue;
        }

        // update TTL
        // recalculate checksum
        ip_hdr->ttl--;
        ip_hdr->check = 0;
        ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

        // getting an arp_entry that matches
        struct arp_entry* arp_entry = get_arp_entry(best_route->next_hop);

        // if get_arp_entry returns no entry, datagrama is thrown
        if (arp_entry == 0) {
            continue;
        }

        // update Ethernet addresses
        get_interface_mac(best_route->interface, eth_hdr->ether_shost);
        memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(arp_entry->mac));
        
        // sending packet
        send_packet(best_route->interface, &m);
    }
}
