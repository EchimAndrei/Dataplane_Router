#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>
#include <linux/if_ether.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>


// Creare tabela de rutare
struct route_table_entry *rtable;
int rtable_len;


// Creare tabela ARP
struct arp_table_entry *arp_table;
int arp_table_len;

// Functia de compare pentru qsort
int compare(const void *a, const void *b) {
    struct route_table_entry *entryA = (struct route_table_entry *) a;
    struct route_table_entry *entryB = (struct route_table_entry *) b;

    // Sortam crescator dupa prefix
    if ((entryA->prefix & entryA->mask) != (entryB->prefix & entryB->mask)) {
        if ((entryA->prefix & entryA->mask) > (entryB->prefix & entryB->mask))
            return 1;
        else
            return -1;
    }

    // Daca prefixurile sunt egale sortam crescator dupa masca
    if (ntohl(entryA->mask) == ntohl(entryB->mask))
        return 0;
    if (ntohl(entryA->mask) > ntohl(entryB->mask))
        return 1;
    return -1;
}

// Folosim cautare binara pentru a gasit cea mai buna ruta
struct route_table_entry *get_best_route(uint32_t ip_dest) {
    long left = 0, right = rtable_len - 1, mid;

    struct route_table_entry *candidate = NULL;

    while (left <= right) {
        mid = left + (right - left) / 2;

        // Verificam daca ip_dest este prefixul pe care il cautam
        if (((ip_dest & rtable[mid].mask) == (rtable[mid].prefix & rtable[mid].mask))) {
            candidate = &rtable[mid];
            long temp_mid = mid + 1;
            // cautam la dreapta prefixul cu cea mai mare masca
            if (temp_mid != rtable_len)
                while (temp_mid < rtable_len) {
                    if (ntohl(rtable[temp_mid].mask) > ntohl(candidate->mask)
                        && (rtable[temp_mid].prefix & rtable[temp_mid].mask) == (ip_dest & rtable[temp_mid].mask)) {
                        candidate = &rtable[temp_mid];
                    }
                    temp_mid++;
                }
            return candidate;
        } else if ((rtable[mid].prefix & rtable[mid].mask) > (ip_dest & rtable[mid].mask)) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }
    return candidate;
}

// Functie pentru a cauta o intrare in tabela ARP
struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
    // Parcurgem tabela si vedem daca gasim ip-ul
    for (int i = 0; i < arp_table_len; i++) {
        if (given_ip == arp_table[i].ip)
            return &arp_table[i];
    }
    return NULL;
}

// Trimitem ICMP
void send_icmp(struct iphdr *old_ip_hdr, int inetrface, char old_buf[], struct ether_header *old_eth_hdr, uint8_t type, uint8_t code) {

    // Luam ether_header si iphdr din pachetul primit
    struct ether_header *new_eth_hdr = (struct ether_header *) old_buf;
    struct iphdr *new_ip_hdr = old_ip_hdr;
    struct icmphdr *icmp_hdr = (struct icmphdr *) (old_buf + sizeof(struct ether_header) + sizeof(struct iphdr));

    // Schimbam destinatia si sursa pentru ether_header
    memcpy(new_eth_hdr->ether_dhost, old_eth_hdr->ether_shost, ETH_ALEN);
    memcpy(new_eth_hdr->ether_shost, old_eth_hdr->ether_dhost, ETH_ALEN);
    new_eth_hdr->ether_type = htons(0x0800);

    // Daca e echo request
    if (type == 8) {
        // Setam tipul de echo reply
        icmp_hdr->type = 0;
        icmp_hdr->code = 0;

        // Calculam checksum
        icmp_hdr->checksum = 0;
        icmp_hdr->checksum = htons(checksum((uint16_t *) icmp_hdr, sizeof(struct icmphdr)));

        // Schimbam destinatia si sursa pentru iphdr
        new_ip_hdr->daddr = old_ip_hdr->saddr;
        new_ip_hdr->saddr = inet_addr(get_interface_ip(inetrface));

        // Trimitem pachetul
        send_to_link(inetrface, old_buf, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
        return;
    }

    // Cream un nou pachet
    char new_buf[MAX_PACKET_LEN];

    new_eth_hdr = (struct ether_header *) new_buf;
    new_ip_hdr = (struct iphdr *) (new_buf + sizeof(struct ether_header));
    icmp_hdr = (struct icmphdr *) (new_buf + sizeof(struct ether_header) + sizeof(struct iphdr));

    // Setam destinatia si sursa pentru ether_header
    memcpy(new_eth_hdr->ether_dhost, old_eth_hdr->ether_shost, ETH_ALEN);
    memcpy(new_eth_hdr->ether_shost, old_eth_hdr->ether_dhost, ETH_ALEN);
    new_eth_hdr->ether_type = htons(0x0800);

    // Setam tipul si codul pentru ICMP
    icmp_hdr->type = type;
    icmp_hdr->code = code;

    // Calculam checksum
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = htons(checksum((uint16_t *) icmp_hdr, sizeof(struct icmphdr)));


    // Setam noul ip_hdr

    new_ip_hdr->tos = 0;
    new_ip_hdr->frag_off = 0;
    new_ip_hdr->ihl = 5;
    new_ip_hdr->id = htons(0);

    new_ip_hdr->version = 4;
    new_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    new_ip_hdr->ttl = 64;
    new_ip_hdr->protocol = IPPROTO_ICMP;

    // Setam sursa si destinatia
    new_ip_hdr->saddr = inet_addr(get_interface_ip(inetrface));
    new_ip_hdr->daddr = old_ip_hdr->saddr;

    // Calculam checksum
    new_ip_hdr->check = 0;
    new_ip_hdr->check = htons(checksum((uint16_t *) new_ip_hdr, sizeof(struct iphdr)));

    // Trimitem pachetul
    send_to_link(inetrface, new_buf, sizeof(struct ether_header) + sizeof(struct iphdr) + 8);
}

// Trimitem ARP
void send_arp(int interface, uint16_t op, struct ether_header *old_eth_hdr, uint32_t next_hop) {

    // Cream un nou pachet ARP
    char buf[MAX_PACKET_LEN];
    struct ether_header *eth_hdr = (struct ether_header *) buf;
    struct arp_header *arp_hdr = (struct arp_header *) (buf + sizeof(struct ether_header));

    // Setam ARP header
    arp_hdr->htype = htons(1);
    arp_hdr->hlen = 6;
    arp_hdr->ptype = htons(0x0800);
    arp_hdr->plen = 4;
    arp_hdr->op = htons(op);

    // Daca trebuie sa trimitem reply
    if (arp_hdr->op == htons(2)) {

        // Setam ether header
        memcpy(eth_hdr->ether_dhost, old_eth_hdr->ether_shost, ETH_ALEN);
        get_interface_mac(interface, eth_hdr->ether_shost);
        eth_hdr->ether_type = htons(0x0806);

        // Setam soursa pentru ARP
        memcpy(arp_hdr->sha, eth_hdr->ether_shost, ETH_ALEN);
        arp_hdr->spa = inet_addr(get_interface_ip(interface));

        // Setam destinatia pentru ARP
        memcpy(arp_hdr->tha, old_eth_hdr->ether_shost, ETH_ALEN);
        arp_hdr->tpa = next_hop;

        // Trimitem pachetul
        send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct arp_header));
        return;
    }

    // Daca trebuie sa trimitem request

    // Setam ether header
    memset(eth_hdr->ether_dhost, 0xff, ETH_ALEN);
    get_interface_mac(interface, eth_hdr->ether_shost);
    eth_hdr->ether_type = htons(0x0806);

    // Setam sursa pentru ARP
    memcpy(arp_hdr->sha, eth_hdr->ether_shost, ETH_ALEN);
    arp_hdr->spa = inet_addr(get_interface_ip(interface));

    // Setam destinatia pentru ARP
    memset(arp_hdr->tha, 0xff, ETH_ALEN);
    arp_hdr->tpa = next_hop;

    // Trimitem pachetul
    send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct arp_header));
}

int main(int argc, char *argv[]) {
    char buf[MAX_PACKET_LEN];

    // Do not modify this line
    init(argc - 2, argv + 2);

    // Initializare tabela de rutare
    rtable = malloc(sizeof(struct route_table_entry) * 70000);
    DIE(rtable == NULL, "memoryRTABLE");
    rtable_len = read_rtable(argv[1], rtable);
    qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare);

    // Initializare tabela ARP
    arp_table = malloc(sizeof(struct arp_table_entry) * 10000);
    DIE(arp_table == NULL, "memoryARP");

    // Cozi pentru ARP
    queue wait_queue_buf = queue_create();
    queue wait_queue_len = queue_create();
    queue wait_queue_interface = queue_create();
    arp_table_len = 0;

    while (1) {

        int interface;
        size_t len;

        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");

        struct ether_header *eth_hdr = (struct ether_header *) buf;
        /* Note that packets received are in network order,
        any header field which has more than 1 byte will need to be conerted to
        host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
        sending a packet on the link, */

        struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));

        // Daca primim mesaj ICMP
        if (ip_hdr->protocol == IPPROTO_ICMP && ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
            send_icmp(ip_hdr, interface, buf, eth_hdr, 8, 0);
            continue;
        }

        // Daca primim ARP
        if (eth_hdr->ether_type == htons(0x0806)) {

            // Luam ARP Header
            struct arp_header *arp_hdr = (struct arp_header *) (buf + sizeof(struct ether_header));

            // Adaugam in cache-ul APR-ului daca nu era deja
            if (get_arp_entry(arp_hdr->spa) == NULL) {
                arp_table[arp_table_len].ip = arp_hdr->spa;
                memcpy(arp_table[arp_table_len].mac, arp_hdr->sha, ETH_ALEN);
                arp_table_len++;
            }

            // Am primit ARP Request
            if (arp_hdr->op == htons(1))
                // Trimitem ARP Reply
                send_arp(interface, 2, eth_hdr, arp_hdr->spa);

            // Am primit ARP Reply
            if (arp_hdr->op == htons(2)) {
                if (queue_empty(wait_queue_buf))
                    continue;

                // Luam pachetul din coada si datele despre el
                char *packet = queue_deq(wait_queue_buf);
                size_t *len_packet = queue_deq(wait_queue_len);
                int *interface_packet = queue_deq(wait_queue_interface);

                // Luam Ether Header si ARP Header
                struct ether_header *eth_hdr_packet = (struct ether_header *) packet;
                struct arp_table_entry *arp_entry = get_arp_entry(arp_hdr->spa);

                // Setam datele pentru Ether
                get_interface_mac(*interface_packet, eth_hdr_packet->ether_shost);
                memcpy(eth_hdr_packet->ether_dhost, arp_entry->mac, ETH_ALEN);
                eth_hdr_packet->ether_type = htons(0x0800);

                // Trimitem pachetul
                send_to_link(*interface_packet, packet, *len_packet);
            }
            continue;
        }

        // Verificare checksum
        if (checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)) != 0) {
            continue;
        }

        // Verificare TTL
        if (ip_hdr->ttl <= 1) {
            // Trimitere mesaj ICMP "Time exceeded"
            send_icmp(ip_hdr, interface, buf, eth_hdr, 11, 0);
            continue;
        }
        ip_hdr->ttl -= 1;

        // Cautare in tabela de rutare
        struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
        if (best_route == NULL) {
            // Trimitere mesaj ICMP "Destination unreachable"
            send_icmp(ip_hdr, interface, buf, eth_hdr, 3, 0);
            continue;
        }


        // Actualizare checksum
        ip_hdr->check = 0;
        ip_hdr->check = htons(checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)));

        // Verificare daca este in cache-ul ARP-ului
        struct arp_table_entry *arp_entry = get_arp_entry(best_route->next_hop);
        if (arp_entry == NULL) {

            // Alocam memorie dinamica pentru nu a avea referinta pe stiva in cozi
            size_t *len_aux = malloc(sizeof(size_t));
            *len_aux = len;
            char *buf_aux = malloc(len);
            memcpy(buf_aux, buf, len);

            // Adaugam in coada
            queue_enq(wait_queue_interface, &best_route->interface);
            queue_enq(wait_queue_buf, buf_aux);
            queue_enq(wait_queue_len, len_aux);

            // Trimitem ARP Request
            send_arp(best_route->interface, 1, eth_hdr, best_route->next_hop);

            continue;
        }


        // Setam destinatia si sursa pentru ether_header
        memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETH_ALEN);
        get_interface_mac(best_route->interface, eth_hdr->ether_shost);

        // Trimitem pachetul
        send_to_link(best_route->interface, buf, len);
    }
}
