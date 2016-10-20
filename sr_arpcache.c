#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include <string.h>

#include "sr_utils.h"


/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) {
    struct sr_arpreq * temp ;
    struct sr_arpcache* cache;
    cache = & (sr->cache);
    for ( temp=cache->requests; temp != NULL; temp=temp->next) {
         handle_arpreq(sr, temp);
    }
}

/* 
   handle arp requests
*/
void handle_arpreq(struct sr_instance* sr,  struct sr_arpreq* request) {
    /*get the current time */
    time_t now =time(NULL);
    /*get the difference between curren time and time that last time arp request was sent */
    double diff = difftime(now, request->sent);
    /*handle arp request */

     if(diff >= 1.0) {
        /*arp request has been sent for 5 times, send icmp host */
        /*unreachable and destory arp request */
        if(request->times_sent >= 5){
            /*send icmp host unreachable to source addr of all pkts waiting */
            struct sr_packet* wait_packet ;

            /*handle each sr packet */
            for(wait_packet=request->packets; wait_packet != NULL; wait_packet = wait_packet ->next){
                /*get ip header from raw Ethernet*/
             
                struct sr_ip_hdr* ip_header = (struct sr_ip_hdr*)(wait_packet->buf+ sizeof( struct sr_ethernet_hdr));
                uint32_t ip_dest = ip_header -> ip_src;
		
                /*go through interface list, find outer inteface with ip address by longest prefix match */
                struct sr_rt* rtable = sr_longest_prefix_match(sr, ip_dest);
               
                /*send imcp to source addr */
                sr_icmp_dest_unreachable(sr, wait_packet->buf, wait_packet->len, rtable->interface, 3, 1);

             
            }
           /* destory arp request in the queue */
           sr_arpreq_destroy(&(sr->cache), request);
        }
        
        /* increment on field request->sent and update request->times_sent */
        else{
            /*
            send arp request 
            get the outgoing inteface for arp_request packets
            */
            char *iface = request->packets->iface;
            struct sr_if* interface = sr_get_interface(sr, iface);
            /*the MAC address and ip address of the outgoing port */
            uint8_t *ifacemac = (uint8_t *)malloc(ETHER_ADDR_LEN);
            memcpy(ifacemac, interface -> addr, ETHER_ADDR_LEN);
            uint32_t ifaceip =interface -> ip;
            /* the destination ip address */
            uint32_t destip = request->ip;
            uint8_t *arp_packet = construct_arp_buff(ifacemac,  ifaceip, destip);
            printf("Send packet:\n");
            print_hdrs(arp_packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr));
            sr_send_packet(sr, arp_packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr), iface);
            /* free packet buffer */
            free(arp_packet);
            free(ifacemac);
            /*set time and number */
            request -> sent = now;
            request -> times_sent++;
        }
    }
}


/*
construct an ARP buffer(Ethenet Header and APR header)
*/
uint8_t *construct_arp_buff(uint8_t *ifacemac, uint32_t ifaceip, uint32_t destip){
    
            /*construct ARP packet */
            uint8_t *arp_packet = malloc(sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_arp_hdr));
            /* construct an Ethenet header */
            struct sr_ethernet_hdr *Ethenet = (struct sr_ethernet_hdr*)arp_packet;
            Ethenet->ether_dhost[0] = 0xff;
            Ethenet->ether_dhost[1] = 0xff;
            Ethenet->ether_dhost[2] = 0xff;
            Ethenet->ether_dhost[3] = 0xff;
            Ethenet->ether_dhost[4] = 0xff;
            Ethenet->ether_dhost[5] = 0xff;
            /* destination Ethenet address is ff:ff:ff:ff:ff:ff */
            /* uint8_t Edest[ETHER_ADDR_LEN];
            Edest[0] = 0xff;
            Edest[1] = 0xff;
            Edest[2] = 0xff;
            Edest[3] = 0xff;
            Edest[4] = 0xff;
            Edest[5] = 0xff; */
            /* memcpy(Ethenet->ether_dhost, Edest, ETHER_ADDR_LEN);*/
            /* source Ethenet address */
            memcpy(Ethenet->ether_shost, ifacemac, ETHER_ADDR_LEN);
            /* Ethenent type is ARP */
            Ethenet->ether_type = htons(ethertype_arp);  
            /* construct an APR header */
            struct sr_arp_hdr* arp_header = (struct sr_arp_hdr*)(arp_packet + sizeof(struct sr_ethernet_hdr));
            arp_header->ar_hrd = htons(arp_hrd_ethernet);
            arp_header->ar_pro = htons(0x0800);
            arp_header->ar_hln = (unsigned char)ETHER_ADDR_LEN;
            arp_header->ar_pln = (unsigned char)4;
            arp_header->ar_op = htons(arp_op_request);
            memcpy(arp_header -> ar_sha, ifacemac, ETHER_ADDR_LEN);
            /* unsigned char Adest[ETHER_ADDR_LEN]; */
            /* destination Ethenet address is 00:00:00:00:00:00 */
            arp_header -> ar_tha[0]= 0xff;
            arp_header -> ar_tha[1]= 0xff;
            arp_header -> ar_tha[2]= 0xff;
            arp_header -> ar_tha[3]= 0xff;
            arp_header -> ar_tha[4]= 0xff;
            arp_header -> ar_tha[5]= 0xff;
            /*memcpy(arp_header -> ar_tha, Adest, ETHER_ADDR_LEN );*/
            arp_header->ar_sip = ifaceip;
            arp_header->ar_tip = destip;
            return arp_packet;
}




/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

