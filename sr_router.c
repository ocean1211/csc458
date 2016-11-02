

/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h" 

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);
  printf("Received packet:\n");
  print_hdrs(packet, len);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

  sr_ethernet_hdr_t *ethernet_hdr;

  if ( len < sizeof(struct sr_ethernet_hdr) ) {
        fprintf(stderr , "** Error: packet is way too short \n");
        return;
  }

  ethernet_hdr = (struct sr_ethernet_hdr *)packet;
  assert(ethernet_hdr);

  /* if the packet is an arp packet */
  if (ethernet_hdr->ether_type == htons(ethertype_arp)) {
    sr_handle_arp_pkt(sr, packet, len, interface);    
  }

  /* if the packet is an ip packet */
  if (ethernet_hdr->ether_type == htons(ethertype_ip)) {
    sr_handle_ip_pkt(sr, packet, len, interface);
  }

  return;
}/* end sr_handlepacket */

/* helper function for sr_handlepacket()
 * if the packet is an arp packet */
int sr_handle_arp_pkt(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface)
{
  if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr)) {
        fprintf(stderr , "** Error: packet is way too short \n");
        return -1;
  }

  sr_arp_hdr_t *arp_hdr;
  arp_hdr = (struct sr_arp_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
  assert(arp_hdr);
  struct sr_if* iface = sr_get_interface(sr, interface);
  assert(iface);

  /* check if the arp is for me */
  if (arp_hdr->ar_tip != iface->ip) {
    return 0;
  }

  /* if the arp is an arp request and target ip is me */
  if (arp_hdr->ar_op == htons(arp_op_request)) {  
    sr_handle_arp_request(sr, packet, len, interface);
  }

  /* if the arp is an arp reply to me */
  if (arp_hdr->ar_op == htons(arp_op_reply)) {
    sr_handle_arp_reply(sr, packet, len, interface);
  }  

  return 0;
} /* end sr_handle_arp_pkt */

/* handle arp request to me */
void sr_handle_arp_request(struct sr_instance* sr,
        uint8_t * packet, 
        unsigned int len,
        char* interface) 
{
  sr_ethernet_hdr_t *ethernet_hdr;
  sr_arp_hdr_t *arp_hdr;
  struct sr_if* iface;
  uint8_t *sr_pkt;

  iface = sr_get_interface(sr, interface);
  assert(iface);
  /* make a copy of the packet */
  sr_pkt = (uint8_t *)malloc(len);
  memcpy(sr_pkt, packet, len);  

  ethernet_hdr = (sr_ethernet_hdr_t *)sr_pkt;
  arp_hdr = (sr_arp_hdr_t *)(sr_pkt + sizeof(struct sr_ethernet_hdr));
  assert(ethernet_hdr);
  assert(arp_hdr);

  /* update arp header */
  arp_hdr->ar_op = htons(arp_op_reply);
  memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
  arp_hdr->ar_tip = arp_hdr->ar_sip;    
  memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
  arp_hdr->ar_sip = iface->ip;

  /* update ethernet header */
  memcpy(ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(ethernet_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

  printf("Send packet:\n");
  print_hdrs(sr_pkt, len);
  sr_send_packet(sr, sr_pkt, len, interface);
  free(sr_pkt);

  return;
} /* end sr_handle_arp_request */

/* handle arp reply to me */
void sr_handle_arp_reply(struct sr_instance* sr,
        uint8_t * packet, 
        unsigned int len,
        char* interface) 
{  
  sr_arp_hdr_t *arp_hdr;  
  arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr));
  assert(arp_hdr);  

  /* cache the arp reply */
  struct sr_arpreq *req;
  req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);

  /* forward packets waiting on this arp reply */
  if (req) {
    sr_ethernet_hdr_t *ethernet_hdr;

    sr_ip_hdr_t *ip_hdr;

    struct sr_if* o_iface; /* outgoing interface */
    struct sr_packet *pkt;   
    for (pkt = req->packets; pkt; pkt = pkt->next) {
      o_iface = sr_get_interface(sr, pkt->iface);
      assert(o_iface);
      /* update ethernet header */
      ethernet_hdr = (sr_ethernet_hdr_t *)(pkt->buf);
      memcpy(ethernet_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      memcpy(ethernet_hdr->ether_shost, o_iface->addr, ETHER_ADDR_LEN);
        
      /* update ip header */

      ip_hdr = (struct sr_ip_hdr *)(pkt->buf + sizeof(struct sr_ethernet_hdr));

      ip_hdr->ip_ttl--;
      bzero(&(ip_hdr->ip_sum), 2);
      uint16_t ip_cksum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));
      ip_hdr->ip_sum = ip_cksum;

      printf("Send packet:\n");
      print_hdrs(pkt->buf, pkt->len);
      sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
    }

    sr_arpreq_destroy(&(sr->cache), req);
  }
  
  return;
} /* end sr_handle_arp_reply */

/* if the packet is an ip packet */
int sr_handle_ip_pkt(struct sr_instance* sr,
        uint8_t * packet, 
        unsigned int len,
        char* interface) 
{
  if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)) {
        fprintf(stderr , "** Error: packet is way to short \n");
        return -1;
  }

  sr_ip_hdr_t *ip_hdr;
  ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr));
  assert(ip_hdr);  

  /* verify ip header checksum */  
  if (cksum(ip_hdr, sizeof(struct sr_ip_hdr)) != 0xffff) {
    fprintf(stderr , "** Error: ip_packet received with error\n");
    return -1;
  }

  struct sr_if* iface = sr_get_interface(sr, interface);
  assert(iface);

  /* if the ip packet is for me */
  struct sr_if *my_iface;
  for (my_iface = sr->if_list; my_iface != NULL; my_iface = my_iface->next){
    if (ip_hdr->ip_dst == my_iface->ip) {
      sr_handle_icmp_pkt(sr, packet, len, interface);
      return 0;
    }
  }

  /*
  if (ip_hdr->ip_dst == iface->ip) {
    sr_handle_icmp_pkt(sr, packet, len, interface);
  }
  */

  /* if it is not for me and its ttl greater than 1 */
  if (ip_hdr->ip_ttl > 1) {
    sr_forward_ip_pkt(sr, packet, len, interface);
  }
  /* if it is not for me and ttl equal or less than 1,
   * drop the packet and send an icmp message to source ip */
  else {
    sr_icmp_dest_unreachable(sr, packet, len, interface, 11, 0);
    fprintf(stderr , "** Error: packet received with time exceeded\n");
    return -1;
  }

  return 0;
} /* end sr_handle_ip_pkt */


/* handle icmp message */
int sr_handle_icmp_pkt(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface)
{
  sr_ethernet_hdr_t *ethernet_hdr;
  sr_ip_hdr_t *ip_hdr;
  sr_icmp_hdr_t *icmp_hdr;
  struct sr_if* iface = sr_get_interface(sr, interface);  
  assert(iface);

  ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
  /* if it is an icmp echo request for me */
  if (ip_hdr->ip_p == ip_protocol_icmp) {
    /* sanity check */
    if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + 
              sizeof(struct sr_icmp_hdr)) {
        fprintf(stderr , "** Error: packet is way too short \n");
        return -1;
    }

    icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr) +
        sizeof(struct sr_ip_hdr));      
  
    if (cksum(icmp_hdr, len - sizeof(struct sr_ethernet_hdr) - 
              sizeof(struct sr_ip_hdr)) != 0xffff) {
      fprintf(stderr , "** Error: icmp_packet received with error\n");
      return -1;

    }

    if (icmp_hdr->icmp_type == 8) {  /* icmp echo request */
      /* make a copy of the packet */
      uint8_t *sr_pkt = (uint8_t *)malloc(len);
      memcpy(sr_pkt, packet, len);

      /* update icmp header */
      uint16_t icmp_cksum;
      icmp_hdr = (sr_icmp_hdr_t *)(sr_pkt + sizeof(struct sr_ethernet_hdr) +
              sizeof(struct sr_ip_hdr));
      icmp_hdr->icmp_type = 0;  /* set icmp type to echo reply */
      bzero(&(icmp_hdr->icmp_sum), 2);
      icmp_cksum = cksum(icmp_hdr, len - sizeof(struct sr_ethernet_hdr) - 
              sizeof(struct sr_ip_hdr));
      icmp_hdr->icmp_sum = icmp_cksum;

      /*update ip header */
      ip_hdr = (sr_ip_hdr_t *)(sr_pkt + sizeof(struct sr_ethernet_hdr));
      
      uint32_t reply_src;
      reply_src = ip_hdr->ip_dst;
      ip_hdr->ip_dst = ip_hdr->ip_src;
      ip_hdr->ip_src = reply_src;
      /* LPM */
      struct sr_rt *rtable;
      rtable = sr_longest_prefix_match(sr, ip_hdr->ip_dst);
      if (rtable->gw.s_addr) {
        struct sr_if *o_iface = sr_get_interface(sr, rtable->interface);
        ip_hdr->ip_p = ip_protocol_icmp;
        ip_hdr->ip_ttl = 0xff;
        bzero(&(ip_hdr->ip_sum), 2);
        uint16_t ip_cksum = cksum(ip_hdr, 4*(ip_hdr->ip_hl));
        ip_hdr->ip_sum = ip_cksum;

        /* check arp cache for next hop mac */
        struct sr_arpentry *arp_entry; 
        arp_entry = sr_arpcache_lookup(&(sr->cache), rtable->gw.s_addr);

        /*arp cache hit */
        if (arp_entry) {
          /* update ethernet header */
          ethernet_hdr = (sr_ethernet_hdr_t *)sr_pkt;
          memcpy(ethernet_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN); 
          memcpy(ethernet_hdr->ether_shost, o_iface->addr, ETHER_ADDR_LEN);         

          /* send icmp echo reply packet */
          printf("Send packet:\n");
          print_hdrs(sr_pkt, len);
          sr_send_packet(sr, sr_pkt, len, rtable->interface);
        }

        /* arp miss */
        else {
          uint8_t *arp_packet = construct_arp_buff(o_iface->addr,  o_iface->ip, rtable->gw.s_addr);
          sr_send_packet(sr, arp_packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr), rtable->interface);
          sr_arpcache_queuereq(&(sr->cache), rtable->gw.s_addr, sr_pkt, len, rtable->interface);
        }      
      }

      free(sr_pkt);
    }
  } 
  
  else if ((len > (sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr))) &&
    ((ip_hdr->ip_p == 0x0006) || (ip_hdr->ip_p == 0x0011))) {  
    /* icmp port unreachable */
    sr_icmp_dest_unreachable(sr, packet, len, interface, 3, 3);
  }  

  return 0;
} /* end sr_handle_icmp_pkt */


/* send icmp destination unreachable message */
void sr_icmp_dest_unreachable(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface,
        uint8_t icmp_type,     
        uint8_t icmp_code)
{
  sr_ethernet_hdr_t *ethernet_hdr;
  sr_ip_hdr_t *ip_hdr;
  sr_icmp_t3_hdr_t *icmp_t3_hdr;
  struct sr_if* iface = sr_get_interface(sr, interface);
  assert(iface);
  unsigned int pkt_len;

  /* construct the icmp packet */
  pkt_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
  uint8_t *sr_pkt = (uint8_t *)malloc(pkt_len);
  memcpy(sr_pkt, packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

  /* update icmp header */
  icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(sr_pkt + sizeof(struct sr_ethernet_hdr) + 
    sizeof(struct sr_ip_hdr));
  icmp_t3_hdr->icmp_type = icmp_type;
  icmp_t3_hdr->icmp_code = icmp_code;
  bzero(&(icmp_t3_hdr->icmp_sum), 2);
  bzero(&(icmp_t3_hdr->unused), 2);
  bzero(&(icmp_t3_hdr->next_mtu), 2);
  memcpy(icmp_t3_hdr->data, packet + sizeof(struct sr_ethernet_hdr), ICMP_DATA_SIZE);
  uint16_t icmp_cksum = cksum(icmp_t3_hdr, sizeof(struct sr_icmp_t3_hdr));
  icmp_t3_hdr->icmp_sum = icmp_cksum;

  /* update ip header */ 
  ip_hdr = (sr_ip_hdr_t *)(sr_pkt + sizeof(struct sr_ethernet_hdr));

  /* Drop packet if ip_src is me */
  struct sr_if *my_iface;
  for (my_iface = sr->if_list; my_iface != NULL; my_iface = my_iface->next){
    if (my_iface->ip == ip_hdr->ip_src){
      return;
    }
  }
  
  if (icmp_code == 3){
    uint32_t reply_src;
    reply_src = ip_hdr->ip_dst;
    ip_hdr->ip_dst = ip_hdr->ip_src;
    ip_hdr->ip_src = reply_src;
  }
  else{
    ip_hdr->ip_dst = ip_hdr->ip_src;
    ip_hdr->ip_src = iface->ip;
  }
  ip_hdr->ip_ttl = 0xff;
  ip_hdr->ip_p = ip_protocol_icmp;
  bzero(&(ip_hdr->ip_sum), 2);
  uint16_t ip_cksum = cksum(ip_hdr, 4*(ip_hdr->ip_hl));
  ip_hdr->ip_sum = ip_cksum;

  /* update ethernet header */
  ethernet_hdr = (sr_ethernet_hdr_t *)sr_pkt;
  memcpy(ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(ethernet_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

  /* send icmp packet */
  printf("Send packet:\n");
  print_hdrs(sr_pkt, pkt_len);
  sr_send_packet(sr, sr_pkt, pkt_len, interface);
  free(sr_pkt);
  fprintf(stderr , "** Error: destination unreachable with error code %d.\n", icmp_code);

  return;
} /* sr_icmp_dest_unreachable */

/* forward ip packet */
void sr_forward_ip_pkt(struct sr_instance* sr,
        uint8_t  *packet, 
        unsigned int len,
        char* interface) 
{
  sr_ethernet_hdr_t *ethernet_hdr;
  sr_ip_hdr_t *ip_hdr;  

  ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr));
  assert(ip_hdr);

  uint32_t ip_dest;
  ip_dest = ip_hdr->ip_dst;

  /* lookup the longest prefix match */
   struct sr_rt *rtable = sr_longest_prefix_match(sr, ip_dest);

  /* if no match, icmp net unreachable */
  if (! rtable->gw.s_addr) {
    sr_icmp_dest_unreachable(sr, packet, len, interface, 3, 0);
    return;
  }
  /* match */
  else {   
    struct sr_if* o_iface = sr_get_interface(sr, rtable->interface);
    assert(o_iface);

    /* make a copy of the packet */
    uint8_t *sr_pkt = (uint8_t *)malloc(len);
    memcpy(sr_pkt, packet, len);

    /* check arp cache for next hop mac */
    struct sr_arpentry *arp_entry; 
    arp_entry = sr_arpcache_lookup(&(sr->cache), rtable->gw.s_addr);

    /*arp cache hit */
    if (arp_entry) {
      /* update ethernet header */
      ethernet_hdr = (sr_ethernet_hdr_t *)sr_pkt;
      memcpy(ethernet_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN); 
      memcpy(ethernet_hdr->ether_shost, o_iface->addr, ETHER_ADDR_LEN); 
    
      /* update ip header */
      ip_hdr = (sr_ip_hdr_t *)(sr_pkt + sizeof(struct sr_ethernet_hdr));
      ip_hdr->ip_ttl--;
      bzero(&(ip_hdr->ip_sum), 2);  
      uint16_t ip_cksum = cksum(ip_hdr, 4*(ip_hdr->ip_hl));
      ip_hdr->ip_sum = ip_cksum;      

      /* send frame to next hop */
      printf("Send packet:\n");
      print_hdrs(sr_pkt, len);
      sr_send_packet(sr, sr_pkt, len, rtable->interface);
      free(arp_entry);
    }    
    /* arp miss */
    else {
      sr_arpcache_queuereq(&(sr->cache), rtable->gw.s_addr, packet, len, rtable->interface);
    }
    free(sr_pkt);
    free(rtable);
  }

  return;
} /* end sr_forward_ip_pkt */

/* Longest prefix match */
struct sr_rt *sr_longest_prefix_match(struct sr_instance* sr, uint32_t ip)
{
  assert(sr);
  assert(ip);
  struct sr_rt *rtable = (struct sr_rt *)malloc(sizeof(struct sr_rt));
  rtable->gw.s_addr = 0;
  rtable->mask.s_addr = 0;

  struct sr_rt *rt;
  for (rt = sr->routing_table; rt != NULL; rt = rt->next) {
    if (((ip & rt->mask.s_addr) == rt->dest.s_addr) && 
        (rt->mask.s_addr > rtable->mask.s_addr)) {
      memcpy(rtable, rt, sizeof(struct sr_rt));      
    }
  }

  return rtable;
} /* end sr_longest_prefix_match */



