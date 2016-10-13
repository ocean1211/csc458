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

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

  sr_ethernet_hdr_t *ethernet_hdr = 0;

  if ( len < sizeof(struct sr_ethernet_hdr) ) {
        fprintf(stderr , "** Error: packet is way to short \n");
        return -1;
  }

  ethernet_hdr = (struct sr_ethernet_hdr *)packet;
  assert(ethernet_hdr);

  // if the packet is an arp packet
  if (ethernet_hdr->ether_type == htons(ethertype_arp)) {
    sr_handle_arp_pkt(sr, packet, len, interface);    
  }

  // if the packet is an ip packet
  if (ethernet_hdr->ether_type == htons(ethertype_ip)) {
    sr_handle_ip_pkt(sr, packet, len, interface);
  }

  return;
}/* end sr_handlepacket */

/* helper function for sr_handlepacket() */
/* if the packet is an arp packet */
void sr_handle_arp_pkt(struct sr_instance* sr,
        uint8_t * packet, 
        unsigned int len,
        char* interface) 
{
  if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr)) {
        fprintf(stderr , "** Error: packet is way to short \n");
        return -1;
  }

  sr_arp_hdr_t *arp_hdr;
  arp_hdr = (struct sr_arp_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
  assert(arp_hdr);

  // if the arp is an arp request
  if (arp_hdr->ar_op == htons(arp_op_request)) {
    sr_handle_arp_request(sr, packet, len, interface);
  }

  //if the arp is an arp reply
  if (arp_hdr->ar_op == htons(arp_op_reply)) {
    sr_handle_arp_reply(sr, packet, len, interface);
  }

  return;
} /* end sr_handle_arp_pkt */

/* handle arp request packet */
void sr_handle_arp_request(struct sr_instance* sr,
        uint8_t * packet, 
        unsigned int len,
        char* interface) 
{
  sr_ethernet_hdr_t *ethernet_hdr = 0;
  sr_arp_hdr_t *arp_hdr = 0;
  struct sr_if* iface = sr_get_interface(sr, interface);
  assert(iface);
  // make a copy of the packet
  uint8_t *sr_pkt = (uint8_t *)malloc(len);
  memcpy(sr_pkt, packet, len);  

  ethernet_hdr = (sr_ethernet_hdr *)sr_pkt;
  arp_hdr = (sr_arp_hdr *)(sr_pkt + sizeof(struct sr_ethernet_hdr));
  assert(ethernet_hdr);
  assert(arp_hdr);

  if (arp_hdr->ar_tip == iface->ip) {
    // update arp header
    arp_hdr->ar_op = htons(arp_op_reply);
    strncpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    strncpy(arp_hdr->ar_tip, arp_hdr->ar_sip, 4);    
    strncpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
    strncpy(arp_hdr->ar_sip, iface->ip, 4);

    // update ethernet header
    strncpy(ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
    strncpy(ethernet_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

    sr_send_packet(sr, sr_pkt, len, interface);
    free(sr_pkt);
  }  

  return;
} /* end sr_handle_arp_request */

/* handle arp reply packet */
void sr_handle_arp_reply(struct sr_instance* sr,
        uint8_t * packet, 
        unsigned int len,
        char* interface) 
{
  sr_ethernet_hdr_t *ethernet_hdr;
  sr_ip_hdr_t ip_hdr;
  sr_arp_hdr_t *arp_hdr;
  arp_hdr = (sr_arp_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
  struct sr_if* iface = sr_get_interface(sr, interface);
  assert(arp_hdr);
  assert(iface);

  if (arp_hdr->ar_tip == iface->ip) {
    struct sr_arpreq *req;
    req = sr_arpcache_insert(sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

    if (req) {
      struct sr_packet *pkt;   
      for (pkt = req->packets; pkt; pkt = pkt->next) {
        // update ethernet header
        ethernet_hdr = (sr_ethernet_hdr_t *)(pkt->buf);
        strncpy(ethernet_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
        strncpy(ethernet_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
        
        // update ip header
        ip_hdr = (sr_ip_hdr *)(pkt->buf + sizeof(struct sr_ethernet_hdr));
        ip_hdr->ip_ttl--;
        bzero(&(ip_hdr->ip_sum), 2);
        uint16_t icmp_cksum = cksum(ip_hdr, 4*(ip_hdr->ip_hl));
        ip_hdr->ip_sum = ip_cksum;

        sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
      }
      sr_arpreq_destroy(sr->cache, req);
    }
  }
  return;
} /* end sr_handle_arp_reply */

/* if the packet is an ip packet */
void sr_handle_ip_pkt(struct sr_instance* sr,
        uint8_t * packet, 
        unsigned int len,
        char* interface) 
{
  if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)) {
        fprintf(stderr , "** Error: packet is way to short \n");
        return -1;
  }

  sr_ip_hdr_t *ip_hdr;
  ip_hdr = (sr_ip_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
  assert(ip_hdr);

  if (ip_hdr->ip_ttl == 0) {
    sr_icmp_dest_unreachable(sr, packet, len, interface, 11, 0);
    fprintf(stderr , "** Error: packet received with time exceeded\n");
    return -1;
  }

  // verify ip header checksum
  uint16_t ip_cksum = ip_hdr->ip_sum;
  bzero(&(ip_hdr->ip_sum), 2);
  if (cksum(ip_hdr, 4*(ip_hdr->ip_hl)) != ip_cksum) {
    fprintf(stderr , "** Error: packet received with error\n");
    return -1;
  }

  struct sr_if* iface = sr_get_interface(sr, interface);  
  assert(iface);

  // if it is for me
  if (ip_hdr->ip_dst == iface->ip) {
    sr_handle_icmp_pkt(sr, packet, len, interface);
  }
  // if it is not for me
  else {
    sr_forward_ip_pkt(sr, packet, len, interface);
  }

  return;
} /* end sr_handle_ip_pkt */


/* handle icmp message */
void sr_handle_icmp_pkt(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface)
{
  sr_ethernet_hdr_t *ethernet_hdr;
  sr_ip_hdr_t *ip_hdr;
  sr_icmp_hdr_t *icmp_hdr;
  struct sr_if* iface = sr_get_interface(sr, interface);  
  assert(iface);

  // if it is an icmp echo request for me
  if (ip_hdr->ip_p == ip_protocol_icmp) {
    icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr) +
        sizeof(struct sr_ip_hdr));
      
    // verify icmp header checksum
    uint16_t icmp_cksum = icmp_hdr->icmp_sum;
    bezero(&(icmp_hdr->icmp_sum), 2);
    if (cksum(icmp_hdr, len - sizeof(struct sr_ethernet_hdr) - 
              sizeof(struct sr_ip_hdr)) != icmp_cksum) {
      fprintf(stderr , "** Error: packet received with error\n");
      return -1;
    }

    if (icmp_hdr->icmp_type == 8) {  // icmp echo request
      // make a copy of the packet
      uint8_t *sr_pkt = (uint8_t *)malloc(len);
      memcpy(sr_pkt, packet, len);

      // update icmp header
      icmp_hdr = (sr_icmp_hdr_t *)(sr_pkt + sizeof(struct sr_ethernet_hdr) +
              sizeof(struct sr_ip_hdr));
      icmp_hdr->icmp_type = 0;  // icmp echo reply
      icmp_cksum = cksum(icmp_hdr, len - sizeof(struct sr_ethernet_hdr) - 
              sizeof(struct sr_ip_hdr));
      icmp_hdr->icmp_sum = icmp_cksum;

      //update ip header
      ip_hdr = (sr_ip_hdr_t *)(sr_pkt + sizeof(struct sr_ethernet_hdr));
      ip_hdr->ip_dst = ip_hdr->ip_src;
      ip_hdr->ip_src = iface->ip;
      ip_hdr->ip_ttl--;
      // ip_hdr->ip_p = ip_protocol_icmp;
      uint16_t ip_cksum = cksum(ip_hdr, 4*(ip_hdr->ip_hl));
      ip_hdr->ip_sum = ip_cksum;

      // update ethernet header
      ethernet_hdr = (sr_ethernet_hdr_t *)sr_pkt;
      strncpy(ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
      strncpy(ethernet_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

      // send icmp echo reply packet
      sr_send_packet(sr, sr_pkt, pkt_len, interface);
      free(sr_pkt);
    }
  } 
  else {
    //
    sr_icmp_dest_unreachable(sr, packet, len, interface, 3, 3);
  }

  return;
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
  sr_icmp_hdr_t *icmp_hdr;
  struct sr_if* iface = sr_get_interface(sr, interface);
  assert(iface);
  unsigned int pkt_len;

  // "The IP header plus the first 8 bytes of the original datagram's data 
  // is returned to the sender. --ICMP protocal RFC792"
  pkt_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + 8;
  uint8_t *sr_pkt = (uint8_t *)malloc(pkt_len);
  memcpy(sr_pkt, packet, pkt_len);

  // update icmp header
  icmp_hdr = (sr_icmp_hdr_t *)(sr_pkt + sizeof(struct sr_ethernet_hdr) +
          sizeof(struct sr_ip_hdr));
  icmp_hdr->icmp_type = icmp_type;
  icmp_hdr->icmp_code = icmp_code;
  uint16_t icmp_cksum = cksum(icmp_hdr, pkt_len - sizeof(struct sr_ethernet_hdr) - 
          sizeof(struct sr_ip_hdr));
  icmp_hdr->icmp_sum = icmp_cksum;

  //update ip header
  ip_hdr = (sr_ip_hdr_t *)(sr_pkt + sizeof(struct sr_ethernet_hdr));
  strncpy(ip_hdr->ip_dst, ip_hdr->ip_src, 4);
  strncpy(ip_hdr->ip_src, iface->ip, 4);
  ip_hdr->ip_ttl--;
  ip_hdr->ip_p = ip_protocol_icmp;
  ip_cksum = cksum(ip_hdr, 4*(ip_hdr->ip_hl));
  uint16_t ip_hdr->ip_sum = ip_cksum;

  // update ethernet header
  ethernet_hdr = (sr_ethernet_hdr_t *)sr_pkt;
  strncpy(ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
  strncpy(ethernet_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

  // send icmp packet
  sr_send_packet(sr, sr_pkt, pkt_len, interface);
  free(sr_pkt);
  fprintf(stderr , "** Error: destination unreachable.\n");

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

  ip_hdr = (sr_ip_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
  assert(ip_hdr);

  uint32_t ip_dst;
  ip_dst = ip_hdr->ip_dst;

  struct sr_rt *rt_entry;
  rt_entry->gw = 0;
  rt_entry->mask = 0;
  // lookup the longest prefix match
  struct sr_rt *rt;
  for (rt = sr->routing_table; rt != NULL; rt = rt->next) {
    if (((ip_dst & rt->mask) == rt->dest) && (rt->mask > rt_entry->mask)){
      rt_entry = rt;
    }
  }

  // if no match
  if (! rt_entry->gw) {
    sr_icmp_dest_unreachable(sr, packet, len, interface, type, code);
    return;
  }
  // match
  else {
    uint32_t gateway = rt_entry->gw;  // next hop ip
    char o_interface[sr_IFACE_NAMELEN];  // outgoing interface
    strncpy(o_interface, rt_entry->interface, sr_IFACE_NAMELEN);
    struct sr_if* o_iface = sr_get_interface(sr, rt_entry->interface);
    assert(iface);

    // make a copy of the packet
    uint8_t *sr_pkt = (uint8_t *)malloc(len);
    memcpy(sr_pkt, packet, len);

    // check arp cache for next hop mac
    struct sr_arpentry *arp_entry; 
    arp_entry = sr_arpcache_lookup(sr->cache, gateway);

    //arp cache hit
    if (arp_entry) {
      strncpy(ethernet_hdr->ether_dhost, arp_entry->mac, 6);
      // send frame to next hop
      sr_send_packet(sr, sr_pkt, len, o_interface);
      free(arp_entry);
    

    // update ip header
    ip_hdr = (sr_ip_hdr *)(sr_pkt + sizeof(struct sr_ethernet_hdr));
    ip_hdr->ip_ttl--;
    bzero(&(ip_hdr->ip_sum), 2);  
    uint16_t icmp_cksum = cksum(ip_hdr, 4*(ip_hdr->ip_hl));
    ip_hdr->ip_sum = ip_cksum;

    // update ethernet header
    ethernet_hdr = (sr_ethernet_hdr_t *)sr_pkt;
    strncpy(ethernet_hdr->ether_shost, o_iface->addr, ETHER_ADDR_LEN);
  }
    
    // arp miss
    else {
      struct sr_arpreq *arp_req;
      arp_req = sr_arpcache_queuereq(&(sr->cache), gateway, sr_pkt, len, o_interface);
      // handle_arpreq(sr->cache, arp_req);
    }
    free(sr_pkt);
    free(o_interface);
  }

  return;
} /* end sr_forward_ip_pkt */

