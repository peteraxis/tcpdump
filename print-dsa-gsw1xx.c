/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/* based on print-dsa.c */

/* \summary: MaxLinear (Ethertype) Distributed Switch Architecture */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "ethertype.h"
#include "addrtoname.h"
#include "extract.h"

/*
 * Ingress and Egress have different formats.
 * Format of (Ethertyped) Ingress tagged frames:
 *
 *      7   6   5   4   3   2   1   0
 *    .   .   .   .   .   .   .   .   .
 *  0 +---+---+---+---+---+---+---+---+
 *    |   Ether Destination Address   |
 * +6 +---+---+---+---+---+---+---+---+
 *    |     Ether Source Address      |
 * +6 +---+---+---+---+---+---+---+---+  +-
 *    |  Prog. DSA Ether Type [15:8]  |  | (8-byte) EDSA Tag
 * +1 +---+---+---+---+---+---+---+---+  | Contains a programmable Ether type.
 *    |  Prog. DSA Ether Type [7:0]   |  |  +
 * +1 +---+---+---+---+---+---+---+---+  |  | (6-byte) Special Tag Content
 *    | ME|TCE|TSE|FNL|  TTC [3:0]    |  |  |
 * +1 +---+---+---+---+---+---+---+---+  |  |
 *    |TEPM Mode  |b29|    Src/Trg Dev|  |  | (4-byte) DSA Tag
 * +1 +---+---+---+---+---+---+---+---+  |  | Contains a DSA tag mode,
 *    |Src/Trg Port/Trunk |b18|b17|b16|  |  | source or target switch device,
 * +1 +---+---+---+---+---+---+---+---+  |  | source or target port or trunk,
 *    | PRI [2:0] |b12|  VID [11:8]   |  |  | and misc (IEEE and FPri) bits.
 * +1 +---+---+---+---+---+---+---+---+  |  |
 *    |           VID [7:0]           |  |  |
 * +1 +---+---+---+---+---+---+---+---+  +- +-
 *    |       Ether Length/Type       |
 * +2 +---+---+---+---+---+---+---+---+
 *    .   .   .   .   .   .   .   .   .
 * Format of (Ethertyped) Egress tagged frames:
 *
 *      7   6   5   4   3   2   1   0
 *    .   .   .   .   .   .   .   .   .
 *  0 +---+---+---+---+---+---+---+---+
 *    |   Ether Destination Address   |
 * +6 +---+---+---+---+---+---+---+---+
 *    |     Ether Source Address      |
 * +6 +---+---+---+---+---+---+---+---+  +-
 *    |  Prog. DSA Ether Type [15:8]  |  | (8-byte) EDSA Tag
 * +1 +---+---+---+---+---+---+---+---+  | Contains a programmable Ether type.
 *    |  Prog. DSA Ether Type [7:0]   |  |  +
 * +1 +---+---+---+---+---+---+---+---+  |  | (6-byte) Special Tag Content
 *    | ME|TCE|TSE|FNL|  TTC [3:0]    |  |  |
 * +1 +---+---+---+---+---+---+---+---+  |  |
 *    |TEPM Mode  |b29|  Src/Trg Dev  |  |  | (4-byte) DSA Tag
 * +1 +---+---+---+---+---+---+---+---+  |  | Contains a DSA tag mode,
 *    |Src/Trg Port/Trunk |b18|b17|b16|  |  | source or target switch device,
 * +1 +---+---+---+---+---+---+---+---+  |  | source or target port or trunk,
 *    | PRI [2:0] |b12|  VID [11:8]   |  |  | and misc (IEEE and FPri) bits.
 * +1 +---+---+---+---+---+---+---+---+  |  |
 *    |           VID [7:0]           |  |  |
 * +1 +---+---+---+---+---+---+---+---+  +- +-
 *    |       Ether Length/Type       |
 * +2 +---+---+---+---+---+---+---+---+
 *    .   .   .   .   .   .   .   .   .
 *
 *
 * Mode: Forward, To_CPU, From_CPU, To_Sniffer
 * b29: (Source or Target) IEEE Tag Mode
 * b18: Forward's Src_Is_Trunk, To_CPU's Code[2], To_Sniffer's Rx_Sniff
 * b17: To_CPU's Code[1]
 * b16: Original frame's CFI
 * b12: To_CPU's Code[0]
 */

#define TOK(tag, byte, mask, shift) ((GET_U_1(&(((const u_char *) tag)[byte])) & (mask)) >> (shift))

#define GSW1XX_ET1(tag) TOK(tag, 0, 0xFF, 0)
#define GSW1XX_ET2(tag) TOK(tag, 1, 0xFF, 0)
#define GSW1XX_PME(tag) TOK(tag, 2, 0x80, 7)  // port map enable
#define GSW1XX_TCE(tag) TOK(tag, 2, 0x40, 6)  // traffic class enable
#define GSW1XX_TSE(tag) TOK(tag, 2, 0x20, 5)  // time stamp enable
#define GSW1XX_FNL(tag) TOK(tag, 2, 0x10, 4)  // force no learning
#define GSW1XX_TTC(tag) TOK(tag, 2, 0x08, 0)  // target traffic class
#define GSW1XX_MAP_LOW(tag) TOK(tag, 3, 0xFF, 0)
#define GSW1XX_MAP_HIGH(tag) TOK(tag, 4, 0xFF, 0)
#define GSW1XX_MAP(tag) ((GSW1XX_MAP_HIGH(tag) << 8) + GSW1XX_MAP_LOW(tag))
// #define GSW1XX_RES(tag) TOK(tag, 5, 0xFF, 0)
#define GSW1XX_LEN_LOW(tag) TOK(tag, 7, 0xFF, 0)
#define GSW1XX_LEN_HIGH(tag) TOK(tag, 6, 0x3F, 0)
#define GSW1XX_LEN(tag) ((GSW1XX_LEN_HIGH(tag) << 8) + GSW1XX_LEN_LOW(tag))
#define GSW1XX_IE(tag) TOK(tag, 5, 0x10, 3)
#define GSW1XX_IPN(tag) TOK(tag, 2, 0x0F, 0) // ingress port number
#define GSW1XX_EG_TC(tag) TOK(tag, 2, 0xF0, 4)
#define GSW1XX_EG_EPN(tag) TOK(tag, 2, 0x0F, 0)
#define GSW1XX_EG_POE(tag) TOK(tag, 2, 0x80, 7)
#define GSW1XX_EG_IV4(tag) TOK(tag, 2, 0x40, 6)
#define GSW1XX_EG_IPO(tag) TOK(tag, 3, 0x3F, 0)

#define EDSA_LEN 8
#define GSW1XX_TAG (0x88c3)
static void
tag_common_print(netdissect_options *ndo, const u_char *p)
{
	if (ndo->ndo_eflag ) {
		int egress = !!GSW1XX_LEN(p);

		if (egress)  {
			ND_PRINT("Egress Port %d,", GSW1XX_IPN(p));
			if (ndo->ndo_eflag > 1) {
				ND_PRINT("TTC %d,", GSW1XX_TTC(p));
				ND_PRINT("TCE %d,", GSW1XX_TCE(p));
				ND_PRINT("TC %d,", GSW1XX_EG_TC(p));
				ND_PRINT("EPN %d,", GSW1XX_EG_EPN(p));
				ND_PRINT("POE %d,", GSW1XX_EG_POE(p));
				if (GSW1XX_EG_IPO(p)) {
					ND_PRINT("IV4 %d,", GSW1XX_EG_IV4(p));
					ND_PRINT("IPO %d,", GSW1XX_EG_IPO(p));
				}
				ND_PRINT("Len %d,", GSW1XX_LEN(p));
			}
		} else {
			ND_PRINT("Ingress Port %d,", GSW1XX_IPN(p));
			ND_PRINT("MAP %d,", GSW1XX_MAP(p));
			if (ndo->ndo_eflag > 1) {
				ND_PRINT("PME %d,", GSW1XX_PME(p));
				ND_PRINT("TCE %d,", GSW1XX_TCE(p));
				ND_PRINT("TTC %d,", GSW1XX_TTC(p));
				ND_PRINT("FNL %d,", GSW1XX_FNL(p));
				ND_PRINT("irq %d,", GSW1XX_IE(p));
			}
		}
	}
}

static void
edsa_tag_print(netdissect_options *ndo, const u_char *bp)
{
	const u_char *p = bp;
	uint16_t edsa_etype;

	edsa_etype = GET_BE_U_2(p);
	if (ndo->ndo_eflag > 2) {
		ND_PRINT("MaxLinear ethertype 0x%04x (%s), ", edsa_etype,
			 tok2str(ethertype_values, "Unknown", edsa_etype));
	} else {
		if (edsa_etype == GSW1XX_TAG)
			ND_PRINT("GSW1XX ");
		else
			ND_PRINT("GSW1XX Unknown 0x%04x, ", edsa_etype);
	}
	tag_common_print(ndo, p);
}

void
edsa_gsw1xx_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h, const u_char *p)
{
	u_int caplen = h->caplen;
	u_int length = h->len;

	ndo->ndo_protocol = "gsw1xx";
	ndo->ndo_ll_hdr_len +=
		ether_switch_tag_print(ndo, p, length, caplen, edsa_tag_print, EDSA_LEN);
}
