/**
 *  Copyright (C) 2014-2017 Neoncomputing EURL
 *
 *     This file is part of Kian.
 *
 *     Kian is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     Kian is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with Kian.  If not, see <http://www.gnu.org/licenses/>.
 *     - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
 *
 *  Kian_slip - An ANSI C transport-agnostic slip library
 *
 *  Kian_slip is purely
 *   - easy to embed      : header-only
 *   - portable           : ANSI C
 *   - transport agnostic : based solely on buffers
 *
 *  TODO: overflow on write is checked, but not reported. for now I just give an
 *  array of equal size. (PACKET WILL SURELLY BE SHORTED.)
 */
#ifndef _TINY_SLIP_
#define _TINY_SLIP_

#include <string.h>

#define MAX_PACKET_SIZE 2048
#define SLIP_END 0300     /* indicates end of packet */
#define SLIP_ESC 0333     /* indicates byte stuffing */
#define SLIP_ESC_END 0334 /* ESC ESC_END encodes END data byte */
#define SLIP_ESC_ESC 0335 /* ESC ESC_ESC means ESC data byte */

/**
 * tiny_slip_decode_packet() - reads and decodes a SLIP packet from the left
 * of an input buffer(buf) into an output buffer(pkt_buf).
 *
 * The success can be defined by pkt_len, which will contain the length of the
 * extracted packet, or 0 if no packet was found.
 *
 * In *any case* the function returns the number of bytes that should be
 * left-extracted from the buffer, they might be either the bytes of a packet
 * extracted or padding SLIP_END bytes that were found at the left, in any case
 * they should go.
 *
 * @buf:          the input buffer
 * @buf_len:      size of the input buffer
 * @pkt_buf:      buffer to contain the packet extracted
 * @pkt_buf_len:  size of the buffer to contain the packet extracted
 * @pkt_len:      pointer for the length of the extracted packet (if success)
 *
 * Example :
 *   size_t pack_len = 0;
 *   size_t ext_bytes = tiny_slip_decode_packet(buf, buf_len, pkt_buf, * pkt_buf_len, &pkt_len);
 *   memcpy(buf, buf+ext_bytes, ext_bytes); // shifting anyways
 *   if(pkt_len){
 *      printf("Found a packet of size %lu", pack_buf_len);
 *   }
 *
 * Return : the bytes consumed that should be extracted from
 * the input buffer. (left for the user to do)
 */
size_t kian_slip_dec_pkt(unsigned char *buf, size_t buf_len, unsigned char *pkt_buf,
			 const size_t pkt_buf_len, size_t *pkt_len)
{
	size_t i = 0, recv = 0, left_end_bytes = 0;
	unsigned char c;

	for (i = 0; i < buf_len && recv < pkt_buf_len;) {
		c = buf[i++];
		switch (c) {
		case SLIP_END:
			if (recv) {
				*pkt_len = recv;
				return i;
			}
			left_end_bytes++;
			break;
		case SLIP_ESC:
			if (!(i + 1 < buf_len && recv + 1 < pkt_buf_len)) {
				return 0;
			}
			c = buf[i++];
			switch (c) {
			case SLIP_ESC_END:
				pkt_buf[recv++] = SLIP_END;
				break;
			case SLIP_ESC_ESC:
				pkt_buf[recv++] = SLIP_ESC;
				break;
			}
			break;
		default:
			pkt_buf[recv++] = c;
		}
	}
	*pkt_len = 0;
	return left_end_bytes;
}

/* The content of the buffer is sent to the stream
 * Returns the written bytes.
 *
 *  TODO: overflow on write is checked, but not reported. for now I just give an
 *  array of equal size. (PACKET WILL SURELLY BE SHORTED.)
 */
size_t kian_slip_enc_pkt(unsigned char *in_buf, const size_t in_buf_len, unsigned char *out_buf,
			 const size_t out_buf_len)
{
	size_t i = 0, written = 0;

	/* Implementation simply taken from RFC1055 */
	out_buf[written++] = SLIP_END;
	for (i = 0; i < in_buf_len; i++) {
		unsigned char c = in_buf[i];
		switch (c) {
		case SLIP_END:
			out_buf[written++] = SLIP_ESC;
			out_buf[written++] = SLIP_ESC_END;
			break;
		case SLIP_ESC:
			out_buf[written++] = SLIP_ESC;
			out_buf[written++] = SLIP_ESC_ESC;
			break;
		default:
			out_buf[written++] = c;
		}
	}
	out_buf[written++] = SLIP_END;
	return written;
}

#endif /* _TINY_SLIP_ */
