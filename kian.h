/*
 *     Copyright (C) 2014-2017 Neoncomputing EURL
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
 *  
 *     - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
 * 
 *	   Kian - a transport agnostic single header library for OSC over SLIP
 *
 *     Kian helps you easily reading and writing OSC message encoded with SLIP to and from
 *     any communication mean.
 *     Kian is equipped with its own internal buffers and takes care of both encoding and
 *     decoding SLIP packets and buffering.
 *
 *     Kian is based on 2 libraries :
 *          tinyosc       - by Matin Roth. Implements OSC
 *          slip RFC 1055 - https://tools.ietf.org/html/rfc1055
 *
 *     USAGE EXAMPLE:          (see API for adding error-checking)
 *
 *     -> write single message
 *
 *          kian_write_message("/my_message", "s", "ciao!");
 *
 *     -> write multiple messages as a bundle
 *
 *          kian_start_bundle();
 *          kian_write_message("/ceo", "s", "Hi!");
 *          kian_write_message("/pdg", "s", "Bonjour!");
 *          kian_end_bundle();
 *
 *     <- read message, by pointer
 *
 *          tosc_message *next = kian_next_message();
 *          if(next != NULL) {
 *              printf("Got a msg with addr %s", tosc_getAddress(next));
 *          }
 *
 *     <- read message, by copy. user is owner if destination msg buffer
 *
 *          unsigned char buf[MAX_OSC_MSG_SIZE];
 *          tosc_message msg;       // <-- the user keeps the message
 *          msg.buffer = buf;
 *          msg.len = sizeof(buf);
 *
 *          if(kian_copy_next_message(&msg)){
 *              printf("Got a msg with addr %s", tosc_getAddress(msg));
 *          }
 *
 *     <- Raw bytes I/O : input
 *
 *         unsigned char net_buf[64];               // an imaginary network,
 *         int recv_bytes = net.recv(net_buf, 64);  // or USB operation
 *         if(!kian_push_input_bytes(net_buf, recv_bytes))
 *              printf("Kian was full.\n");
 *
 *     -> Raw bytes I/O : output (note: num of bytes returned is *always multiple of 64*)
 *
 *         unsigned char to_send[64];
 *         int num_bytes = kian_pick_up_output_bytes(to_send, 64);
 *         if(num_bytes){
 *             printf("%d bytes to send\n", num_bytes);
 *             while(num_bytes){
 *                  net.send(to_send, 64);
 *                  num_bytes-=64;
 *             }
 *         }
 *
 *     -- Utility functions
 *
 *         kian_dump_in();
 *         kian_dump_out();
 *
 */

#ifndef kian_h
#define kian_h

#include "kian_slip.h"
#include "tinyosc.h"

/*  ++++++++++++++++++++++++++    API    +++++++++++++++++++++++++++++++++++++   */

/**
 * kian_write_message() - writes an osc message to the queue.
 * @bnd:	The bundle to send.
 *
 * Return: 1 in case of success, 0 otherwise (no space left).
 */
int kian_write_message(const char *address, const char *format, ...);

/**
 * kian_start_bundle() - writes an osc message to the queue.
 */
void kian_start_bundle();

/**
 * kian_end_bundle() - writes an osc message to the queue.
 *
 * Return: 1 in case of success, 0 otherwise (no space left).
 */
int kian_end_bundle();

/**
 * kian_get_next_message() - copies the next message
 * @next:   The destination message. Its memory and ownership is responsible of
 *          the user
 *
 * The pointer message will be available for access until the next call of read
 * operation (either kian_get_next_message or kian_next_message)
 *
 * Return: 1 in case of success, 0 if no message is found.
 */
int kian_get_next_message(tosc_message *next);

/*
 * kian_next_message() - retrieves the pointer to the next message
 *
 * The pointer message will be available for access until the next call of read
 * operation (either kian_get_next_message or kian_next_message)
 *
 * Return: 1 in case of success, 0 if no message is found.
 */
tosc_message *kian_next_message();

/*
 * TODO : document
 */
size_t kian_push_input_bytes(char *buf, size_t len);

/*
 * TODO : document
 */
size_t kian_pick_up_output_bytes(char *buf, size_t len);

/* TODO : document */
void kian_dump_in();
/* TODO : document */
void kian_dump_out();

/* +++++++++++++++++++++++++++    Implementation    ++++++++++++++++++++++++++++++  */

#define KIAN_BUF_SIZE 4096
#define MAX_OSC_MSG_SIZE 64
#define MAX_OSC_BUNDLE_SIZE 640
#define MAX_SLIP_PACKET 1024

static struct kian_data {

	int is_initialized; /* Since field of a static struct, it is initalized to 0 */

	unsigned char in_buf[KIAN_BUF_SIZE]; /* Raw bytes input buffer */
	unsigned char *in_next;
	unsigned char *in_end;
	unsigned char out_buf[KIAN_BUF_SIZE]; /* Raw bytes output buffer */
	unsigned char *out_next;
	unsigned char *out_end;

	tosc_bundle bnd_out; /* The next OSC bundle to be written */
	char bnd_out_buf[MAX_OSC_BUNDLE_SIZE];
	int bnd_out_is_open;

	char bnd_in_buf[MAX_OSC_BUNDLE_SIZE]; /* Holds the last OSC bundle read */
	tosc_bundle bnd_in;
	int bnd_in_is_present;

	char msg_buf[MAX_OSC_MSG_SIZE]; /* Holds the last OSC message read */
	tosc_message msg;

} kian_bag;

void kian_print_buffer(unsigned char *buf, size_t buf_len)
{
	size_t i = 0;
	for (i = 0; i < buf_len; i++) {
		printf("%o ", buf[i]);
	}
	printf("\n");
}

static void kian_init()
{
	/* Init input and output data buffers */
	memset(kian_bag.in_buf, SLIP_END, sizeof(kian_bag.in_buf));
	memset(kian_bag.out_buf, SLIP_END, sizeof(kian_bag.out_buf));
	kian_bag.in_next = kian_bag.in_buf;
	kian_bag.in_end = kian_bag.in_buf + sizeof(kian_bag.in_buf);
	kian_bag.out_next = kian_bag.out_buf;
	kian_bag.out_end = kian_bag.out_buf + sizeof(kian_bag.out_buf);

	/* Resetting the OSC bundle that is used as temprary storage */
	kian_bag.bnd_out_is_open = 0;
	memset(kian_bag.bnd_out_buf, 0, sizeof(kian_bag.bnd_out_buf));
	tosc_writeBundle(&(kian_bag.bnd_out), 0, kian_bag.bnd_out_buf,
			 sizeof(kian_bag.bnd_out_buf));

	/* Resetting the OSC bundle that is used as temprary storage */
	kian_bag.bnd_in_is_present = 0;
	memset(kian_bag.bnd_in_buf, 0, sizeof(kian_bag.bnd_in_buf));
	tosc_writeBundle(&(kian_bag.bnd_in), 0, kian_bag.bnd_in_buf, sizeof(kian_bag.bnd_in_buf));

	/* Resetting the OSC message that is used as temprary storage */
	memset(kian_bag.msg_buf, 0, sizeof(kian_bag.msg_buf));
	kian_bag.msg.buffer = kian_bag.msg_buf;

	kian_bag.is_initialized = 1;
}

static int kian_flush_bnd_to_buf()
{
	/* TODO : here I should need to know, from slip, how many bytes will take. */
	size_t out_bytes_left = kian_bag.out_end - kian_bag.out_next;
	int written_bytes =
	    kian_slip_enc_pkt((unsigned char *)(kian_bag.bnd_out.buffer),
			      kian_bag.bnd_out.bundleLen, kian_bag.out_next, (int)out_bytes_left);
	kian_bag.out_next += written_bytes;

	/* Resetting the OSC bundle that is be used as temprary storage */
	memset(kian_bag.bnd_out_buf, SLIP_END, sizeof(kian_bag.bnd_out_buf));
	tosc_writeBundle(&(kian_bag.bnd_out), 0, kian_bag.bnd_out_buf,
			 sizeof(kian_bag.bnd_out_buf));
	return 1;
}

/* TODO : check that there is space on the bundle for the message */
int kian_write_message(const char *address, const char *format, ...)
{
	tosc_bundle *b = NULL;
	va_list ap;
	uint32_t i;

	if (!kian_bag.is_initialized)
		kian_init();

	b = &kian_bag.bnd_out;

	/* code taken, as it is, from the tosc library. */
	va_start(ap, format);
	if (b->bundleLen >= b->bufLen)
		return 0;
	i = tosc_vwrite(b->marker + 4, b->bufLen - b->bundleLen - 4, address, format, ap);
	va_end(ap);
	encode_32(i, b->marker); /* write the length of the message */
	b->marker += (4 + i);
	b->bundleLen += (4 + i);
	/* end of code taken, as it is, from the tosc library. */

	if (!kian_bag.bnd_out_is_open)
		return kian_end_bundle();

	return 1;
}

void kian_start_bundle()
{
	if (!kian_bag.is_initialized)
		kian_init();

	kian_bag.bnd_out_is_open = true;
}

int kian_end_bundle()
{
	if (!kian_bag.is_initialized)
		kian_init();

	kian_bag.bnd_out_is_open = false;
	return kian_flush_bnd_to_buf();
}

int kian_get_next_message(tosc_message *dst)
{
	tosc_message *next_msg = NULL;

	if (!kian_bag.is_initialized)
		kian_init();

	next_msg = kian_next_message();
	if (next_msg != NULL) {
		tosc_copy_message(dst, next_msg);
		return 1;
	}
	return 0;
}

tosc_message *kian_next_message()
{
	unsigned char slip_pkt[MAX_SLIP_PACKET];
	size_t bytes_present = 0, pkt_len = 0, ext = 0;

	if (!kian_bag.is_initialized)
		kian_init();

	/* Check if a message is available in the lastly extracted bundle. */
	if (kian_bag.bnd_in_is_present) {
		if (tosc_getNextMessage(&kian_bag.bnd_in, &kian_bag.msg))
			return &kian_bag.msg;
		else {
			kian_bag.bnd_in_is_present = 0;
			memset(kian_bag.bnd_in_buf, 0, sizeof(kian_bag.bnd_in_buf));
			tosc_writeBundle(&(kian_bag.bnd_in), 0, kian_bag.bnd_in_buf,
					 sizeof(kian_bag.bnd_in_buf));
		}
	}

	/* Extracting the next slip package */
	memset(slip_pkt, 0, sizeof(slip_pkt));
	bytes_present = kian_bag.in_next - kian_bag.in_buf;
	ext =
	    kian_slip_dec_pkt(kian_bag.in_buf, bytes_present, slip_pkt, sizeof(slip_pkt), &pkt_len);
	memmove(kian_bag.in_buf, kian_bag.in_buf + ext, bytes_present - ext);
	kian_bag.in_next -= ext;

	if (pkt_len) {
		if (tosc_isBundle((char *)slip_pkt)) {
			tosc_bundle temp_bundle;
			tosc_parseBundle(&temp_bundle, (char *)slip_pkt, (int)pkt_len);
			tosc_copy_bundle(&kian_bag.bnd_in, &temp_bundle);
			kian_bag.bnd_in_is_present = 1;
			return kian_next_message();
		} else {
			tosc_message temp_message;
			tosc_parseMessage(&temp_message, (char *)slip_pkt, (int)pkt_len);
			tosc_copy_message(&kian_bag.msg, &temp_message);
			return &kian_bag.msg;
		}
	}
	return NULL;
}

size_t kian_push_input_bytes(char *buf, size_t len)
{
	size_t bytes_left = 0;

	if (!kian_bag.is_initialized)
		kian_init();

	bytes_left = kian_bag.in_end - kian_bag.in_next;
	if (len > bytes_left)
		return 0;

	memcpy(kian_bag.in_next, buf, len);
	kian_bag.in_next += len;
	return 1;
}

size_t kian_pick_up_output_bytes(char *buf, size_t len)
{
	size_t bytes_present = 0, bytes_to_pad = 0, total_bytes = 0;

	if (!kian_bag.is_initialized)
		kian_init();

	bytes_present = kian_bag.out_next - kian_bag.out_buf;
	bytes_to_pad = 64 - (bytes_present % 64);
	total_bytes = bytes_present + bytes_to_pad;

	if (bytes_present == 0 || total_bytes > len)
		return 0;

	memcpy(buf, kian_bag.out_buf, bytes_present);
	memset(buf + bytes_present, SLIP_END, bytes_to_pad);

	kian_bag.out_next -= bytes_present;

	return (unsigned int)total_bytes;
}

void kian_dump_in()
{
	size_t filled = 0;
	unsigned char *p = NULL;
	char *nb = NULL, *nm = NULL;

	if (!kian_bag.is_initialized)
		kian_init();

	filled = kian_bag.in_next - kian_bag.in_buf;
	printf("__ in dump _____ ___ ___ __ __ _\n");

	nb = kian_bag.bnd_in_buf;
	printf("Next bundle present : %s. [%x %x ... ]\n",
	       kian_bag.bnd_in_is_present ? "yes" : "no", *nb, *(nb + 1));
	nm = kian_bag.msg_buf;
	printf("Next message : [%x %x ... ]\n", *nm, *(nm + 1));

	printf("Filled [%ld/%lu]", filled, sizeof(kian_bag.in_buf));
	/* for (p = kian_bag.in_buf; p < kian_bag.in_end; p++) { */
	for (p = kian_bag.in_buf; p < kian_bag.in_buf + 240; p++) {
		if ((p - kian_bag.in_buf) % 16 == 0) {
			printf("\n");
		}

		if (p < kian_bag.in_next)
			printf("%3o ", *p);
		else
			printf("--- ");
	}
	printf("\n_____ ___ ___ __ __ _\n\n");
	fflush(stdout);
}

void kian_dump_out()
{
	size_t filled = 0;
	unsigned char *p = NULL;

	if (!kian_bag.is_initialized)
		kian_init();

	filled = kian_bag.out_next - kian_bag.out_buf;
	printf("__ out dump _____ ___ ___ __ __ _\n");
	printf("Filled [%ld/%lu]", filled, sizeof(kian_bag.out_buf));
	for (p = kian_bag.out_buf; p < kian_bag.out_end; p++) {
		if ((p - kian_bag.out_buf) % 16 == 0) {
			printf("\n");
		}

		if (p < kian_bag.out_next)
			printf("%3o ", *p);
		else
			printf("--- ");
	}
	printf("\n_____ ___ ___ __ __ _\n\n");
	fflush(stdout);
}

#endif /* #ifdef kian_h */
