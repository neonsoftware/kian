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
 */
#define OS_NONE

#include "kian.h"
#include "test_utils.h"
#include <stdio.h>

static int slip_echo(unsigned char *in_buf, size_t in_buf_len, unsigned char *enc_buf,
		     size_t enc_buf_len)
{
	int dirty_bytes = 0;
	unsigned char packet[MAX_PACKET_SIZE];
	unsigned char packet_in[MAX_PACKET_SIZE];
	size_t w = 0, r = 0, ext = 0;

	memset(packet, 0, MAX_PACKET_SIZE);
	memset(packet_in, 0, MAX_PACKET_SIZE);

	w = kian_slip_enc_pkt(in_buf, in_buf_len, packet, MAX_PACKET_SIZE);
	EXPECT(memcmp(packet, enc_buf, w) == 0);
	while (w++ < MAX_PACKET_SIZE && packet[w] != 0) {
		dirty_bytes++;
	}
	EXPECT(dirty_bytes == 0);
	ext = kian_slip_dec_pkt(packet, w, packet_in, MAX_PACKET_SIZE, &r);
	EXPECT(r == in_buf_len);		   /* legth of read is ok */
	EXPECT(memcmp(packet_in, in_buf, r) == 0); /* rading the same */
	return 0;
}

static int slip_single()
{
	typedef unsigned char uc;
	uc b1[] = {'a', 'b', 'c'};
	uc b1_enc[] = {SLIP_END, 'a', 'b', 'c', SLIP_END};
	uc b2[] = {'a', 'b', SLIP_END, 'c'};
	uc b2_enc[] = {SLIP_END, 'a', 'b', SLIP_ESC, SLIP_ESC_END, 'c', SLIP_END};
	uc b3[] = {'a', 'b', SLIP_ESC, 'c'};
	uc b3_enc[] = {SLIP_END, 'a', 'b', SLIP_ESC, SLIP_ESC_ESC, 'c', SLIP_END};
	uc b4[] = {'a', 'b', SLIP_ESC, 'c', SLIP_END};
	uc b4_enc[] = {SLIP_END, 'a',      'b',		 SLIP_ESC, SLIP_ESC_ESC,
		       'c',      SLIP_ESC, SLIP_ESC_END, SLIP_END};
	EXPECT(slip_echo(b1, sizeof(b1), b1_enc, sizeof(b1_enc)) == 0);
	EXPECT(slip_echo(b2, sizeof(b2), b2_enc, sizeof(b2_enc)) == 0);
	EXPECT(slip_echo(b3, sizeof(b3), b3_enc, sizeof(b3_enc)) == 0);
	EXPECT(slip_echo(b4, sizeof(b4), b4_enc, sizeof(b4_enc)) == 0);
	return 0;
}

static int slip_multiple()
{
	typedef unsigned char uc;

	size_t wm1 = 0, wm2 = 0, r1 = 0, r2 = 0, ext = 0;
	uc buf[2048];
	uc packet[1024];
	uc m1[] = {'a', 'b', SLIP_END, 'c'};
	uc m2[] = {'d', 'e', SLIP_ESC, 'f'};
	uc m_enc[] = {SLIP_END, 'a', 'b', SLIP_ESC, SLIP_ESC_END, 'c', SLIP_END,
		      SLIP_END, 'd', 'e', SLIP_ESC, SLIP_ESC_ESC, 'f', SLIP_END};

	uc m_enc_dirty[] = {SLIP_END,     SLIP_END, SLIP_END, 'a',	  'b',      SLIP_ESC,
			    SLIP_ESC_END, 'c',      SLIP_END, SLIP_END,     SLIP_END, SLIP_END,
			    'd',	  'e',      SLIP_ESC, SLIP_ESC_ESC, 'f',      SLIP_END,
			    SLIP_END,     SLIP_END, 'a'};
	uc *m_enc_dirty_end = m_enc_dirty + sizeof(m_enc_dirty);
	uc open_pck[] = {SLIP_END, SLIP_END, SLIP_END, 'a', 'b'};

	memset(buf, 0, 2048);
	memset(packet, 0, sizeof(packet));

	wm1 = kian_slip_enc_pkt(m1, sizeof(m1), buf, 2048);
	wm2 = kian_slip_enc_pkt(m2, sizeof(m2), buf + wm1, 2048 - wm1);
	EXPECT(wm1);
	EXPECT(wm2);
	EXPECT(sizeof(m_enc) == wm1 + wm2);
	EXPECT(memcmp(buf, m_enc, wm1 + wm2) == 0);

	ext = kian_slip_dec_pkt(m_enc, sizeof(m_enc), packet, 1024, &r1);
	memcpy(m_enc, m_enc + ext, ext);
	EXPECT(r1);
	EXPECT(memcmp(packet, m1, r1) == 0);

	memset(packet, 0, sizeof(packet));
	ext = kian_slip_dec_pkt(m_enc, sizeof(m_enc), packet, 1024, &r2);
	memcpy(m_enc, m_enc + ext, ext);
	EXPECT(r2);
	EXPECT(memcmp(packet, m2, r2) == 0);

	/* testing also the cleaning up */
	memset(packet, 0, sizeof(packet));
	ext = kian_slip_dec_pkt(m_enc_dirty, sizeof(m_enc_dirty), packet, sizeof(packet), &r1);
	EXPECT(ext == 9);
	EXPECT(r1);
	memmove(m_enc_dirty, m_enc_dirty + ext, sizeof(m_enc_dirty) - ext);
	memset(m_enc_dirty_end - ext, SLIP_END, ext);
	EXPECT(memcmp(packet, m1, r1) == 0);

	memset(packet, 0, sizeof(packet));
	ext = kian_slip_dec_pkt(m_enc_dirty, sizeof(m_enc), packet, sizeof(packet), &r2);
	EXPECT(ext == 9);
	EXPECT(r2);
	memmove(m_enc_dirty, m_enc_dirty + ext, sizeof(m_enc_dirty) - ext);
	memset(m_enc_dirty_end - ext, SLIP_END, ext);
	EXPECT(memcmp(packet, m2, r2) == 0);

	memset(packet, 0, sizeof(packet));
	ext = kian_slip_dec_pkt(m_enc_dirty, sizeof(m_enc), packet, sizeof(packet), &r2);
	EXPECT(ext == 4);
	EXPECT(r2 == 1);
	memmove(m_enc_dirty, m_enc_dirty + ext, sizeof(m_enc_dirty) - ext);
	memset(m_enc_dirty_end - ext, SLIP_END, ext);

	/* the open packet */
	memset(packet, 0, sizeof(packet));
	ext = kian_slip_dec_pkt(open_pck, sizeof(open_pck), packet, sizeof(packet), &r2);
	EXPECT(ext == 3);
	EXPECT(r2 == 0);

	return 0;
}

static int io_echo()
{
	size_t to_write = 0, result = 0;
	char fake_network[1024];

	memset(fake_network, 0, sizeof(fake_network));

	to_write = kian_pick_up_output_bytes(fake_network, sizeof(fake_network));
	EXPECT(to_write > 0);
	EXPECT(to_write % 16 == 0);

	result = kian_push_input_bytes(fake_network, to_write);
	EXPECT(result == 1);

	to_write = kian_pick_up_output_bytes(fake_network, sizeof(fake_network));
	EXPECT(to_write == 0); /* out buf is clean this time. */
	return 0;
}

static int send_and_read_back_single()
{
	tosc_message *new_msg = NULL;

	EXPECT(kian_next_message() == NULL);

	EXPECT(kian_write_message("/ceo", "s", "ciao") != 0);
	EXPECT(kian_write_message("/pdg", "s", "bonjour") != 0);

	EXPECT(io_echo() == 0);

	new_msg = kian_next_message();
	EXPECT(new_msg != NULL);
	EXPECT(strcmp("/ceo", tosc_getAddress(new_msg)) == 0);
	EXPECT(strcmp("ciao", tosc_getNextString(new_msg)) == 0);

	new_msg = kian_next_message();
	EXPECT(new_msg != NULL);
	EXPECT(strcmp("/pdg", tosc_getAddress(new_msg)) == 0);
	EXPECT(strcmp("bonjour", tosc_getNextString(new_msg)) == 0);

	EXPECT(kian_next_message() == NULL);
	EXPECT(kian_next_message() == NULL);
	EXPECT(kian_next_message() == NULL);
	return 0;
}

static int send_and_read_back_bundle()
{
	tosc_message *new_msg = NULL;

	EXPECT(kian_next_message() == NULL);

	EXPECT(kian_write_message("/ceo", "s", "hello") != 0);

	kian_start_bundle();
	EXPECT(kian_write_message("/dg", "s", "buongiorno") != 0);
	EXPECT(kian_write_message("/dg", "s", "signor") != 0);
	EXPECT(kian_write_message("/dg", "s", "direttore") != 0);
	EXPECT(kian_end_bundle() != 0);

	EXPECT(kian_write_message("/pdg", "s", "bonjour") != 0);

	EXPECT(io_echo() == 0);

	new_msg = kian_next_message();
	EXPECT(new_msg != NULL);
	EXPECT(strcmp("/ceo", tosc_getAddress(new_msg)) == 0);
	EXPECT(strcmp("hello", tosc_getNextString(new_msg)) == 0);

	new_msg = kian_next_message();
	EXPECT(new_msg != NULL);
	EXPECT(strcmp("/dg", tosc_getAddress(new_msg)) == 0);
	EXPECT(strcmp("buongiorno", tosc_getNextString(new_msg)) == 0);

	new_msg = kian_next_message();
	EXPECT(new_msg != NULL);
	EXPECT(strcmp("/dg", tosc_getAddress(new_msg)) == 0);
	EXPECT(strcmp("signor", tosc_getNextString(new_msg)) == 0);

	new_msg = kian_next_message();
	EXPECT(new_msg != NULL);
	EXPECT(strcmp("/dg", tosc_getAddress(new_msg)) == 0);
	EXPECT(strcmp("direttore", tosc_getNextString(new_msg)) == 0);

	new_msg = kian_next_message();
	EXPECT(new_msg != NULL);
	EXPECT(strcmp("/pdg", tosc_getAddress(new_msg)) == 0);
	EXPECT(strcmp("bonjour", tosc_getNextString(new_msg)) == 0);

	EXPECT(kian_next_message() == NULL);

	return 0;
}

int main()
{
	TEST(slip_single);
	TEST(slip_multiple);
	TEST(send_and_read_back_single);
	TEST(send_and_read_back_single);
	TEST(send_and_read_back_single);
	TEST(send_and_read_back_bundle);
	TEST(send_and_read_back_bundle);
	TEST(send_and_read_back_bundle);
}
