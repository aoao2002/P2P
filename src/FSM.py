from enum import Enum
import struct
import socket
from collections import defaultdict, namedtuple
import time

MAX_PAYLOAD = 1024
MAGIC = 52305
TEAM = 29
CHUNK_DATA_SIZE = 512 * 1024
HEADER_LEN = struct.calcsize("HBBHHII")
DATA = 3

Timer = namedtuple('Timer', ['seq', 'send_time'])

class State(Enum):
    SLOW_START = 0
    CONGESTION_AVOIDANCE = 1
    FINISHED = 2
    
class Event(Enum):
    DUP_ACK = 0
    NEW_ACK = 1
    TIMEOUT = 2
    THREE_DUP_ACKS = 3
    CWND_TOO_LARGE = 4

class FSM():
    '''
    Finate state machine of peers who have established a connection.
    Initialized when receiving a GET packet from a peer, and expires
    when the whole chunk is successfully sent.
    '''
    def __init__(self, addr, chunkhash_str, chunkdata, timeout, logger) -> None:
        self.__addr = addr                               # peer's address, (ip, port)

        self.__sending_chunkhash_str = chunkhash_str     # the chunkhash str of the chunk being sent to the peer
        self.__sending_chunkdata = chunkdata             # the data of the chunk being sent to the peer

        self.__estimated_RTT = 1                         # estimated RTT, only useful when timeout not set
        self.__dev_RTT = 0                               # RTT deviation, only useful when timeout not set
        if timeout == 0:
            # estimate timeout via RTT
            self.timeout = self.__estimated_RTT
            self.__estimate_timeout = True
        else:
            # use set timeout
            self.timeout = timeout
            self.__original_timeout = timeout
            self.__estimate_timeout = False

        self.__logger = logger

        self.__cwnd = 0                                  # congestion window
        self.__unacked = 1                               # num of sent but unacked pkt
        self.__ssthresh = 64                             # ssthresh
        self.__dup_acks = defaultdict(int)               # duplicate ack num per seq-ack round
        self.__new_acks = 0                              # num of new acks, only used in congestion avoidance
        self.__last_ack = -1                             # the last acked seq
        self.__last_sent = 0                             # the last sent pkt seq

        self.timer = Timer(-1, -1)                       # always times the lask unacked pkt 
        self.state = State.SLOW_START

        # {old state: {event: event handler(sock, pkt) -> new state}}
        self.transition_table = {
            State.SLOW_START: dict(),
            State.CONGESTION_AVOIDANCE: dict()
        } 
        self.__add_event_handler()

    def transit(self, sock, ack_num):
        if ack_num <= self.__last_ack:
            event = Event.DUP_ACK
        else:
            # self.__last_ack = ack_num
            event = Event.NEW_ACK
        self.__logger.debug(f'state: {self.state}, event: {event}')
        self.state = self.transition_table[self.state][event](sock, ack_num)

    def __send_data(self, sock, ack_num):
        # estimate RTT
        if self.timer.seq == ack_num:
            sample_RTT = time.perf_counter() - self.timer.send_time
            if self.__estimate_timeout:
                self.__estimated_RTT = 0.875 * self.__estimated_RTT + 0.125 * sample_RTT
                self.__dev_RTT = 0.75 * self.__dev_RTT + 0.25 * abs(sample_RTT - self.__estimated_RTT)
                self.timeout = self.__estimated_RTT + 4 * self.__dev_RTT
            else:
                self.timeout = self.__original_timeout
        # restart timer
        self.timer = Timer(ack_num + 1, time.perf_counter())
        
        # received a new ACK, send data until cwnd is full
        prev_seq = ack_num # sequence number of last sent packet
        # self.__logger.debug(f'before sending, unacked: {self.__unacked}, cwnd: {self.__cwnd}')
        while self.__unacked < self.__cwnd:
            if prev_seq * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
                # finished
                self.__logger.info(f"finished sending {self.__sending_chunkhash_str}")
                self.state = State.FINISHED
                break
            else:
                left = self.__last_sent * MAX_PAYLOAD
                right = min((self.__last_sent + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                next_data = self.__sending_chunkdata[left: right]
                # send next data
                data_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, DATA, socket.htons(HEADER_LEN),
                                        socket.htons(HEADER_LEN + len(next_data)), socket.htonl(self.__last_sent + 1), 0)
                sock.sendto(data_header + next_data, self.__addr)
                self.__logger.info(f'sent DATA pkt to {self.__addr}, seq: {self.__last_sent + 1}')
                self.__unacked += 1
                self.__last_sent += 1
        # self.__logger.debug(f'finished sending, unacked: {self.__unacked}, cwnd: {self.__cwnd}')

    def __fast_retransmit(self, sock, ack_num):
        left = ack_num * MAX_PAYLOAD
        right = min((ack_num + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
        retransmit_data = self.__sending_chunkdata[left: right]
        # send retransmitted data
        data_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, DATA, socket.htons(HEADER_LEN),
                                    socket.htons(HEADER_LEN + len(retransmit_data)), socket.htonl(ack_num + 1), 0)
        sock.sendto(data_header + retransmit_data, self.__addr)
        self.__logger.info(f'fast retransmit DATA pkt to {self.__addr}, seq: {ack_num + 1}')

    def __timeout_retransmit(self, sock, ack_num):
        left = (self.timer.seq - 1) * MAX_PAYLOAD
        right = min(self.timer.seq * MAX_PAYLOAD, CHUNK_DATA_SIZE)
        retransmit_data = self.__sending_chunkdata[left: right]
        # send retransmitted data
        data_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, DATA, socket.htons(HEADER_LEN),
                                    socket.htons(HEADER_LEN + len(retransmit_data)), socket.htonl(self.timer.seq), 0)
        sock.sendto(data_header + retransmit_data, self.__addr)
        # restart timer
        self.timer = Timer(self.timer.seq, time.perf_counter())
        self.__logger.info(f'timeout retransmit DATA pkt to {self.__addr}, seq: {self.timer.seq}')

    def __add_event_handler(self):
        self.transition_table[State.SLOW_START][Event.DUP_ACK] = self.__slow_start_dup_ack
        self.transition_table[State.SLOW_START][Event.NEW_ACK] = self.__slow_start_new_ack
        self.transition_table[State.SLOW_START][Event.THREE_DUP_ACKS] = self.__slow_start_fast_retransmit
        self.transition_table[State.SLOW_START][Event.TIMEOUT] = self.__slow_start_timeout_retransmit
        self.transition_table[State.SLOW_START][Event.CWND_TOO_LARGE] = self.__slow_start_cwnd_too_large
        self.transition_table[State.CONGESTION_AVOIDANCE][Event.NEW_ACK] = self.__congestion_avoidance_new_ack
        self.transition_table[State.CONGESTION_AVOIDANCE][Event.DUP_ACK] = self.__congestion_avoidance_dup_ack
        self.transition_table[State.CONGESTION_AVOIDANCE][Event.THREE_DUP_ACKS] = self.__congestion_avoidance_fast_retransmit
        self.transition_table[State.CONGESTION_AVOIDANCE][Event.TIMEOUT] = self.__congestion_avoidance_timeout_retransmit

    def __slow_start_dup_ack(self, sock, ack_num):
        self.__dup_acks[ack_num] += 1
        if self.__dup_acks[ack_num] == 3:
            return self.transition_table[State.SLOW_START][Event.THREE_DUP_ACKS](sock, ack_num)
        return State.SLOW_START

    def __slow_start_new_ack(self, sock, ack_num):
        self.__unacked -= (ack_num - self.__last_ack)
        self.__cwnd += (ack_num - self.__last_ack)
        self.__last_ack = ack_num
        # self.__logger.debug(f'slow start new ack, unacked: {self.__unacked}, cwnd: {self.__cwnd}')
        self.__send_data(sock, ack_num)
        if self.__cwnd >= self.__ssthresh:
            return self.transition_table[State.SLOW_START][Event.CWND_TOO_LARGE](sock, ack_num)
        return State.SLOW_START

    def __slow_start_fast_retransmit(self, sock, ack_num):
        self.__ssthresh = max(self.__cwnd // 2, 2)
        self.__cwnd = 1
        self.__fast_retransmit(sock, ack_num)
        return State.SLOW_START

    def __slow_start_timeout_retransmit(self, sock, ack_num):
        self.__ssthresh = max(self.__cwnd // 2, 2)
        self.__cwnd = 1
        self.__timeout_retransmit(sock, ack_num)
        return State.SLOW_START

    def __slow_start_cwnd_too_large(self, sock, ack_num):
        return State.CONGESTION_AVOIDANCE

    def __congestion_avoidance_new_ack(self, sock, ack_num):
        self.__new_acks += (ack_num - self.__last_ack)
        self.__unacked -= (ack_num - self.__last_ack)
        self.__last_ack = ack_num
        if self.__new_acks >= self.__cwnd:
            self.__cwnd += 1
            self.__new_acks = 0
        self.__logger.debug(f'congestion avoidance new ack, unacked: {self.__unacked}, cwnd: {self.__cwnd}')
        self.__send_data(sock, ack_num)
        return State.CONGESTION_AVOIDANCE

    def __congestion_avoidance_dup_ack(self, sock, ack_num):
        self.__dup_acks[ack_num] += 1
        if self.__dup_acks[ack_num] == 3:
            return self.transition_table[State.CONGESTION_AVOIDANCE][Event.THREE_DUP_ACKS](sock, ack_num)
        return State.CONGESTION_AVOIDANCE

    def __congestion_avoidance_fast_retransmit(self, sock, ack_num):
        self.__ssthresh = max(self.__cwnd // 2, 2)
        self.__cwnd = 1
        self.__new_acks = 0
        self.__fast_retransmit(sock, ack_num)
        return State.SLOW_START

    def __congestion_avoidance_timeout_retransmit(self, sock, ack_num):
        self.__ssthresh = max(self.__cwnd // 2, 2)
        self.__cwnd = 1
        self.__new_acks = 0
        self.__timeout_retransmit(sock, ack_num)
        return State.SLOW_START