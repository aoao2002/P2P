import enum
class State(enum):
    SLOW_START = 0
    CONGESTION_AVOIDANCE = 1
    
class Action(enum):
    DUP_ACK = 0
    NEW_ACK = 1
    RETRANSMIT = 2
    CWND_TOO_LARGE = 3

class FSM():
    '''
    Finate state machine of peers who have established a connection.
    Initialized when receiving a GET packet from a peer, and expires
    when the whole chunk is successfully sent.
    '''
    def __init__(self, addr, chunkhash_str) -> None:
        self.__addr = addr
        self.__cwnd = 1
        self.__ssthresh = 64
        self.__dup_acks = 0
        self.__new_acks = 0
        self.__prev_ack = 0
        self.__prev_pkt = None
        self.__state = State.SLOW_START

        self.sending_chunkhash_str = chunkhash_str

        # {old state: {action: event handler(sock, pkt) -> new state}}
        self.__transition_table = {
            State.SLOW_START: dict(),
            State.CONGESTION_AVOIDANCE: dict()
        } 
        self.__add_event_handler()

    def transit(self, sock, pkt, ack_num):
        self.__state = self.__transition_table[self.__state][action]()

    def __add_event_handler(self):
        self.__transition_table[State.SLOW_START][Action.DUP_ACK] = self.__slow_start_dup_ack
        self.__transition_table[State.SLOW_START][Action.NEW_ACK] = self.__slow_start_new_ack
        self.__transition_table[State.SLOW_START][Action.RETRANSMIT] = self.__slow_start_retransmit
        self.__transition_table[State.SLOW_START][Action.CWND_TOO_LARGE] = self.__slow_start_cwnd_too_large
        self.__transition_table[State.CONGESTION_AVOIDANCE][Action.NEW_ACK] = self.__congestion_avoidance_new_ack
        self.__transition_table[State.CONGESTION_AVOIDANCE][Action.DUP_ACK] = self.__congestion_avoidance_dup_ack
        self.__transition_table[State.CONGESTION_AVOIDANCE][Action.RETRANSMIT] = self.__congestion_avoidance_retransmit

    def __slow_start_dup_ack(self, sock, pkt):
        self.__dup_acks += 1
        return State.SLOW_START

    def __slow_start_new_ack(self, sock, pkt):
        self.__cwnd += 1
        sock.sendto(pkt, self.__addr)
        return State.SLOW_START

    def __slow_start_retransmit(self, sock, pkt):
        self.__ssthresh = max(self.__cwnd // 2, 2)
        self.__cwnd = 1
        sock.sendto(pkt, self.__addr)
        return State.SLOW_START

    def __slow_start_cwnd_too_large(self, sock, pkt):
        return State.CONGESTION_AVOIDANCE

    def __congestion_avoidance_new_ack(self, sock, pkt):
        self.__new_ACKs += 1
        if self.__new_ACKs == self.__cwnd:
            self.__cwnd += 1
            self.__new_ACKs = 0
        sock.sendto(pkt, self.__addr)
        return State.CONGESTION_AVOIDANCE

    def __congestion_avoidance_dup_ack(self, sock, pkt):
        self.__dup_acks += 1
        return State.CONGESTION_AVOIDANCE

    def __congestion_avoidance_retransmit(self, sock, pkt):
        self.__ssthresh = max(self.__cwnd // 2, 2)
        self.__cwnd = 1
        self.__new_ACKs = 0
        sock.sendto(pkt, self.__addr)
        return State.SLOW_START