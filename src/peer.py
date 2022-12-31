import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import select
import util.simsocket as simsocket
import struct
import socket
import util.bt_utils as bt_utils
import hashlib
import argparse
import pickle
import logging
import time
from FSM import FSM, State, Event

"""
This is CS305 project skeleton code.
Please refer to the example files - example/dumpreceiver.py and example/dumpsender.py - to learn how to play with this skeleton.
"""

MAX_PAYLOAD = 1024
CHUNK_DATA_SIZE = 512 * 1024
BUF_SIZE = 1400
HEADER_LEN = struct.calcsize("HBBHHII")
HASH_LEN = 20

WHOHAS = 0
IHAVE = 1
GET = 2
DATA = 3
ACK = 4
DENIED = 5

# Code2Type = ['WHOHAS', 'IHAVE', 'GET', 'DATA', 'ACK', 'DENIED']

TEAM = 29
MAGIC = 52305

finished = dict()
ex_output_file = None
ex_downloading_chunkhash = ""
received_chunks = dict()    # hashstr to data
peer_chunkhash_str = dict() # ip to hashstr
ex_sending_chunkhash = ''
peer_fsm = dict()
num_concurrent_send = 0
last_get_data_time = None

# peer 和 seq 对应关系 其中key是peer的地址，value是上一次的seq
peer_seq = dict()

# to restart the download to avoid some peers dead
LAST_COMMAND = ''

def process_download(sock, chunkfile, outputfile):
    """
    if DOWNLOAD is used, the peer will keep getting files until it is done
    """
    # print('PROCESS DOWNLOAD SKELETON CODE CALLED.  Fill me in!')
    global ex_output_file
    global received_chunks
    global ex_downloading_chunkhash
    global finished

    ex_output_file = outputfile
    download_hash = bytes()  # list of chunkhashes
    with open(chunkfile, 'r') as cf:
        chunkhash_strs = map(lambda line: line.strip().split(" ")[1], cf.readlines())

    # TODO: send WHOHAS packet
    # TODO: remove already had chunks from requested chunks
    for chunkhash_str in chunkhash_strs:
        if chunkhash_str not in config.haschunks:
            # hex_str to bytes
            chunkhash = bytes.fromhex(chunkhash_str)
            download_hash += chunkhash
            finished[chunkhash_str] = False

    # Step2: make WHOHAS pkt
    # |2byte magic|1byte team |1byte type|
    # |2byte  header len  |2byte pkt len |
    # |      4byte  seq                  |
    # |      4byte  ack                  |

    # struct format
    # H -> unsigned short 2 bytes
    # B -> unsigned char  1 byte
    # I -> unsigned int   4 bytes

    # socket.htons(), socket.htonl(): convert from host byte order to network byte order
    # h -> host, n -> network, s -> short, l -> long 
    if len(download_hash) > 0:
        whohas_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, WHOHAS, socket.htons(HEADER_LEN),
                                    socket.htons(HEADER_LEN + len(download_hash)), socket.htonl(0), socket.htonl(0))
        whohas_pkt = whohas_header + download_hash

        # Step3: flooding whohas to all peers in peer list
        peer_list = config.peers
        for p in peer_list:  # nodeid, hostname, port
            if int(p[0]) != config.identity:
                sock.sendto(whohas_pkt, (p[1], int(p[2])))

def process_inbound_udp(sock):
    global num_concurrent_send
    global received_chunks
    global peer_chunkhash_str
    global ex_sending_chunkhash
    global peer_fsm
    global finished
    global last_get_data_time
    # Receive pkt
    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    Magic, Team, Type, hlen, plen, Seq, Ack = struct.unpack("HBBHHII", pkt[:HEADER_LEN])
    data = pkt[HEADER_LEN:]
    # logger.info(f'received {Code2Type[Type]} pkt from {from_addr}, data: {bytes.hex(data) if Type != DATA else ""}')

    if Type == WHOHAS:
        # TODO: send IHAVE packet
        # TODO: control number of concurrent send

        # already sending to <max send> peers
        if num_concurrent_send == config.max_conn:
            # send DENIED packet
            denied_pkt = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, DENIED, socket.htons(HEADER_LEN),
                                     socket.htons(HEADER_LEN), socket.htonl(0), socket.htonl(0))
            sock.sendto(denied_pkt, from_addr)
            logger.info(f'sent DENIED pkt to {from_addr}')
            pass

        # see what chunk the sender has
        whohas_chunk_hashes = [data[i:i + HASH_LEN] for i in range(0, len(data), HASH_LEN)]

        logger.info(f'received WHOHAS pkt from {from_addr}, whohas: {map(bytes.hex, whohas_chunk_hashes)}')

        # bytes to hex_str
        has_hash = bytes()
        chunkhash_strs = []  # debug
        for chunk_hash in whohas_chunk_hashes:
            chunkhash_str = bytes.hex(chunk_hash)
            chunkhash_strs.append(chunkhash_str)  # debug
            if chunkhash_str in config.haschunks:
                has_hash += chunk_hash

        ex_sending_chunkhash = chunkhash_str

        logger.debug(f"whohas: {chunkhash_strs}, has: {list(config.haschunks.keys())}")  # debug
        # if chunkhash_str in config.haschunks:
        # send back IHAVE pkt
        if len(has_hash) > 0:
            ihave_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, IHAVE, socket.htons(HEADER_LEN),
                                       socket.htons(HEADER_LEN + len(has_hash)), socket.htonl(0), socket.htonl(0))
            ihave_pkt = ihave_header + has_hash
            sock.sendto(ihave_pkt, from_addr)
            logger.info(f'sent IHAVE pkt to {from_addr}, data: {bytes.hex(has_hash)}')

    elif Type == IHAVE:
        # see what chunk the sender has
        has_chunkhashes = [data[i:i + HASH_LEN] for i in range(0, len(data), HASH_LEN)]

        logger.info(f'received IHAVE pkt from {from_addr}, ihave: {map(bytes.hex, has_chunkhashes)}')

        # TODO: send back GET pkt
        # TODO: design a policy to determine request which chunk from which peer
        # request the first unrequsted chunk from each peer
        # if no unrequested chunk, just pass
        # check if there're still unrequested chunks when finished receiving a chunk from a peer
        # if yes, request it
        for has_chunkhash in has_chunkhashes:
            has_chunkhash_str = bytes.hex(has_chunkhash)
            
            if has_chunkhash_str not in received_chunks:
                peer_chunkhash_str[from_addr] = has_chunkhash_str
                received_chunks[has_chunkhash_str] = bytes()
                get_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, GET, socket.htons(HEADER_LEN),
                                         socket.htons(HEADER_LEN + len(has_chunkhash)), socket.htonl(0),
                                         socket.htonl(0))
                get_pkt = get_header + has_chunkhash
                sock.sendto(get_pkt, from_addr)
                logger.info(f'sent GET pkt to {from_addr}, data: {has_chunkhash_str}')
                break

    elif Type == GET:
        # TODO: deal with GET

        logger.info(f'received GET pkt from {from_addr}, get: {bytes.hex(data)}')

        # increment concurrent send number
        num_concurrent_send += 1
        chunkhash_str = bytes.hex(data)
        chunkdata = config.haschunks[chunkhash_str]

        # initialize peer's FSM
        peer_fsm[from_addr] = FSM(from_addr, chunkhash_str, chunkdata, config.timeout, logger)

        # send first pkt
        peer_fsm[from_addr].transit(sock, 0)

        # send back DATA
        # pkt_data = chunkdata[:MAX_PAYLOAD]
        # data_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, DATA, socket.htons(HEADER_LEN),
        #                           socket.htons(HEADER_LEN + len(pkt_data)), socket.htonl(1), 0)
        # sock.sendto(data_header + pkt_data, from_addr)
        # logger.info(f'sent DATA pkt to {from_addr}, seq: 1')

    elif Type == DATA:
        # TODO: receive DATA packet
        # TODO: distinguish packets to corresponding chunks
        # 如果没有有这个peer，就添加到peer_seq字典中
        # print(from_addr)
        Seq = socket.ntohl(Seq)
        if from_addr not in peer_seq:
            peer_seq[from_addr] = Seq
            received_chunks[peer_chunkhash_str[from_addr]] += data
            # send back ACK
            ack_pkt = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, ACK, socket.htons(HEADER_LEN),
                                  socket.htons(HEADER_LEN), 0, socket.htonl(Seq))
            sock.sendto(ack_pkt, from_addr)
            logger.info(f'sent ACK pkt to {from_addr}, ACK: {Seq}')
        # 如果有这个peer，就判断seq是否是期望的
        else:
            last_received_seq = peer_seq[from_addr]
            if Seq == last_received_seq + 1:
                peer_seq[from_addr] = Seq
                received_chunks[peer_chunkhash_str[from_addr]] += data

                last_get_data_time = time.time()

                # send back ACK
                ack_pkt = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, ACK, socket.htons(HEADER_LEN),
                                        socket.htons(HEADER_LEN), 0, socket.htonl(Seq))
                sock.sendto(ack_pkt, from_addr)
                logger.info(f'recv seq: {Seq}, sent ACK pkt to {from_addr}, ACK: {Seq}')
            else:
                # send back ACK
                ack_pkt = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, ACK, socket.htons(HEADER_LEN),
                                        socket.htons(HEADER_LEN), 0, socket.htonl(last_received_seq))
                sock.sendto(ack_pkt, from_addr)
                # sock.sendto(ack_pkt, from_addr)
                # sock.sendto(ack_pkt, from_addr)
                logger.info(f'recv seq: {Seq}, sent ACK pkts to {from_addr}, ACK: {last_received_seq}')     

        # see if finished
        # TODO: request unrequested chunks when finish receiving a chunk
        if len(received_chunks[peer_chunkhash_str[from_addr]]) == CHUNK_DATA_SIZE:
            # finished downloading this chunkdata!
            finished[peer_chunkhash_str[from_addr]] = True

            # see if finished downloading all chunks
            if all(finished.values()):
                # dump your received chunk to file in dict form using pickle
                with open(ex_output_file, "wb") as wf:
                    pickle.dump(received_chunks, wf)

                # add to this peer's haschunk:
                config.haschunks[ex_downloading_chunkhash] = received_chunks[ex_downloading_chunkhash]

                # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
                print(f"GOT {ex_output_file}")

                # The following things are just for illustration, you do not need to print out in your design.
                sha1 = hashlib.sha1()
                sha1.update(received_chunks[ex_downloading_chunkhash])
                received_chunkhash_str = sha1.hexdigest()
                print(f"Expected chunkhash: {ex_downloading_chunkhash}")
                print(f"Received chunkhash: {received_chunkhash_str}")
                success = ex_downloading_chunkhash == received_chunkhash_str
                print(f"Successful received: {success}")
                if success:
                    print("Congrats! You have completed the example!")
                else:
                    print("Example fails. Please check the example files carefully.")

                # decrement concurrent send number 
                num_concurrent_send -= 1

    elif Type == ACK:
        # TODO: deal with ACK
        # received an ACK pkt
        ack_num = socket.ntohl(Ack)
        logger.info(f'received ACK pkt from {from_addr}, ACK num: {ack_num}')
        
        peer_fsm[from_addr].transit(sock, ack_num)
        if peer_fsm[from_addr].state == State.FINISHED:
            # finished sending the chunk, remove the fsm
            peer_fsm.pop(from_addr)

    elif Type == DENIED:
        # TODO: deal with DENIED
        pass

def process_user_input(sock):
    global LAST_COMMAND
    LAST_COMMAND = input()
    command, chunkf, outf = LAST_COMMAND.split(' ')  # command: DOWNLOAD, chunkf: *.chunkhash file, outf: *.fragment file
    if command == 'DOWNLOAD':
        process_download(sock, chunkf, outf)
    else:
        pass

def restart_download(sock):
    logger.debug('begin restart_download')
    download_hash = bytes()
    
    for hash_str, if_finish in finished.items():
        if not if_finish:
            hash =  bytes.fromhex(hash_str)
            download_hash += hash
            if hash_str in received_chunks:
                received_chunks.pop(hash_str)
            # received_chunks[hash_str] = bytes()

    whohas_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, WHOHAS, socket.htons(HEADER_LEN),
                                    socket.htons(HEADER_LEN + len(download_hash)), socket.htonl(0), socket.htonl(0))
    whohas_pkt = whohas_header + download_hash

    peer_list = config.peers
    for p in peer_list:  # nodeid, hostname, port
        if int(p[0]) != config.identity:
            sock.sendto(whohas_pkt, (p[1], int(p[2])))

def peer_run(config):
    addr = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, addr, verbose=config.verbose)
    global peer_fsm
    global last_get_data_time

    try:
        while True:
            dead_peers = []
            for peer_addr, fsm in peer_fsm.items():
                if time.perf_counter() - fsm.timer.send_time > fsm.timeout:
                    # timeout occured, retransmit seq's pkt
                    fsm.state = fsm.transition_table[fsm.state][Event.TIMEOUT](sock, fsm.timer.seq - 1)
                    # double the timeout interval
                    fsm.timeout *= 2
                # if fsm.ttl == 0:
                #     dead_peers.append[peer_addr]
            # clear dead peer
            # for f_addr in dead_peers:
            #     peer_fsm.pop(f_addr)
            #     logger.debug('peer crash')
            

            ready = select.select([sock, sys.stdin], [], [], 0.1)
            read_ready = ready[0]
            if len(read_ready) > 0:
                if sock in read_ready:
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    process_user_input(sock)
            else:
                # No pkt nor input arrives during this period 
                pass

            # no conn left but tasks not all finish --> send WHOHAS for unfinisg tasks
            if not last_get_data_time is None:
                logger.debug(f'dataTime: {time.time()-last_get_data_time }')
                if time.time()-last_get_data_time > 5 and not all(finished.values()):
                    last_get_data_time = time.time()
                    restart_download(sock)


    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == '__main__':
    """
    -p: Peer list file, it will be in the form "*.map" like nodes.map.
    -c: Chunkfile, a dictionary dumped by pickle. It will be loaded automatically in bt_utils. The loaded dictionary has the form: {chunkhash: chunkdata}
    -m: The max number of peer that you can send chunk to concurrently. If more peers ask you for chunks, you should reply "DENIED"
    -i: ID, it is the index in nodes.map
    -v: verbose level for printing logs to stdout, 0 for no verbose, 1 for WARNING level, 2 for INFO, 3 for DEBUG.
    -t: pre-defined timeout. If it is not set, you should estimate timeout via RTT. If it is set, you should not change this time out.
        The timeout will be set when running test scripts. PLEASE do not change timeout if it set.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', type=str, help='<peerfile>     The list of all peers', default='nodes.map')
    parser.add_argument('-c', type=str, help='<chunkfile>    Pickle dumped dictionary {chunkhash: chunkdata}')
    parser.add_argument('-m', type=int, help='<maxconn>      Max # of concurrent sending')
    parser.add_argument('-i', type=int, help='<identity>     Which peer # am I?')
    parser.add_argument('-v', type=int, help='verbose level', default=0)
    parser.add_argument('-t', type=int, help="pre-defined timeout", default=0)
    args = parser.parse_args()

    config = bt_utils.BtConfig(args)
    logger = logging.getLogger(f"PEER{args.i}_LOGGER")
    peer_run(config)
