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

"""
This is CS305 project skeleton code.
Please refer to the example files - example/dumpreceiver.py and example/dumpsender.py - to learn how to play with this skeleton.
"""

BUF_SIZE = 1400
CHUNK_DATA_SIZE = 512 * 1024
HEADER_LEN = struct.calcsize("HBBHHII")
HASH_LEN = 20
MAX_PAYLOAD = 1024

WHOHAS = 0
IHAVE = 1
GET = 2
DATA = 3
ACK = 4
DENIED = 5

Code2Type = ['WHOHAS', 'IHAVE', 'GET', 'DATA', 'ACK', 'DENIED']

TEAM = 29
MAGIC = 52305

ex_output_file = None
ex_received_chunk = dict()
ex_downloading_chunkhash = ""
received_chunks = dict()
peer_chunkhashes = dict()
ex_sending_chunkhash = ''

num_concurrent_send = 0

# peer 和 seq 对应关系 其中key是peer的地址，value是上一次的seq
peer_seq = dict()

def process_download(sock, chunkfile, outputfile):
    """
    if DOWNLOAD is used, the peer will keep getting files until it is done
    """
    # print('PROCESS DOWNLOAD SKELETON CODE CALLED.  Fill me in!')
    global ex_output_file
    global ex_received_chunk
    global ex_downloading_chunkhash

    ex_output_file = outputfile
    download_hash = bytes()  # list of chunkhashes
    with open(chunkfile, 'r') as cf:
        chunkhash_strs = map(lambda line: line.strip().split(" ")[1], cf.readlines())

    # TODO: send WHOHAS packet
    # TODO: remove already had chunks from requested chunks
    for chunkhash_str in chunkhash_strs:
        ex_received_chunk[chunkhash_str] = bytes()
        ex_downloading_chunkhash = chunkhash_str
        if chunkhash_str not in config.haschunks:
            # hex_str to bytes
            chunkhash = bytes.fromhex(chunkhash_str)
            download_hash += chunkhash

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
    global peer_chunkhashes
    global ex_sending_chunkhash
    # Receive pkt
    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    Magic, Team, Type, hlen, plen, Seq, Ack = struct.unpack("HBBHHII", pkt[:HEADER_LEN])
    data = pkt[HEADER_LEN:]
    logger.info(f'received {Code2Type[Type]} pkt from {from_addr}, data: {bytes.hex(data) if Type != DATA else ""}')

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

        # TODO: send back GET pkt
        # TODO: design a policy to determine request which chunk from which peer
        # request the first unrequsted chunk from each peer
        # if no unrequested chunk, just pass
        # check if there're still unrequested chunks when finished receiving a chunk from a peer
        # if yes, request it
        for has_chunkhash in has_chunkhashes:
            if has_chunkhash not in received_chunks:
                peer_chunkhashes[from_addr] = has_chunkhashes
                received_chunks[has_chunkhash] = bytes()
                get_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, GET, socket.htons(HEADER_LEN),
                                         socket.htons(HEADER_LEN + len(has_chunkhash)), socket.htonl(0),
                                         socket.htonl(0))
                get_pkt = get_header + has_chunkhash
                sock.sendto(get_pkt, from_addr)
                logger.info(f'sent GET pkt to {from_addr}, data: {bytes.hex(has_chunkhash)}')
                break
    elif Type == GET:
        # TODO: deal with GET

        # increment concurrent send number
        num_concurrent_send += 1
        chunk_data = config.haschunks[ex_sending_chunkhash][:MAX_PAYLOAD]

        # send back DATA
        data_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, DATA, socket.htons(HEADER_LEN),
                                  socket.htons(HEADER_LEN), socket.htonl(1), 0)
        sock.sendto(data_header + chunk_data, from_addr)
        # logger.info(f'sent DATA pkt to {from_addr}') 
       
    # this part is used to reply ACK after receiving DATA 
    elif Type == DATA:
        # TODO: receive DATA packet
        # TODO: distinguish packets to corresponding chunks
        # 如果没有有这个peer，就添加到peer_seq字典中
        print(from_addr)
        if from_addr not in peer_seq:
            peer_seq[from_addr] = Seq
            ex_received_chunk[ex_downloading_chunkhash] += data
            # send back ACK
            ack_pkt = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, ACK, socket.htons(HEADER_LEN),
                                  socket.htons(HEADER_LEN), 0, Seq)
            sock.sendto(ack_pkt, from_addr)
            logger.info(f'sent 1 ACK pkt to {from_addr}')
        # 如果有这个peer，就判断seq是否是期望的
        else:
            last_send_seq = peer_seq[from_addr]
            if socket.htonl(Seq) == socket.htonl(last_send_seq) + 1:
                peer_seq[from_addr] = Seq
                ex_received_chunk[ex_downloading_chunkhash] += data
                # send back ACK
                ack_pkt = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, ACK, socket.htons(HEADER_LEN),
                                        socket.htons(HEADER_LEN), 0, Seq)
                sock.sendto(ack_pkt, from_addr)
                logger.info(f'sent 1 ACK pkt to {from_addr}')
            else:
                # send back ACK
                ack_pkt = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, ACK, socket.htons(HEADER_LEN),
                                        socket.htons(HEADER_LEN), 0, last_send_seq)
                sock.sendto(ack_pkt, from_addr)
                sock.sendto(ack_pkt, from_addr)
                sock.sendto(ack_pkt, from_addr)
                logger.info(f'sent 3 ACK pkts to {from_addr}')     

        # see if finished
        # TODO: request unrequested chunks when finish receiving a chunk
        if len(ex_received_chunk[ex_downloading_chunkhash]) == CHUNK_DATA_SIZE:
            # finished downloading this chunkdata!
            # dump your received chunk to file in dict form using pickle
            with open(ex_output_file, "wb") as wf:
                pickle.dump(ex_received_chunk, wf)

            # add to this peer's haschunk:
            config.haschunks[ex_downloading_chunkhash] = ex_received_chunk[ex_downloading_chunkhash]

            # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
            print(f"GOT {ex_output_file}")

            # The following things are just for illustration, you do not need to print out in your design.
            sha1 = hashlib.sha1()
            sha1.update(ex_received_chunk[ex_downloading_chunkhash])
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
        if (ack_num) * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
            # finished
            print(f"finished sending {ex_sending_chunkhash}")
            pass
        else:
            left = (ack_num) * MAX_PAYLOAD
            right = min((ack_num + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
            next_data = config.haschunks[ex_sending_chunkhash][left: right]
            # send next data
            data_header = struct.pack("HBBHHII", socket.htons(MAGIC), TEAM, DATA, socket.htons(HEADER_LEN),
                                      socket.htons(HEADER_LEN + len(next_data)), socket.htonl(ack_num + 1), 0)
            sock.sendto(data_header + next_data, from_addr)
    elif Type == DENIED:
        # TODO: deal with DENIED
        pass


def process_user_input(sock):
    command, chunkf, outf = input().split(' ')  # command: DOWNLOAD, chunkf: *.chunkhash file, outf: *.fragment file
    if command == 'DOWNLOAD':
        process_download(sock, chunkf, outf)
    else:
        pass


def peer_run(config):
    addr = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, addr, verbose=config.verbose)

    try:
        while True:
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
