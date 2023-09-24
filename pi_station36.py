## pi_station ##

import time, struct, board, os, select, fcntl, sys, subprocess, socket, pyshark
import threading
import chardet, pyx

from scapy.all import *
from digitalio import DigitalInOut
from pytun import TunTapDevice
from circuitpython_nrf24l01.rf24 import RF24

from multiprocessing import Process

sys.path.append('/usr/local/lib/python3.9/dist-packages')


## Global variables/Constants ##
timeout = 6
TUN_NAME = "tun1"
MTU = 32
IP = "192.168.1.2" 
MASK = "255.255.255.0"


# invalid default values for scoping
SPI_BUS, CSN_PIN, CE_PIN = (None, None, None)

# on Linux
try:  
    import spidev

    SPI_BUS = spidev.SpiDev()  
    CSN_PIN = 0  
    CE_PIN = DigitalInOut(board.D17) 

# on CircuitPython only
except ImportError:  
    SPI_BUS = board.SPI()  
    CE_PIN = DigitalInOut(board.D4)
    CSN_PIN = DigitalInOut(board.D5)
    
# initialize the nRF24L01 on the spi bus object
nrf = RF24(SPI_BUS, CSN_PIN, CE_PIN)

# set the Power Amplifier level to -12 dBm since this test example is
# usually run with nRF24L01 transceivers in close proximity
nrf.pa_level = -12

#sets the channel for both the TX and RX
nrf.channel = 125

# addresses needs to be in a buffer protocol object (bytearray)
address = [b"1Node", b"2Node"]

# to use different addresses on a pair of radios
# 0 uses address[0] to transmit, 1 uses address[1] to transmit
radio_number = bool(
    int(input("Which radio is this? Enter '0' or '1'. Defaults to '0' ") or 0)
)

# set TX address of RX node into the TX pipe | always uses pipe 0
nrf.open_tx_pipe(address[radio_number])  

# set RX address of TX node into an RX pipe | using pipe 1
nrf.open_rx_pipe(1, address[not radio_number])  

# list to store our float number for the payloads sent
payload = [0.0]

def capturepack():
    capture = pyshark.LiveCapture(interface='tun1')
    capture.sniff(timeout=50)
    capture


def create_tun(name="tun0"):
    """Tun creation"""
    #Create and configuration a TUN interface
    tun_fd = TunTapDevice(name=name)
    tun_fd.addr = IP
    tun_fd.netmask = MASK
    tun_fd.mtu = 1500
    tun_fd.up()
    return tun_fd

def create_header():
    """Create header of 1 byte for the payload"""
    #create header
    header = bytes([0b00000000]) #\x00
    return header

def create_footer():
    """Create footer of 1 byte for the payload"""
    #create footer
    footer = bytes([0b11111111]) #\xff
    return footer

#A: Represents the mobile station where the data is sent - TX
#B: Represents the base station where the data is received - RX

#1A. retrieve packets from tun interface
def read_from_tun(tun_fd):
    while True:
        """Read from TUN interface"""
        #read tundevice data with given size. returns bytes (len(data) = 32)
        print("[T1] -----------Starting a new reading from tun---------------")
        data = tun_fd.read(MTU)
        length_data = len(data)
        #print("Length of data: ", length_data, "type of data: ", type(data))
        print("[T1] The actual data: \n", data)

        #fragment the data into smaller chunks of size 31 bytes = payload
        print("[T1] ** Beginning packet fragmentation **")
        
        header = create_header()
        footer = create_footer()
        chunks = fragment_packet(data)
        if len(chunks) == 1:
            chunks = [header + chunks + footer]
            # chunks[0] = [header + chunks[0]]
            # chunks[-1] = [chunks[-1] + footer]
        else:
            for i in range(len(chunks)):
                if len(chunks[i]) > 1:
                    if i == 0:
                        chunks[0] = [header + chunks[0]]  # Add header to the first chunk - represented by 1 byte at the beginning
                    elif i == (len(chunks)-1):
                        chunks[-1] = [chunks[-1] + footer] # Add end of packet to the last chunk - represented by 1 byte at the end

        
        print("[T1] First chunk: ", chunks[0])        
        print("[T1] Last chunk: ", chunks[-1])        
        print("[T1] Amount of chunks: ", len(chunks))
        print("[T1] All the chunks: ", chunks)

        if data != None:
            nrf.listen = False
            for i in range(len(chunks)):
                print("[T1] -> chunk[",i, "]:", chunks[i])
                #print("-> length of chunk[",i, "]:" , len(chunks[i]), "bytes")
                print('[T1] --- Sending chunk to Radio transmitter ---')
                result = radio_TX(chunks[i])
                time.sleep(1)
            if not result:
                print("[T1] send() failed or timed out")


#2A. fragment the packet into chunks
def fragment_packet(data):
    """Fragmentation of packets into chunks"""
    length_data = len(data)
    payload_len = 30  #31
    payloads = [data[i:i+payload_len] for i in range(0, length_data, payload_len)]
    return payloads

#3A. send packets to other radios RX
def radio_TX(buffer):
    """Send data to the other radio: TX->RX"""
    result = nrf.send(buf = buffer, ask_no_ack=False, send_only=True)
    print('[T1] --- Chunk is now sent on radio transmitter ---')
    retransmit = nrf.arc
    print("[T1] number of retransmits: ", retransmit)
    return result


#1B. receive packets from other radios TX
def radio_RX(tun_fd):
    """Receive data from the other radio: RX->TX"""
    
    nrf.listen = True
    i=0
    reass = []
    print('[T2] ##### RADIO_RX #####')

    global payload_size 
    payload_size = nrf.any()
    print("[T2] Payload size", payload_size)
    while True:
        if nrf.available(): #if there is a payload in the reciever
            # grab information about the received payload
            new_payload_size, pipe_number = (nrf.any(), nrf.pipe)
            payload_size = payload_size + new_payload_size
            print("[T2] ------- Reading recieved packets from RX -----")
            fragment = nrf.read()  
            print('[T2] ##### Listening on Radio receiver #####')
            print("[T2] Data from radio:", fragment)
            print(
                "[T2] Received {} bytes on pipe {}: {}".format(
                    new_payload_size, pipe_number, fragment
                )
            )
            print("[T2] ** Appending above recieved fragment to vector of packets **")
            
            #turning packets from bytearrayss to bytes
            reass.append(to_bytes(fragment))
            print("[T2] Reass vector: ", reass)
            #print("length of reass vector: ", len(reass))

            #reassemble packets
            print("[T2] Starts with 0b00000000: ", reass[0].startswith(bytes([0b00000000])))
            print("[T2] Ends with 0b11111111: ", reass[-1].endswith(bytes([0b11111111])))
            if reass[0].startswith(bytes([0b00000000])) and reass[-1].endswith(bytes([0b11111111])):
                print("[T2] IN!!!!")
                result_list = reassemble_packet(reass, tun_fd)
                call_tun_actions(result_list,tun_fd)
                del reass[:]
                
            
    
# Reassemble the packet from the fragments with removed header and footer
def reassemble_packet(reass, tun_fd):
    """Reassemble a packet from its fragments"""
    
    # Removes the b'' from the fragments
    print("[T2] ** Adding all fragments in vector together to 1 packet **")
    result_list = [b"".join(reass)]
    print("[T2] Vector with reassembeld", result_list)
    
    # Remove the header and footer from the fragments
    print("[T2] Result list: ", result_list)
    
    modified_list = list(result_list[0])[1:-1]
    #print("[T2] Removed first and last index:", modified_list)
    
    new_result_list = [bytes(modified_list)]
    print("[T2] New result list: ", new_result_list)
        
    return new_result_list
    

def call_tun_actions(result_list,tun_fd):
    """Send to tun interface and read from tun interface"""
    
    print("[T2] --- Sending packet to own tun interface ---")
    send_to_tun(result_list,tun_fd) 
    #nrf.listen = True

#2B. reassemble the packet from chunks    
def to_bytes(fragments):
    """1. change from bytearray. 2.Reassemble a packet from its fragments"""
    fragments = bytes(fragments)
    return fragments 

#3B. packets sent from RX -> going to tun interface
def send_to_tun(packet, tun_fd):
    """Send data to TUN interface"""
    tun_fd.write(packet[0])
    
    
#Master: transmit 5 packets
def master(count=5):  
    """Transmits an incrementing integer every second"""
    nrf.listen = False  # nRF24L01 is in TX mode
    while count:
        buffer = struct.pack("<f", payload[0])
        start_timer = time.monotonic_ns()  # start timer
        result = nrf.send(buffer)
        end_timer = time.monotonic_ns()  # end timer
        if not result:
            print("send() failed or timed out")
        else:
            print(
                "Transmission successful! Time to Transmit:",
                "{} us. Sent: {}".format((end_timer - start_timer) / 1000, payload[0]),
            )
            payload[0] += 0.01
        time.sleep(1)
        count -= 1

def slave(timeout=6):
    """Polls the radio and prints the received value. This method expires
    after 6 seconds of no received transmission"""
    nrf.listen = True  # nRF24L01 is in RX mode

    start = time.monotonic()
    while (time.monotonic() - start) < timeout:
        if nrf.available():
            # grab information about the received payload
            payload_size, pipe_number = (nrf.any(), nrf.pipe)
            buffer = nrf.read() 
            payload[0] = struct.unpack("<f", buffer[:4])[0]
            # print details about the received packet
            print(
                "Received {} bytes on pipe {}: {}".format(
                    payload_size, pipe_number, payload[0]
                )
            )
            start = time.monotonic()

    nrf.listen = False  #nRF24L01 is in TX mode


def main():
    """Main function"""

    # Create and configure a TUN interface
    tun_fd = create_tun(TUN_NAME)

    #Adds 8.8.8.8 to the routing table
    #Show routing table: route print OR netstat -rn
    #subprocess.run(["sudo", "ip", "route", "add", "8.8.8.8", "dev", TUN_NAME])
    #ping {IP on base station on TUN interface} -c 1 -s 16

    #ifconfig - see the packets | watch

    # Create threads to process the data
    t_read = threading.Thread(target=read_from_tun, args=(tun_fd,))   
    #t_write = threading.Thread(target=radio_RX, args=(tun_fd,))

    # Start threads: they will run in parallel
    t_read.start()
    #time.sleep(1)
    #t_write.start()

    #time.sleep(1)
    t_read.join()
    #t_write.join()


    # Close and destroy interface
    #tun_fd.close()


if __name__ == "__main__":
    main()
