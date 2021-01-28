import socket             
import sys
import threading
import math
import os
import time
import hashlib
import random
from Crypto.Cipher import DES3
import pickle

P = 'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc98041746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff'
P = int(P, 16)
G = 2
grp2Key = dict()

class sendObject:
	def __init__(self,Type,GroupName,Message,FileName,chunkLength):
		self.Type=Type
		self.GroupName=GroupName
		self.Message=Message
		self.FileName=FileName
		self.chunkLength=chunkLength

def getGroupKey(tokens, sock):
	global grp2Key
	grpKey = sock.recv(1024)
	#grp2Key[tokens[1]] = grpKey
	session_key = makeSessionKey(psw)
	desKey=DES3.new(session_key,DES3.MODE_ECB)
	grpKey = (desKey.decrypt(grpKey)).decode('utf-8','ignore')
	grp2Key[tokens[1]] = grpKey

def makeSessionKey(psw):
	#global psw
	n = 24 // len(psw)
	n += 1
	session_key = psw * n
	session_key = session_key[:24]
	return session_key

def generate_pvt_key():
	global rollno
	global private_key
	r = random.getrandbits(100)
	pvt = (str(r) + rollno)
	result = hashlib.sha256(pvt.encode())
	hex_str = "0x"+result.hexdigest() 
	hex_int = int(hex_str, 16)
	new_int = (hex_int + 0x200)
	private_key = int(hex(new_int), 16)
	x = int(pow(G,private_key,P))
	return str(x)

def diffie_hellman(snd_sock):
	global private_key
	x = generate_pvt_key()
	y = int((snd_sock.recv(1024)).decode('utf-8','ignore'))
	snd_sock.sendall(str.encode(x))
	session_key = str(int(pow(y,private_key,P)))
	session_key = session_key[:24]
	return session_key

def diffie_hellman_2(snd_sock):
	global private_key
	x = generate_pvt_key()
	snd_sock.sendall(str.encode(x))
	y = int((snd_sock.recv(1024)).decode('utf-8','ignore'))
	snd_sock.sendall(str.encode(x))
	session_key = str(int(pow(y,private_key,P)))
	session_key = session_key[:24]
	return session_key	

def encryptDES3(session_key, msg):
	desKey=DES3.new(str(session_key),DES3.MODE_ECB)
	paddedText=padding(msg)
	cipheredText = desKey.encrypt(paddedText)
	msg2peer = cipheredText
	return cipheredText
def encryptDES3Bytes(session_key, msg):
	desKey=DES3.new(str(session_key),DES3.MODE_ECB)
	paddedText=paddingBytes(msg)
	cipheredText = desKey.encrypt(paddedText)
	msg2peer = cipheredText
	return cipheredText

def sendFile2Peer(port, filename):
	filesize = os.stat(filename).st_size
	total_chunks = math.ceil(filesize / 1024)
	snd_sock = socket.socket()
	snd_sock.connect(('127.0.0.1', int(port)))
	msg2peerObject=sendObject("PeerFile","","",filename,total_chunks)
	msg2peer=pickle.dumps(msg2peerObject)
	snd_sock.sendall(msg2peer)
	session_key = diffie_hellman(snd_sock)
	desKey=DES3.new(str(session_key),DES3.MODE_ECB)
	inFile = open(filename, mode='rb')
	chunk = inFile.read(1024)
	#chunk = chunk.decode('utf-8')
	while chunk:
		paddedText=paddingBytes(chunk)
		cipheredText = desKey.encrypt(paddedText)
		#chunk = encryptDES3(session_key, chunk)
		snd_sock.sendall(cipheredText)
		chunk = inFile.read(1024)
	ACK = (snd_sock.recv(1024)).decode('utf-8','ignore')
	if(ACK == "RECEIVED"):
		print("FILE SENT")
		snd_sock.close()
	
def sendFile2Group(port, filename,groupname):
	filesize = os.stat(filename).st_size
	total_chunks = math.ceil(filesize / 1024)
	snd_sock = socket.socket()
	snd_sock.connect(('127.0.0.1', int(port)))
	msg2peerObject=sendObject("GroupFile",groupname,"",filename,total_chunks)
	msg2peer=pickle.dumps(msg2peerObject)
	snd_sock.sendall(msg2peer)
	session_key = grp2Key[groupname]
	desKey=DES3.new(str(session_key),DES3.MODE_ECB)
	inFile = open(filename, mode='rb')
	chunk = inFile.read(1024)
	#chunk = chunk.decode('utf-8')
	while chunk:
		paddedText=paddingBytes(chunk)
		cipheredText = desKey.encrypt(paddedText)
		#chunk = encryptDES3(session_key, chunk)
		snd_sock.sendall(cipheredText)
		chunk = inFile.read(1024)
	ACK = (snd_sock.recv(1024)).decode('utf-8','ignore')
	if(ACK == "RECEIVED"):
		print("FILE SENT")
		snd_sock.close()

# def getPeerMsg(sock):
# 	global usrname
# 	session_key = diffie_hellman_2(sock)
# 	desKey=DES3.new(session_key,DES3.MODE_ECB)
# 	msg = sock.recv(1024)
# 	msg =desKey.decrypt(msg)
# 	msg=pickle.loads(msg)
# 	# msg = msg.decode('utf-8')
# 	# msg = msg.strip()
# 	print(msg.Message)
# 	tokens = msg.split()
# 	if(tokens[0]=="FILE"):
# 		file = tokens[1].split('.')
# 		recv_filename = file[0]+ usrname + "_recv." + file[1]
# 		outFile = open(recv_filename, mode='ab')
# 		n = int(tokens[2])
# 		while(n>0):
# 			chunk = sock.recv(1024)
# 			chunk = (desKey.decrypt(chunk))
# 			#chunk = desKey.decrypt(chunk)
# 			outFile.write(chunk)
# 			n-=1
# 		print("FILE RECEIVED")
# 		ACK = str.encode("RECEIVED")
# 		sock.sendall(ACK)


def getPeerMsg2(sock):
	global usrname
	msg = sock.recv(1024)
	msg=pickle.loads(msg)
	if msg.Type == "PeerText" :
		#print("peer")
		session_key = diffie_hellman_2(sock)
		desKey=DES3.new(session_key,DES3.MODE_ECB)
		msg = sock.recv(1024)
		recmsg=desKey.decrypt(msg)
		recmsg = recmsg.decode('utf-8','ignore')
		recmsg = recmsg.strip()
		print(recmsg)
	elif msg.Type == "GroupText" :
		#print("group")
		session_key=grp2Key[msg.GroupName]
		desKey=DES3.new(session_key,DES3.MODE_ECB)
		recmsg=desKey.decrypt(msg.Message)
		recmsg = recmsg.decode('utf-8','ignore')
		recmsg = recmsg.strip()
		print(recmsg)
	elif msg.Type == "PeerFile" :
		#print("peerfile")
		file = msg.FileName.split('.')
		recv_filename = file[0]+ usrname + "_recv." + file[1]
		outFile = open(recv_filename, mode='ab')
		n = int(msg.chunkLength)
		session_key = diffie_hellman_2(sock)
		desKey=DES3.new(session_key,DES3.MODE_ECB)
		while(n>0):
			chunk = sock.recv(1024)
			chunk = (desKey.decrypt(chunk))
			outFile.write(chunk)
			n-=1
		print("FILE RECEIVED")
		ACK = str.encode("RECEIVED")
		sock.sendall(ACK)

	elif msg.Type == "GroupFile" :
		#print("GroupFile")
		file = msg.FileName.split('.')
		recv_filename = file[0]+ usrname + "_recv." + file[1]
		outFile = open(recv_filename, mode='ab')
		n = int(msg.chunkLength)
		session_key = grp2Key[msg.GroupName]
		desKey=DES3.new(session_key,DES3.MODE_ECB)
		while(n>0):
			try:
				chunk = sock.recv(1024)
				chunk = (desKey.decrypt(chunk))
				outFile.write(chunk)
				n-=1
			except:
				g=""

		print("FILE RECEIVED")
		ACK = str.encode("RECEIVED")
		sock.sendall(ACK)

def myServer():
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind(('', listen_port))
	s.listen(10)
	while True:
		c, addr = s.accept()      
		# PEER_thread = threading.Thread(target=getPeerMsg1, args=(c,))  
		# PEER_thread.start()
		PEER_thread1 = threading.Thread(target=getPeerMsg2, args=(c,))  
		PEER_thread1.start()

def sign_up_or_in(sock):
	global usrname
	global psw
	global rollno
	print("Enter 1 to sign up, 2 for sign in")
	choice = int(input("Enter ur choice : "))
	if(choice == 1):
		print("Enter name :", sep='')
		usrname = input()
		print("Enter psw :", sep='')
		psw = input()
		print("Enter roll number :", sep='')
		rollno = input()
		msg = "SIGNUP " + usrname + " " + psw
		msg = str.encode(msg)
		s.sendall(msg)
		ACK = sock.recv(1024)
		print(ACK)
	else:
		while(True):
			print("Enter ur name :", sep='')
			usrname = input()
			print("Enter psw :", sep='')
			psw = input()
			msg = "SIGNIN " + usrname + " " + psw
			msg = str.encode(msg)
			s.sendall(msg)
			ACK = sock.recv(1024)
			print(ACK)
			if(ACK.decode('utf-8','ignore')=="VALID"):
	  			break
			print("INVALID CREDENTIALS, Enter details again")		

def padding(text):
  while len(text)%8 != 0:
    text=text+' '
  return text

def paddingBytes(text):
  while len(text)%8 != 0:
    text=text+ bytes([0])
  return text

s = socket.socket()       
  
port = 5131
listen_port = int(sys.argv[1])
server_thread = threading.Thread(target=myServer, args=())  
server_thread.start()

s.connect(('127.0.0.1', port))
#SHARE UR LISTENING PORT NO.
msg = str(listen_port)
msg = str.encode(msg)  
s.sendall(msg)
usrname = ""
psw = ""
rollno = ""
private_key = 0
sign_up_or_in(s)
print("--------------------------------------------------------")
print("List of Commands")
print("SEND Username Message")
print("SENDGROUP Groupname Message")
print("CREATE Groupname")
print("JOIN Groupname")
print("LIST")
print("SENDFILE Filename Username")
print("SENDGROUPFILE Filename Username")
print("----------------------------------------------------------")

while(True):   
	msg = input()
	tokens = msg.split(' ')
	if(tokens[0]=="SEND"):
		msg = str.encode("PEER " + tokens[1])  
		s.sendall(msg)
		ACK = s.recv(1024)
		ACK = ACK.decode('utf-8','ignore')
		print(ACK) 
		snd_sock = socket.socket()
		snd_sock.connect(('127.0.0.1', int(ACK)))
		msg2peerObject=sendObject("PeerText","","","",0)
		msg2peer=pickle.dumps(msg2peerObject)
		snd_sock.sendall(msg2peer)
		session_key = diffie_hellman(snd_sock)
		msg2peer1 = encryptDES3(session_key, usrname+"-"+tokens[2])
		# msg2peer = encryptDES3(session_key, tokens[2])
		#msg2peer = str.encode(msg2peer)
		
		snd_sock.sendall(msg2peer1)
		snd_sock.close()
	elif(tokens[0]=="CREATE"):	# CREATE GROUP_NAME ADMIN_NAME
		msg = str.encode("CREATE " + tokens[1] + " " + usrname)
		s.sendall(msg)
		ACK = s.recv(1024)
		ACK = ACK.decode('utf-8','ignore')
		print(ACK)
		getGroupKey(tokens, s)
	elif(tokens[0]=="JOIN"):
		msg = str.encode("JOIN " + tokens[1] + " " + usrname)
		s.sendall(msg)
		ACK = s.recv(1024)
		print(ACK)
		ACK = ACK.decode('utf-8','ignore')
		print(ACK)
		#if(ACK=="GROUP CREATED"):
		getGroupKey(tokens, s)
		#print("key got - ",grp2Key[tokens[1]])
		#else:

	elif(tokens[0]=="LIST"):
		msg = str.encode("LIST")
		s.sendall(msg)
		ACK = s.recv(1024)
		ACK = ACK.decode('utf-8','ignore')
		print(ACK)
	elif(tokens[0]=="SENDGROUP"):
		msg = str.encode("SENDGROUP " + tokens[1] )
		s.sendall(msg)
		ACK = s.recv(1024)
		ACK = ACK.decode('utf-8','ignore')
		ports = ACK.split(' ')
		for port in ports:
			if(int(port) == listen_port):
				continue
			snd_sock = socket.socket()
			snd_sock.connect(('127.0.0.1', int(port)))
			#print(grp2Key)
			session_key = grp2Key[tokens[1]]
			msg2peer = usrname + " - " + tokens[2]
			msg2peer2 = encryptDES3(session_key, msg2peer)
			msg2peerObject=sendObject("GroupText",tokens[1],msg2peer2,"",0)
			msg2peer1=pickle.dumps(msg2peerObject)
			snd_sock.sendall(msg2peer1)
			snd_sock.close()
	elif(tokens[0]=="SENDFILE"):
		msg = str.encode("SENDFILE " + tokens[2])
		s.sendall(msg)
		ACK = s.recv(1024)
		ACK = ACK.decode('utf-8','ignore')
		port = ACK
		file_snd_thread = threading.Thread(target=sendFile2Peer, args=(port, tokens[1]))  
		file_snd_thread.start()
	elif(tokens[0]=="SENDGROUPFILE"):	#SENDGROUPFILE filename receiver_group_name
		msg = str.encode("SENDGROUPFILE " + tokens[2])
		s.sendall(msg)
		ACK = s.recv(1024)
		ACK = ACK.decode('utf-8','ignore')
		ports = ACK.split(' ')
		for port in ports:
			if(port == str(listen_port)):
				continue
			file_snd_thread = threading.Thread(target=sendFile2Peer, args=(port, tokens[1]))  
			file_snd_thread.start()
			time.sleep(1)

s.close()     