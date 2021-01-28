import socket             
import threading
import random
from Crypto.Cipher import DES3

groups = dict()			# key = grpName  , value = grp members name(assume unique names)
login_cred = dict()
name2sock = dict()
name2port = dict()
grpKey = dict()

def makeGrpKey():
	key = str(random.getrandbits(120))
	key = key[:24]
	print("grp key - ",key)
	return key

def makeSessionKey(psw):
	n = 24 // len(psw)
	n += 1
	session_key = psw * n
	session_key = session_key[:24]
	print("session_key - ",session_key, len(session_key))
	return session_key

def getClientMsg(sock):
	print("in thread func")
	listen_port = (sock.recv(1024)).decode('utf-8','ignore')
	print(listen_port)
	while(True):
		#print("b4 recv")
		msg = sock.recv(1024)
		print (msg)
		msg = msg.decode('utf-8','ignore')
		#print (type(msg))
		tokens = msg.split()
		print(tokens)
		ACK = ""
		if(tokens[0]=="SIGNUP"):
			login_cred[tokens[1]]=tokens[2]
			name2sock[tokens[1]]=sock
			name2port[tokens[1]]=listen_port
			ACK = "U R SIGNED UP"
			ACK = str.encode(ACK)
			sock.sendall(ACK)
		elif(tokens[0]=="SIGNIN"):
			if tokens[1] in login_cred.keys():
				if(login_cred[tokens[1]]==tokens[2]):
					ACK = "VALID"
				else:
					ACK = "INVALID PSW"
			else:
				ACK = "INVALID USERNAME"
			ACK = str.encode(ACK)
			sock.sendall(ACK)
		elif(tokens[0]=="PEER"):
			'''
			# add check here for valid receiver
			sockid = name2sock[tokens[1]]
			#print(sockid, type(sockid))
			ACK = (sockid.getpeername())
			#print(ACK, type(ACK))
			#print()
			#print(name2sock)
			'''
			if tokens[1] in name2port.keys():
				ACK = name2port[tokens[1]]
			else:
				ACK = "NO SUCH USER"
			ACK = str.encode(ACK)
			sock.sendall(ACK)
		elif(tokens[0]=="CREATE"):
			groups[tokens[1]]=[]
			groups[tokens[1]].append(tokens[2])
			grpKey[tokens[1]] = makeGrpKey()
			session_key = makeSessionKey(login_cred[tokens[2]])
			desKey=DES3.new(session_key,DES3.MODE_ECB)
			ACK = str.encode("GROUP CREATED")
			sock.sendall(ACK)
			print("ACK - ",ACK)
			key =  desKey.encrypt(grpKey[tokens[1]])
			sock.sendall(key)
			print("key - ",key)
		elif(tokens[0]=="JOIN"):
			session_key = makeSessionKey(login_cred[tokens[2]])
			desKey=DES3.new(session_key,DES3.MODE_ECB)
			if tokens[1] in groups.keys(): 
				groups[tokens[1]].append(tokens[2])
				ACK="GROUP JOINED"
				ACK = str.encode(ACK)
				sock.sendall(ACK)

			else:
				groups[tokens[1]]=[]
				groups[tokens[1]].append(tokens[2])
				ACK = str.encode("GROUP CREATED")
				sock.sendall(ACK)
				#ACK = str.encode("NO SUCH GROUP")
				grpKey[tokens[1]] = makeGrpKey()
				#session_key = makeSessionKey(login_cred[tokens[2]])
				#desKey=DES3.new(session_key,DES3.MODE_ECB)
			print("key - ",grpKey[tokens[1]])
			key =  desKey.encrypt(grpKey[tokens[1]])
			sock.sendall(key)
			print("key - ",key)
		elif(tokens[0]=="LIST"):
			ACK = ""
			if(len(groups.keys())==0):
				ACK = "NO GROUP AVAILABLE"
			for key in groups.keys():
				ACK += key + " - " + str(len(groups[key])) + "\n"
			ACK = str.encode(ACK)
			sock.sendall(ACK)
		elif(tokens[0]=="SENDGROUP" or tokens[0]=="SENDGROUPFILE" ):
			ACK = ""
			if tokens[1] not in groups.keys():
				ACK = str.encode("NO SUCH GROUP")
			else:
				for val in groups[tokens[1]]:
					ACK += str(name2port[val]) + " "
				ACK = ACK.strip()
				ACK = str.encode(ACK)
			sock.sendall(ACK)
		elif(tokens[0]=="SENDFILE"):
			if tokens[1] in name2port.keys():
				ACK = str(name2port[tokens[1]])
			else:
				ACK = "NO SUCH USER"
			ACK = str.encode(ACK)
			sock.sendall(ACK)
		print(name2port)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)       
print ("Socket successfully created") 

port = 5131

s.bind(('', port))        
print ("socket binded to %s" %(port))  

s.listen(5)   
print ("socket is listening")            

while True:  
	c, addr = s.accept()    
	print ('Got connection from', addr ) 
	th = threading.Thread(target=getClientMsg, args=(c,))  
	th.start()
c.close()  