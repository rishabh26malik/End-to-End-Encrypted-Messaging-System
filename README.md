### End to end messaging system like WhatsApp
Your task will be to design an end to end messaging system like WhatsApp with the below functional-
ities:
• Multiclient chat application that has a server component and 4 clients [atleast].
• The system should support the signup and sign in feature. [error message with wrong credentials].
• User can send message to other user [p2p message] [ SEND command] [<SEND> <USERNAME>
<MESSAGE>]
• Each user can join multiple chat rooms (groups) at a time.
• Each user can list all the groups. [LIST Command] [show all group and number of participants in
each group]
• Each user can join a group [JOIN command]. If the group does not exist then the first create it then
joins it.
• Each user can create a group [CREATE command].
• If one user sends a message to a group it should be sent to all members of that group.
• The message is encrypted using Tripple DES (3DES) and the key will be Diffie–Hellman key type
exchanged between clients.
• For each group make one key (random nonce).
• Message can be any type, for example, text, images, video, and audio.
Note: The one time Diffie–Hellman type key must be include a prive key (for instance roll nos.).

**For End to end encryption, we have done following:**
**1) For direct peer to peer**
**For chat message**
- First a secret key a generated on both sides using Diffi-hellman.
- Message is encrypted and decrypted using the same key.
- Everytime a new key is generated, even if the 2 end might have done communications in the past.

**For Sending File**
- First a signal message is send indicating the receiver that it's receiving 
	a file and not a text message so that it runs code to receive file on it's
	end.
- Now key is generated using Diffi-hellman and is used on both ends.

**2) For Group messaging**
- When a group is created, a secret number is generated on server side, this is
	shared with group creator using his password as the key.			
- When other peers join group, they get the key from server using their password as key.
- For sending message in group, first a signal message to each group member to indicate that it's a group message
**GROUP SIGNAL SYNTAX** 
`GROUP <GROUP_NAME>` for text message
`GROUP <GROUP_NAME> <FILE_NAME>` for sending file in group		
- This indicator message informs receiver to decrypt using the specified group mentioned in the signal message.		

### List of Commands
**- For Running Server**
```
python3 server.py 
Eg. python3 server.py 
```
**- For Running Server**
```
python3 clienr.py <port_number>
Eg. python3 client.py 5000
```
**- For sending message to a single client:**
 ```
SEND <Username> <Message>`
 Eg. SEND a Hello
 ```
**- For sending message in a group:**
 ``` 
 SENDGROUP <Groupname> <Message>`
 Eg. SENDGROUP xyz Hello
 ```
**- For creating a new group:**
 ``` 
CREATE <Groupname>
 Eg. CREATE xyz
  ```
**- For joining a group:**
 ```
JOIN <Groupname>
 Eg. JOIN xyz
 ```
**- To show all the groups available:**
```
 LIST
  ```
**- For sending  file to a single client:**
 ```
SENDFILE <Filename> <Username>
 Eg. SENDFILE abc a
 ```
**- For sending file in a group:**
 ```
 SENDGROUPFILE <Filename> <Groupname>
 Eg. SENDGROUPFILE abc xyz
  ```