#FAHAD MAHMOOD AND TAHA KHAN
#April 3rd 2019

########################################################################

import socket
import argparse
import sys
import time
import threading
import hashlib
import os

CMD_FIELD_LEN = 1 
FILE_SIZE_FIELD_LEN  = 8 
CMD = { "getdir" : 0,
                "makeroom" : 1,
                "deleteroom" : 2,
                "BYE" : 3}

RX_IFACE_ADDRESS = "0.0.0.0"

########################################################################
# Echo Server class
########################################################################

class Server:

	RECV_SIZE = 1024
	BACKLOG = 5
	MSG_ENCODING = "utf-8"
    
	HOST = "0.0.0.0"
	CHAT_ROOM_DIRECTORY_PORT = (HOST, 30000)

	RECV_BUFFER_SIZE = 1024
	MAX_CONNECTION_BACKLOG = 10
    
	room_list = []
	def __init__(self):
		
		print(self.CHAT_ROOM_DIRECTORY_PORT)
		self.get_sockets()
		self.tcp_connection_loop()


	def get_sockets(self):
		try:
			self.socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

			self.socket_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

			self.socket_tcp.bind(self.CHAT_ROOM_DIRECTORY_PORT)

			self.socket_tcp.listen(self.MAX_CONNECTION_BACKLOG)

		except Exception as msg:
			print(msg)
			sys.exit(1)
			

	def tcp_connection_loop(self):
		print("Chat Room Directory Server listening on port " + str(30000))
		while True:
			try:

				client = self.socket_tcp.accept()

				tcp_thread = threading.Thread(target = self.connection_handler, args=(client,))
				tcp_thread.start()
			except KeyboardInterrupt:
				print(); exit()
			except Exception as msg:
				print(msg)
				sys.exit(1)

                
	def socket_recv_size(self, length, connection):
		bytes = connection.recv(length)
		if len(bytes) < length:
			connection.close()
			exit()
		return(bytes)
    

	def connection_handler(self, client):
		connection, address = client
		print("-" * 72)
		print("Connection received from {}.".format(address))

		while True:
			cmd = int.from_bytes(connection.recv(CMD_FIELD_LEN), byteorder='big')

			if cmd == CMD["getdir"]:
				returnString = ""
				if(len(self.room_list) == 0):
					returnString = "Chat Directory is Empty"
				else:
					for room in self.room_list:
						for i in room:
							returnString = returnString + i + ","
						returnString = returnString[:-1]
						returnString = returnString + "|"
					returnString = returnString[:-1]
				
				connection.sendall(returnString.encode(self.MSG_ENCODING))
                
			elif cmd == CMD["makeroom"]:

				room_info_bytes = connection.recv(self.RECV_SIZE)
				room_info_string = room_info_bytes.decode(self.MSG_ENCODING)
				
				room_info = room_info_string.split(",")
				room_info.pop() 

				for room in self.room_list:
					if room[0] == room_info[0]:
						print("This chat room name is already in use")
						return
					elif (room[1] == room_info[1]) & (room[2]==room_info[2]):
						print("This chat room Ip/Port is already in use")
						return
				self.room_list.append(room_info)
				

			elif cmd == CMD["deleteroom"]:
				
				room_info_bytes = connection.recv(self.RECV_SIZE)
				room_name = room_info_bytes.decode(self.MSG_ENCODING)

				for i in range(0,len(self.room_list)):
						if self.room_list[i][0] == room_name:
							print("deleting room with name:", room_name)
							self.room_list.pop(i)
						return
				
				print("A room with the given name did no exist for it to be deleted")

			elif cmd == CMD["BYE"]:
				connection.close()
				print("Connection terminated from {}.".format(address))
				break
            
########################################################################
# Echo Client class
########################################################################

class Client:

	print(socket.gethostname())
	SERVER_HOSTNAME = socket.gethostname()

	HOST = "0.0.0.0"
	CHAT_ROOM_DIRECTORY_PORT = (SERVER_HOSTNAME, 30000)
    
	MSG_ENCODING = "utf-8"
    
	RECV_BUFFER_SIZE = 1024
	RECV_SIZE = 256
	
	TTL = 1 
	TTL_SIZE = 1 
	TTL_BYTE = TTL.to_bytes(TTL_SIZE, byteorder='big')
	

	def __init__(self):
		self.return_message = ""
		self.connect_prompt_cmd = ""
		self.name = "Anonymous"
		self.isChatting = False
		self.return_message = ""
		
		self.get_socket()
		self.process_connect_prompt_input()

	def get_socket(self):
		try:
			self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		except Exception as msg:
			print(msg)
			sys.exit(1)


	def connect_to_server(self):
		try:
			address = (self.connect_prompt_args[0], int(self.connect_prompt_args[1]))
			address
			self.socket.connect(address)
		except Exception as msg:
			print(msg)
			sys.exit(1)


	def process_connect_prompt_input(self):
		while True:

			self.return_message = ""
			self.connect_prompt_cmd = ""
			self.isChatting = False
			self.return_message = ""
			self.connect_prompt_input = input("Input: ")
			if self.connect_prompt_input:
				try:
					self.connect_prompt_cmd, *self.connect_prompt_args = self.connect_prompt_input.split()

				except KeyboardInterrupt:
					print("Exiting Client")
					sys.exit(1)
				if self.connect_prompt_cmd == "connect":
					self.connect_to_server()
				elif self.connect_prompt_cmd =='getdir':
					self.list_rooms()
					pass
				elif self.connect_prompt_cmd =='makeroom':

					self.make_room()
					pass
				elif self.connect_prompt_cmd =='deleteroom':
					self.delete_room()
					pass
				elif self.connect_prompt_cmd =='bye':

					bye_field = CMD["BYE"].to_bytes(CMD_FIELD_LEN, byteorder='big')
					self.socket.sendall(bye_field)
					print("Connection Terminated with server")
					self.socket.close()
					pass
				elif self.connect_prompt_cmd == 'name':
					self.name = self.connect_prompt_args[0] 
					print("User name changed to:", self.name)
				elif self.connect_prompt_cmd == 'chat':
					self.chatroom()
				else:
					pass          


	def socket_recv_size(self, length):
		bytes = self.socket.recv(length)
		if len(bytes) < length:
			self.socket.close()
			exit()
		return(bytes)


	def list_rooms(self):
		try:
			local_list_rooms=[]
			list_field = CMD["getdir"].to_bytes(CMD_FIELD_LEN, byteorder='big')
			self.socket.sendall(list_field)

			recvd_bytes = self.socket.recv(self.RECV_BUFFER_SIZE)

			if len(recvd_bytes) == 0:
				print("Closing server connection ... ")
				self.socket.close()
				sys.exit(1)

			self.return_message = recvd_bytes.decode(self.MSG_ENCODING)

			print("Received: ", self.return_message)
			local_list_rooms=self.return_message
			return self.return_message
		except Exception as msg:
			print(msg)
			sys.exit(1)
		
        

	def delete_room(self):
		room_info = self.connect_prompt_args[0]

		delete_field = CMD["deleteroom"].to_bytes(CMD_FIELD_LEN, byteorder='big')

		room_info_field = room_info.encode(self.MSG_ENCODING)


		pkt = delete_field + room_info_field

		print(socket)
		self.socket.sendall(pkt)


	def make_room(self):
		room_info = ""
		for arg in self.connect_prompt_args:
			room_info = room_info + arg + "," 
		make_field = CMD["makeroom"].to_bytes(CMD_FIELD_LEN, byteorder='big')

		room_info_field = room_info.encode(self.MSG_ENCODING)

		pkt = make_field + room_info_field

		print(socket)

		self.socket.sendall(pkt)

        
	def chatroom(self):
		try:
			chat_room_name = self.connect_prompt_args[0]
			self.chat_room_address = ("",0)
			chat_rooms_info = self.local_list_rooms().split('|')
			for room_info_string in chat_rooms_info:
				print(room_info_string)
				room_info = room_info_string.split(',')
				if room_info[0] == chat_room_name:
					self.chat_room_address = (room_info[1], int(room_info[2]))
					break
			
			
			if self.chat_room_address != ("",0):
				print("Connecting to : ", self.chat_room_address)
			else:
				print("Invalid chat room name.")
		
			self.MCSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self.MCSocket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.TTL_BYTE)

			self.isChatting = True
			listening_thread = threading.Thread(target = self.listen_chat, args=())
			listening_thread.start()
			
			time.sleep(1)
			
			while self.isChatting:
				self.chatbox = input("")
				if self.chatbox == "exit":
					isChatting = False
				else:
					self.chat_message = self.name + ": " + self.chatbox
					self.MCSocket.sendto(self.chat_message.encode(self.MSG_ENCODING), self.chat_room_address)
			
		except KeyboardInterrupt:
			print("Exiting chat room")
			self.isChatting = False
			return
			
	def listen_chat(self):
		self.Rsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.Rsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

		print(self.chat_room_address)
		self.Rsocket.bind(("0.0.0.0", self.chat_room_address[1]))
					
		multicast_group_bytes = socket.inet_aton(self.chat_room_address[0])

		print("Multicast Group: ", self.chat_room_address[0])

		multicast_if_bytes = socket.inet_aton(RX_IFACE_ADDRESS)

		multicast_request = multicast_group_bytes + multicast_if_bytes

		print("Adding membership (address/interface): ", self.chat_room_address[0],"/", RX_IFACE_ADDRESS)
		self.Rsocket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)
		
		while self.isChatting:
			data, address_port = self.Rsocket.recvfrom(self.RECV_SIZE)
			address, port = address_port
			print(data.decode('utf-8'))

if __name__ == '__main__':
	roles = {'server':Server, 'client':Client}
	parser = argparse.ArgumentParser()

	parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='server or client',
                        required=True, type=str)

	args = parser.parse_args()
	roles[args.role]()

########################################################################







