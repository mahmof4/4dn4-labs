#FAHAD MAHMOOD AND TAHA KHAN
#MARCH 19 2019

########################################################################

import socket
import argparse
import sys
import time
import threading
import hashlib
import os

CMD_FIELD_LEN = 1 # 1 byte commands sent from the client.
FILE_SIZE_FIELD_LEN  = 8 # 8 byte file size field.
CMD = { "LIST" : 0,
                "PUT" : 1,
                "GET" : 2,
                "BYE" : 3}
FILE_NOT_FOUND_MSG = "Error: Requested file is not available!"

########################################################################
# Broadcast Server class
########################################################################

class Server:

    RECV_SIZE = 1024
    BACKLOG = 5
    MESSAGE =  "SERVICE DISCOVERY"
    MSG_ENCODING = "utf-8"
    FILE_NOT_FOUND_MSG = "Error: Requested file is not available!"
    #File_sharing address:
    FILE_SHARING_PATH = 'C:\server'
    
    HOST = "0.0.0.0"
    SERVER_DISCOVERY_PORT = (HOST, 30017)
    FILE_SHARING_PORT = (HOST, 30018)

    RECV_BUFFER_SIZE = 1024
    MAX_CONNECTION_BACKLOG = 10
    
    def __init__(self):
	
		# Print intial server contents
        print("\nFiles in Server Folder:")
        for filenames in os.listdir(path=r"C:\server"):
            print(filenames)
        print()
        #Create two sockets, one for each connection type
        self.get_sockets()

        #Create and start two threads, one for each type of connection
        udp_thread = threading.Thread(target = self.receive_forever, args=[])
        udp_thread.start()
        print("Listening for service discovery messages on SDP port " + str(30017))
        
        self.tcp_connection_loop()
        
        #Join threads eventually, dont thinkI need this
        udp_thread.join()



    def get_sockets(self):
        try:
            # Create an IPv4 UDP socket.
            self.socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Bind to all interfaces and the agreed on broadcast port.
            self.socket_udp.bind(self.SERVER_DISCOVERY_PORT)

             # Create an IPv4 TCP socket.
            self.socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set socket layer socket options. This allows us to reuse
            # the socket without waiting for any timeouts.
            self.socket_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.socket_tcp.bind(self.FILE_SHARING_PORT)

            # Set socket to listen state.
            self.socket_tcp.listen(self.MAX_CONNECTION_BACKLOG)

        except Exception as msg:
            print(msg)
            sys.exit(1)
            

    def receive_forever(self):
        while True:
            try:
                data, address = self.socket_udp.recvfrom(Server.RECV_SIZE)
                
                print("Broadcast received: ", 
                      data.decode(self.MSG_ENCODING), address)

                if data.decode(self.MSG_ENCODING) == self.MESSAGE: #Server waits for message "SERVICE DISCOVERY"
                    self.socket_udp.sendto("Fahad's File Sharing Service".encode(self.MSG_ENCODING), address)
                else:
                    self.socket_udp.sendto("Placeholder return message".encode(self.MSG_ENCODING), address)
                    
            except KeyboardInterrupt:
                print(); exit()
            except Exception as msg:
                print(msg)
                sys.exit(1)


    def tcp_connection_loop(self):
        #This will run as a thread while there is a connection
        print("Listening for file sharing connections on port " + str(30018))
        while True:
            try:
                # Block while waiting for accepting incoming
                # connections. When one is accepted, pass the new
                # (cloned) socket reference to the connection handler
                # function.
                client = self.socket_tcp.accept()

                #Start a thread with the new tcp client
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
            # Read the command and see if it is a GET.
            cmd = int.from_bytes(connection.recv(CMD_FIELD_LEN), byteorder='big')

            if cmd == CMD["LIST"]:
                list_files = os.listdir(self.FILE_SHARING_PATH) #Get all files list within the file sharing directory
                connection.sendall(str(list_files).encode(self.MSG_ENCODING))
                
            elif cmd == CMD["GET"]:
                # The command is good. Now read and decode the requested
                # filename.
                filename_bytes = connection.recv(self.RECV_SIZE)
                filename = filename_bytes.decode(self.MSG_ENCODING)

                # Open the requested file and get set to send it to the
                # client.
                try:
                    file = open(self.FILE_SHARING_PATH + filename, 'r').read()
                except FileNotFoundError:
                    print(self.FILE_NOT_FOUND_MSG)
                    connection.close()                   
                    return

                # Encode the file contents into bytes, record its size and
                # generate the file size field used for transmission.
                file_bytes = file.encode(self.MSG_ENCODING)
                file_size_bytes = len(file_bytes)
                file_size_field = file_size_bytes.to_bytes(FILE_SIZE_FIELD_LEN, byteorder='big')

                # Create the packet to be sent with the header field.
                pkt = file_size_field + file_bytes
                
                try:
                    # Send the packet to the connected client.
                    connection.sendall(pkt)
                    # print("Sent packet bytes: \n", pkt)
                    print("Sending file: ", filename)
                except socket.error:
                    # If the client has closed the connection, close the
                    # socket on this end.
                    print("Closing client connection ...")
                    connection.close()
                    return

            elif cmd == CMD["PUT"]:
                # The command is good. Now read and decode the requested
                # filename.
                filename_bytes = connection.recv(self.RECV_SIZE)
                filename = filename_bytes.decode(self.MSG_ENCODING)

                # Read the file size field.
                file_size_bytes = self.socket_recv_size(FILE_SIZE_FIELD_LEN, connection)
                if len(file_size_bytes) == 0:
                       connection.close()
                       return

                # Make sure that you interpret it in host byte order.
                file_size = int.from_bytes(file_size_bytes, byteorder='big')

                # Receive the file itself.
                recvd_bytes_total = bytearray()
                try:
                    # Keep doing recv until the entire file is downloaded. 
                    while len(recvd_bytes_total) < file_size:
                        recvd_bytes_total += connection.recv(self.RECV_SIZE)

                    # Create a file using the received filename and store the
                    # data.
                    print("Received {} bytes. Creating file: {}" \
                          .format(len(recvd_bytes_total), filename))

                    with open(self.FILE_SHARING_PATH + filename, 'w') as f:
                        f.write(recvd_bytes_total.decode(self.MSG_ENCODING))
                except KeyboardInterrupt:
                    print()
                    exit(1)
                # If the socket has been closed by the server, break out
                # and close it on this end.
                except socket.error:
                    connection.close()

            elif cmd == CMD["BYE"]:
                connection.close()
                print("Connection was terminated with client")
                break
            
########################################################################
# Echo Client class
########################################################################

class Client:

    # Set the server hostname to connect to. If the server and client
    # are running on the same machine, we can use the current
    # hostname.
    print(socket.gethostname())
    SERVER_HOSTNAME = socket.gethostname()

    HOST = "0.0.0.0"
    FILE_SHARING_PORT = (SERVER_HOSTNAME, 30018)
    FILE_NOT_FOUND_MSG = "Error: Requested file is not available!"
    LOCAL_FILE_SHARING_PATH = 'C:\client'
    
    MSG_ENCODING = "utf-8"
        # Define the message to broadcast.
    MESSAGE =  "SERVICE DISCOVERY"
    MESSAGE_ENCODED = MESSAGE.encode(MSG_ENCODING)
    
    RECV_BUFFER_SIZE = 1024
    RECV_SIZE = 10
    # Use the broadcast-to-everyone IP address or a directed broadcast
    # address. Define a broadcast port.
    BROADCAST_ADDRESS = "255.255.255.255" # or e.g., "192.168.1.255"
    SERVER_DISCOVERY_PORT = (BROADCAST_ADDRESS, 30017)

    def __init__(self):
        self.return_message = ""
        self.connect_prompt_cmd = ""
        
        self.get_socket()
        self.get_service_discovery_socket()
        #self.connect_to_server()
        self.process_connect_prompt_input()
        #self.send_console_input_forever()

    def get_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            sys.exit(1)


    def connect_to_server(self):
        try:
            # Connect to the server using its socket address tuple.
            #address = *self.connect_prompt_args
            address = (self.connect_prompt_args[0], int(self.connect_prompt_args[1]))
            address
            self.socket.connect(address)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    #----------------------------------------------------Changes--------------------------------------------------------------#

    def clean_data(self):
        self.username = ""
        self.password = ""
        self.login_hash = hashlib.sha256()
        self.return_message = ""
        

    def get_service_discovery_socket(self):
        try:
            # Set up a UDP socket.
            self.sd_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            ############################################################
            # Set the option for broadcasting.
            self.sd_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            ############################################################            
        except Exception as msg:
            print(msg)
            sys.exit(1)


    def scan_for_server(self):
        print("SERVICE DISCOVERY scan ...")
        # Send a service scan broadcast. If a socket timeout occurs,
        # there is probably no FS server listening.
        self.sd_socket.sendto(self.MESSAGE_ENCODED, self.SERVER_DISCOVERY_PORT)
        try:
            recvd_bytes, address = self.sd_socket.recvfrom(1024)
            # If a FS server responds, print out the details so that
            # we can connect to its file sharing port.
            print(recvd_bytes.decode('utf-8'), "found.", address)
        except socket.timeout:
            print("No services found.")


    def process_connect_prompt_input(self):
        while True:
            # We are connected to the FS. Prompt the user for what to
            # do.
            self.connect_prompt_input = input("Input: ")
            #connect_prompt_input = input(Client.CONNECT_PROMPT)
            if self.connect_prompt_input:
            # If the user enters something, process it.
                try:
                    # Parse the input into a command and its
                    # arguments.
                    self.connect_prompt_cmd, *self.connect_prompt_args = self.connect_prompt_input.split()
                    print(self.connect_prompt_args)
                except Exception as msg:
                    print(msg)
                    continue
                if self.connect_prompt_cmd == "scan":
                    self.scan_for_server()
                elif self.connect_prompt_cmd == "connect":
                    self.connect_to_server()
                elif self.connect_prompt_cmd =='llist':
                    # Get a local files listing and print it out.
                    print(os.listdir(self.LOCAL_FILE_SHARING_PATH)) # returns lis
                    pass
                elif self.connect_prompt_cmd =='rlist':
                    # Do a sendall and ask the FS for a remote file listing.
                    self.list_files()
                    pass
                elif self.connect_prompt_cmd =='put':
                    # Write code to interact with the FS and upload a
                    # file.
                    self.put_file()
                    pass
                elif self.connect_prompt_cmd =='get':
                    self.get_file()
                    pass
                elif self.connect_prompt_cmd =='bye':
                    # Disconnect from the FS.
                    #add if statement to check if socket exists
                    bye_field = CMD["BYE"].to_bytes(CMD_FIELD_LEN, byteorder='big')
                    self.socket.sendall(bye_field)
                    print("Connection Terminated with server")
                    self.socket.close()
                    pass
                else:
                    pass          


    def socket_recv_size(self, length):
        bytes = self.socket.recv(length)
        if len(bytes) < length:
            self.socket.close()
            exit()
        return(bytes)


    def list_files(self):
        try:
            list_field = CMD["LIST"].to_bytes(CMD_FIELD_LEN, byteorder='big')
            self.socket.sendall(list_field)
            # Receive and print out text. The received bytes objects
            # must be decoded into string objects.
            recvd_bytes = self.socket.recv(self.RECV_BUFFER_SIZE)

            # recv will block if nothing is available. If we receive
            # zero bytes, the connection has been closed from the
            # other end. In that case, close the connection on this
            # end and exit.
            if len(recvd_bytes) == 0:
                print("Closing server connection ... ")
                self.socket.close()
                sys.exit(1)

            self.return_message = recvd_bytes.decode(self.MSG_ENCODING)

            print("Received: ", self.return_message)

        except Exception as msg:
            print(msg)
            sys.exit(1)
        
    def get_file(self):
        file_name = self.connect_prompt_args[0]
        # Create the packet GET field.
        get_field = CMD["GET"].to_bytes(CMD_FIELD_LEN, byteorder='big')

        # Create the packet filename field.
        filename_field = file_name.encode(self.MSG_ENCODING)

        # Create the packet.
        pkt = get_field + filename_field

        # Send the request packet to the server.
        self.socket.sendall(pkt)

        # Read the file size field.
        file_size_bytes = self.socket_recv_size(FILE_SIZE_FIELD_LEN)
        if len(file_size_bytes) == 0:
               self.socket.close()
               return

        # Make sure that you interpret it in host byte order.
        file_size = int.from_bytes(file_size_bytes, byteorder='big')

        # Receive the file itself.
        recvd_bytes_total = bytearray()
        try:
            # Keep doing recv until the entire file is downloaded. 
            while len(recvd_bytes_total) < file_size:
                recvd_bytes_total += self.socket.recv(self.RECV_SIZE)

            # Create a file using the received filename and store the
            # data.
            print("Received {} bytes. Creating file: {}" \
                  .format(len(recvd_bytes_total), file_name))

            with open(self.LOCAL_FILE_SHARING_PATH + file_name, 'w') as f:
                f.write(recvd_bytes_total.decode(self.MSG_ENCODING))
        except KeyboardInterrupt:
            print()
            exit(1)
        # If the socket has been closed by the server, break out
        # and close it on this end.
        except socket.error:
            self.socket.close()


    def put_file(self):
        file_name = self.connect_prompt_args[0]
        # Create the packet GET field.
        put_field = CMD["PUT"].to_bytes(CMD_FIELD_LEN, byteorder='big')
        # Create the packet filename field.
        filename_field = file_name.encode(self.MSG_ENCODING)

        # Create the packet.
        pkt = put_field + filename_field

        print(socket)
        # Send the request packet to the server.
        self.socket.sendall(pkt)
        
        # Open the requested file and get set to send it to the
        # client.
        try:
            file = open(self.LOCAL_FILE_SHARING_PATH + file_name, 'r').read()
        except FileNotFoundError:
            print(self.FILE_NOT_FOUND_MSG)
            self.socket.close()                   
            return

        # Encode the file contents into bytes, record its size and
        # generate the file size field used for transmission.
        file_bytes = file.encode(self.MSG_ENCODING)
        file_size_bytes = len(file_bytes)
        file_size_field = file_size_bytes.to_bytes(FILE_SIZE_FIELD_LEN, byteorder='big')

        # Create the packet to be sent with the header field.
        pkt = file_size_field + file_bytes

        try:
            # Send the packet to the connected client.
            self.socket.sendall(pkt)
            # print("Sent packet bytes: \n", pkt)
            print("Sending file: ", file_name)
        except socket.error:
            # If the client has closed the connection, close the
            # socket on this end.
            print("Closing client connection ...")
            self.socket.close()
            return
        
########################################################################
# Process command line arguments if run directly.
########################################################################

if __name__ == '__main__':
    roles = {'server': Server, 'client':Client}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################







