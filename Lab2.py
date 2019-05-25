#FAHAD MAHMOOD AND TAHA KHAN
#MARCH 7TH 2019

import argparse
import csv
import socket
import sys
import getpass
import hashlib

GET_MIDTERM_AVG_CMD = "GMA"  #String constants for the input commands
GET_LAB_1_AVG_CMD = "GL1A"
GET_LAB_2_AVG_CMD = "GL2A"
GET_LAB_3_AVG_CMD = "GL3A"
GET_LAB_4_AVG_CMD = "GL4A"
GET_GRADES = "GG"


class Server:
    
    HOSTNAME = "0.0.0.0"

    PORT = 50000

    RECV_BUFFER_SIZE = 1024
    MAX_CONNECTION_BACKLOG = 10
    
    MSG_ENCODING = "utf-8"

    SOCKET_ADDRESS = (HOSTNAME, PORT)
    
    def __init__(self):
        self.grades_database_file =  "./course_grades_2019.csv"

        self.student_list = []					#Variables for grade retrieval database and average calculations
        self.student_list_header = []
        self.profile = ""
        self.average = 0
        self.return_data = []
        
        
        print(self.grades_database_file)  #Call function for opening, reading and then printing the contents of the grades database
	    self.read_database()


        self.create_listen_socket()
        self.process_connections_forever()


    def read_database(self):   #Function for reading the csv file
        try:
            file = open(self.grades_database_file, "r")
        except FileNotFoundError:
            print("Creating database: {}". format(self.grades_database_file))
            file = open(self.grades_database_file, "w+")

        print("Data read from CSV:")
        readCSV = csv.reader(file, delimiter=',')
        
        self.student_list_header = next(readCSV) # Store the first row of CSV file as the header and mvoe onto next row
        print(self.student_list_header) 				   #Print the header 
        
        for row in readCSV:								#Loop through the remaining rows and store the data into our list	
            self.student_list.append(row) 
            print(row)
            
        file.close()

    def get_profile(self, command):					
        if command == GET_MIDTERM_AVG_CMD:
			self.profile = 4
        elif command == GET_LAB_1_AVG_CMD:
			self.profile = 5
        elif command == GET_LAB_2_AVG_CMD:
			self.profile = 6
        elif command == GET_LAB_3_AVG_CMD:
			self.profile = 7
        elif command == GET_LAB_4_AVG_CMD:
			self.profile = 8
        elif command == GET_GRADES:
            self.profile =  "Get Grades"
        else:
            self.profile = "Error"

    def get_average(self):	 #calculates average of given column
        total = 0
        for row in self.student_list:
            total+=1
            self.average += int(row[self.profile])

        self.average = self.average/total
        print(self.average)

    def create_listen_socket(self):
        try:

            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            self.socket.bind(Server.SOCKET_ADDRESS)

            self.socket.listen(Server.MAX_CONNECTION_BACKLOG)
            print("Listening on port {} ...".format(Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def process_connections_forever(self):
        try:
            while True:

                self.connection_handler(self.socket.accept())
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()
            sys.exit(1)

    def connection_handler(self, client):
        connection, address_port = client
        print("-" * 72)
        print("Connection received from {}.".format(address_port))

        while True:
            try:
                recvd_bytes = connection.recv(Server.RECV_BUFFER_SIZE)

                if len(recvd_bytes) == 0:
                    print("Closing client connection ... ")
                    connection.close()
                    break
                
                recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)
               
               self.get_profile(recvd_str)
			   if self.profile != "Get Grades":
                   print("Received ", recvd_str, " command from client")  #print out which command was recieved


                if self.profile == "Get Grades":			#Waiting for ID/password hash to retrieve grades
                    recvd_hash = connection.recv(Server.RECV_BUFFER_SIZE)
                    print("Received ID/Password hash ", recvd_hash, " from client")
                    
					if len(recvd_bytes) == 0:
                        print("Closing client connection ... ")
                        connection.close()
                        break

                    self.login(recvd_hash)			#Use received hash to retreive grades or throw error if none found
                    if self.return_data != []:
                        print("Correct Password, record found")
                        connection.sendall(str(self.return_data).encode(Server.MSG_ENCODING))	#encode and send grades
                    else:
                        print("Password Failure")
                        connection.sendall("Password Failure".encode(Server.MSG_ENCODING))  #encode and send error message
                elif self.profile == "Error":
                    print("Could not complete the request")
                    connection.sendall("Could no complete the request".encode(Server.MSG_ENCODING))
                else:				
                    self.get_average()				#If command was for an average, encode and send average
                    connection.sendall(str(self.average).encode(Server.MSG_ENCODING))

				self.profile = ""
				self.average = 0
				self.return_data = []
                

            except KeyboardInterrupt:
                print()
                print("Closing client connection ... ")
                connection.close()
                break
        
    def login(self, recvd_hash):
        try:
            for row in self.student_list:			#searches throuigh database for provided credentials and returns grades if valid
                temp_hash = hashlib.sha256()
                temp_hash.update(row[0].encode("utf-8"))
                temp_hash.update(row[1].encode("utf-8"))
                
                if temp_hash.digest() == recvd_hash:
                    for i in range(4,len(row)):
                        self.return_data.append(str(self.student_list_header[i]) + ":" + str(row[i]))
                    print(self.return_data)
                    break;
                    
        except Exception as msg:
            print(msg)
            sys.exit(1)


##########################################################################################################


class Client:

    print(socket.gethostname())
    SERVER_HOSTNAME = socket.gethostname()

    RECV_BUFFER_SIZE = 1024

    def __init__(self):
        self.username = ""
        self.password = ""
        self.login_hash = hashlib.sha256()
        self.return_message = ""
        
        self.get_socket()
        self.connect_to_server()
        self.get_user_input_forever()

    def get_socket(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connect_to_server(self):
        try:
            self.socket.connect((Client.SERVER_HOSTNAME, Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def get_console_input(self):
        while True:
            self.input_text = input("Input: ")
            if self.input_text != "":
                print("Command entered: ", self.input_text)  #print out recieved command
                break

    def get_user_input_forever(self):
        while True:
            try:
                self.get_console_input()
                if self.input_text == GET_MIDTERM_AVG_CMD:	#if command for average is given, notify user and send command
                    print("Fetching Midterm average...")
                    self.connection_send()
                    self.connection_receive()
                elif self.input_text == GET_LAB_1_AVG_CMD:
                    print("Fetching Lab 1 average...")
                    self.connection_send()
                    self.connection_receive()
                elif self.input_text == GET_LAB_2_AVG_CMD:
                    print("Fetching Lab 2 average...")
                    self.connection_send()
                    self.connection_receive()
                elif self.input_text == GET_LAB_3_AVG_CMD:
                    print("Fetching Lab 3 average...")
                    self.connection_send()
                    self.connection_receive()
                elif self.input_text == GET_LAB_4_AVG_CMD:
                    print("Fetching Lab 4 average...")
                    self.connection_send()
                    self.connection_receive()
                elif self.input_text == GET_GRADES:  #if command for grades is given, ask for ID/password hash
                    while True:
                        self.username = input("Student ID number: ")
                        if self.username != "":
                            break
                    self.password = getpass.getpass(prompt='Password: ', stream=None)

                    print("ID number " + self.username + " and password " + self.password + " received") 
                    self.get_hash()   #convert input ID/password inot a hash
                    self.connection_send()
                    self.connection_receive()

                else:
                    print("Incorrect request, please try again")

				self.username = ""    #reset variables
				self.password = ""
				self.login_hash = hashlib.sha256()
				self.return_message = ""
                    
            except (KeyboardInterrupt, EOFError):
                print()
                print("Closing server connection ...")
                self.socket.close()
                sys.exit(1)

        
    def send_console_input_forever(self):
        while True:
            try:
                self.get_console_input()
                self.connection_send()
                self.connection_receive()
            except (KeyboardInterrupt, EOFError):
                print()
                print("Closing server connection ...")
                self.socket.close()
                sys.exit(1)

    def get_hash(self):
        try:  	
            self.login_hash.update(self.username.encode("utf-8"))  #add username and password into hash after encoding
            self.login_hash.update(self.password.encode("utf-8"))
            self.login_hash = self.login_hash.digest()
        except Exception as msg:
            print(msg)
            sys.exit(1)
            
    def connection_send(self):
        try:
            self.socket.sendall(self.input_text.encode(Server.MSG_ENCODING))
			
            if self.input_text == GET_GRADES:
                print("ID/password hash " + str(self.login_hash) + " sent to server")
                self.socket.sendall(self.login_hash)
            
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connection_receive(self):
        try:
            recvd_bytes = self.socket.recv(Client.RECV_BUFFER_SIZE)

            if len(recvd_bytes) == 0:
                print("Closing server connection ... ")
                self.socket.close()
                sys.exit(1)

            self.return_message = recvd_bytes.decode(Server.MSG_ENCODING)
			
            if self.input_text == GET_GRADES:  # for returning grades/error message, format to correctly display
                if self.return_message == "Password Failure":
                    print(self.return_message)
                else:
                    data = self.return_message.split(",")
                    for i in data:
                        print(i)
            else:
                print("Received: ", self.return_message)

        except Exception as msg:
            print(msg)
            sys.exit(1)

if __name__ == '__main__':


    roles = {'client': Client, 'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='server or client role',
                        required=True, type=str)
    
    args = parser.parse_args()
    server_operation = roles[args.role]()



