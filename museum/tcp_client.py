from museum.models import *
from rest_framework.views import APIView
from django.http import JsonResponse
import uuid
import socket
import sys
import time
from .models import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def encrypt(message, pub_key):
    print('inside encrypt++++++++++++++++++++=', message,'***** ', pub_key)
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(message)


class TcpClientMessage(APIView):

    def get(self, request, node_id, command):
        try:
            print("hello")
            node_obj = Node.objects.get(mac_addr=node_id)
            print(node_obj.ip)
            print(node_obj.port)
        except Node.DoesNotExist:
            node_obj = None
        if node_obj:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((node_obj.ip, int(node_obj.port)))
                sock.sendall(command.encode())
                sock.setblocking(0)
                # data = sock.recv(1024)
                # print('Received', repr(data))
                sock.close()
                return JsonResponse('Message successfully sent to device')
            except socket.error as ex:
                return JsonResponse('Connect error with current device. -- ' + str(ex))
        else:
            return JsonResponse('Invalid IP address and port number')



class TCPClient():

    def sendTcpCommandTimestamp(self, ip, port, message):
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, int(port)))
            #sock.sendall('timestamp'.encode())
            sock.sendall(message.encode())
            #sock.setblocking(0)
            data = sock.recv(1024)
            timestamp=data.decode('utf-8').split(' ')[1]
            
            sock.close()
            return float(timestamp)
        except socket.error as ex:
            print(ex)
            return ex

    def sendTcpCommand(self, ip, port, message):
        
        try:
            nodeO=Node.objects.get(ip=ip)
            if False:
                print('pem file inside if-------------',message, type(message),nodeO.pem_file)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((ip, 2627))
                encrypted_message=encrypt(message.encode(),RSA.importKey(nodeO.pem_file))
                print
                sock.sendall(encrypted_message)
                sock.setblocking(0)
                # data = sock.recv(1024)
                # print('Received', repr(data))
                # timeout=10
                # time_start=time.time()
                # while time.time()<time_start+timeout:
                #     try:
                #         data=sock.recv(1024)
                #     except:
                #         print('no data yet')
                    
                # if data:
                #     print('Received', repr(data), data)
                #     sock.close()
                #     print('connection closed')
                #     return data
                    
                sock.close()
                return True

                
            else:
                print('no pem file inside else')
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((ip, int(port)))
                sock.sendall(message.encode())
                sock.setblocking(0)
                # data = sock.recv(1024)
                # print('Received', repr(data))
                # timeout=10
                # time_start=time.time()
                # while time.time()<time_start+timeout:
                #     try:
                #         data=sock.recv(1024)
                #     except:
                #         print('no data yet')
                    
                # if data:
                #     print('Received', repr(data), data)
                #     sock.close()
                #     print('connection closed')
                #     return data
                    
                sock.close()
                return True

        except socket.error as ex:
            print(ex)
            return ex


class EncryptedTCPClient():

    def sendTcpCommandTimestamp(self, ip, port, message):
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, int(port)))
            #sock.sendall('timestamp'.encode())
            sock.sendall(message)
            #sock.setblocking(0)
            data = sock.recv(1024)
            timestamp=data.decode('utf-8').split(' ')[1]
            
            sock.close()
            return float(timestamp)
        except socket.error as ex:
            print(ex)
            return ex

    def sendTcpCommand(self, ip, port, message):
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, int(port)))
            sock.sendall(message)
            sock.setblocking(0)
            # data = sock.recv(1024)
            # print('Received', repr(data))
            # timeout=10
            # time_start=time.time()
            # while time.time()<time_start+timeout:
            #     try:
            #         data=sock.recv(1024)
            #     except:
            #         print('no data yet')
                
            # if data:
            #     print('Received', repr(data), data)
            #     sock.close()
            #     print('connection closed')
            #     return data
                
            sock.close()
            return True
        except socket.error as ex:
            print(ex)
            return ex
