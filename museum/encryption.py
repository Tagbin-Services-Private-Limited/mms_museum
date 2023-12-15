import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
import base64
import json
import codecs
import chardet

key2="-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2nP1TgffPfTspyNv2oaR\nXizTu6cSDfLoHgcHhvI2fb19bLsLgD3PdYap+b7i4exTkQ7X7TghsoWYNrkdHqQQ\n/zrq5YCdBV75M3/zPbndt+mvmmM4P1lDuD026k3v3WrW9dwjDE/dQqXNqmp7G6Vi\nKWzCsLS34a50ieJ2mPk0IDBMScgmPTbb2kTUaJRkS5CFdhrJjfxi4FSpLm0Qx8Nx\nB5cv8s0Ppl5uIW/t2mtk0mA9Ut9lbYUE6fEEtBsjtbOp0k2AwPwekJIj4Vmtk7Kx\nIGv7C/jxFeySUb3uKJaXKalZ85HTfYR0W8i3gG0k2JytjmTownUVhvw8FRk0lGXV\nIJCnFE2jyfWl+wS40tPHsrYgV6uKhpUbFJzDv0lvHhDHlLlI2nO5pPTFLyI/jrXr\n1SOqOwV7TRZ4tj5RA+2i7jfpxgwzdBJdCXhnrL5d5FdhDHClcDjfCJOO44pk1Oi6\nuR0MzGKuy0AfUEcZGO5tJbvBOU8mNOBoB5U3ze7DHK77VerlhDkoVt06g88N6TLx\nz6UYUxPs8fQb7j6indDiLaDNrD30Cgzo5Hgp4WhCXiHeaWy6JJW+F6E8DwPhrsKK\nUT/RZlO6hkZlyLHr92poDwRliG7nE2qz/QGXc0khmnwLCu9eT9+g+ZcEH9DpbuZ9\nM/ceu3C2EsfqnFuQ+5h2uD8CAwEAAQ==\n-----END PUBLIC KEY-----"

print(key2)
special_key=RSA.importKey(key2)

# ip="127.0.0.1"
# port=2627
# print("special_key",special_key)
# message="halt"


def encrypt(message, pub_key):
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(message)
class TCPClient():

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
            

tcp = TCPClient()
tcp_response = tcp.sendTcpCommandTimestamp('192.168.1.115','2627',encrypt("timestamp".encode(),RSA.importKey(key2)))
print(tcp_response)
# the_encoding = chardet.detect(encrypt("timestamp".encode(),RSA.importKey(key2)))['encoding']
# print(the_encoding)
#print(codecs.decode(encrypt("timestamp".encode(),RSA.importKey(key2))))