#! /usr/bin/python3

import socket,sys,string,re,threading

def rtspheader(mb,sjdk):
    global str_options_header
    str_options_header = 'DESCRIBE rtsp://'+mb+':'+str(sjdk)+'/ '+'/RTSP/1.0\r\n'
    str_options_header += 'CSeq:3 \r\n'
    str_options_header += 'User-Agent:LibVLC/3.0.2 (LIVE555 Streaming Media v2016.11.28) \r\n'
    str_options_header += 'Accept: application/sdp'
    return str_options_header
    #rtsp.sendall(str.encode('DESCRIBE rtsp://'+target+':'+str(port)+'/ '+'/RTSP/1.0\r\n')) #DESCRIBE
    #rtsp.sendall(str.encode('OPTIONS rtsp://'+target+':'+str(port)+'/ '+'/RTSP/1.0\r\n')) #OPTIONS
    #rtsp.sendall(str.encode('GET_PARAMETER rtsp://'+target+':'+str(port)+' '+'/RTSP/1.0\r\n')) #GET_PARAMETER
    #rtsp.sendall(str.encode('SET_PARAMETER rtsp://'+target+':'+str(port)+' '+'/RTSP/1.0\r\n')) #SET_PARAMETER

def add_header_according_to_protocol(str_header):
    str_header = str_header[0:len(str_header)-2]
    str_header += 'Accept: application/rtsl, application/sdp;level=2'
    str_header += 'Accept-Encoding: \r\n'
    str_header += 'Accept-Language: \r\n'
    str_header += 'Authorization: \r\n'
    str_header += 'Bandwidth: 1*DIGIT \r\n'
    str_header += 'Blocksize: \r\n'
    str_header += 'Cache-Control: no-cache \r\n'
    str_header += 'Conference: 199702170042.SAA08642@obiwan.arl.wustl.edu%20Starr \r\n'
    str_header += 'Connection: \r\n'
    str_header += 'Content-Base: \r\n'
    str_header += 'Content-Encoding: \r\n'
    str_header += 'Content-Language: \r\n'
    str_header += 'Content-Length: 20 \r\n'
    str_header += 'Content-Location: \r\n'
    str_header += 'Content-Type: \r\n'
    str_header += 'Date: \r\n'
    str_header += 'Expires: Thu, 01 Dec 1994 16:00:00 GMT \r\n'
    str_header += 'From: \r\n'
    str_header += 'If-Modified-Since: Sat, 29 Oct 1994 19:43:31 GMT \r\n'
    str_header += 'Last-Modified: \r\n'
    str_header += 'Proxy-Require: \r\n'
    str_header += 'Referer: \r\n'
    str_header += 'Require: funky-feature \r\n'
    str_header += 'Scale: -3.5 \r\n'
    str_header += 'Speed: 2.5 \r\n'
    str_header += 'Transport: RTP/AVP;unicast;client_port=3456-3457;mode="PLAY" \r\n'
    str_header += 'User-Agent: \r\n'
    str_header += 'Via: \r\n'
    str_header += 'Range: npt=2\r\n'
    str_header += '\r\n'
    return str_header   



def run():    
    with open('host.txt', 'r') as file:
        fi = file.readlines()

    re_ip = re.compile("[0-9]+(?:\.[0-9]+){3}")
    re_port = re.compile("[0-9]+(?:\.[0-9]+){3}(:[0-9]+)?")
    ip = re.findall(re_ip,str(fi))
    port = re.findall(re_port,str(fi))
    #print(ip[0])
    #print(port[0][1:])

    mundata = len(ip)
    for mun in range(int(mundata)):
        target = ip[mun]
        ports = port[mun][1:]       
        ipport = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        ipport.settimeout(1)
        result = ipport.connect_ex((str(target),int(ports)))
        if result == 0:
            address = (str(target), int(ports))
            rtspdata = add_header_according_to_protocol(rtspheader(target,ports))
            try:
                #print(rtspheader()) rtsp header options
                rtsp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                rtsp.settimeout(1)
                rtsp.connect(address)
                rtsp.sendall(str.encode(rtspdata))
                data = rtsp.recv(1024)
                pf = str(data)
                #print(data) #返回数据
                #print ('[!] Data transmission success!')
                if 'RTSP/1.0 400' in pf:
                    print('[+]rtsp server RTSP/1.0 400'+' '+target+':'+str(ports))
                    with open('good.txt',"a") as file:   #只需要将之前的”w"改为“a"即可，代表追加内容
                        file.write(target+':'+str(ports)+'\n')
                    
                else:
                    print('[*]unknown server!'+' '+target+':'+str(ports))
                    with open('unknown_server.txt',"a") as file:   #只需要将之前的”w"改为“a"即可，代表追加内容
                        file.write(target+':'+str(ports)+'\n')

                
            except:
                print('[-]Request establishment failed!'+' '+target+':'+str(ports))
                with open('request_failed.txt',"a") as file:   #只需要将之前的”w"改为“a"即可，代表追加内容
                    file.write(target+':'+str(ports)+'\n')
        else:
            print('[-]port close'+' '+target+':'+str(ports))
            with open('port_close.txt',"a") as file:   #只需要将之前的”w"改为“a"即可，代表追加内容
                file.write(target+':'+str(ports)+'\n')
       
if __name__ == '__main__':
    thre = threading.Thread(target=run(), args=(500,))
    thre.start()
    thre.join()
    
