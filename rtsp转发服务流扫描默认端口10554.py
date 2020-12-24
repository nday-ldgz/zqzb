#! /usr/bin/python3

import socket,sys,string,re,threading

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
            rtspdata = '\x01\x00\x02r\x17\x02\x00\t\x18sD\x03\x00\x01\x00\x00\x00\x00\x00\x02\x0b\x00\x00x\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\xc0\x00\x00\x00\x00\x04\x00\t\x18sD\x03\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x005\x00\x00\x00;\x00\x00\x00\x17\x00\x00\x00\x0e\x00\x00\x00\x08\x00\x00\x00j\x00\x00\x00\x04\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
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
                if 'RTSP/1.0' in pf:
                    print('[+]rtsp server'+' '+target+':'+str(ports))
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
    
