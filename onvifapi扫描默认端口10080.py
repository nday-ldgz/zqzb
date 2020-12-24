#! /usr/bin/python3

import socket,sys,string,re,threading,requests

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
            url = 'http://'+str(target)+':'+str(ports)+'/onvif/device_service'
            postdata ='<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><help xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>'
            headers = {'Content-Type':'application/soap+xml; charset=utf-8',
            'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.87 Safari/537.36'}

            try:
                #print(rtspheader()) rtsp header options
                data = requests.post(url,data=postdata,headers=headers,timeout=2)
                #print(data.text) #返回数据
                #print ('[!] Data transmission success!')
                if 'http://www.onvif.org/ver10/device/wsdl' in data.text:
                    print('[+]onvif server'+' '+target+':'+str(ports))
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
    
