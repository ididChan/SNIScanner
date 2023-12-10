import socket
import ssl
import http3
import urllib.parse
import dns.resolver
import dns.rdatatype

from keyParser import check_ESNIKey, check_ECHKey

headers = {'Accept': '*text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en,zh-CN;q=0.9,zh;q=0.8',
            'Cache-Control': 'max-age=0',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
            'Connection': 'keep-alive',
            'Referer': 'http://www.google.com/'
            }

def show_banner():
    print("""
            _____  __________                          
           / __/ |/ /  _/ __/______ ____  ___  ___ ____
          _\ \/    // /_\ \/ __/ _ `/ _ \/ _ \/ -_) __/
         /___/_/|_/___/___/\__/\_,_/_//_/_//_/\__/_/ 
    """)
    print(":////////////////////////////////////////////////////////////:")

class SNIScanner:

    def __init__(self, hostname):
        self.hostname = self.get_hostname(hostname)

    def get_hostname(self, hostname):
        if hostname.startswith(("http", "https")):
            netloc = urllib.parse.urlsplit(hostname).netloc
        else:
            netloc = hostname

        if not netloc.startswith("www."):
            netloc = "www." + netloc

        return netloc.split(":")[0]
    
    def get_tls_versions(self, hostname):
        context = ssl.create_default_context()
        context.set_ciphers("ALL:@SECLEVEL=1")
        try:
            socket.setdefaulttimeout(15)
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    tls_highest = ssock.selected_alpn_protocol()
                    tls_ssl_highest = ssock.version()
                    npn_highest = ssock.selected_npn_protocol()
                    print("[TLS scanning] TLS information detected")
                    print("[TLS scanning] Result --> TLS/SSL Highest Version: {}, ALPN Highest Version: {}, NPN Highest Version: {}".format(tls_ssl_highest, tls_highest, npn_highest))
                    return (1, [tls_ssl_highest, tls_highest, npn_highest])
        except (ConnectionRefusedError, ConnectionResetError):
            print("[TLS scanning] Connection error, please retry...")
            return (0, None)
        except ssl.SSLError as error:
            print("[TLS scanning] SSL error, please retry...")
            return (-1, error)
        except socket.error as msg:
            print("[TLS scanning] Socket error, please retry...")
            return (-1, msg)
    
    def check_ESNI(self, hostname):
        rrset_info = set()
        esni_record = "_esni." + hostname.split("www.")[1]
        try:
            dns_record = dns.resolver.resolve(esni_record, dns.rdatatype.TXT)
        except dns.resolver.NXDOMAIN:
            print("[ESNI scanning] Failed to retrieve DNS response, please check your input domain name again...")
            return (0, "DNS Error")
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers) as error:
            print("[ESNI scanning] Failed to retrieve DNS response, no TXT record found...")
            return (0, error)
        except dns.resolver.Timeout:
            print("[ESNI scanning] DNS query timeout...")
            return (-1, "DNS query timeout")
        
        for record in dns_record.rrset:
            record_text = record.to_text()
            if record_text.find("==") != -1:
                pkey = record_text[1:-1]
                result, info, keyStruct = check_ESNIKey(pkey)
                if result == True:
                    rrset_info.add(keyStruct)
        
        if len(rrset_info) == 0:
            print("[ESNI scanning] ESNIKey not detected...")
            return (0, "No valid ESNIKey found")
        else:
            print("[ESNI scanning] ESNIkey detected")
            print("[ESNI scanning] Result --> ESNI supported, {} ESNIKey detected".format(len(rrset_info)))
            return (1, rrset_info)
            
    def check_ECH(self, hostname):
        try:
            dns_record = dns.resolver.resolve(hostname, dns.rdatatype.HTTPS)
            find_ech = dns_record.rrset[0].params._odict.__contains__(5)

            if find_ech:
                pkey = dns_record.rrset[0].params[5].ech
                result, info, keyStruct = check_ECHKey(pkey)
                if result == True:
                    print("[ECH scanning] ECHConfig detected")
                    print("[ECH scanning] Result --> ECH supported, ECHConfig identified as: {}".format(keyStruct))
                    return (1, keyStruct)
                else:
                    print("[ECH scanning] {}".format(info))
                    return (0, keyStruct)
            else:
                print("[ECH scanning] ECHConfig not detected...")
                return (0, "No HTTPS-RR record found")
        except dns.resolver.NXDOMAIN:
            print("[ECH scanning] Failed to retrieve DNS response, please check your input domain name again...")
            return (0, "DNS Error")
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers) as error:
            print("[ECH scanning] Failed to retrieve DNS response, no HTTPS-RR record found...")
            return (0, error)
        except dns.resolver.Timeout:
            print("[ECH scanning] DNS query timeout...")
            return (-1, "DNS query timeout")
        
    def check_QUIC(self, hostname):
        url = "https://" + hostname
        try:
            response = http3.get(url, headers=headers)
            if 'alt-svc' in response.headers:
                print("[QUIC scanning] Alt-Svc detected")
                if str(response.headers['alt-svc']).find('h3') != -1:
                    print("[QUIC scanning] h3 field detected")
                    print("[QUIC scanning] Result --> QUIC supported, Version info: {}".format(str(response.headers['alt-svc'])))
                    return (1, str(response.headers['alt-svc']))
                else:
                    print("[QUIC scanning] h3 field not detected...")
                    return (0, str(response.headers['alt-svc']))
            else:
                print("[QUIC scanning] Alt-Svc not detected...")
                return (0, None)
        except Exception as e:
            print("[QUIC scanning] Connection error occured, please retry...")
            return (-1, e)


if __name__ == '__main__':
    show_banner()

    while True:
        hostname = input("Please enter the domain name for scanning (or enter Q/q to quit): ")
        if not hostname or hostname.upper() == "Q":
            break
        else:
            instance = SNIScanner(hostname)
            qname = instance.hostname
            while True:
                type = input("Please choose the type of scanning you want to process (TLS/ESNI/ECH/QUIC/All): ")
                if not type or type.upper() == "Q":
                    break
                else:
                    if type.upper() == "ESNI":
                        instance.check_ESNI(qname)
                    elif type.upper() == "TLS":
                        instance.get_tls_versions(qname)
                    elif type.upper() == "ECH":
                        instance.check_ECH(qname)
                    elif type.upper() == "QUIC":
                        instance.check_QUIC(qname)
                    elif type.upper() == "ALL":
                        instance.get_tls_versions(qname)
                        instance.check_ESNI(qname)
                        instance.check_ECH(qname)
                        instance.check_QUIC(qname)
    

