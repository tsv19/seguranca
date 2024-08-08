import subprocess
import socket

# Porta para ouvir
porta = 8349

def executa_comando():
    # Executa o comando ls no diretório /root e captura a saída
    saida = subprocess.check_output('ls /root', shell=True)
    return saida

def servidor():
    # Cria um socket TCP/IP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Associa o socket à porta
    s.bind(('172.19.0.99', porta))

    # Escuta por conexões
    s.listen(1)

    print(f"[*] Ouvindo na porta {porta}...")

    while True:
        # Aceita uma conexão
        conexao, endereco = s.accept()
        print(f"[*] Conexão recebida de {endereco}")

        try:
            # Executa o comando e captura a saída
            saida = executa_comando()

            # Envia a saída para o cliente
            conexao.sendall(saida)
            print("[*] Dados enviados com sucesso")

        except Exception as e:
            print("[!] Erro:", e)

        finally:
            # Fecha a conexão
            conexao.close()

if __name__ == "__main__":
    servidor()
