Aluno: Tiago Serique Valadares
GRR20195138


Arquivos no diretório "volumes":
    - arp_spoofing.py: Script que realiza o ataque de ARP Spoofing
    - get_iface.py: Script que retorna a interface de rede das máquinas
    - requirements.txt: Arquivo com as dependências necessárias para rodar os
    - rsh_attack.py: Script que realiza o ataque de Mitnick


Foi adicionado ao docker-compose.yml a criação do arquivo .rhosts nas 
configurações do X Terminal. O arquivo .rhosts é um arquivo de configuração do
rsh que permite que um usuário execute comandos em um servidor remoto sem a
necessidade de autenticação. Caso o arquivo não exista, crie no /root do 
X Terminal com o seguinte conteúdo:

```
    10.9.0.6
```

O arquivo requirements.txt tem o necessário para rodar os scripts de ataque.

Ordem de execução para mostrar o funcionamento do ataque:

    1 - Executar o comando "docker-compose up" na pasta do arquivo 
docker-compose.yml
    2 - Abrir o shell do atacante e rodar o comando "python3 arp_spoofing.py" no
diretório "volumes"
    3 - Abrir o shell do atacante e rodar o comando "python3 rsh_attack.py" no
diretório "volumes"
    4 - Rodar o comando "rsh 10.9.0.5" no shell do Trusted Server
    5 - Checar output do rsh_attack.py no shell do atacante, que deve mostrar
que o ataque foi bem sucedido
    6 - Executar o comando "rsh 10.9.0.5" no shell do atacante
