import psutil


ATACKKER = "10.9.0.1"


def get_iface(ip_address):
    """
    Obter o nome da interface de rede para o IP fornecido

    :param ip_address: str

    :return: str
    """
    ifaces = psutil.net_if_addrs()
    
    for iface, addresses in ifaces.items():
        for addr in addresses:
            if addr.address == ip_address:
                return iface
    return None


if __name__ == '__main__':
    # Pega a interface do IP do 
    iface = get_iface(ATACKKER)