import socket

class FreePortPicker:
    def __init__(self, 
                ipv6: bool = False,
                reserve_timeout: int = 15
                ) -> None:
        
        self.ipv6 = ipv6
        self.reserve_timeout = reserve_timeout
        
        self.used_ports = []

    def get(self):

        while True:

            with socket.socket(socket.AF_INET6 if self.ipv6 == True else socket.AF_INET, socket.SOCK_DGRAM) as s:

                ip = '::' if self.ipv6 else '0.0.0.0'

                s.bind((ip, 0))

                s.settimeout(float(self.reserve_timeout))

                port = int(s.getsockname()[1])

                # Check if the port is in the exclude list
                if port not in self.used_ports:
                    # Optionally, wait for a reserve timeout
                    self.used_ports.append(port)
                    print(self.used_ports)
                    break
                    
        return port