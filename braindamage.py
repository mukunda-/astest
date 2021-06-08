import socket

with socket.create_connection( ("192.168.1.32",80) ) as s:

   s.send( b'''POST /Microsoft-Server-ActiveSync?jRQJBBBRZkNHIVeRkWMoY4GGI1hiBAAAAAACU1A= HTTP/1.1
Host: 192.168.1.32
User-Agent: MJOHNSONTEST/1.0
Authorization: Basic dGJveEBhcmNoLmxvY2FsOlBhc3N3b3JkMTs=
Content-Type: application/vnd.ms-sync
Content-Length: 157

''')

   s.send( b'\x03\x01j\x00\x00\x0eE\x00\x12VHW\x03MJohnson Test\x00\x01\x18Y\x03MJOHNSON-TEST/1.0\x00\x01Z\x03Test OS 1.0\x00\x01[\x03English\x00\x01\x1c`\x03MJOHNSON-TEST/1.0\x00\x01a\x030\x00\x01b\x03OperatorName\x00\x01\x01\x01\x00\x0eFGH\x03MS-EAS-Provisioning-WBXML\x00\x01\x01\x01\x01' )

   print( s.recv(4096) )
