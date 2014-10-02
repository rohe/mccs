import socket
import ssl
import sys


def dump_https_page(hostname, uri='/'):
  _sock = socket.socket(socket.AF_INET)
  _s = ssl.SSLSocket(sock=_sock,
                    ca_certs='/etc/ssl/certs',
                    server_hostname=hostname)
  print 'have socket'
  s.connect((hostname, 443))
  print 'connected'

  print >>s, 'GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n' % (
      uri, hostname),

  t = s.read()
  while t:
    print t,
    t = s.read()

if __name__ == '__main__':
  for x in sys.argv[1:]:
    dump_https_page(hostname=x)