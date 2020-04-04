# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
import struct
import asyncio

class HttpRequestInfo(object):
    """
    Represents a HTTP request information

    Since you'll need to standardize all requests you get
    as specified by the document, after you parse the
    request from the TCP packet put the information you
    get in this object.

    To send the request to the remote server, call to_http_string
    on this object, convert that string to bytes then send it in
    the socket.

    client_address_info: address of the client;
    the client of the proxy, which sent the HTTP request.

    requested_host: the requested website, the remote website
    we want to visit.

    requested_port: port of the webserver we want to visit.

    requested_path: path of the requested resource, without
    including the website name.

    NOTE: you need to implement to_http_string() for this class.
    """

    def __init__(self, client_info, method: str, requested_host: str,
                 requested_port: int,
                 requested_path: str,
                 headers: list):
        self.method = method
        self.client_address_info = client_info
        self.requested_host = requested_host
        self.requested_port = requested_port
        self.requested_path = requested_path
        # Headers will be represented as a list of lists
        # for example ["Host", "www.google.com"]
        # if you get a header as:
        # "Host: www.google.com:80"
        # convert it to ["Host", "www.google.com"] note that the
        # port is removed (because it goes into the request_port variable)
        self.headers = headers

    def to_http_string(self):
        """
        Convert the HTTP request/response
        to a valid HTTP string.
        As the protocol specifies:

        [request_line]\r\n
        [header]\r\n
        [headers..]\r\n
        \r\n

        (just join the already existing fields by \r\n)

        You still need to convert this string
        to byte array before sending it to the socket,
        keeping it as a string in this stage is to ease
        debugging and testing.
        """
        req_line = " ".join([self.method, self.requested_path, "HTTP/1.0"])
        stringified = [": ".join([k, v]) for (k, v) in self.headers] # Header: Value
        stringified.insert(0, req_line) # Insert request line at first place to maintain format
        http_string = "\r\n".join(stringified) + "\r\n\r\n"

        return http_string

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Host:", self.requested_host)
        print(f"Port:", self.requested_port)
        stringified = [": ".join([k, v]) for (k, v) in self.headers]
        print("Headers:\n", "\n".join(stringified))


class HttpErrorResponse(object):
    """
    Represents a proxy-error-response.
    """

    def __init__(self, code, message):
        self.code = code
        self.message = message

    def to_http_string(self):
        """ Same as above """
        return "HTTP/1.0 {} {}\r\n".format(self.code, self.message)

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(self.to_http_string())


class HttpRequestState(enum.Enum):
    """
    The values here have nothing to do with
    response values i.e. 400, 502, ..etc.

    Leave this as is, feel free to add yours.
    """
    INVALID_INPUT = 0
    NOT_SUPPORTED = 1
    GOOD = 2
    PLACEHOLDER = -1

    CACHE = {}


def entry_point(proxy_port_number):
    """
    Entry point, start your code here.

    Please don't delete this function,
    but feel free to modify the code
    inside it.
    """

    proxysock = setup_sockets(int(proxy_port_number))
    remotesock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    while True:
        try:
            clientsock, clientaddr = proxysock.accept()
            print(f"Connection between {clientaddr} has been established")
            http_request_msg = ''
            while True:
                msg = clientsock.recv(1024) #Receive Request
                if len(msg) <= 2:
                    break
                http_request_msg += msg.decode("utf-8")
            result = http_request_pipeline(clientaddr, http_request_msg) #Forming in correct format
            if isinstance(result, HttpErrorResponse):
                clientsock.send(result.to_byte_array(result.to_http_string()))
            elif result in HttpRequestState.CACHE.keys(): #check for response in cache
                print("Sending Data to Client From Cache...")
                clientsock.sendall(HttpRequestState.CACHE[result])
            else:
                http_response_msg = ''
                remotesock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                remotesock.connect((result.requested_host, result.requested_port))
                remotesock.send(result.to_byte_array(result.to_http_string()))
                while True:
                    msg = remotesock.recv(1024)
                    if len(msg) <= 0:
                        break
                    http_response_msg += msg.decode("utf-8")
                HttpRequestState.CACHE[result] = http_response_msg #Storing in cache
                remotesock.close()
                clientsock.send(bytes(http_response_msg, "utf-8"))
            clientsock.close()
        except:
            clientsock.close()
            pass
    return None


def setup_sockets(proxy_port_number):
    """
    Socket logic MUST NOT be written in the any
    class. Classes know nothing about the sockets.

    But feel free to add your own classes/functions.

    Feel free to delete this function.
    """
    print("Starting HTTP proxy on port:", proxy_port_number)
    proxysock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    proxysock.bind(('127.0.0.1', proxy_port_number))
    proxysock.listen(12)
    # when calling socket.listen() pass a number
    # that's larger than 10 to avoid rejecting
    # connections automatically.
    return proxysock


def do_socket_logic():
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.

    Feel free to delete this function.
    """
    pass


def http_request_pipeline(source_addr, http_raw_data):
    """
    HTTP request processing pipeline.

    - Validates the given HTTP request and returns
      an error if an invalid request was given.
    - Parses it
    - Returns a sanitized HttpRequestInfo

    returns:
     HttpRequestInfo if the request was parsed correctly.
     HttpErrorResponse if the request was invalid.

    Please don't remove this function, but feel
    free to change its content
    """
    # Parse HTTP request
    validity = check_http_request_validity(http_raw_data)
    # Return error if needed, then:
    if validity == HttpRequestState.INVALID_INPUT:
        return HttpErrorResponse("400", "Bad Request")
    elif validity == HttpRequestState.NOT_SUPPORTED:
        return HttpErrorResponse("501", "Method Not Implemented")
    elif validity == HttpRequestState.GOOD:
        return HttpErrorResponse("200","OK")
    # parse_http_request()
    request = parse_http_request(source_addr, http_raw_data)
    # sanitize_http_request()
    sanitize_http_request(request)
    # Validate, sanitize, return Http object.
    return request


def parse_http_request(source_addr, http_raw_data):
    """
    This function parses a "valid" HTTP request into an HttpRequestInfo
    object.
    """
    parsed_req = http_raw_data.split("\r\n") # Extract request components
    
    # Request line
    req_line = parsed_req[0].split(" ")
    method = req_line[0]
    url = req_line[1]
    if url.startswith("/"):
        path_name = url # relative address
        # Get host info
        for h in parsed_req[1:]:
            k, v = h.split(":", 1)
            if k == 'Host':
                v = v[1:]
                if v.lower().startswith("http://"):
                    v = v.split(":")
                    host_name = v[0] + ":" + v[1]
                    if len(v) > 2:
                        port_num = int(v[2])
                    else:
                        port_num = 80
                else:
                    v = v.split(":")
                    host_name = v[0]
                    if len(v) > 1:
                        port_num = int(v[1])
                    else:
                        port_num = 80
            break
    else:
        if url.lower().startswith("http://"):
            url = url.split("/")
            host_info = url[0] + "//" + url[2]
            host_info = host_info.split(":")
            host_name = host_info[0] + ":" + host_info[1]
            if len(host_info) > 2:
                port_num = int(host_info[2])
            else:
                port_num = 80
            path_name = "/" + "/".join(url[3:])
        else:
            url = url.split("/")
            host_info = url[0]
            host_info = host_info.split(":")
            host_name = host_info[0]
            if len(host_info) > 1:
                port_num = int(host_info[1]) # Extracted port number
            else:
                port_num = 80 # Default
            path_name = "/" + "/".join(url[1:])

    version = req_line[2]

    # Headers
    headers = [] # Represented as list of lists
    for h in parsed_req[1:len(parsed_req) - 1]:
        k, v = h.split(":", 1) # split each line by http field name and value
        v = v[1:]
        if k == 'Host':
            continue
        headers.append([k,v])
    
    # Replace this line with the correct values.
    return HttpRequestInfo(source_addr, method, host_name, port_num, path_name, headers)


def check_http_request_validity(http_raw_data) -> HttpRequestState:
    """
    Checks if an HTTP request is valid

    returns:
    One of values in HttpRequestState
    """
    req_line, *headers_and_body = http_raw_data.split("\r\n")
    headers = {}
    
    import re
    # Validate headers
    for el in headers_and_body:
        if el == '':
            break
        if re.match(r"[a-zA-Z0-9]+: [a-zA-Z0-9]+", el) is None:
            return HttpRequestState.INVALID_INPUT
    
    for i in range(len(headers_and_body)):
        if headers_and_body[i] == '':
            break
        headers[headers_and_body[i][:headers_and_body[i].find(':')]] = headers_and_body[i][headers_and_body[i].find(' ') + 1:]
    body = headers_and_body[i:]
    
    req_line = req_line.split()
    if len(req_line) != 3: # Missing one of the fields 
        return HttpRequestState.INVALID_INPUT
    
    hostregex = re.compile(r'\A((http:\/\/){0,1}(w{3}\.){0,1}(?!w*\.)(?!http:\/\/))'
                           r'((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}'
                           r'(?::\d+)?'
                           r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    if req_line[1][0] == '/': # Check for the Host header in headers dictionary
        if 'Host' not in headers:
            return HttpRequestState.INVALID_INPUT
        if headers['Host'].lower().startswith("http://"): # There is a path in the Host header which is invalid (/ after http:// if present)
            if headers['Host'].count('/') > 2:
                return HttpRequestState.INVALID_INPUT
        elif '/' in headers['Host']:
            return HttpRequestState.INVALID_INPUT
        
        host = headers['Host']
    else:
        host = req_line[1]
    
    if re.match(hostregex, host) is None:
        return HttpRequestState.INVALID_INPUT
    
    methods = ['POST','HEAD','PUT','DELETE','OPTIONS','TRACE'] # Availabale methods
    if req_line[0] != 'GET': 
        if req_line[0] in methods:
            return HttpRequestState.NOT_SUPPORTED
        else:
            return HttpRequestState.INVALID_INPUT

    version = req_line[2] # Extract version number
    if re.match(r"\A(HTTP/)\d+\.\d+$", version) is None:
        return HttpRequestState.INVALID_INPUT
    
    return HttpRequestState.GOOD # Valid Request


def sanitize_http_request(request_info: HttpRequestInfo):
    """
    Puts an HTTP request on the sanitized (standard) form
    by modifying the input request_info object.

    for example, expand a full URL to relative path + Host header.

    returns:
    nothing, but modifies the input object
    """
    # Insert host in headers
    request_info.headers.insert(0, ['Host', request_info.requested_host + ":" + str(request_info.requested_port)])


#######################################
# Leave the code below as is.
#######################################


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.

        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comand-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.


def check_file_name():
    """
    Checks if this file has a valid name for *submission*

    leave this function and as and don't use it. it's just
    to notify you if you're submitting a file with a correct
    name.
    """
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_){,2}lab2\.py", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    else:
        print(f"[LOG] File name is correct.")


def main():
    """
    Please leave the code in this function as is.

    To add code that uses sockets, feel free to add functions
    above main and outside the classes.
    """
    print("\n\n")
    print("*" * 50)
    print(f"[LOG] Printing command line arguments [{', '.join(sys.argv)}]")
    check_file_name()
    print("*" * 50)

    # This argument is optional, defaults to 18888
    proxy_port_number = get_arg(1, 18888)
    entry_point(proxy_port_number)


if __name__ == "__main__":
    main()
