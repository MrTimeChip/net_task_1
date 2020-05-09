import subprocess
import re
import argparse
import sys

from askWhois import Whois

TRACERT_LINE_NUMBER_IP = re.compile(r'\s(\d+?)\s .+?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
TRACERT_TIMEOUT = re.compile(r'\s(\d+?)\s .+?\s\*\s*?\*\s*?\*')


def create_parser():
    parser = argparse.ArgumentParser(description=
                                     'Программа для трассировки автономных систем.',
                                     epilog=
                                     'Данил Панков КН-201 МЕН-280206')

    parser.add_argument('ip', help='IP адресс узла до которого будет происходить трассировка.')

    return parser


def trace(ip):
    process = subprocess.Popen(["tracert", ip],
                               stdout=subprocess.PIPE,
                               stdin=subprocess.PIPE)
    print(f'№\tIP\t\tASN\t\tinfo')
    while True:
        received = process.stdout.readline()
        if not received:
            break
        decoded = received.decode('windows-1251', errors='ignore')
        process_tracert_data(decoded)
        timeout = re.search(TRACERT_TIMEOUT, decoded)
        if timeout:
            print(f'{timeout.group(1)}\t*\t*\t*')
            break


def process_tracert_data(decoded):
    info = re.search(TRACERT_LINE_NUMBER_IP, decoded)
    if info:
        number = info.group(1)
        ip = info.group(2)
        result = f'{number}\t{ip}'
        data = Whois.info_on(ip)
        result += f'\t{data["origin"]}\t\t{data["descr"]} [{data["country"]}]'
        print(result)


if __name__ == '__main__':
    parser = create_parser()
    namespace = parser.parse_args(sys.argv[1:])
    ip = namespace.ip
    trace(ip)
