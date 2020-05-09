import requests
import re


class Whois:
    URL = 'http://www.nic.ru/whois/?query='
    COUNTRY_REGEX = re.compile(r'.*?country:\s*(.*?)\n.*?', re.DOTALL)
    ORIGIN_REGEX = re.compile(r'.*?origin:\s*(.*?)\n', re.DOTALL)
    PRIVATE_IPS = ('10', '192.168', '172.16', '127', '169.254')

    @staticmethod
    def info_on(ip):
        if ip.startswith(Whois.PRIVATE_IPS):
            return {'country': '-', 'origin': '-------', 'descr': 'PRIVATE'}
        response = requests.get(Whois.URL + ip)
        decoded = response.content.decode('utf-8')
        parsed = Whois.__parse_from(decoded)
        return Whois.__make_dict(parsed[0], parsed[1], parsed[2])

    @staticmethod
    def __parse_from(decoded):
        country = re.search(Whois.COUNTRY_REGEX, decoded)
        origin = re.search(Whois.ORIGIN_REGEX, decoded)
        descr_regex = re.compile(fr".*?{origin.group(1)}'.*?descr:\s*(.*?)\n.*?",
                                 re.DOTALL)
        descr = re.search(descr_regex, decoded)
        return country, origin, descr

    @staticmethod
    def __make_dict(country, origin, descr):
        result = {'country': 'None', 'origin': 'None', 'descr': 'None'}
        if country:
            result['country'] = country.group(1)
        if origin:
            result['origin'] = origin.group(1)
        if descr:
            result['descr'] = descr.group(1)
        return result
