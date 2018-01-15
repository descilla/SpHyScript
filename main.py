#!/usr/bin/env python3
import urllib.request
import urllib.parse
import json
import re
from bs4 import BeautifulSoup
import hashlib

PASSWORD = b'PASSWORD'


def list_to_dict(in_list):
    result = {}
    for el in in_list:
        result[el['varid']] = el['varvalue']
    return result


def tupleslist_to_dict(tupleslist):
    result = {}
    for t in tupleslist:
        result[t[0]] = t[1]
    return result


def remove_spacing(string):
    return re.sub("[\t ]*([\r\n]+)[\t ]*", "\\1", string)


def clean_json(string):
    string = string.decode('utf-8').replace("'", '"')
    string = re.sub("[\r\n\t ]+", "", string)
    string = re.sub("([}\]]),([}\]])", "\\1\\2", string)
    return string


def get_challenge(challenge_script_tag):
    for line in challenge_script_tag.splitlines():
        if '=' in line:
            name, value = line.split('=', 1)
            if name.find("challenge") != -1:
                return value.split('"', 2)[1]
    return None


def get_session_id(cookies):
    cookies = cookies.replace(' ', '')
    for cookie in cookies.split(';'):
        name, value = cookie.split('=')
        if 'SessionID_R3':
            return value
    return None


def request_challenge_code():
    req = urllib.request.Request(
        url='http://speedport.ip/html/login/index.html', method='GET')
    res = urllib.request.urlopen(req, timeout=5)
    res_body = res.read()
    soup = BeautifulSoup(res_body, 'html.parser')
    challenge_script_tag = remove_spacing(soup.find('script').text)
    challenge_code = get_challenge(challenge_script_tag)
    if challenge_code != None:
        pw_hash = hashlib.sha256(
            bytes(challenge_code, 'utf-8') + b':' + PASSWORD).hexdigest()
        return challenge_code, pw_hash
    else:
        print("Challenge Error")
        return None


def send_password(challenge_code, hashed_pass):
    header = {}
    payload = urllib.parse.urlencode({
        'challengev': challenge_code,
        'password': hashed_pass,
        'showpw': "0",
        'csrf_token': "nulltoken"
    }).encode('UTF-8')
    req = urllib.request.Request(
        url='http://speedport.ip/data/Login.json', data=payload, headers=header, method='POST')
    res = urllib.request.urlopen(req, timeout=5)
    res_body = res.read()
    # print(res.info())
    res_json = json.loads(clean_json(res_body).replace('\\', ''))
    res_dict = list_to_dict(res_json)

    if res_dict.get('login', '') != 'success':
        print('Login failed!')
        return None

    print('Login success!')
    res_headers = tupleslist_to_dict(res.getheaders())
    session_id = get_session_id(res_headers['Set-Cookie'])
    if session_id == None:
        print('No Session ID retrieved!')
        return None
    return session_id


def get_json_file(file_name, challenge_code, session_id):
    header = {'Cookie': 'lang=de; SessionID_R3=' + session_id + '; challengev=' +
              challenge_code}
    req = urllib.request.Request(
        url='http://speedport.ip/' + file_name, headers=header, method='GET')
    res = urllib.request.urlopen(req, timeout=5)
    res_body = json.loads(clean_json(res.read()))
    return res_body


challenge_code, hashed_pass = request_challenge_code()
if challenge_code == None:
    exit(1)
session_id = send_password(challenge_code, hashed_pass)
if session_id == None:
    exit(1)

res = get_json_file('/data/dsl.json', challenge_code, session_id)
print(json.dumps(res, indent=4))
res = get_json_file('/data/lteinfo.json', challenge_code, session_id)
print(json.dumps(res, indent=4))

# print(res.status)
# print(res.reason)
