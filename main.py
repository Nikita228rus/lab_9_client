from conf_sha import *
from conf_math import *
import json
from datetime import datetime


def generation_key(size, message_hash, zero):
    _private_key_ = {
        'SubjectPublickeyInfo': {
            'a': None,
            'p': None,
            'q': None,
        }
    }
    _public_key_ = {
        'b': None,
        'n': None
    }
    p = generation_prime(size)
    q = generation_prime(size)
    n = p * q
    m = len(bin(int(message_hash, 16))[2:].zfill(zero))

    a = []
    b = []
    for i in range(m):
        a.append(random.randint(1, n))
        b.append(pow(reciprocal_integer(a[i], n), 2, n))

    _private_key_['SubjectPublickeyInfo']['a'] = a
    _private_key_['SubjectPublickeyInfo']['p'] = p
    _private_key_['SubjectPublickeyInfo']['q'] = q
    _public_key_['b'] = b
    _public_key_['n'] = n

    json.dump(_public_key_, open('PKCS8.json', 'w+'), indent=4)
    json.dump(_private_key_, open('PKCS12.json', 'w+'), indent=4)


def user(hash_func, size):
    _document_ = {
        'CMSVersion': 1,
        'DigestAlgorithmIdentifiers': 'sha-256',
        'EncapsulatedContentInfo': {'ContentType': 'text',
                                    'OCTET STRING OPTIONAL': 'исходный текст',
                                    },
        'CertificateSet OPTIONAL': 'открытый ключ',
        'RevocationInfoChoises OPTIONAL': None,
        'SignerInfos': {
            'CMSVersion': 1,
            'SignerIdentifier': 'Nikich228rus',
            'DigestAlgorithmIdentifier': 'sha-256',
            'SignedAttributes OPTIONAL': None,
            'SignatureAlgorithmIdentifier': 'RSAdsi',
            'SignatureValue': 'h(m)^d1 mod n',
            'UnsignedAttributes OPTIONAL': {
                'OBJECT IDENTIFIER': 'signature-time-stamp',
                'SET OF AttributeValue': None
            }
        }
    }

    message = open('input.txt', 'r', encoding='utf-8').read()
    _document_['EncapsulatedContentInfo']['OCTET STRING OPTIONAL'] = message

    if hash_func == '1':
        message_hash = sha_256(message)
        zero = 256
        _document_['SignerInfos']['DigestAlgorithmIdentifier'] = 'sha-256'

    elif hash_func == '2':
        message_hash = sha_512(message)
        zero = 512
        _document_['SignerInfos']['DigestAlgorithmIdentifier'] = 'sha-512'

    else:
        message_hash = None
        zero = 0

    generation_key(size, message_hash, zero)

    _public_key_ = json.load(open('PKCS8.json', 'r'))
    _private_key_ = json.load(open('PKCS12.json', 'r'))

    b = _public_key_['b']
    n = _public_key_['n']
    a = _private_key_['SubjectPublickeyInfo']['a']
    p = _private_key_['SubjectPublickeyInfo']['p']
    q = _private_key_['SubjectPublickeyInfo']['q']

    r = random.randint(1, n - 1)
    u = pow(r, 2, n)
    u = str(u)
    s = bin(int(sha_256(message + u), 16))[2:].zfill(zero)

    t = 1
    for i in range(len(s)):
        t *= pow(a[i], int(s[i]))

    print(n)
    t = pow(r * t, 1, n)
    print('THIS---->', u)

    signature = (s, t)

    _document_['SignerInfos']['SignatureValue'] = signature
    _document_['CertificateSet OPTIONAL'] = [b, n]
    json.dump(_document_, open('PKCS_send.json', 'w+'), indent=4)

    send_file = str(json.load(open('PKCS_send.json', 'r')))
    client_send(send_file)

    _data_ = json.load(open('PKCS_get.json', 'r'))
    s, t = _data_['signature centre']
    b, n = _data_['public key']
    time_stamp = _data_['time-stamp']

    w = 1
    for i in range(len(s)):
        w *= pow(b[i], int(s[i]))

    w = pow(t * t * w, 1, n)
    print(w)
    w = str(w)
    s_check = bin(int(sha_256(message + w + time_stamp), 16))[2:].zfill(256)

    if s == s_check:
        print('All ok')
        _document_['SignerInfos']['UnsignedAttributes OPTIONAL']['OBJECT IDENTIFIER'] = _data_['signature centre']
        _document_['SignerInfos']['UnsignedAttributes OPTIONAL']['SET OF AttributeValue'] = time_stamp
        json.dump(_document_, open('PKCS_send.json', 'w+'), indent=4)
    else:
        print('Error')




def server(signature, _public_key_, message):

    b = _public_key_[0]
    n = _public_key_[1]
    s = signature[0]
    t = signature[1]


    w = 1
    for i in range(len(s)):
        w *= pow(b[i], int(s[i]))

    w = pow(t * t * w, 1, n)
    print(w)
    w = str(w)
    s_check = bin(int(sha_256(message + w), 16))[2:].zfill(256)

    print(s == s_check)



def centre_time():

    _data_result_ = {
        'signature centre': None,
        'public key': None,
        'time-stamp': None,
    }
    _document_ = json.load(open('PKCS_send.json', 'r', encoding='utf-8'))
    gama = _document_['SignerInfos']['SignatureValue'][0]
    delta = _document_['SignerInfos']['SignatureValue'][1]

    alfa, beta, p = _document_['CertificateSet OPTIONAL']
    message = _document_['EncapsulatedContentInfo']['OCTET STRING OPTIONAL']
    message_int = text_to_int(message)

    size = len(bin(p)[2:])
    hash_func = _document_['DigestAlgorithmIdentifiers']

    if pow(pow(beta, gama) * pow(gama, delta), 1, p) == pow(alfa, message_int, p):

        time_stamp = str(datetime.now())
        generation_key(size)

        _public_key_ = json.load(open('PKCS8.json', 'r'))
        _private_key_ = json.load(open('PKCS12.json', 'r'))

        p = _public_key_['SubjectPublickeyInfo']['p']
        alfa = _public_key_['SubjectPublickeyInfo']['alpha']
        beta = _public_key_['SubjectPublickeyInfo']['beta']
        a = _private_key_['privateExponent']

        if hash_func == 'sha-256':
            message_hash = sha_256(message + time_stamp)

        elif hash_func == 'sha-512':
            message_hash = sha_512(message + time_stamp)

        else:
            message_hash = None

        r = random.randint(1, p - 2)
        while euclid_algorithm(r, p - 1, False)[0] != 1:
            r = random.randint(1, p - 2)

        r_1 = reciprocal_integer(r, p - 1)

        gama = pow(alfa, r, p)
        message_int = text_to_int(message_hash)

        delta = pow((message_int - a * gama) * r_1, 1, p - 1)
        signature = (gama, delta)

        _data_result_['signature centre'] = signature
        _data_result_['public key'] = [alfa, beta, p]
        _data_result_['time-stamp'] = time_stamp
        json.dump(_data_result_, open('PKCS_get.json', 'w+'), indent=4)


if __name__ == '__main__':
    choose = input('Choose hash func:\n1 - sha-256\n2 - sha-512\n>>>\t')
    if choose == '1':
        user('1', 128)
    elif choose == '2':
        user('2', 128)