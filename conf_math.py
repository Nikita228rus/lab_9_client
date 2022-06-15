import random
import math
import json
from socket import *


def reciprocal_integer(a, p):

    a_1 = euclid_algorithm(a, p, False)[1]
    while a_1 < 0:
        a_1 += p

    return a_1


def parent_element(p):

    gf = [int(x) for x in range(1, p)]

    alfa = random.randint(1, p - 1)
    while pow(alfa, 2) % p == 1 or pow(alfa, int((p - 1) * 0.5), p) == 1:
        alfa = random.randint(1, p - 1)

    gf_check = []
    for i in range(p-1):
        gf_check.append(pow(alfa, i, p))
    gf_check.sort()

    if gf == gf_check:
        return alfa
    else:
        return parent_element(p)


def euclid_algorithm(a, b, flag):
    r = [a, b]
    x = [1, 0]
    y = [0, 1]

    i = 0
    while r[i] != 0:
        if r[i + 1] != 0:

            q = (r[i] // r[i + 1])
            c = r[i] - q * r[i + 1]
            a = x[i] - q * x[i + 1]
            b = y[i] - q * y[i + 1]

            x.append(a)
            y.append(b)
            r.append(c)
            i += 1

        elif r[i + 1] == 0:
            break

    d = r[i]
    u = x[i]
    v = y[i]

    if flag is True:

        choose = input("1 - линейное представление НОД.\n2 - НОД.\n")
        if choose == "1":
            return f"{d} = {r[0]} * {u} + {r[1]} * {v}"
        elif choose == "2":
            return f"НОД{r[0], r[1]} = {d}"
        elif choose != "1" and choose != "2":
            return "Exit."

    elif flag is False:
        return [d, u, v]


def test_miller2(n):
    a = random.randint(1, n - 2)
    exp = n - 1
    while not exp & 1:
        exp >>= 1

    if pow(a, exp, n) == 1:
        return True

    while exp < n - 1:
        if pow(a, exp, n) == n - 1:
            return True
        exp <<= 1

    return False


def generation_prime(k):
    binary = []
    for i in range(k):
        bit = random.randint(0, 1)
        binary.append(bit)

    del binary[-1]
    binary.append(1)
    del binary[0]
    binary.insert(0, 1)

    p = int(''.join(str(x) for x in binary), 2)

    test = []
    for i in range(5):
        test.append(test_miller2(p))

    if test.count(True) == len(test):

        return p

    else:
        return generation_prime(k)


def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def text_to_int(text: str) -> int:
    return int.from_bytes(text.encode('utf-8'), 'big')


def text_to_bin(text):
    return ''.join(format(x, '08b') for x in bytearray(text, 'utf-8'))


def client_send(file):
    client = socket(AF_INET, SOCK_STREAM)
    client.connect(('192.168.153.128', 2501))

    file_list = [file.encode()[x:x + 128] for x in range(0, len(file.encode()), 128)]
    for i in file_list:
        client.send(i)
        mess = client.recv(128)
        print(mess)

    client.send(b'END')

    data = b''
    while True:
        package = client.recv(128)

        if package != b'END':
            data = data + package
            client.send(b'OK')
        elif package == b'END':
            break

    json.dump(eval(data), open('PKCS_get.json', 'w+'))

    client.close()