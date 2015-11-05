import re

PEM_PK_ALG = re.compile(b"Public Key Algorithm: (.*?)$", re.MULTILINE)


def stringify_components(components):
    return ', '.join('%s=%s' % (x[0].decode('utf-8'), x[1].decode('utf-8')) for x in components)


def make_string_raw(s):
    return repr(s)[1:-1]


def get_pubkey_alg_from_openssl_output(openssl_output_str):
    try:
        return PEM_PK_ALG.findall(openssl_output_str)[0]
    except IndexError:
        return None

