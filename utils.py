
def stringify_components(components):
    return ', '.join('%s=%s' % (x[0].decode('utf-8'), x[1].decode('utf-8')) for x in components)


def make_string_raw(s):
    return repr(s)[1:-1]

