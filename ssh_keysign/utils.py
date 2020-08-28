def lv_parser(
        b, keys={},
        no_len_pos=[], length=4
):
    i = 0
    j = i + length
    ret = []
    while j <= len(b):
        if len(ret) + 1 in no_len_pos:
            ret.append(int.from_bytes(b[i:j], "big"))
        else:
            l = int.from_bytes(bytes(b[i:j]), "big")
            i = j
            j = j + l
            v = bytes(b[i:j])
            ret.append(v)
        i = j
        j = i + length
    if keys:
        return dict(zip(keys, ret))
    else:
        return ret

def bytes2hex(b):
    return hex(int.from_bytes(b, "big"))


def hex2bytes(h):
    return bytes.fromhex(h.split("0x")[1])
