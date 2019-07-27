"""
Python 实现SHA-1
"""
import struct
import binascii

##循环移位函数
lrot = lambda x, n: (x << n) | (x >> (32 - n))


class SHA1():
    """
    MD5类，输入message，输出md5摘要值
    """
    #初始化寄存器h0, h1, h2, h3, h4
    _h0, _h1, _h2, _h3, _h4, = (
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0)

    def __init__(self, message):
        #对输入message进行填充
        length = struct.pack('>Q', len(message) * 8)
        while len(message) > 64:
            self._handle(message[:64])
            message = message[64:]
        message += b'\x80'
        message += bytes((56 - len(message) % 64) % 64)
        message += length
        #对message的每一块进行迭代
        while len(message):
            self._handle(message[:64])
            message = message[64:]

    def _handle(self, chunk):
        """迭代函数，每一次迭代四轮20遍共进行80步操作"""
        w = list(struct.unpack('>' + 'I' * 16, chunk))

        for i in range(16, 80):
            w.append(lrot(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
                     & 0xffffffff)

        a = self._h0
        b = self._h1
        c = self._h2
        d = self._h3
        e = self._h4

        for i in range(80):

            if i <= i <= 19:
                f, k = d ^ (b & (c ^ d)), 0x5a827999
            elif 20 <= i <= 39:
                f, k = b ^ c ^ d, 0x6ed9eba1
            elif 40 <= i <= 59:
                f, k = (b & c) | (d & (b | c)), 0x8f1bbcdc
            elif 60 <= i <= 79:
                f, k = b ^ c ^ d, 0xca62c1d6

            temp = lrot(a, 5) + f + e + k + w[i] & 0xffffffff
            a, b, c, d, e = temp, a, lrot(b, 30), c, d

        self._h0 = (self._h0 + a) & 0xffffffff
        self._h1 = (self._h1 + b) & 0xffffffff
        self._h2 = (self._h2 + c) & 0xffffffff
        self._h3 = (self._h3 + d) & 0xffffffff
        self._h4 = (self._h4 + e) & 0xffffffff

    def digest(self):
        """输出MD5摘要结果"""
        return struct.pack('>IIIII', self._h0, self._h1,
                           self._h2, self._h3, self._h4)

    def hexdigest(self):
        """以16进制输出MD5摘要结果"""
        return binascii.hexlify(self.digest()).decode()