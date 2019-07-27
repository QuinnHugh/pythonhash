"""
Python 实现MD5
"""
import struct
import binascii
import math

##循环移位函数
lrot = lambda x, n: (x << n) | (x >> (32 - n))


class MD5():
    """
    MD5类，输入message，输出md5摘要值
    """
    #初始化寄存器A、B、C、D
    A, B, C, D = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)

    # r 为每轮循环中每步对X的操作
    r = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
         5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
         4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
         6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

    # 计算T，i为弧度
    k = [math.floor(abs(math.sin(i + 1)) * (2 ** 32)) for i in range(64)]

    def __init__(self, message):
        #对输入message进行填充
        length = struct.pack('<Q', len(message) * 8)
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
        """迭代函数，每一次迭代四轮16遍共进行64步操作"""
        w = list(struct.unpack('<' + 'I' * 16, chunk))

        a, b, c, d = self.A, self.B, self.C, self.D

        for i in range(64):
            if i < 16:
                f = (b & c) | ((~b) & d)
                g = i
            elif i < 32:
                f = (d & b) | ((~d) & c)
                g = (5 * i + 1) % 16
            elif i < 48:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | (~d))
                g = (7 * i) % 16

            x = b + lrot((a + f + self.k[i] + w[g]) & 0xffffffff, self.r[i])
            a, b, c, d = d, x & 0xffffffff, b, c

        self.A = (self.A + a) & 0xffffffff
        self.B = (self.B + b) & 0xffffffff
        self.C = (self.C + c) & 0xffffffff
        self.D = (self.D + d) & 0xffffffff

    def digest(self):
        """输出MD5摘要结果"""
        return struct.pack('<IIII', self.A, self.B, self.C, self.D)

    def hexdigest(self):
        """以16进制输出MD5摘要结果"""
        return binascii.hexlify(self.digest()).decode()