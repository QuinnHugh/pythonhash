"""Python实现MD4"""
import struct
import binascii

class md4(object):
    """创建md4类"""
    A = 0x67452301
    B = 0xefcbab89
    C = 0x98badcfe
    D = 0x10325476
    H = []
    X = []
    M = []
    org = []

    _lrot = lambda self, x, n: (x << n) | (x >> (32 - n))

    _F = lambda self, x, y, z: ((x & y) | (~x & z))
    _G = lambda self, x, y, z: ((x & y) | (x & z) | (y & z))
    _H = lambda self, x, y, z: (x ^ y ^ z)

    def __init__(self, message):
        self.H[0] = self.A
        self.H[1] = self.B
        self.H[2] = self.C
        self.H[3] = self.D

    def calc(self, msg):
        """计算输入为字符串的MD4"""
        self.org = msg

    def fill(self):
        """填充输入信息"""
        pass

    def seg(self):
        """分割输入信息"""
        pass

    def ita(self):
        """迭代"""
        pass
