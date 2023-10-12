# 通用置换函数
def permute(input_str, table):
    output_str = ""
    for bit_position in table:
        output_str += input_str[bit_position - 1]
    return output_str


# 循环左移函数
def ls(key, n):
    left_half = key[:5]
    right_half = key[5:]
    shifted_left = left_half[n:] + left_half[:n]
    shifted_right = right_half[n:] + right_half[:n]
    return shifted_left + shifted_right


# 子密钥生成
def generate_key(k, p10_table, p8_table):
    p10_key = permute(k, p10_table)
    k1 = permute(ls(p10_key, 1), p8_table)
    k2 = permute(ls(ls(p10_key, 1), 2), p8_table)
    return k1, k2


# S-DES 的 F 函数
def F(right_half, k):
    expanded = permute(right_half, ep_table)
    xored = '{0:08b}'.format(int(expanded, 2) ^ int(k, 2))
    s0_input = xored[:4]
    s1_input = xored[4:]
    s0_row = int(s0_input[0] + s0_input[-1], 2)
    s0_col = int(s0_input[1:-1], 2)
    s1_row = int(s1_input[0] + s1_input[-1], 2)
    s1_col = int(s1_input[1:-1], 2)
    s0_output = '{0:02b}'.format(sbox0[s0_row][s0_col])
    s1_output = '{0:02b}'.format(sbox1[s1_row][s1_col])
    s_output = s0_output + s1_output
    return permute(s_output, p4_table)


# 加密过程
def encrypt(p, k1, k2):
    p = permute(p, ip_table)
    l0 = p[:4]
    r0 = p[4:]
    l1 = r0
    f_result = F(r0, k1)
    r1 = '{0:04b}'.format(int(l0, 2) ^ int(f_result, 2))
    f_result = F(r1, k2)
    r2 = '{0:04b}'.format(int(l1, 2) ^ int(f_result, 2))
    return permute(r2 + r1, ip_ni_table)


# 解密过程
def decrypt(c, k1, k2):
    c = permute(c, ip_table)
    r2 = c[:4]
    l2 = c[4:]
    f_result = F(l2, k2)
    l1 = '{0:04b}'.format(int(r2, 2) ^ int(f_result, 2))
    f_result = F(l1, k1)
    r1 = '{0:04b}'.format(int(l2, 2) ^ int(f_result, 2))
    return permute(r1 + l1, ip_ni_table)


# 设置参数
key = "1010000010"
p10_table = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
p8_table = (6, 3, 7, 4, 8, 5, 10, 9)
p4_table = (2, 4, 3, 1)
p = "a"
ip_table = (2, 6, 3, 1, 4, 8, 5, 7)
ep_table = (4, 1, 2, 3, 2, 3, 4, 1)
ip_ni_table = (4, 1, 3, 5, 7, 2, 8, 6)
sbox0 = [
    [1, 0, 2, 3],
    [2, 3, 0, 1],
    [0, 1, 3, 2],
    [3, 2, 1, 0]
]

sbox1 = [
    [0, 1, 2, 3],
    [2, 0, 3, 1],
    [1, 3, 0, 2],
    [3, 2, 1, 0]
]

# 生成子密钥
k1, k2 = generate_key(key, p10_table, p8_table)

# 将明文转换为二进制字符串
binary_p = ''.join(format(ord(c), '08b') for c in p)

# 加密过程
ciphertext = encrypt(binary_p, k1, k2)

# 将密文转换为ASCII码
ciphertext_ascii = ''.join(chr(int(ciphertext[i:i+8], 2)) for i in range(0, len(ciphertext), 8))

# 输出加密结果
print("明文：", p)
print("密文：", ciphertext_ascii)
