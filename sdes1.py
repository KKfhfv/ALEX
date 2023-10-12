# 通用置换函数
def permute(input_str, table):
    output_str = ""
    for bit_position in table:
        output_str += input_str[bit_position - 1]
    return output_str


# 循环左移函数
def ls(key, n):
    # 将密钥分成两段并循环左移 n 位
    left_half = key[:5]
    right_half = key[5:]
    shifted_left = left_half[n:] + left_half[:n]
    shifted_right = right_half[n:] + right_half[:n]
    return shifted_left + shifted_right


# 子密钥生成
def generate_key(k, p10_table, p8_table):
    # 执行 P10 置换
    p10_key = permute(k, p10_table)
    # 对结果进行左移操作和P8置换，得到 K1
    k1 = permute(ls(p10_key, 1), p8_table)
    # 再次对上一步结果进行左移操作h和P8置换，得到 K2
    k2 = permute(ls(ls(p10_key, 1), 2), p8_table)
    return k1, k2


# S-DES 的 F 函数
def F(right_half, k):
    # 对右半部分进行 E/P 扩展置换
    expanded = permute(right_half, ep_table)
    # 对结果与 K1 进行异或操作
    xored = '{0:08b}'.format(int(expanded, 2) ^ int(k, 2))
    # 将结果分为两组，并根据 S-box 进行替换
    s0_input = xored[:4]
    s1_input = xored[4:]
    # 根据S盒规则行列查找
    s0_row = int(s0_input[0] + s0_input[-1], 2)
    s0_col = int(s0_input[1:-1], 2)
    s1_row = int(s1_input[0] + s1_input[-1], 2)
    s1_col = int(s1_input[1:-1], 2)
    s0_output = '{0:02b}'.format(sbox0[s0_row][s0_col])
    s1_output = '{0:02b}'.format(sbox1[s1_row][s1_col])
    # 对两个输出串进行 P4 置换得到最终结果
    s_output = s0_output + s1_output
    return permute(s_output, p4_table)


# 加密过程
def encrypt(p, k1, k2):
    # 执行初始置换
    p = permute(p, ip_table)
    # 进行两轮 Feistel 加密
    l0 = p[:4]
    r0 = p[4:]
    l1 = r0
    # 第一轮的P4
    f_result = F(r0, k1)
    # p41和L0异或
    r1 = '{0:04b}'.format(int(l0, 2) ^ int(f_result, 2))
    # 第二轮的P4
    f_result = F(r1, k2)
    # p42和L1异或
    r2 = '{0:04b}'.format(int(l1, 2) ^ int(f_result, 2))
    # 逆置换并返回结果(左边R2右边R1)
    return permute(r2 + r1, ip_ni_table)


# 解密过程
def decrypt(c, k1, k2):
    # 执行初始置换
    c = permute(c, ip_table)
    # 进行两轮 Feistel 解密（注意子密钥的使用顺序）
    r2 = c[:4]
    l2 = c[4:]
    # 第一轮的P4
    f_result = F(l2, k2)
    # p41和R2异或
    l1 = '{0:04b}'.format(int(r2, 2) ^ int(f_result, 2))
    # 第二轮的P4
    f_result = F(l1, k1)
    # p42和R1异或
    r1 = '{0:04b}'.format(int(l2, 2) ^ int(f_result, 2))
    # 逆置换并返回明文
    return permute(r1 + l1, ip_ni_table)


# 测试

# 密钥key、明文p、各个置换、S盒
key = "1010000010"
p10_table = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
p8_table = (6, 3, 7, 4, 8, 5, 10, 9)
p4_table = (2, 4, 3, 1)
p = "10110101"
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

# 生成子密钥 K1 和 K2
k1, k2 = generate_key(key, p10_table, p8_table)

# 对明文进行加密
ciphertext = encrypt(p, k1, k2)
# 对密文进行解密
plaintext = decrypt(ciphertext, k1, k2)

# 输出解密结果
print("明文P：", p)
print("密钥K：", key)
print("子密钥k1：", k1)
print("子密钥k2：", k2)
print("密文：", ciphertext)
print("解密后的明文：", plaintext)
