import matplotlib.pyplot as plt
import time
# S-DES置换表和S盒
p10_table = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
p8_table = (6, 3, 7, 4, 8, 5, 10, 9)
ip_table = (2, 6, 3, 1, 4, 8, 5, 7)
ep_table = (4, 1, 2, 3, 2, 3, 4, 1)
ip_ni_table = (4, 1, 3, 5, 7, 2, 8, 6)
p4_table = (2, 4, 3, 1)
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

# 生成子密钥
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

# 已知的明文和密文
plaintext = "10110101"
ciphertext = "11111000"

# 枚举所有10位二进制密钥
possible_keys = []
key_progress = []
time_progress = []
start_time = time.time()
for key in range(1024):
    binary_key = '{0:010b}'.format(key)
    k1, k2 = generate_key(binary_key, p10_table, p8_table)
    decrypted = decrypt(ciphertext, k1, k2)
    if decrypted == plaintext:
        possible_keys.append(binary_key)
    key_progress.append(len(possible_keys))
    time_progress.append(time.time() - start_time)

# 可视化密钥生成过程
plt.plot(time_progress, key_progress)
plt.xlabel("Running Time (seconds)")
plt.ylabel("Number of Possible Keys")
plt.title("Key Generation Process")
plt.show()

# 输出可能的密钥
print("可能的密钥：")
for key in possible_keys:
    print(key)
