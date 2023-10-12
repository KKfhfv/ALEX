from tkinter import *
import tkinter.messagebox as messagebox
from sdes1 import *

class SDES:
    def __init__(self, root):
        self.root = root
        self.root.title("S-DES解密")
        self.root.geometry("400x400")
        self.root.resizable(False, False)
        self.key = StringVar()
        self.plaintext = StringVar()
        self.ciphertext = StringVar()
        self.k1_var = StringVar()
        self.k2_var = StringVar()

        # 密钥输入框
        key_label = Label(root, text="请输入10位二进制密钥：")
        key_label.pack(pady=10)
        key_entry = Entry(root, textvariable=self.key, width=30)
        key_entry.pack(pady=5)

        # 明文输入框
        plaintext_label = Label(root, text="请输入8位二进制明文：")
        plaintext_label.pack()
        plaintext_entry = Entry(root, textvariable=self.plaintext, width=30)
        plaintext_entry.pack(pady=5)

        # 密文输出框
        ciphertext_label = Label(root, text="密文：")
        ciphertext_label.pack()
        ciphertext_entry = Entry(root, textvariable=self.ciphertext, width=30, state='readonly')
        ciphertext_entry.pack(pady=5)

        # K1值输出框
        k1_label = Label(root, text="K1：")
        k1_label.pack()
        k1_entry = Entry(root, textvariable=self.k1_var, width=30, state='readonly')
        k1_entry.pack(pady=5)

        # K2值输出框
        k2_label = Label(root, text="K2：")
        k2_label.pack()
        k2_entry = Entry(root, textvariable=self.k2_var, width=30, state='readonly')
        k2_entry.pack(pady=5)

        # 加密、解密按钮
        button_frame = Frame(root)
        button_frame.pack(pady=10)
        encrypt_button = Button(button_frame, text="加密", command=self.encrypt)
        decrypt_button = Button(button_frame, text="解密", command=self.decrypt)
        encrypt_button.pack(side=LEFT, padx=10)
        decrypt_button.pack(side=LEFT, padx=10)

    def permute(self, input_str, table):
        output_str = ""
        for bit_position in table:
            output_str += input_str[bit_position - 1]
        return output_str

    def ls(self, key, n):
        left_half = key[:5]
        right_half = key[5:]
        shifted_left = left_half[n:] + left_half[:n]
        shifted_right = right_half[n:] + right_half[:n]
        return shifted_left + shifted_right

    def generate_key(self, k, p10_table, p8_table):
        p10_key = self.permute(k, p10_table)
        k1 = self.permute(self.ls(p10_key, 1), p8_table)
        k2 = self.permute(self.ls(self.ls(p10_key, 1), 2), p8_table)
        return k1, k2

    def F(self, right_half, k):
        expanded = self.permute(right_half, ep_table)
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
        return self.permute(s_output, p4_table)

    def encrypt(self):
        key = self.key.get()
        plaintext = self.plaintext.get()

        if len(key) != 10:
            messagebox.showerror("错误", "密钥必须是10位二进制数！")
            return

        if len(plaintext) != 8:
            messagebox.showerror("错误", "明文必须是8位二进制数！")
            return

        k1, k2 = self.generate_key(key, p10_table, p8_table)
        self.k1_var.set(k1)
        self.k2_var.set(k2)

        ciphertext = encrypt(plaintext, k1, k2)
        self.ciphertext.set(ciphertext)

    def decrypt(self):
        key = self.key.get()
        ciphertext = self.ciphertext.get()

        if len(key) != 10:
            messagebox.showerror("错误", "密钥必须是10位二进制数！")
            return

        if len(ciphertext) != 8:
            messagebox.showerror("错误", "密文必须是8位二进制数！")
            return

        k1, k2 = self.generate_key(key, p10_table, p8_table)
        self.k1_var.set(k1)
        self.k2_var.set(k2)

        plaintext = decrypt(ciphertext, k1, k2)
        self.plaintext.set(plaintext)


# S-DES 的各个置换、S盒
p10_table = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
p8_table = (6, 3, 7, 4, 8, 5, 10, 9)
p4_table = (2, 4, 3, 1)
ep_table = (4, 1, 2, 3, 2, 3, 4, 1)
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


root = Tk()
sdes = SDES(root)
root.mainloop()
