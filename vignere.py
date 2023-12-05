import tkinter as tk
from tkinter import ttk

def string_to_bits(input_string):
    return ''.join(format(ord(char), '08b') for char in input_string)

def bits_to_string(bit_string):
    return ''.join(chr(int(bit_string[i:i+8], 2)) for i in range(0, len(bit_string), 8))

def vigenere_encrypt(plaintext, key):
    encrypted_text = ""
    key = key * (len(plaintext) // len(key)) + key[:len(plaintext) % len(key)]

    for i in range(len(plaintext)):
        encrypted_char = chr(ord(plaintext[i]) ^ ord(key[i]))
        encrypted_text += encrypted_char

    return encrypted_text

def vigenere_decrypt(ciphertext, key):
    decrypted_text = ""
    key = key * (len(ciphertext) // len(key)) + key[:len(ciphertext) % len(key)]

    for i in range(len(ciphertext)):
        decrypted_char = chr(ord(ciphertext[i]) ^ ord(key[i]))
        decrypted_text += decrypted_char

    return decrypted_text

def on_encrypt():
    plaintext = plaintext_entry.get()
    key = key_entry.get()

    # Enkripsi
    ciphertext = vigenere_encrypt(plaintext, key)
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, f"Plaintext (bit):\n{string_to_bits(plaintext)}\n\nKunci (bit):\n{string_to_bits(key)}\n\nHasil Enkripsi (bit):\n{string_to_bits(ciphertext)}\n\nHasil Enkripsi:\n{ciphertext}")

def on_decrypt():
    ciphertext_bit = ciphertext_bit_entry.get()
    key = key_entry.get()

    # Dekripsi
    decrypted_text = vigenere_decrypt(bits_to_string(ciphertext_bit), key)
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, f"Ciphertext (bit):\n{ciphertext_bit}\n\nKunci (bit):\n{string_to_bits(key)}\n\nHasil Dekripsi (bit):\n{string_to_bits(decrypted_text)}\n\nHasil Dekripsi:\n{decrypted_text}")

# Membuat GUI
root = tk.Tk()
root.title("Vigenere Cipher GUI")

# Label dan Entry untuk Plaintext
plaintext_label = ttk.Label(root, text="Plaintext:")
plaintext_label.grid(row=0, column=0, padx=10, pady=5, sticky="e")
plaintext_entry = ttk.Entry(root, width=30)
plaintext_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")

# Label dan Entry untuk Ciphertext (bit)
ciphertext_bit_label = ttk.Label(root, text="Ciphertext (bit):")
ciphertext_bit_label.grid(row=1, column=0, padx=10, pady=5, sticky="e")
ciphertext_bit_entry = ttk.Entry(root, width=30)
ciphertext_bit_entry.grid(row=1, column=1, padx=10, pady=5, sticky="w")

# Label dan Entry untuk Kunci
key_label = ttk.Label(root, text="Kunci:")
key_label.grid(row=2, column=0, padx=10, pady=5, sticky="e")
key_entry = ttk.Entry(root, width=30)
key_entry.grid(row=2, column=1, padx=10, pady=5, sticky="w")

# Button untuk Enkripsi dan Dekripsi
encrypt_button = ttk.Button(root, text="Enkripsi", command=on_encrypt)
encrypt_button.grid(row=3, column=0, columnspan=2, pady=10)

decrypt_button = ttk.Button(root, text="Dekripsi", command=on_decrypt)
decrypt_button.grid(row=4, column=0, columnspan=2, pady=10)

# Text widget untuk menampilkan hasil
result_text = tk.Text(root, height=15, width=50)
result_text.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

root.mainloop()
