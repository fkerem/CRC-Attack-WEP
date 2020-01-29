#!/usr/bin/env python
# coding: utf-8

# In[1]:


# Returns XOR of 'a' and 'b'
# (both of same length)
def xor(a, b):
    # initialize result
    result = []

    # Traverse all bits, if bits are
    # same, then XOR is 0, else 1
    for i in range(1, len(b)):
        if a[i] == b[i]:
            result.append('0')
        else:
            result.append('1')

    return ''.join(result)


# Performs Modulo-2 division
def mod2div(divident, divisor):
    # Number of bits to be XORed at a time.
    pick = len(divisor)

    # Slicing the divident to appropriate
    # length for particular step
    tmp = divident[0: pick]

    while pick < len(divident):

        if tmp[0] == '1':

            # replace the divident by the result
            # of XOR and pull 1 bit down
            tmp = xor(divisor, tmp) + divident[pick]

        else:  # If leftmost bit is '0'
            # If the leftmost bit of the dividend (or the
            # part used in each step) is 0, the step cannot
            # use the regular divisor; we need to use an
            # all-0s divisor.
            tmp = xor('0' * pick, tmp) + divident[pick]

            # increment pick to move further
        pick += 1

    # For the last n bits, we have to carry it out
    # normally as increased value of pick will cause
    # Index Out of Bounds.
    if tmp[0] == '1':
        tmp = xor(divisor, tmp)
    else:
        tmp = xor('0' * pick, tmp)

    checkword = tmp
    return checkword


# Function used at the sender side to encode
# data by appending remainder of modular divison
# at the end of data.
def calculateNativeCRC(data, key):
    l_key = len(key)

    # Appends n-1 zeroes at end of data
    appended_data = data + '0' * (l_key - 1)
    remainder = mod2div(appended_data, key)

    return remainder


def pairwise_xor(a, b):
    if len(a) != len(b):
        return "The inputs do not have the same length!"

    y = int(a, 2) ^ int(b, 2)
    return (bin(y)[2:].zfill(len(a)))

"""
def hex_to_bin(hex_representation):
    return bin(int(hex_representation, 16))[2:]


def bin_to_hex(bin_representation):
    return '%0*X' % ((len(bin_representation) + 3) // 4, int(bin_representation, 2))
"""


def hex_to_bin(hex_representation):
    return bin(int(hex_representation, 16))[2:].zfill(len(hex_representation) * 4)


def bin_to_hex(bin_representation):
    return '%0*X' % ((len(bin_representation) + 3) // 4, int(bin_representation, 2))



def getFlippedMessage(flipping_bits, length):
    zero_message = length * "0"
    list_zero_message = list(zero_message)
    for flip_index in flipping_bits:
        list_zero_message[len(zero_message) - int(flip_index)] = "1"

    return "".join(list_zero_message)


def check_flipped_bits(a, b):
    flip_lst = []

    for elt_index in range(0, len(a)):
        if a[len(a) - elt_index - 1] != b[len(b) - elt_index - 1]:
            flip_lst.append(str(elt_index + 1))

    return " ".join(flip_lst)


def remove_leading_zeros(gen):
    ind = 0
    for ch in gen:
        if ch == "0":
            ind += 1
        else:
            break

    return gen[ind:]


if __name__ == "__main__":

    generator = "0104C11DB7"
    message = input("Enter the message: ")
    flipping = input("Flipping Bits (separate with a space character): ").split(" ")
    print()

    # Convert Hex Message and Generator to Binary
    bin_message = hex_to_bin(message)
    bin_generator = remove_leading_zeros(hex_to_bin(generator))

    bin_message_native_crc = calculateNativeCRC(bin_message, bin_generator)
    both_bin_message_native_crc = bin_message + bin_message_native_crc

    key = len(both_bin_message_native_crc) * "1"

    sender_ciphertext = pairwise_xor(both_bin_message_native_crc, key)

    print("Sender's Computations:")
    print("Message:", message)
    print("Generator:", generator)
    print("Native CRC-32 of Message (CRC-32(M)):", bin_to_hex(bin_message_native_crc))
    print("CRC Appended to the Message (M||CRC-32(M)):", bin_to_hex(both_bin_message_native_crc))
    print("Key (K):", bin_to_hex(key))
    print("Ciphertext Sent to the Receiver ((M||CRC-32(M)) ⊕ K):", bin_to_hex(sender_ciphertext))
    print()

    # Attacker's Part Begins
    bin_deltaM = getFlippedMessage(flipping, len(bin_message))
    bin_deltaM_native_crc = calculateNativeCRC(bin_deltaM, bin_generator)

    both_bin_deltaM_native_crc = bin_deltaM + bin_deltaM_native_crc
    attacker_ciphertext = pairwise_xor(sender_ciphertext, both_bin_deltaM_native_crc)

    print("Attacker's Computations:")
    # print("DeltaM (Flipped Bits):", bin_deltaM)
    print("DeltaM (ΔM):", bin_to_hex(bin_deltaM))
    print("Native CRC-32 of DeltaM (CRC-32(ΔM)):", bin_to_hex(bin_deltaM_native_crc))
    print("CRC Appended to Delta M (ΔM||CRC-32(ΔM)):", bin_to_hex(both_bin_deltaM_native_crc))
    print("Ciphertext Sent by the Sender to the Receiver (C) was", bin_to_hex(sender_ciphertext))
    print("Ciphertext Sent to the Receiver by the Attacker:(C ⊕ (ΔM||CRC-32(ΔM))):", bin_to_hex(attacker_ciphertext))
    print()

    # Receiver's Part Begins
    plaintext_attacker = pairwise_xor(attacker_ciphertext, key)
    bin_message_attacker = plaintext_attacker[:len(bin_deltaM)]

    bin_message_attacker_native_crc = calculateNativeCRC(plaintext_attacker, bin_generator)

    print("Receiver's Computations:")
    print("Ciphertext Received from the Attacker:", bin_to_hex(attacker_ciphertext))
    print("Plaintext of that Ciphertext:", bin_to_hex(plaintext_attacker))
    print("Attack Message:", bin_to_hex(bin_message_attacker))
    print("CRC(Attack Message):", bin_to_hex(plaintext_attacker[len(bin_message_attacker):]))
    print("Sender's Message in Bits:", bin_message)
    print("Attacker Message in Bits:", bin_message_attacker)
    print("Flipped Bits:", check_flipped_bits(bin_message, bin_message_attacker))
    # print("Native CRC-32 of Attacker's Message:", bin_to_hex(bin_crc_attacker))
    print("Validate CRC-32 of Incoming Plaintext:", bin_to_hex(bin_message_attacker_native_crc))

    if "1" not in bin_message_attacker_native_crc:
        print("CRC is correct, attack works!")
    else:
        print("There is a problem, attack doesn't work...")