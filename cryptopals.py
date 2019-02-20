from __future__ import division
import operator
import base64
import binascii
import itertools
from Crypto.Cipher import AES

def validator(set, challenge, result, output):
    if(result == output):
        print("Passed Challenge " + str(challenge) + " of Set " + str(set))
    else:
        print("Something is wrong, try again")

def set_1_challenge_1():
    #Covert HEX to base64
    #https://cryptopals.com/sets/1/challenges/1

    #Define in- and output
    input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    #Convert to raw bytes
    raw = binascii.unhexlify(input)

    #Encode in base64
    result = base64.b64encode(raw)

    validator(1, 1, result, output)


def fixed_xor(input_1, input_2):
    #Define empty string
    output = ""
    #Loop through both RAW strings
    for char_1, char_2 in zip(input_1.decode('hex'), input_2.decode('hex')):
        #Add the chr of the XOR of both strings at position X to the output
        output += chr(ord(char_1) ^ ord(char_2))

    #Encode output
    return output

def set_1_challenge_2():
    #Fixed XOR
    #https://cryptopals.com/sets/1/challenges/2
    output = "746865206b696420646f6e277420706c6179"
    result = fixed_xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965").encode('hex')

    validator(1, 2, result, output)

def single_key_xor(input, key):
    output = ""
    for char in input:
        output += chr(ord(char) ^ ord(key))

    return output

def english_probability(input):
    character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }

    scores = []
    for char in input.lower():
        score = character_frequencies.get(char, 0)
        scores.append(score)
    return sum(scores)

def set_1_challenge_3():
    #Single-byte XOR cipher
    input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    outputs = []
    scores = []
    for i in range(0, 128):
        result = single_key_xor(input.decode('hex'), chr(i))
        outputs.append(result)
        scores.append(english_probability(result))

    highest_score = 0
    for score in scores:
        if(score > highest_score):
            highest_score = score
    # print("The string with the highest probability is: " + outputs[scores.index(highest_score)] + " (" + str(highest_score) + ")")

    validator(1, 3, outputs[scores.index(highest_score)], "Cooking MC's like a pound of bacon")


def set_1_challenge_4():
    with open("4.txt") as file:
        file_lines = file.readlines()

    file_lines = [x.strip() for x in file_lines]

    outputs = []
    scores = []
    for line in file_lines:
        for i in range(0, 128):
            result = single_key_xor(line.decode('hex'), chr(i))
            outputs.append(result)
            scores.append(english_probability(result))

    highest_score = 0
    for score in scores:
        if(score > highest_score):
            highest_score = score

    # print("The string with the highest probability is: " + outputs[scores.index(highest_score)] + " (" + str(highest_score) + ")")

    validator(1, 4, outputs[scores.index(highest_score)], "Now that the party is jumping\n")

def multi_key_xor(input, key):
    output = ""
    key_to_use = 0
    for char in input:
        output += chr(ord(char) ^ ord(key[key_to_use]))

        if(key_to_use == len(key) - 1):
            key_to_use = 0
        else:
            key_to_use += 1

    return output


def set_1_challenge_5():
    input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    output = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    key = "ICE"
    result = multi_key_xor(input, key).encode('hex')

    validator(1, 5, result, output)

def hamming_distance(input_1, input_2):
    differing_bits = 0

    for char_1, char_2 in zip(input_1, input_2):
        xor = ord(char_1) ^ ord(char_2)
        for bit in bin(xor):
            if(bit == "1"):
                differing_bits += 1

    return differing_bits

def brute_force_single_key_xor(input):
    outputs = []
    scores = []
    for i in range(0, 128):
        result = single_key_xor(input, chr(i))
        outputs.append(chr(i))
        scores.append(english_probability(result))

    highest_score = 0
    for score in scores:
        if(score > highest_score):
            highest_score = score

    return outputs[scores.index(highest_score)]


def set_1_challenge_6():
    # Read file
    with open("6.txt") as file:
        base64_input = file.read()

    # Decode base64
    input = base64_input.decode('base64')
    keysizes = {

    }
    # Loop through a keysize of 2 to 39
    for keysize in range(2, 40):
        #Take first & second input size of keysize
        first_keysize_input = input[0:keysize]
        second_keysize_input = input[keysize:keysize*2]

        distance = hamming_distance(first_keysize_input, second_keysize_input)

        normalized_distance = distance / keysize
        keysizes[keysize] = normalized_distance


    keysizes = sorted(keysizes.items(), key=operator.itemgetter(1))

    outputs = []
    scores = []
    highest_score = 0

    for possible_key in keysizes:
        key = ""
        for length in range(possible_key[0] + 1):
            transposed_block = ""
            for i in range(length, len(input), possible_key[0] + 1):
                transposed_block += input[i]

            key += brute_force_single_key_xor(transposed_block)
        result = multi_key_xor(input, key)

        outputs.append(result)
        scores.append(english_probability(result))

    for score in scores:
        if(score > highest_score):
            highest_score = score

    print(outputs[scores.index(highest_score)])

def set_1_challenge_7():
    with open("7.txt") as file:
        base64_input = file.read()
    key = "YELLOW SUBMARINE"
    input = base64_input.decode('base64')
    decipher = AES.new(key, AES.MODE_ECB)

    print(decipher.decrypt(input))

def chunks(input, n):
    output = []
    for start in range(0, len(input), n):
        output.append(input[start:start+n])

    return output

def set_1_challenge_8():
    with open("8.txt") as file:
        input = file.readlines()

    output = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"

    for line in input:
        line = line.replace('\n', '')
        blocks = chunks(line, 16)
        ebc = False
        for x,y in itertools.combinations(blocks, 2):
            if(x == y):
                ebc = True

        if(ebc):
            result = line

    validator(1, 8, result, output)

# set_1_challenge_1()
# set_1_challenge_2()
# set_1_challenge_3()
# set_1_challenge_4()
# set_1_challenge_5()
# set_1_challenge_6()
# set_1_challenge_7()
# set_1_challenge_8()
