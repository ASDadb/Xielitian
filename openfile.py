# read file
with open('C:/Users/26051/Desktop/antim/test/malware_file3.dll', 'rb') as f:
    content = f.read()

# Print the contents in hexadecimal form
print(content.hex())
