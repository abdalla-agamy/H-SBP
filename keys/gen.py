from cryptography import openssl


# Generate SL keys (e.g., 2048 bits)
openssl genrsa -out keys/sl_private.pem 1024
openssl rsa -pubout -in keys/sl_private.pem -out keys/sl_public.pem

# Generate CH1 keys
openssl genrsa -out keys/ch1_private.pem 1024
openssl rsa -pubout -in keys/ch1_private.pem -out keys/ch1_public.pem

# Generate CH2 keys
openssl genrsa -out keys/ch2_private.pem 1024
openssl rsa -pubout -in keys/ch2_private.pem -out keys/ch2_public.pem
