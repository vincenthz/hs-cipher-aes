import Crypto.Cipher.Benchmarks
import Crypto.Cipher.AES (AES128, AES192, AES256)

main = defaultMain
    [GBlockCipher (undefined :: AES128)
    ,GBlockCipher (undefined :: AES192)
    ,GBlockCipher (undefined :: AES256)]
