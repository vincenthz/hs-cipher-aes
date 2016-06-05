{-# LANGUAGE OverloadedStrings #-}
module KATXTS where

import qualified Data.ByteString as B
import Data.ByteString.Char8 ()

type KATXTS = (B.ByteString, B.ByteString, B.ByteString, B.ByteString, B.ByteString, B.ByteString)

vectors_aes128_enc, vectors_aes128_dec, vectors_aes256_enc, vectors_aes256_dec :: [KATXTS]
vectors_aes128_enc =
    [
        ( "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        , "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        , "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        , "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        , "\x66\xe9\x4b\xd4\xef\x8a\x2c\x3b\x88\x4c\xfa\x59\xca\x34\x2b\x2e\xcc\xd2\x97\xa8\xdf\x15\x59\x76\x10\x99\xf4\xb3\x94\x69\x56\x5c"
        , "\x91\x7c\xf6\x9e\xbd\x68\xb2\xec\x9b\x9f\xe9\xa3\xea\xdd\xa6\x92\xcd\x43\xd2\xf5\x95\x98\xed\x85\x8c\x02\xc2\x65\x2f\xbf\x92\x2e"
        )
    ,
        ( "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
        , "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22"
        , "\x33\x33\x33\x33\x33\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        , "\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44"
        , "\x3f\x80\x3b\xcd\x0d\x7f\xd2\xb3\x75\x58\x41\x9f\x59\xd5\xcd\xa6\xf9\x00\x77\x9a\x1b\xfe\xa4\x67\xeb\xb0\x82\x3e\xb3\xaa\x9b\x4d"
        , "\xc4\x54\x18\x5e\x6a\x16\x93\x6e\x39\x33\x40\x38\xac\xef\x83\x8b\xfb\x18\x6f\xff\x74\x80\xad\xc4\x28\x93\x82\xec\xd6\xd3\x94\xf0"
        )
    ,
        ( "\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6\xf5\xf4\xf3\xf2\xf1\xf0"
        , "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22"
        , "\x33\x33\x33\x33\x33\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        , "\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44"
        , "\x3f\x80\x3b\xcd\x0d\x7f\xd2\xb3\x75\x58\x41\x9f\x59\xd5\xcd\xa6\xf9\x00\x77\x9a\x1b\xfe\xa4\x67\xeb\xb0\x82\x3e\xb3\xaa\x9b\x4d"
        , "\xaf\x85\x33\x6b\x59\x7a\xfc\x1a\x90\x0b\x2e\xb2\x1e\xc9\x49\xd2\x92\xdf\x4c\x04\x7e\x0b\x21\x53\x21\x86\xa5\x97\x1a\x22\x7a\x89"
        )
    ,
        ( "\x27\x18\x28\x18\x28\x45\x90\x45\x23\x53\x60\x28\x74\x71\x35\x26"
        , "\x31\x41\x59\x26\x53\x58\x97\x93\x23\x84\x62\x64\x33\x83\x27\x95"
        , "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        , "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
        , ""
        , "\x27\xa7\x47\x9b\xef\xa1\xd4\x76\x48\x9f\x30\x8c\xd4\xcf\xa6\xe2\xa9\x6e\x4b\xbe\x32\x08\xff\x25\x28\x7d\xd3\x81\x96\x16\xe8\x9c\xc7\x8c\xf7\xf5\xe5\x43\x44\x5f\x83\x33\xd8\xfa\x7f\x56\x00\x00\x05\x27\x9f\xa5\xd8\xb5\xe4\xad\x40\xe7\x36\xdd\xb4\xd3\x54\x12\x32\x80\x63\xfd\x2a\xab\x53\xe5\xea\x1e\x0a\x9f\x33\x25\x00\xa5\xdf\x94\x87\xd0\x7a\x5c\x92\xcc\x51\x2c\x88\x66\xc7\xe8\x60\xce\x93\xfd\xf1\x66\xa2\x49\x12\xb4\x22\x97\x61\x46\xae\x20\xce\x84\x6b\xb7\xdc\x9b\xa9\x4a\x76\x7a\xae\xf2\x0c\x0d\x61\xad\x02\x65\x5e\xa9\x2d\xc4\xc4\xe4\x1a\x89\x52\xc6\x51\xd3\x31\x74\xbe\x51\xa1\x0c\x42\x11\x10\xe6\xd8\x15\x88\xed\xe8\x21\x03\xa2\x52\xd8\xa7\x50\xe8\x76\x8d\xef\xff\xed\x91\x22\x81\x0a\xae\xb9\x9f\x91\x72\xaf\x82\xb6\x04\xdc\x4b\x8e\x51\xbc\xb0\x82\x35\xa6\xf4\x34\x13\x32\xe4\xca\x60\x48\x2a\x4b\xa1\xa0\x3b\x3e\x65\x00\x8f\xc5\xda\x76\xb7\x0b\xf1\x69\x0d\xb4\xea\xe2\x9c\x5f\x1b\xad\xd0\x3c\x5c\xcf\x2a\x55\xd7\x05\xdd\xcd\x86\xd4\x49\x51\x1c\xeb\x7e\xc3\x0b\xf1\x2b\x1f\xa3\x5b\x91\x3f\x9f\x74\x7a\x8a\xfd\x1b\x13\x0e\x94\xbf\xf9\x4e\xff\xd0\x1a\x91\x73\x5c\xa1\x72\x6a\xcd\x0b\x19\x7c\x4e\x5b\x03\x39\x36\x97\xe1\x26\x82\x6f\xb6\xbb\xde\x8e\xcc\x1e\x08\x29\x85\x16\xe2\xc9\xed\x03\xff\x3c\x1b\x78\x60\xf6\xde\x76\xd4\xce\xcd\x94\xc8\x11\x98\x55\xef\x52\x97\xca\x67\xe9\xf3\xe7\xff\x72\xb1\xe9\x97\x85\xca\x0a\x7e\x77\x20\xc5\xb3\x6d\xc6\xd7\x2c\xac\x95\x74\xc8\xcb\xbc\x2f\x80\x1e\x23\xe5\x6f\xd3\x44\xb0\x7f\x22\x15\x4b\xeb\xa0\xf0\x8c\xe8\x89\x1e\x64\x3e\xd9\x95\xc9\x4d\x9a\x69\xc9\xf1\xb5\xf4\x99\x02\x7a\x78\x57\x2a\xee\xbd\x74\xd2\x0c\xc3\x98\x81\xc2\x13\xee\x77\x0b\x10\x10\xe4\xbe\xa7\x18\x84\x69\x77\xae\x11\x9f\x7a\x02\x3a\xb5\x8c\xca\x0a\xd7\x52\xaf\xe6\x56\xbb\x3c\x17\x25\x6a\x9f\x6e\x9b\xf1\x9f\xdd\x5a\x38\xfc\x82\xbb\xe8\x72\xc5\x53\x9e\xdb\x60\x9e\xf4\xf7\x9c\x20\x3e\xbb\x14\x0f\x2e\x58\x3c\xb2\xad\x15\xb4\xaa\x5b\x65\x50\x16\xa8\x44\x92\x77\xdb\xd4\x77\xef\x2c\x8d\x6c\x01\x7d\xb7\x38\xb1\x8d\xeb\x4a\x42\x7d\x19\x23\xce\x3f\xf2\x62\x73\x57\x79\xa4\x18\xf2\x0a\x28\x2d\xf9\x20\x14\x7b\xea\xbe\x42\x1e\xe5\x31\x9d\x05\x68"
        )
    ]

vectors_aes128_dec =
    []

vectors_aes256_enc =
    [
        ( "\x27\x18\x28\x18\x28\x45\x90\x45\x23\x53\x60\x28\x74\x71\x35\x26\x62\x49\x77\x57\x24\x70\x93\x69\x99\x59\x57\x49\x66\x96\x76\x27"
        , "\x31\x41\x59\x26\x53\x58\x97\x93\x23\x84\x62\x64\x33\x83\x27\x95\x02\x88\x41\x97\x16\x93\x99\x37\x51\x05\x82\x09\x74\x94\x45\x92"
        , "\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        , "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
        , ""
        , "\x1c\x3b\x3a\x10\x2f\x77\x03\x86\xe4\x83\x6c\x99\xe3\x70\xcf\x9b\xea\x00\x80\x3f\x5e\x48\x23\x57\xa4\xae\x12\xd4\x14\xa3\xe6\x3b\x5d\x31\xe2\x76\xf8\xfe\x4a\x8d\x66\xb3\x17\xf9\xac\x68\x3f\x44\x68\x0a\x86\xac\x35\xad\xfc\x33\x45\xbe\xfe\xcb\x4b\xb1\x88\xfd\x57\x76\x92\x6c\x49\xa3\x09\x5e\xb1\x08\xfd\x10\x98\xba\xec\x70\xaa\xa6\x69\x99\xa7\x2a\x82\xf2\x7d\x84\x8b\x21\xd4\xa7\x41\xb0\xc5\xcd\x4d\x5f\xff\x9d\xac\x89\xae\xba\x12\x29\x61\xd0\x3a\x75\x71\x23\xe9\x87\x0f\x8a\xcf\x10\x00\x02\x08\x87\x89\x14\x29\xca\x2a\x3e\x7a\x7d\x7d\xf7\xb1\x03\x55\x16\x5c\x8b\x9a\x6d\x0a\x7d\xe8\xb0\x62\xc4\x50\x0d\xc4\xcd\x12\x0c\x0f\x74\x18\xda\xe3\xd0\xb5\x78\x1c\x34\x80\x3f\xa7\x54\x21\xc7\x90\xdf\xe1\xde\x18\x34\xf2\x80\xd7\x66\x7b\x32\x7f\x6c\x8c\xd7\x55\x7e\x12\xac\x3a\x0f\x93\xec\x05\xc5\x2e\x04\x93\xef\x31\xa1\x2d\x3d\x92\x60\xf7\x9a\x28\x9d\x6a\x37\x9b\xc7\x0c\x50\x84\x14\x73\xd1\xa8\xcc\x81\xec\x58\x3e\x96\x45\xe0\x7b\x8d\x96\x70\x65\x5b\xa5\xbb\xcf\xec\xc6\xdc\x39\x66\x38\x0a\xd8\xfe\xcb\x17\xb6\xba\x02\x46\x9a\x02\x0a\x84\xe1\x8e\x8f\x84\x25\x20\x70\xc1\x3e\x9f\x1f\x28\x9b\xe5\x4f\xbc\x48\x14\x57\x77\x8f\x61\x60\x15\xe1\x32\x7a\x02\xb1\x40\xf1\x50\x5e\xb3\x09\x32\x6d\x68\x37\x8f\x83\x74\x59\x5c\x84\x9d\x84\xf4\xc3\x33\xec\x44\x23\x88\x51\x43\xcb\x47\xbd\x71\xc5\xed\xae\x9b\xe6\x9a\x2f\xfe\xce\xb1\xbe\xc9\xde\x24\x4f\xbe\x15\x99\x2b\x11\xb7\x7c\x04\x0f\x12\xbd\x8f\x6a\x97\x5a\x44\xa0\xf9\x0c\x29\xa9\xab\xc3\xd4\xd8\x93\x92\x72\x84\xc5\x87\x54\xcc\xe2\x94\x52\x9f\x86\x14\xdc\xd2\xab\xa9\x91\x92\x5f\xed\xc4\xae\x74\xff\xac\x6e\x33\x3b\x93\xeb\x4a\xff\x04\x79\xda\x9a\x41\x0e\x44\x50\xe0\xdd\x7a\xe4\xc6\xe2\x91\x09\x00\x57\x5d\xa4\x01\xfc\x07\x05\x9f\x64\x5e\x8b\x7e\x9b\xfd\xef\x33\x94\x30\x54\xff\x84\x01\x14\x93\xc2\x7b\x34\x29\xea\xed\xb4\xed\x53\x76\x44\x1a\x77\xed\x43\x85\x1a\xd7\x7f\x16\xf5\x41\xdf\xd2\x69\xd5\x0d\x6a\x5f\x14\xfb\x0a\xab\x1c\xbb\x4c\x15\x50\xbe\x97\xf7\xab\x40\x66\x19\x3c\x4c\xaa\x77\x3d\xad\x38\x01\x4b\xd2\x09\x2f\xa7\x55\xc8\x24\xbb\x5e\x54\xc4\xf3\x6f\xfd\xa9\xfc\xea\x70\xb9\xc6\xe6\x93\xe1\x48\xc1\x51"
        )
    ]

vectors_aes256_dec = []

vectors_encrypt :: [(String, [KATXTS])]
vectors_encrypt =
    [ ("AES 128 Enc", vectors_aes128_enc)
    , ("AES 256 Enc", vectors_aes256_enc)
    ]

vectors_decrypt :: [(String, [KATXTS])]
vectors_decrypt =
    [ ("AES 128 Dec", vectors_aes128_dec)
    , ("AES 256 Dec", vectors_aes256_dec)
    ]
