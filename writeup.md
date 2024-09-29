Vì mình không quen dùng C, nên mình theo hướng dẫn của link github này: https://github.com/crappycrypto/wincrypto để sử dụng các hàm encrypt Win 32 trên python.

![image](https://github.com/user-attachments/assets/ef64845f-66a1-4e17-ac7a-2af9d2157351)

Tải và giải nén folder wincrypto vào cùng directory với file wu để có thể import.

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  void *input; // rbx
  FILE *v4; // rax
  unsigned int v5; // esi
  __int64 dwBufLen; // rdi
  __int64 v8; // r8
  __int64 v9; // rax
  int *v10; // rcx
  const char *v11; // rcx
  int v12[7]; // [rsp+40h] [rbp-9h] BYREF
  char v13; // [rsp+5Ch] [rbp+13h]
  HCRYPTPROV phProv; // [rsp+60h] [rbp+17h] BYREF
  HCRYPTHASH phHash; // [rsp+68h] [rbp+1Fh] BYREF
  DWORD pdwDataLen; // [rsp+70h] [rbp+27h] BYREF
  HCRYPTKEY phKey; // [rsp+78h] [rbp+2Fh] BYREF
  BYTE pbData[24]; // [rsp+80h] [rbp+37h] BYREF

  v12[0] = 0x8688FC48;
  v12[1] = 0x8B6EAB89;
  v12[2] = 0x82519474;
  v12[3] = 0xA7DA51A4;
  v12[4] = 0x9827EFA0;
  v12[5] = 0xE4D30302;
  v12[6] = 0xD6B9EDFA;
  v13 = 81;
  input = malloc(0xC8ui64);
  memset(input, 0, 0xC8ui64);
  printf("Flag: ");
  v4 = _acrt_iob_func(0);
  fgets(input, 200, v4);
  v5 = 0;
  if ( !CryptAcquireContextA(&phProv, 0i64, 0i64, 1u, 0) )
    goto LABEL_4;
  if ( !CryptCreateHash(phProv, 0x8004u, 0i64, 0, &phHash) )
  {
    CryptReleaseContext(phProv, 0);
LABEL_4:
    free(input);
    return 0;
  }
  dwBufLen = -1i64;
  v8 = -1i64;
  strcpy(pbData, "warmup_challenge");
  do
    ++v8;
  while ( pbData[v8] );
  if ( !CryptHashData(phHash, pbData, v8, 0) )
  {
    CryptReleaseContext(phProv, 0);
LABEL_11:
    CryptDestroyHash(phHash);
    free(input);
    return 0;
  }
  if ( !CryptDeriveKey(phProv, 0x6801u, phHash, 0, &phKey) )
  {
    CryptReleaseContext(phProv, 0);
    CryptDestroyKey(phKey);
    goto LABEL_11;
  }
  v9 = -1i64;
  do
    ++v9;
  while ( *(input + v9) );
  pdwDataLen = v9;
  do
    ++dwBufLen;
  while ( *(input + dwBufLen) );
  if ( !CryptEncrypt(phKey, 0i64, 1, 0, input, &pdwDataLen, dwBufLen) )
    printf("Failed encrypted");
  v10 = v12;
  while ( *v10 == *(v10 + input - v12) )
  {
    ++v5;
    v10 = (v10 + 1);
    if ( v5 >= 0x1D )
    {
      v11 = "Correct!!";
      goto LABEL_23;
    }
  }
  v11 = "Incorrect!!";
LABEL_23:
  puts(v11);
  free(input);
  if ( !CryptReleaseContext(phProv, 0) && CryptDestroyKey(phKey) )
  {
    if ( CryptDestroyHash(phHash) )
      printf("The handle could not be released.\n");
  }
  return 1;
}
```

Load vào IDA. Chall dùng các hàm crypto trong thư viện wincrypt.h để encrypt input nhập vào của chúng ta gồm 28 kí tự:

![image](https://github.com/user-attachments/assets/197e978b-e051-4bee-b293-7e47e5635f71)

Input nhập vào là flag bị encrypt, là const từ mảng v12:

![image](https://github.com/user-attachments/assets/dde4e70c-bd59-42a6-9957-e77f5dcb3591)

![image](https://github.com/user-attachments/assets/82b1374e-4d0c-454c-871a-3ad39d56bd24)

Và key được gen từ chuỗi "warmup_challenge"

![image](https://github.com/user-attachments/assets/07a2707a-ff54-4972-bf32-bab84bf69a04)


Giờ đã biết được key, và input nhập vào của chính là flag bị encrypt. Giờ ta chỉ cần decrypt ngược lại là xong.
```python3
from ctypes import FormatError, GetLastError
from ctypes import windll, c_void_p, byref, create_string_buffer, c_int
import struct

from wincrypto.constants import HP_ALGID, HP_HASHSIZE, KP_KEYLEN, KP_ALGID, CRYPT_EXPORTABLE

PROV_RSA_FULL = 1
PROV_RSA_AES = 24

CRYPT_NEWKEYSET = 8
NTE_BAD_KEYSET = 0x80090016


def assert_success(success):
    if not success:
        raise AssertionError(FormatError())


def CryptAcquireContext():
    hprov = c_void_p()
    success = windll.advapi32.CryptAcquireContextA(byref(hprov), 0, 0, PROV_RSA_AES, 0)
    if not success and GetLastError() & 0xffffffff == NTE_BAD_KEYSET:
        success = windll.advapi32.CryptAcquireContextA(byref(hprov), 0, 0, PROV_RSA_AES, CRYPT_NEWKEYSET)
    assert_success(success)
    return hprov


def CryptReleaseContext(hprov):
    success = windll.advapi32.CryptReleaseContext(hprov, 0)
    assert_success(success)


def CryptImportKey(hprov, keyblob, hPubKey=0):
    hkey = c_void_p()
    success = windll.advapi32.CryptImportKey(hprov, keyblob, len(keyblob), hPubKey, 0, byref(hkey))
    assert_success(success)
    return hkey


def CryptExportKey(hkey, hexpkey, blobType):
    # determine output buffer length
    bdatalen = c_int(0)
    success = windll.advapi32.CryptExportKey(hkey, hexpkey, blobType, 0, 0, byref(bdatalen))
    assert_success(success)

    # export key
    bdata = create_string_buffer(b'', bdatalen.value)
    success = windll.advapi32.CryptExportKey(hkey, hexpkey, blobType, 0, bdata, byref(bdatalen))
    assert_success(success)
    return bdata.raw[:bdatalen.value]


def CryptDestroyKey(hkey):
    success = windll.advapi32.CryptDestroyKey(hkey)
    assert_success(success)


def CryptDecrypt(hkey, encrypted_data):
    bdata = create_string_buffer(encrypted_data)
    bdatalen = c_int(len(encrypted_data))
    success = windll.advapi32.CryptDecrypt(hkey, 0, 1, 0, bdata, byref(bdatalen))
    assert_success(success)
    return bdata.raw[:bdatalen.value]


def CryptEncrypt(hkey, plain_data):
    # determine output buffer length
    bdatalen_test = c_int(len(plain_data))
    success = windll.advapi32.CryptEncrypt(hkey, 0, 1, 0, 0, byref(bdatalen_test), len(plain_data))
    assert_success(success)
    out_buf_len = bdatalen_test.value

    # encrypt data
    bdata = create_string_buffer(plain_data, out_buf_len)
    bdatalen = c_int(len(plain_data))
    success = windll.advapi32.CryptEncrypt(hkey, 0, 1, 0, bdata, byref(bdatalen), out_buf_len)
    assert_success(success)
    return bdata.raw[:bdatalen.value]


def CryptGetKeyParam(hkey, dwparam):
    # determine output buffer length
    bdatalen = c_int(0)
    success = windll.advapi32.CryptGetKeyParam(hkey, dwparam, 0, byref(bdatalen), 0)
    assert_success(success)

    # get hash param
    bdata = create_string_buffer(b'', bdatalen.value)
    success = windll.advapi32.CryptGetKeyParam(hkey, dwparam, bdata, byref(bdatalen), 0)
    assert_success(success)
    result = bdata.raw[:bdatalen.value]
    if dwparam in [KP_KEYLEN, KP_ALGID]:
        result = struct.unpack('I', result)[0]
    return result


def CryptCreateHash(hProv, Algid):
    hCryptHash = c_void_p()
    success = windll.advapi32.CryptCreateHash(hProv, Algid, 0, None, byref(hCryptHash))
    assert_success(success)
    return hCryptHash


def CryptHashData(hHash, data):
    bdata = create_string_buffer(data)
    dwdatalen = c_int(len(data))
    success = windll.advapi32.CryptHashData(hHash, bdata, dwdatalen, 0)
    assert_success(success)


def CryptGetHashParam(hHash, dwParam):
    # determine output buffer length
    bdatalen = c_int(0)
    success = windll.advapi32.CryptGetHashParam(hHash, dwParam, 0, byref(bdatalen), 0)
    assert_success(success)

    # get hash param
    bdata = create_string_buffer(b'', bdatalen.value)
    success = windll.advapi32.CryptGetHashParam(hHash, dwParam, bdata, byref(bdatalen), 0)
    assert_success(success)
    result = bdata.raw[:bdatalen.value]
    if dwParam in [HP_ALGID, HP_HASHSIZE]:
        result = struct.unpack('I', result)[0]
    return result


def CryptDestroyHash(hCryptHash):
    success = windll.advapi32.CryptDestroyHash(hCryptHash)
    assert_success(success)


def CryptDeriveKey(hProv, Algid, hBaseData):
    hkey = c_void_p()
    success = windll.advapi32.CryptDeriveKey(hProv, Algid, hBaseData, CRYPT_EXPORTABLE, byref(hkey))
    assert_success(success)
    return hkey




input = b"H\xfc\x88\x86\x89\xabn\x8bt\x94Q\x82\xa4Q\xda\xa7\xa0\xef'\x98\x02\x03\xd3\xe4\xfa\xed\xb9\xd6"
part = "warmup_challenge"
part = bytes(bytearray([ord(i) for i in part]))
a = CryptAcquireContext()
b = CryptCreateHash(a,0x8004)
c = CryptHashData(b, part)
d = CryptDeriveKey(a,0x6801,b)
f = CryptDecrypt(d,input)
flag = f.decode()
print(flag)
#CIS2024{900dw0rk_foR_w4RmUp}
```





