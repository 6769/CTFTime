# Login

<login.exe> file could be download from [here](https://dn.jarvisoj.com/challengefiles/login.exe.0e043cc84e9273f1e34b6b27330c8e5a)

Use pyinstaller extractor,we get a file: main<.pyc>;
The main file is a pyObject dumped string file.
Convert to a normal pycfile(add a pyc file header,4bytes MAGIC_NUMBER,4bytes Timestamp),  reverse it to source code:

```python 
# Embedded file name: main.py
# Compiled at: 2016-08-16 19:36:25
# Size of source mod 2**32: 89 bytes
import hxbctf
print(hxbctf.Login(0, input('UserName: ')))
# okay decompiling tryrepair.main.pyc
```

## Pre.Bug

This **Onefile** compressed pyinstaller bootloader has a [bug](https://github.com/pyinstaller/pyinstaller/issues/1565) 
of unable to run when vcruntime is upx-compressed under 64-bit Windows, which may lead to some errors.

Now  we use 010editor to change the strings in login.exe file,
`strings login.exe |grep dll`,find the string`bVCRUNTIME140.dll`'s position,
and rename it to `bccruntime140.dll`or any other strings to bypass this bug.
Remember to place a normal `VCRUNTIME140.dll` file under system's search path.

# Consider

if we use strings to serach `hxbctf` after all binary files were upx-decompressed,
'python.dll' has reported a string reference to `hxbctf`.
So, it's had been clear and next step was to reverse core dll.
And if we use a python front shell`python.exe` to run the core dll, we'll find that `hxbctf` has been compiled as a built-in module 
into this python file.

## crack

Luckily, the String "Congratulations" is a plain text in .rodata segment.

Locate his usage position:

In the dll, segment  position `.text:1E183D20`,it's the major function of the game;

```c 
int __cdecl coreCTFfunction(int a1, void *pyobj)
{
  int result; // eax@1
  int i; // edx@5
  int v4; // eax@6
  int v5; // ecx@6
  char *userName; // [sp+4h] [bp-40Ch]@2
  int paraNumber1; // [sp+8h] [bp-408h]@1
  char Dst; // [sp+Ch] [bp-404h]@8
  char inputStrDstcache[512]; // [sp+20Ch] [bp-204h]@1

  memset(inputStrDstcache, 0, 0x200u);
  result = PyArg_ParseTuple(pyobj, "is", (unsigned int)&paraNumber1);// http://wiki.jikexueyuan.com/project/interpy-zh/c_extensions/python_c_api.html
  if ( result )
  {
    sub_1E04E550((int)"Password: ", (char)userName);
    getInputScanf("%s", inputStrDstcache);
    if ( paraNumber1 == 0x1352 && strlen(inputStrDstcache) == 16 && !strncmp("HXB_Admin", userName, 9u) )
    {
      i = 0;
      while ( 1 )
      {
        v4 = inputStrDstcache[i];
        v5 = i ^ v4 ^ secrectKey[i];
        if ( i != (v4 ^ secrectKey[i]) )
          break;
        if ( ++i >= 16 )
        {
          memset(&Dst, v5, 0x200u);
          printfFormator(&Dst, "Congratulations!\nflag{%s}.", inputStrDstcache);
          return Py_BuildValue("s", (unsigned int)&Dst);
        }
      }
    }
    result = Py_BuildValue("s", (unsigned int)"Access Denied!");
  }
  return result;
}
```

find out the strings in secKey:`.rdata:1E253040 secrectKey`
Here is the algorithm :Xor with each inputed char and his index;

```python 
sec='Pxvk4kYcIVlJSeO?'
res=[]
for i in range(len(sec)):
    n1=ord(sec[i])
    res.append(chr(i^n1))
print(''.join(res))
## -- End pasted text --
#got >>>Pyth0n_dA_fA_hA0
```

## Result

```python 
import hxbctf
>>> hxbctf.Login(0x1352,'HXB_Admin')
Password: Pyth0n_dA_fA_hA0
'Congratulations!\nflag{Pyth0n_dA_fA_hA0}.'
>>> 
```

#Reference

强行动态调试解出:http://bbs.pediy.com/thread-215002.htm