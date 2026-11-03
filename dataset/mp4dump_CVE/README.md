
git clone https://github.com/axiomatic-systems/Bento4.git
git checkout d02ef8230a8fee4904a750eb912521c5f1c74e0b

cmake -B build \         
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="-g -O0 -fno-pie" \
    -DCMAKE_EXE_LINKER_FLAGS="-no-pie"

cmake --build build


```
#include <iostream>
int counter = 0;
AP4_Result
AP4_DataBuffer::SetData(const AP4_Byte* data, AP4_Size size)
{
    if (size > m_BufferSize) {
        if (m_BufferIsLocal) {
            AP4_Result result = ReallocateBuffer(size);
            if (AP4_FAILED(result)) return result;
        } else {
            return AP4_FAILURE;
        }
    }
    counter ++;
    if (counter == 2) {
      abort();
    }
    AP4_CopyMemory(m_Buffer, data, size);
    m_DataSize = size;

    return AP4_SUCCESS;
}
```
