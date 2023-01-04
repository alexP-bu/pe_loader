//making a custom PE loader, for this one, I'm going to try to load calc.exe
#include <windows.h>
#include <stdio.h>

BYTE* getFileBytes(char* path){
  HANDLE hFile = NULL;
  DWORD fileSize = 0;
  hFile = CreateFileA(path,
                      GENERIC_READ,
                      0,
                      NULL,
                      OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL,
                      NULL);
  if (hFile == INVALID_HANDLE_VALUE){
    printf("[!] ERROR: failed to read file....\n");
    return NULL;
  }
  fileSize = GetFileSize(hFile, NULL);
  if(fileSize == 0){
    printf("[!] ERROR: no file, or empty file given...\n");
    return NULL;
  }
  BYTE* buffer = (BYTE*) malloc(fileSize * sizeof(BYTE) + 1);
  if (!buffer){
    printf("[!] ERROR: failed to allocate memory to read file bytes...\n");
    return NULL;
  }
  DWORD read = 0;
  if(!ReadFile(hFile, buffer, fileSize, &read, NULL)){
    printf("[!] ERROR: failed to read file bytes...\n");
    return NULL;
  }
  buffer[fileSize] = '\0';
  printf("[+] Finished reading file bytes successfully...\n");
  //cleanup
  CloseHandle(hFile);
  return buffer;
}

int main(int argc, char *argv[]){
  if (argc < 2){
    printf("[!] USAGE: loader.exe <path_to_file>");
    return 1;
  }
  //first, read file bytes
  BYTE* fileBytes = getFileBytes(argv[1]);
  if(!fileBytes){
    printf("[!] ERROR getting file bytes. Exiting...\n");
    return 1;
  }
  //now let's map the pe-header (dos header -> nt header -> optional header, file header)
  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) fileBytes;
  PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS) (fileBytes + dosHeader->e_lfanew);
  PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeader);
  IMAGE_FILE_HEADER fileHeader = ntHeader->FileHeader;
  IMAGE_OPTIONAL_HEADER optionalHeader = ntHeader->OptionalHeader;
  //get information needed for loading
  DWORD entryPoint = optionalHeader.AddressOfEntryPoint;
  DWORD imageBase = optionalHeader.ImageBase;
  DWORD headerSize = optionalHeader.SizeOfHeaders;
  DWORD imageSize = optionalHeader.SizeOfImage;
  DWORD numSections = fileHeader.NumberOfSections;
  //allocate memory for image
  BYTE* baseAddress = VirtualAlloc(NULL,
                                   imageSize,
                                   MEM_RESERVE | MEM_COMMIT,
                                   PAGE_EXECUTE_READWRITE); 
  //copy headers into the memory
  memcpy(baseAddress, fileBytes, headerSize);
  //copy sections into the memory
  for(DWORD i = 0; i < numSections; i++){
    void* destination = sections[i].VirtualAddress + baseAddress;
    void* source = sections[i].PointerToRawData + baseAddress;
    if(sections[i].SizeOfRawData == 0){
      memset(destination, 0, sections[i].Misc.VirtualSize);
    }else{
      memcpy(destination, source, sections[i].SizeOfRawData);
    }
  }
  printf("[+] Finished memory mapping PE headers and sections successfully...\n");
  //load dependencies: pe -> for dll in dlls -> for function in dlls -> get virtual address and patch
  //base relocations
  //handle TLS callbacks
  //run entry point
  return 0;
}
