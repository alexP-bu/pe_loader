//making a custom PE loader, for this one, I'm going to try to load calc.exe
#include <windows.h>
#include <stdio.h>

//function to execute entrypoint
typedef void EntryPoint(void);

//function to read file bytes
BYTE* getFileBytes(char* path){
  HANDLE hFile = NULL;
  DWORD fileSize = 0;
  hFile = CreateFileA(
    path,
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
  DWORD prefImageBase = optionalHeader.ImageBase;
  DWORD headerSize = optionalHeader.SizeOfHeaders;
  DWORD imageSize = optionalHeader.SizeOfImage;
  DWORD numSections = fileHeader.NumberOfSections;
  //allocate memory for image
  BYTE* baseAddress = (BYTE*) VirtualAlloc(
    NULL,
    imageSize,
    MEM_RESERVE | MEM_COMMIT,
    PAGE_EXECUTE_READWRITE
  ); 
  //copy headers into the memory
  memcpy(baseAddress, fileBytes, headerSize);
  //copy sections into the memory
  for(DWORD i = 0; i < numSections; i++){
    void* destination = (void*) (sections[i].VirtualAddress + (UINT_PTR)baseAddress);
    void* source = (void*) (sections[i].PointerToRawData + fileBytes);
    printf("[-] Copying section %s with size %d\n", sections[i].Name, sections[i].SizeOfRawData);
    if(sections[i].SizeOfRawData == 0){
      memset(destination, 0, sections[i].Misc.VirtualSize);
    }else{
      memcpy(destination, source, sections[i].SizeOfRawData);
    }
  }
  printf("[+] Finished memory mapping PE headers and sections successfully...\n");
  //load dependencies: pe -> for dll in dlls -> for function in dlls -> get virtual address and patch
  PIMAGE_IMPORT_DESCRIPTOR imageDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((UINT_PTR)baseAddress + optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
  HMODULE hLibrary = NULL;
  PIMAGE_THUNK_DATA lookupTable = NULL;
  PIMAGE_THUNK_DATA addrTable = NULL;
  int i = 0;
  while(imageDescriptor[i].FirstThunk != 0){
    //load dll
    char* dllName = (char*) (imageDescriptor[i].Name + baseAddress);
    if((hLibrary = LoadLibraryA(dllName)) == NULL){
      printf("[!] ERROR loading DLL: %s\n", dllName);
    }else{
      printf("[-] Loaded DLL: %s\n", dllName);
    }
    //load functions in dlls
    lookupTable = (PIMAGE_THUNK_DATA) (baseAddress + imageDescriptor[i].OriginalFirstThunk);
    addrTable = (PIMAGE_THUNK_DATA) (baseAddress + imageDescriptor[i].FirstThunk);
    int j = 0;
    while(lookupTable[j].u1.AddressOfData != 0){
      FARPROC function = NULL;
      UINT_PTR addr = lookupTable[j].u1.AddressOfData;
      if((addr & IMAGE_ORDINAL_FLAG) == 0){
        PIMAGE_IMPORT_BY_NAME imageImport = (PIMAGE_IMPORT_BY_NAME) (addr + baseAddress);
        char* functionName = (char*) imageImport->Name;
        function = GetProcAddress(hLibrary, functionName);
        printf("[-] Loaded function: %s\n", functionName);
      }else{
        function = GetProcAddress(hLibrary, (LPSTR) lookupTable);
      }
      if(function == NULL){
        printf("[!] FAILED TO LOAD FUNCTION: %d\n", GetLastError());
        return 1;
      }
      addrTable[j].u1.Function = (UINT_PTR) function;
      j++;
    }
    i++;
  }
  printf("[+] Finished loading dependencies sucessfully!\n");
  //base relocations (TODO)
  if(baseAddress - prefImageBase != 0){
    PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(baseAddress + optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    while(relocation->VirtualAddress > 0){
      DWORD nRelocs = relocation->SizeOfBlock - (sizeof(DWORD) * 2) / sizeof(WORD);
      PWORD pages = (PWORD) (baseAddress + relocation->VirtualAddress);
      for(DWORD i = 0; i < nRelocs; i++){
        WORD relocType = pages[i] >> 12;
        WORD relocOffset = pages[i] & 0xFFF;
        PDWORD relocAddress = (PDWORD)(baseAddress + relocOffset + relocation->VirtualAddress);
        printf("[-] Performing relocation with type: %d\n", relocType);
        PULONGLONG relocVA = NULL;
        switch(relocType){
          case IMAGE_REL_BASED_ABSOLUTE:
            break;
          case IMAGE_REL_BASED_HIGHLOW:
            relocAddress += (DWORD) baseAddress;
            break;
          case IMAGE_REL_BASED_DIR64: //TODO FIX?
            relocVA = (PULONGLONG) (pages + relocOffset);
            relocVA = *relocVA + (baseAddress - prefImageBase);
            break; 
          case IMAGE_REL_BASED_HIGHADJ:
            break; 
          default:
            printf("Unsupported relocation type: %d\n", relocType);
        }
        //get next reloc block
        relocation = (PIMAGE_BASE_RELOCATION) (relocation + relocation->SizeOfBlock);
      }
    }
  }
  printf("[+] Finished base relocations\n");
  //TLS (thread local storage) callbacks
  if(optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size != 0){
    PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)(baseAddress + optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    PIMAGE_TLS_CALLBACK *tlsCallback = (PIMAGE_TLS_CALLBACK *) tls->AddressOfCallBacks;
    while(tlsCallback){
      printf("[-] TLS callback found: %s", tlsCallback);
      (*tlsCallback)((LPVOID)baseAddress, DLL_PROCESS_ATTACH, NULL);
      tlsCallback++;
    }
  }
  printf("[+] Finished handling TLS callbacks...");
  //run entry point
  UINT_PTR entry = (UINT_PTR) (baseAddress + entryPoint);
  ((EntryPoint*)entry)();
  return 0;
}
