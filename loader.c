//making a custom PE loader, for this one, I'm going to try to load calc.exe
#include <windows.h>
#include <stdio.h>

//function to execute entrypoint
typedef void EntryPoint(void);

typedef struct RelocationBlock {
    DWORD VirtualAddress;
    DWORD SizeOfBlock;
    WORD relocation[];
} RelocationBlock, *PIMAGE_RELOCATION_BLOCK;

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
  UINT_PTR prefImageBase = optionalHeader.ImageBase;
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
  if(baseAddress == NULL){
    printf("[!]Failed to allocate memory!");
  }
  //copy headers into the memory
  memcpy(baseAddress, fileBytes, headerSize);
  //copy sections into the memory
  for(DWORD i = 0; i < numSections; i++){
    void* destination = (void*) (sections[i].VirtualAddress + baseAddress);
    void* source      = (void*) (sections[i].PointerToRawData + fileBytes);
    printf("[-] Copying section %s with size %d\n", sections[i].Name, sections[i].SizeOfRawData);
    if(sections[i].SizeOfRawData == 0){
      memset(destination, 0, sections[i].Misc.VirtualSize);
    }else{
      memcpy(destination, source, sections[i].SizeOfRawData);
    }
  }
  printf("[+] Finished memory mapping PE headers and sections successfully...\n");
  //load dependencies: pe -> for dll in dlls -> for function in dlls -> get virtual address and patch
  PIMAGE_IMPORT_DESCRIPTOR imageDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(baseAddress + optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
  int i = 0;
  while(imageDescriptor[i].FirstThunk != 0){
    char* dllName = (char*) (imageDescriptor[i].Name + baseAddress);
    HMODULE hLibrary = LoadLibraryA(dllName);
    if(hLibrary == NULL){
      printf("[!] ERROR loading DLL");
    }
    //load functions in dlls
    PIMAGE_THUNK_DATA lookupTable = (PIMAGE_THUNK_DATA) (baseAddress + imageDescriptor[i].OriginalFirstThunk);
    PIMAGE_THUNK_DATA addrTable = (PIMAGE_THUNK_DATA) (baseAddress + imageDescriptor[i].FirstThunk);
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
        function = GetProcAddress(hLibrary, (LPSTR) addr);
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
  //base relocations 
  if (baseAddress - prefImageBase != 0){
    PIMAGE_RELOCATION_BLOCK relocation = (PIMAGE_RELOCATION_BLOCK)(baseAddress + optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    while(relocation->VirtualAddress > 0){
        //n_relocation = dwBlockSize - 8) //2
        DWORD numRelocs = (relocation->SizeOfBlock - (sizeof(DWORD) * 2) )/ (sizeof(WORD));
        UINT_PTR page = (UINT_PTR) (baseAddress + relocation->VirtualAddress);
        printf("[+] There are %d relocations to perform\n", numRelocs);
        for(DWORD i = 0; i < numRelocs; i++){
            WORD block = relocation->relocation[i];
            DWORD type = block >> 12;
            DWORD offset = block & 0xfff;
            printf("[-] Performation Relocation: %lu, %d\n", type, offset);
            ULONGLONG *relocVirtualAddress = NULL;
            switch( type){
                case IMAGE_REL_BASED_ABSOLUTE:
                    printf("[-] IMAGE_REL_BASED_ABSOLUTE -> nothing to be done!\n");
                    break;
                case  IMAGE_REL_BASED_DIR64:
                    relocVirtualAddress = (ULONGLONG*) (page + offset );
                    *relocVirtualAddress =  *relocVirtualAddress  + (ptrdiff_t)(baseAddress - prefImageBase);
                    break;
                default:
                    printf("[!] Unrecongized relocation type! %lu\n", type);
                    break;
            }
        }
        relocation = (PIMAGE_RELOCATION_BLOCK) ((UINT_PTR)relocation +  relocation->SizeOfBlock);
    }
  }
  printf("[+] Finished base relocations\n");
  //TLS (thread local storage) callbacks
  if(optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size){
    PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)((UINT_PTR)baseAddress + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    PIMAGE_TLS_CALLBACK *tlsCallback = (PIMAGE_TLS_CALLBACK *) tls->AddressOfCallBacks;
    while(*tlsCallback){
        printf("[+] Found TLS callback at %p\n", (void*) tlsCallback);
        (*tlsCallback)((LPVOID) baseAddress, DLL_PROCESS_ATTACH, NULL);
        tlsCallback++;
    }
  }
  printf("[+] Finished handling TLS callbacks...");
  //run entry point
  UINT_PTR entry = (UINT_PTR) (baseAddress + entryPoint);
  ((EntryPoint*)entry)();
  return 0;
}
