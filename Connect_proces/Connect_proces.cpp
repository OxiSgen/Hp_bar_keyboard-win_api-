#define CORSAIR_LIGHTING_SDK_DISABLE_DEPRECATION_WARNINGS
#include "Headers.h"




BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))

    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;

    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }
    return TRUE;
}

//SIZE_T IsArrayMatch(HANDLE proc, SIZE_T address, SIZE_T segmentSize,
//    BYTE array[], SIZE_T arraySize)
//{
//    BYTE* procArray = new BYTE[segmentSize];
//
//    if (ReadProcessMemory(proc, (void*)address, procArray, segmentSize, NULL) != 0)
//    {
//        printf("Failed to read memory: %u\n", GetLastError());
//        delete[] procArray;
//        return 0;
//    }
//
//    for (SIZE_T i = 0; i < segmentSize; ++i)
//    {
//        if ((array[0] == procArray[i]) && ((i + arraySize) < segmentSize))
//        {
//            if (!memcmp(array, procArray + i, arraySize))
//            {
//                delete[] procArray;
//                return address + i;
//            }
//        }
//    }
//
//    delete[] procArray;
//    return 0;
//}
//
//SIZE_T ScanSegments(HANDLE proc, BYTE array[], SIZE_T size)
//{
//    MEMORY_BASIC_INFORMATION meminfo;
//    LPCVOID addr = 0;
//    SIZE_T result = 0;
//
//    if (!proc)
//        return 0;
//
//    while (true)
//    {
//        if (VirtualQueryEx(proc, addr, &meminfo, sizeof(meminfo)) == 0)
//            break;
//
//        if ((meminfo.State & MEM_COMMIT) && (meminfo.Type & MEM_PRIVATE)
//            && (meminfo.Protect & PAGE_READWRITE)
//            && !(meminfo.Protect & PAGE_GUARD))
//        {
//            result = IsArrayMatch(proc, (SIZE_T)meminfo.BaseAddress,
//                meminfo.RegionSize, array, size);
//
//            if (result != 0)
//                return result;
//        }
//        addr = (unsigned char*)meminfo.BaseAddress + meminfo.RegionSize;
//    }
//    return 0;
//}
//
//DWORD64 PIDByName(WCHAR* AProcessName)
//{
//    HANDLE pHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
//    PROCESSENTRY32 Process;
//    DWORD64 PID;
//    Process.dwSize = sizeof(Process);
//    bool Loop = Process32First(pHandle, &Process);
//
//    while (Loop)
//    {
//        if (Process.szExeFile == AProcessName)
//        {
//            PID = Process.th32ProcessID;
//            CloseHandle(pHandle);
//            return PID;
//        }
//        Loop = Process32Next(pHandle, &Process);
//    }
//    return 0;
//}

template<class D>
DWORD ReadDword(HANDLE hProc, D address)
{
     DWORD result = 0;
  
         if (ReadProcessMemory(hProc, (void*)address, &result, sizeof(result), NULL) == 0)
         {
              printf("Failed to read memory: %u\n", GetLastError());
        }
    return result;
}


double getKeyboardWidth(CorsairLedPositions* ledPositions)
{
    const auto minmaxLeds = std::minmax_element(ledPositions->pLedPosition, ledPositions->pLedPosition + ledPositions->numberOfLed,
        [](const CorsairLedPosition& clp1, const CorsairLedPosition& clp2) {
        return clp1.left < clp2.left;
    });
    return minmaxLeds.second->left + minmaxLeds.second->width - minmaxLeds.first->left;
}
void chooseLayerPriority()
{
    CorsairSetLayerPriority(255);
}




int main()
{
    HANDLE hProc = GetCurrentProcess();
     HANDLE hToken = NULL;
  
          if (!OpenProcessToken(hProc, TOKEN_ADJUST_PRIVILEGES, &hToken))
               printf("Failed to open access token\n");
   
            if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
               printf("Failed to set debug privilege\n");
   
          DWORD64 pid = 1276;
   
          HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
      if (hTargetProcess)
              printf("Target process handle = %p\n", hTargetProcess);
      else 
      {
          printf("Target process not found\n");
          system("pause");
      }

 /*     BYTE array[] = 
         {0, 0, 0x02, 0, 0, 0, 0x02, 0, 0, 0,
          0, 0, 0x4C, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0x3F,
          0, 0, 0x80, 0x3F, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0x64, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0x4C, 0, 0, 0, 0, 0 };

   SIZE_T objectAddress = ScanSegments(hTargetProcess, array, sizeof(array));*/

   SIZE_T hpAddress = 0x14B33035518;    //objectaddres - offset

   ULONG hp = 0;

 
   CorsairPerformProtocolHandshake();
   if (const auto error = CorsairGetLastError()) {
       return -1;
   }
   const auto ledPositions = CorsairGetLedPositions();
   if (!ledPositions || ledPositions->numberOfLed < 0) {
       return 1;
   }
   CorsairSetLayerPriority(255);
   const auto numberOfSteps = 100;
   const auto keyboardWidth = getKeyboardWidth(ledPositions);
 
   while (true)
   {
       hp = ReadDword(hTargetProcess, hpAddress);
       //printf("Result of reading dword at 0x%llx value = 0x%x\n", hpAddress,
       //ReadDword(hTargetProcess, hpAddress));
       std::vector<CorsairLedColor> vec;
       const auto currWidth = double(keyboardWidth) * ((int)hp % (numberOfSteps + 1)) / numberOfSteps;
       for (auto i = 0; i < ledPositions->numberOfLed; i++) {
           const auto ledPos = ledPositions->pLedPosition[i];
           auto ledColor = CorsairLedColor();
           ledColor.ledId = ledPos.ledId;
           if (ledPos.left < currWidth) {
               if ((int)hp >= 50)
               {
                   ledColor.r = 2 * (255 - 2.55 * hp);
                   ledColor.g = 255;
                   ledColor.b = 0;
               }
               if ((int)hp < 50)
               {
                   ledColor.r = 255;
                   ledColor.g = 255 - 5.1 * (50 - hp);
                   ledColor.b = 0;
               }
           }
           vec.push_back(ledColor);
       }
       CorsairSetLedsColors(static_cast<int>(vec.size()), vec.data());
       Sleep((BYTE)1000);
   }
   CloseHandle(hTargetProcess);

   return 0;
}
