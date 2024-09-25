#include <Windows.h>

#include <wtsapi32.h>
#include <userenv.h>
#include <stdio.h>

#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Userenv.lib")

#define SERVICE_NAME L"LeakyService"
#define SERVICE_PATH L"C:\\LeakyService.exe"
#define SERVICE_LOGF "C:\\LeakyServiceLog.txt"

extern "C" void __fastcall gadget();

// Global variables
SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;
HANDLE clientProcess;

// Function declarations
void InstallService();
void UninstallService();
void WINAPI ServiceMain(DWORD argc, LPSTR* argv);
void WINAPI ServiceCtrlHandler(DWORD request);
int InitService();
void WriteToLog(const char* str);

#pragma optimize("", off)
void keepme(void) {
    volatile int dummy = 0;
    gadget();
}
#pragma optimize("", on)


// Main function
int main(int argc, char* argv[]) {

    //gadget();

    if (argc > 1) {
        if (strcmp(argv[1], "install") == 0) {
            InstallService();
        }
        else if (strcmp(argv[1], "uninstall") == 0) {
            UninstallService();
        }
        else {
            printf("Unknown parameter\n");
        }
        return 0;
    }

    // Service entry point
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        { (TCHAR*)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcher(ServiceTable)) {
        WriteToLog("StartServiceCtrlDispatcher failed.");
    }

    return 0;
}

// Install the service
void InstallService() {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hSCManager == NULL) {
        printf("OpenSCManager failed\n");
        return;
    }

    SC_HANDLE hService = CreateService(
        hSCManager,
        SERVICE_NAME,
        SERVICE_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        SERVICE_PATH,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );

    if (hService == NULL) {
        printf("CreateService failed\n");
        CloseServiceHandle(hSCManager);
        return;
    }

    printf("Service installed successfully\n");

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
}

// Uninstall the service
void UninstallService() {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hSCManager == NULL) {
        printf("OpenSCManager failed\n");
        return;
    }

    SC_HANDLE hService = OpenService(hSCManager, SERVICE_NAME, SERVICE_STOP | DELETE);
    if (hService == NULL) {
        printf("OpenService failed\n");
        CloseServiceHandle(hSCManager);
        return;
    }

    if (!DeleteService(hService)) {
        printf("DeleteService failed\n");
    }
    else {
        printf("Service uninstalled successfully\n");
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
}



HANDLE GetUserToekn() {
    PWTS_SESSION_INFOW pSessionInfo = NULL;
    DWORD sessionCount = 0;
    DWORD i;

    // Enumerate all sessions
    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &sessionCount)) {
        for (i = 0; i < sessionCount; i++) {
            if (pSessionInfo[i].State == WTSActive) {
                HANDLE hUserToken;

                // Get the user token for the active session
                if (WTSQueryUserToken(pSessionInfo[i].SessionId, &hUserToken)) {
                    WriteToLog("Successfully obtained user token handle for session ID %lu.\n");

                    // Use hUserToken as needed
                    WTSFreeMemory(pSessionInfo);
                    return hUserToken;
                    
                }
                else {
                    WriteToLog("Failed to obtain user token for session ID %lu. Error: %lu\n");
                }
            }
        }

        WTSFreeMemory(pSessionInfo);
    }
    else {
        WriteToLog("Failed to enumerate sessions. Error\n");
    }

    return NULL;
}


BOOL LaunchProcessInUserSession(const wchar_t* exePath) {

    if (clientProcess != nullptr) {
        DWORD exitCode;
        if (GetExitCodeProcess(clientProcess, &exitCode) && exitCode == STILL_ACTIVE) {
            return TRUE;
        }
    }

    //DWORD sessionId = WTSGetActiveConsoleSessionId();  // Get the active session ID
    HANDLE userToken = GetUserToekn();

    //if (!WTSQueryUserToken(sessionId, &userToken)) {
    //    WriteToLog("WTSQueryUserToken failed with error\n");
    //    return FALSE;
    //}

    // Duplicate the token for impersonation
    HANDLE dupToken = NULL;
    if (!DuplicateTokenEx(userToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &dupToken)) {
        WriteToLog("DuplicateTokenEx failed with error\n");
        CloseHandle(userToken);
        return FALSE;
    }

    // Create the environment block for the new process
    LPVOID envBlock = NULL;
    if (!CreateEnvironmentBlock(&envBlock, dupToken, FALSE)) {
        WriteToLog("CreateEnvironmentBlock failed with error\n");
        CloseHandle(dupToken);
        CloseHandle(userToken);
        return FALSE;
    }

    // Set up the startup info and process information structures
    STARTUPINFO startupInfo = { 0 };
    PROCESS_INFORMATION procInfo = { 0 };
    startupInfo.cb = sizeof(STARTUPINFO);

    wchar_t desktop[] = L"winsta0\\default";
    startupInfo.lpDesktop = desktop;  // Run on the interactive desktop

    // Create the process in the user's session
    if (!CreateProcessAsUser(
        dupToken,
        exePath,                 // Path to the executable
        NULL,                    // Command line arguments
        NULL,                    // Process attributes
        NULL,                    // Thread attributes
        TRUE,                   // Inherit handles
        CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE,  // Creation flags
        envBlock,                // Environment block
        NULL,                    // Current directory
        &startupInfo,            // Startup info
        &procInfo                // Process info
    )) {
        WriteToLog("CreateProcessAsUser failed with error\n");
        DestroyEnvironmentBlock(envBlock);
        CloseHandle(dupToken);
        CloseHandle(userToken);
        return FALSE;
    }

    // Clean up
    DestroyEnvironmentBlock(envBlock);
    clientProcess = procInfo.hProcess;
    //CloseHandle(procInfo.hProcess);
    CloseHandle(procInfo.hThread);
    CloseHandle(dupToken);
    CloseHandle(userToken);

    WriteToLog("Process created successfully in user session\n");
    return TRUE;
}

// Service main function
void WINAPI ServiceMain(DWORD argc, LPSTR* argv) {
    hStatus = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
    if (hStatus == (SERVICE_STATUS_HANDLE)0) {
        WriteToLog("RegisterServiceCtrlHandler failed.");
        return;
    }

    // Initialize the service
    ServiceStatus.dwServiceType = SERVICE_WIN32;
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;

    SetServiceStatus(hStatus, &ServiceStatus);

    if (InitService() == 0) {
        ServiceStatus.dwCurrentState = SERVICE_RUNNING;
        SetServiceStatus(hStatus, &ServiceStatus);
    }
    else {
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
        return;
    }

    //HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, GetCurrentProcessId());
    DWORD currentThreadId = GetCurrentThreadId();
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, TRUE, currentThreadId);

    // Service running loop
    while (ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
        // Perform service tasks here
        //const wchar_t* exePath = L"C:\\Windows\\System32\\cmd.exe";
        const wchar_t* exePath = L"C:\\Windows\\SysWOW64\\cmd.exe";

        if (!LaunchProcessInUserSession(exePath)) {
            WriteToLog("Failed to launch process in user session.\n");
        }
        //WriteToLog("Ran a loop.\n");
        Sleep(5000);
    }
}

// Control handler function
void WINAPI ServiceCtrlHandler(DWORD request) {
    switch (request) {
    case SERVICE_CONTROL_STOP:
        WriteToLog("Service stopped.");
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
        return;

    case SERVICE_CONTROL_SHUTDOWN:
        WriteToLog("Service shutdown.");
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
        return;

    default:
        break;
    }

    SetServiceStatus(hStatus, &ServiceStatus);
}

// Initialize the service (custom initialization code goes here)
int InitService() {
    WriteToLog("Service initialization in progress.");
    // Initialization code here
    return 0;  // return 0 for success, non-zero for failure
}

// Log function
void WriteToLog(const char* str) {
    FILE* log;
    log = fopen(SERVICE_LOGF, "a+");
    if (log == NULL) return;
    fprintf(log, "%s\n", str);
    fclose(log);
}
