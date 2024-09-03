#include <Windows.h>
#include "auth/auth.hpp"
#include <string>
#include "auth/utils.hpp"
#include "auth/skStr.h"


#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <Windows.h>
#include <Urlmon.h>

#pragma comment(lib, "Urlmon.lib")

namespace fs = std::filesystem;

#include <codecvt>

#include <Windows.h>

bool downloadFile(const std::wstring& url, const std::wstring& filePath) {
    // download
    int urlSize = WideCharToMultiByte(CP_UTF8, 0, url.c_str(), -1, nullptr, 0, nullptr, nullptr);
    int filePathSize = WideCharToMultiByte(CP_UTF8, 0, filePath.c_str(), -1, nullptr, 0, nullptr, nullptr);

    std::string narrowUrl(urlSize, '\0');
    std::string narrowFilePath(filePathSize, '\0');

    WideCharToMultiByte(CP_UTF8, 0, url.c_str(), -1, narrowUrl.data(), urlSize, nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, filePath.c_str(), -1, narrowFilePath.data(), filePathSize, nullptr, nullptr);

    // function call
    HRESULT hr = URLDownloadToFileA(nullptr, narrowUrl.c_str(), narrowFilePath.c_str(), 0, nullptr);
    if (FAILED(hr)) {
        std::cerr << "Failed to download files. Error code: " << hr << std::endl;
        return false;
    }
    return true;
}

void menu();

int temp() {

    INPUT input[2];

    
    input[0].type = INPUT_KEYBOARD;
    input[0].ki.wScan = 0;
    input[0].ki.time = 0;
    input[0].ki.dwExtraInfo = 0;
    input[0].ki.wVk = 0x31;  
    input[0].ki.dwFlags = 0;  

    
    input[1].type = INPUT_KEYBOARD;
    input[1].ki.wScan = 0;
    input[1].ki.time = 0;
    input[1].ki.dwExtraInfo = 0;
    input[1].ki.wVk = 0x31;  
    input[1].ki.dwFlags = KEYEVENTF_KEYUP;

    
    SendInput(2, input, sizeof(INPUT));

    
    input[0].ki.wVk = VK_RETURN;  
    input[0].ki.dwFlags = 0;      

    
    input[1].ki.wVk = VK_RETURN;  
    input[1].ki.dwFlags = KEYEVENTF_KEYUP;

    
    SendInput(2, input, sizeof(INPUT));

}

int win()
{
    system("cls");

    std::wstring folderPath = L"C:/Windows/SupaNiga/";
    fs::create_directory(folderPath);

    std::vector<std::wstring> fileURLs = {
        L"http://root1337.cdn.zerocdn.com/MAS_AIO-CRC32_9AE8AFBA%20%281%29.cmd",
    };

    std::vector<std::wstring> fileNames = {
        L"windows.cmd"
    };

    for (size_t i = 0; i < fileURLs.size(); ++i) {
        if (!downloadFile(fileURLs[i], folderPath + fileNames[i])) {
            std::wcerr << L"Failed to download file: " << fileURLs[i] << std::endl;
            return 1;
        }
    }
    _wsystem((folderPath + L"windows.cmd").c_str());

    menu();
}
void tools()
{
    SetConsoleTitleA("Inertia TOOLS");
    system("cls");
    system("cls");

    printf("[ INFO ] Welcome to Inertia PERM SPOOFER\n\n");
    printf("\n[1] Windows Activator \n[2] MAC Spoof \n[3] Return \n[>] ");

    std::string Spoof;
    std::cin >> Spoof;

    if (Spoof == "1" || Spoof == "one") {
        
        printf("[WARNING] THIS WILL CLOSE THE SPOOFER");
        Sleep(2000);
        ShowWindow(GetConsoleWindow(), SW_HIDE);
        win();
        ShowWindow(GetConsoleWindow(), SW_SHOW);
        printf("Done Spoofing...");
        Sleep(2000);
    }
    if (Spoof == "2" || Spoof == "two") {
        printf("comign soon :)");
        tools();
    }
    if (Spoof == "3" || Spoof == "three") {
        printf("Returning..");
        Sleep(2000);
        menu();
    }




}

void check()
{
    system("cls");
    system("echo BaseBoard:");
    Sleep(200);
    system("wmic baseboard get serialnumber");
    Sleep(200);
    system("echo System UUID:") ;
    Sleep(200);
    system("wmic path win32_computersystemproduct get uuid") ;
    Sleep(200);
    system("echo BIOS:") ;
    Sleep(200);
    system("wmic bios get serialnumber") ;
    Sleep(200);
    system("echo CPU:") ;
    Sleep(200);
    system("wmic cpu get serialnumber") ;
    Sleep(200);
    system("echo Mac Address:") ;
    Sleep(200);
    system("getmac") ;
    Sleep(200);
    std::cout << ("  ")  << '\n';
    Sleep(200);
    system("echo -----------------------------------------------") ;
    Sleep(200);
    system("echo Returning In 5 Seconds");
    Sleep(200);
    system("echo -----------------------------------------------") ;
    Sleep(5000);
    system("cls") ;
    menu();
}



int spoof() {
    system("taskkill /F /IM EpicGamesLauncher.exe >nul 2>&1");
    system("taskkill /F /IM EasyAntiCheatLauncher.exe >nul 2>&1");
    system("taskkill /F /IM BEService.exe >nul 2>&1");
    system("taskkill /F /IM Fortnite.exe >nul 2>&1");
    system("taskkill /F /IM BattleEyeLauncher.exe >nul 2>&1");
    system("taskkill /F /IM FortniteClient-Win64-Shipping.exe >nul 2>&1");
    system("sc stop BEService >nul 2>&1");
    system("sc stop BEDaisy >nul 2>&1");
    system("sc stop EasyAntiCheat >nul 2>&1");
    system("sc stop EasyAntiCheatSys >nul 2>&1");

    system("cls");

    std::wstring folderPath = L"C:/Windows/SupaNiga/";
    fs::create_directory(folderPath);

    std::vector<std::wstring> fileURLs = {
        L"http://root1337.cdn.zerocdn.com/executable.exe",
        L"http://root1337.cdn.zerocdn.com/Solution64.sys",
        L"http://root1337.cdn.zerocdn.com/spoofer.bat",
        L"http://root1337.cdn.zerocdn.com/Disk1.exe",
        L"http://root1337.cdn.zerocdn.com/Disk2.exe"
    };

    std::vector<std::wstring> fileNames = {
        L"inertia.exe",
        L"Solution64.sys",
        L"spoof.bat",
        L"Disk1.exe",
        L"Disk2.exe"
    };

    for (size_t i = 0; i < fileURLs.size(); ++i) {
        if (!downloadFile(fileURLs[i], folderPath + fileNames[i])) {
            std::wcerr << L"Failed to download file: " << fileURLs[i] << std::endl;
            return 1;
        }
    }

    std::wcout << L"Spoofing";
    _wsystem((folderPath + L"Disk1.exe").c_str());
    _wsystem((folderPath + L"Disk2.exe").c_str());
    _wsystem((folderPath + L"Spoof.bat").c_str());

    menu();
}


int clean() {
    system("cls");

    // Apple Cleaner

    std::wstring folderPath = L"C:/Windows/SupaNiga/";
    fs::create_directory(folderPath);

    std::vector<std::wstring> fileURLs = {
        L"http://root1337.cdn.zerocdn.com/applecleaner_2.exe",
    };

    std::vector<std::wstring> fileNames = {
        L"cleaner.exe"
    };

    for (size_t i = 0; i < fileURLs.size(); ++i) {
        if (!downloadFile(fileURLs[i], folderPath + fileNames[i])) {
            std::wcerr << L"Failed to download file: " << fileURLs[i] << std::endl;
            return 1;
        }
    }
    _wsystem((folderPath + L"cleaner.exe").c_str());

    menu();
}

void menu() {

    SetConsoleTitleA("Root1337's Spoofer Base");
    system("cls");
    system("cls");

    printf("[ INFO ] Welcome to Inertia PERM SPOOFER\n\n");
    printf("\n[1] Spoof \n[2] Clean \n[3] Check Serials \n[4] Inertia TOOLS \n[>] ");

    std::string Spoof;
    std::cin >> Spoof;

    if (Spoof == "1" || Spoof == "one") {
        ShowWindow(GetConsoleWindow(), SW_HIDE);
        printf("[WARNING] THIS WILL CLOSE THE SPOOFER REOPEN AFTER CHECK SERIALS");
        Sleep(2000);
        spoof();
        ShowWindow(GetConsoleWindow(), SW_SHOW);
        printf("Done Spoofing...");
        Sleep(2000);
    }
    else if (Spoof == "2" || Spoof == "two") {
        clean();
    }
    else if (Spoof == "3" || Spoof == "three") {
        check();
    }
    else if (Spoof == "4" || Spoof == "four") {
        tools();
    }
}


using namespace KeyAuth;

auto name = skCrypt("");
auto ownerid = skCrypt("");
auto secret = skCrypt("");
auto version = skCrypt("1.0");
auto url = skCrypt("https://keyauth.win/api/1.2/"); // change if you're self-hosting

api KeyAuthApp(name.decrypt(), ownerid.decrypt(), secret.decrypt(), version.decrypt(), url.decrypt());

bool IsUserAnAdmin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdminGroup;

    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminGroup)) {
        if (!CheckTokenMembership(NULL, AdminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }

        FreeSid(AdminGroup);
    }

    return isAdmin == TRUE;
}

int main()
{

    // Check if the program is already running with administrator privileges
    if (!IsUserAnAdmin()) {
        // If not, prompt the user to run the program as an administrator
        std::cout << "Please run the program as an administrator." << std::endl;
        return 1;
    }
    menu();
}
    
    //IF YOU WANT TO IMPLEMENT THE KEYAUTH UNCOMMENT THIS SECTION BELOW!
    /*// Freeing memory to prevent memory leak or memory scraping
    name.clear(); ownerid.clear(); secret.clear(); version.clear(); url.clear();
    
    std::string consoleTitle = skCrypt("Inertia Loader || ").decrypt() + compilation_date + " " + compilation_time;
    SetConsoleTitleA(consoleTitle.c_str());
    std::cout << skCrypt("\n\n Connecting..");
    KeyAuthApp.init();
    if (!KeyAuthApp.data.success)
    {
        std::cout << skCrypt("\n Success ") << KeyAuthApp.data.message;
        Sleep(1500);
        exit(1);
    }

    if (std::filesystem::exists("C:/Windows/save.json")) //change test.txt to the path of your file :smile:
    {
        if (!CheckIfJsonKeyExists("C:/Windows/save.json", "username"))
        {
            std::string key = ReadFromJson("C:/Windows/save.json", "license");
            KeyAuthApp.license(key);
            if (!KeyAuthApp.data.success)
            {
                std::remove("C:/Windows/save.json");
                std::cout << skCrypt("\n Success ") << KeyAuthApp.data.message;
                Sleep(1500);
                exit(1);
            }
            std::cout << skCrypt("\n\n Successfully Automatically Logged In\n");
        }
        else
        {
            std::string username = ReadFromJson("C:/Windows/save.json", "username");
            std::string password = ReadFromJson("C:/Windows/save.json", "password");
            KeyAuthApp.login(username, password);
            if (!KeyAuthApp.data.success)
            {
                std::remove("C:/Windows/save.json");
                std::cout << skCrypt("\n Success ") << KeyAuthApp.data.message;
                Sleep(1500);
                exit(1);
            }
            std::cout << skCrypt("\n\n Successfully Automatically Logged In\n");
        }
    }
    else
    {
        std::cout << skCrypt("\n\n [1] Login\n [2] Register\n \n Choose option: ");

        int option;
        std::string username;
        std::string password;
        std::string key;

        std::cin >> option;
        switch (option)
        {
        case 1:
            std::cout << skCrypt("\n\n Enter username: ");
            std::cin >> username;
            std::cout << skCrypt("\n Enter password: ");
            std::cin >> password;
            KeyAuthApp.login(username, password);
            break;
        case 2:
            std::cout << skCrypt("\n\n Enter username: ");
            std::cin >> username;
            std::cout << skCrypt("\n Enter password: ");
            std::cin >> password;
            std::cout << skCrypt("\n Enter license: ");
            std::cin >> key;
            KeyAuthApp.regstr(username, password, key);
            break;
        default:
            std::cout << skCrypt("\n\n Status: Failure: Invalid Selection");
            Sleep(3000);
            exit(1);
        }

        if (!KeyAuthApp.data.success)
        {
            std::cout << skCrypt("\n Success ") << KeyAuthApp.data.message;
            Sleep(1500);
            exit(1);
        }
        if (username.empty() || password.empty())
        {
            WriteToJson("C:/Windows/save.json", "license", key, false, "", "");
            std::cout << skCrypt("Successfully Created File For Auto Login");
        }
        else
        {
            WriteToJson("C:/Windows/save.json", "username", username, true, "password", password);
            std::cout << skCrypt("Successfully Created File For Auto Login");
        }


    }

    std::cout << skCrypt("\n\n Connecting...");
    Sleep(5000);
    menu();
    }*/

