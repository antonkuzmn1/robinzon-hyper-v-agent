#include <windows.h>
#include <iostream>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

int main() {
    HRESULT hres;

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::cerr << "Error CoInitializeEx: " << std::hex << hres << std::endl;
        return 1;
    }
    std::cerr << "CoInitializeEx result: " << std::hex << hres << std::endl;

    hres = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL
    );
    if (FAILED(hres)) {
        std::cerr << "Error CoInitializeSecurity: " << std::hex << hres << std::endl;
        CoUninitialize();
        return 1;
    }
    std::cerr << "CoInitializeSecurity result: " << std::hex << hres << std::endl;

    IWbemLocator *pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&pLoc);
    if (FAILED(hres)) {
        std::cerr << "Error CoCreateInstance: " << std::hex << hres << std::endl;
        CoUninitialize();
        return 1;
    }
    std::cerr << "CoCreateInstance result: " << std::hex << hres << std::endl;

    IWbemServices *pSvc = NULL;
    BSTR namespaceStr = SysAllocString(L"ROOT\\Virtualization\\v2");
    hres = pLoc->ConnectServer(
        namespaceStr, NULL, NULL, NULL, 0, NULL, NULL, &pSvc
    );
    SysFreeString(namespaceStr);

    if (FAILED(hres)) {
        std::cerr << "Error ConnectServer: " << std::hex << hres << std::endl;
        pLoc->Release();
        CoUninitialize();
        return 1;
    }
    std::cerr << "ConnectServer result: " << std::hex << hres << std::endl;

    hres = CoSetProxyBlanket(
        pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE
    );
    if (FAILED(hres)) {
        std::cerr << "Error CoSetProxyBlanket: " << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }
    std::cerr << "CoSetProxyBlanket result: " << std::hex << hres << std::endl;

    BSTR query = SysAllocString(L"SELECT Name, NumberOfVirtualProcessors, OperationalStatus FROM Msvm_ComputerSystem");
    BSTR wql = SysAllocString(L"WQL");

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        wql, query,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL, &pEnumerator
    );
    std::cerr << "ExecQuery result: " << std::hex << hres << std::endl;
    SysFreeString(query);
    SysFreeString(wql);

    if (FAILED(hres)) {
        std::cerr << "Error ExecQuery: " << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    IWbemClassObject *pclsObj = NULL;
    ULONG uReturn = 0;
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) break;

        VARIANT vtName, vtCores, vtStatus;
        hr = pclsObj->Get(L"Name", 0, &vtName, 0, 0);
        hr = pclsObj->Get(L"NumberOfVirtualProcessors", 0, &vtCores, 0, 0);
        hr = pclsObj->Get(L"OperationalStatus", 0, &vtStatus, 0, 0);

        if (SUCCEEDED(hr)) {
            std::wcout << L"ВМ: " << vtName.bstrVal
                       << L" | CPU: " << vtCores.uintVal
                       << L" | State: " << vtStatus.uintVal << std::endl;
        }
        VariantClear(&vtName);
        VariantClear(&vtCores);
        VariantClear(&vtStatus);
        pclsObj->Release();
    }

    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    return 0;
}