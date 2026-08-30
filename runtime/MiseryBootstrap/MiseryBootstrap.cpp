// MiseryBootstrap.cpp -- the whole of what gets installed into the game.
//
// This file is deliberately small, and staying small is a requirement rather
// than a preference. It is the only code of ours that runs before the game has
// finished starting, it runs partly under the loader lock, and it is the piece
// a user cannot uninstall without deleting a file from their Steam directory.
// Everything that could possibly be done later is done later, in MiseryRuntime.
//
// WHAT IT DOES, IN ORDER
// ----------------------
//   DllMain          bind the real dwmapi, start one thread, return. Nothing
//                    else -- see the loader-lock note below.
//   bootstrap thread wait for the process to be past its own startup, then:
//                      1. fingerprint the running executable
//                      2. find bindings for exactly that fingerprint
//                      3. hand them to MiseryRuntime
//
// FAIL CLOSED, AND WHAT THAT MEANS HERE
// -------------------------------------
// Every failure below leaves the game running VANILLA. Not degraded, not
// partially modded -- vanilla, exactly as if this file were not present. An
// unknown fingerprint, a missing bindings file, a bindings file for another
// build, a missing runtime, a runtime that refuses: each writes a line to the
// log and returns. There is no path in this file that continues with a guess,
// because a guessed binding means writing to an address derived from a
// different build of the game.
//
// THE LOADER LOCK
// ---------------
// DllMain runs with the loader lock held, where almost nothing is safe.
// LoadLibrary of a leaf system DLL by absolute path is the one liberty taken,
// and it is the conventional one for a proxy: without the real dwmapi bound,
// the first game call through a thunk would jump through a null pointer. The
// bootstrap itself -- file I/O, hashing, loading our runtime -- happens on a
// thread, which the loader will not schedule until the lock is released.
#include <windows.h>

#include <stdio.h>
#include <string.h>

#include "dwmapi_proxy.h"

namespace {

// Where the framework lives. Beside the game's Binaries directory, in one
// folder, so an uninstall is "delete two things".
const char kFrameworkDir[] = "MiseryFramework";
const char kRuntimeDll[] = "MiseryRuntime.dll";
const char kBindingsName[] = "bindings.json";
const char kLogName[] = "bootstrap.log";

char g_module_dir[MAX_PATH] = {0};
char g_log_path[MAX_PATH] = {0};

void Log(const char* format, ...) {
    if (g_log_path[0] == '\0') {
        return;
    }
    FILE* file = nullptr;
    if (fopen_s(&file, g_log_path, "a") != 0 || file == nullptr) {
        return;
    }
    SYSTEMTIME now;
    GetLocalTime(&now);
    fprintf(file, "[%02d:%02d:%02d.%03d] ", now.wHour, now.wMinute, now.wSecond,
            now.wMilliseconds);
    va_list args;
    va_start(args, format);
    vfprintf(file, format, args);
    va_end(args);
    fprintf(file, "\n");
    fclose(file);
}

bool JoinPath(char* out, size_t capacity, const char* a, const char* b) {
    return _snprintf_s(out, capacity, _TRUNCATE, "%s\\%s", a, b) > 0;
}

// SHA-256 of the running executable, through the OS. The identity of the build
// is the whole gate, so it is computed rather than read from anywhere that
// could be edited independently of the file it describes.
bool HashFile(const char* path, char* out_hex, size_t capacity) {
    if (capacity < 65) {
        return false;
    }
    HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    bool ok = false;
    if (CryptAcquireContextA(&provider, nullptr, nullptr, PROV_RSA_AES,
                             CRYPT_VERIFYCONTEXT) &&
        CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) {
        BYTE buffer[64 * 1024];
        DWORD read = 0;
        ok = true;
        while (ReadFile(file, buffer, sizeof(buffer), &read, nullptr) && read > 0) {
            if (!CryptHashData(hash, buffer, read, 0)) {
                ok = false;
                break;
            }
        }
        if (ok) {
            BYTE digest[32];
            DWORD size = sizeof(digest);
            if (CryptGetHashParam(hash, HP_HASHVAL, digest, &size, 0) && size == 32) {
                for (int i = 0; i < 32; ++i) {
                    _snprintf_s(out_hex + i * 2, capacity - i * 2, _TRUNCATE,
                                "%02x", digest[i]);
                }
            } else {
                ok = false;
            }
        }
    }
    if (hash) CryptDestroyHash(hash);
    if (provider) CryptReleaseContext(provider, 0);
    CloseHandle(file);
    return ok;
}

// Does the bindings file claim this exact build? A substring match on the hash
// inside a "build_key" field is enough here: the runtime re-validates properly,
// and the bootstrap's job is only to refuse obviously-wrong bindings before
// handing anything over.
bool BindingsMatch(const char* bindings_path, const char* wanted_hex) {
    HANDLE file = CreateFileA(bindings_path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    LARGE_INTEGER size;
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        size.QuadPart > 8 * 1024 * 1024) {
        CloseHandle(file);
        return false;
    }
    char* text = static_cast<char*>(malloc(static_cast<size_t>(size.QuadPart) + 1));
    if (text == nullptr) {
        CloseHandle(file);
        return false;
    }
    DWORD read = 0;
    bool ok = ReadFile(file, text, static_cast<DWORD>(size.QuadPart), &read,
                       nullptr) != 0;
    CloseHandle(file);
    if (ok) {
        text[read] = '\0';
        ok = strstr(text, wanted_hex) != nullptr;
    }
    free(text);
    return ok;
}

typedef int (*RuntimeEntryFn)(const char* framework_dir, const char* bindings_path,
                             const char* build_key);

DWORD WINAPI BootstrapThread(LPVOID) {
    // Let the process get past its own startup before touching anything. The
    // runtime needs the engine far enough along to have a tick source, and
    // racing it buys nothing: a mod that loads a second later is invisible to a
    // player, a mod that loads too early is a crash.
    Sleep(3000);

    char exe[MAX_PATH] = {0};
    if (GetModuleFileNameA(nullptr, exe, MAX_PATH) == 0) {
        Log("could not determine the running executable; staying out of the way");
        return 0;
    }
    Log("bootstrap: exe=%s", exe);

    char digest[65] = {0};
    if (!HashFile(exe, digest, sizeof(digest))) {
        Log("could not fingerprint the executable; the game runs vanilla");
        return 0;
    }
    Log("bootstrap: fingerprint sha256=%s", digest);

    char framework[MAX_PATH] = {0};
    if (!JoinPath(framework, sizeof(framework), g_module_dir, kFrameworkDir)) {
        return 0;
    }
    if (GetFileAttributesA(framework) == INVALID_FILE_ATTRIBUTES) {
        Log("no %s directory beside the game; nothing to load", kFrameworkDir);
        return 0;
    }

    char bindings[MAX_PATH] = {0};
    if (!JoinPath(bindings, sizeof(bindings), framework, kBindingsName)) {
        return 0;
    }
    if (GetFileAttributesA(bindings) == INVALID_FILE_ATTRIBUTES) {
        Log("FAIL CLOSED: no bindings file at %s", bindings);
        return 0;
    }
    if (!BindingsMatch(bindings, digest)) {
        // The single most important refusal in this file.
        Log("FAIL CLOSED: the bindings present do not describe this build "
            "(sha256=%s). The game runs vanilla rather than using bindings "
            "measured against a different executable.", digest);
        return 0;
    }
    Log("bootstrap: bindings match this build");

    char runtime[MAX_PATH] = {0};
    if (!JoinPath(runtime, sizeof(runtime), framework, kRuntimeDll)) {
        return 0;
    }
    HMODULE module = LoadLibraryA(runtime);
    if (module == nullptr) {
        Log("FAIL CLOSED: %s could not be loaded (%lu)", runtime, GetLastError());
        return 0;
    }
    auto entry = reinterpret_cast<RuntimeEntryFn>(
        GetProcAddress(module, "MiseryRuntimeBootstrap"));
    if (entry == nullptr) {
        Log("FAIL CLOSED: the runtime has no MiseryRuntimeBootstrap entry");
        return 0;
    }

    Log("bootstrap: handing over to the runtime");
    int rc = entry(framework, bindings, digest);
    Log("bootstrap: runtime returned %d", rc);
    return 0;
}

}  // namespace

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason != DLL_PROCESS_ATTACH) {
        return TRUE;
    }
    DisableThreadLibraryCalls(module);

    GetModuleFileNameA(module, g_module_dir, MAX_PATH);
    char* slash = strrchr(g_module_dir, '\\');
    if (slash != nullptr) {
        *slash = '\0';
    }
    _snprintf_s(g_log_path, sizeof(g_log_path), _TRUNCATE, "%s\\%s\\%s",
                g_module_dir, kFrameworkDir, kLogName);

    // Bind the real dwmapi FIRST. Until this succeeds every exported thunk is a
    // jump through a null pointer, and the game calls four of them.
    char system_dll[MAX_PATH] = {0};
    UINT length = GetSystemDirectoryA(system_dll, MAX_PATH);
    if (length == 0 || length >= MAX_PATH - 16) {
        return FALSE;
    }
    strcat_s(system_dll, MAX_PATH, "\\dwmapi.dll");
    HMODULE real = LoadLibraryA(system_dll);
    if (!MiseryBindReal(real)) {
        // Refusing to load is correct: a proxy that cannot forward would break
        // the game, and breaking the game is worse than not modding it.
        return FALSE;
    }

    // Everything else happens off the loader lock.
    HANDLE thread = CreateThread(nullptr, 0, &BootstrapThread, nullptr, 0, nullptr);
    if (thread != nullptr) {
        CloseHandle(thread);
    }
    return TRUE;
}
