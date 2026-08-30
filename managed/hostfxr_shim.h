// hostfxr_shim.h -- starting CoreCLR from native code, in one place.
//
// Shared by the off-game harness and the in-game runtime, because the ONLY
// difference between them should be which items backend is installed. If the
// hosting code were duplicated, the harness would stop being evidence about the
// thing that actually ships.
//
// THE SEQUENCE, AND WHY EACH STEP IS THERE
// ----------------------------------------
//   1. nethost::get_hostfxr_path   -- find hostfxr without hardcoding a version
//   2. hostfxr_initialize_for_runtime_config  -- start a runtime described by
//      the host assembly's own .runtimeconfig.json, so the framework version is
//      the managed project's decision rather than this file's
//   3. get_runtime_delegate(load_assembly_and_get_function_pointer)
//   4. load Misery.ModHost and take a pointer to its UnmanagedCallersOnly entry
//
// Errors are returned, never thrown: this is called from a DLL loaded into a
// shipping game, where an uncaught exception is a crash rather than a message.
#pragma once

#include <windows.h>

#include <string>

#include "../runtime/MiseryRuntime/Public/MiseryBridge.h"

// Minimal hostfxr/coreclr declarations. Taken from the public headers rather
// than including them, so this compiles with only the import library present.
extern "C" {
typedef int32_t(__stdcall* get_hostfxr_path_fn)(wchar_t* buffer,
                                                size_t* buffer_size,
                                                const void* parameters);

typedef void* hostfxr_handle;
typedef int32_t(__cdecl* hostfxr_initialize_for_runtime_config_fn)(
    const wchar_t* runtime_config_path, const void* parameters,
    hostfxr_handle* host_context_handle);
typedef int32_t(__cdecl* hostfxr_get_runtime_delegate_fn)(
    hostfxr_handle host_context_handle, int32_t type, void** delegate);
typedef int32_t(__cdecl* hostfxr_close_fn)(hostfxr_handle host_context_handle);

typedef int32_t(__cdecl* load_assembly_and_get_function_pointer_fn)(
    const wchar_t* assembly_path, const wchar_t* type_name,
    const wchar_t* method_name, const wchar_t* delegate_type_name,
    void* reserved, void** delegate);
}

// hdt_load_assembly_and_get_function_pointer
static const int32_t kHdtLoadAssemblyAndGetFunctionPointer = 5;
// Passed as delegate_type_name for an [UnmanagedCallersOnly] method.
#define MISERY_UNMANAGED_CALLERS_ONLY ((const wchar_t*)-1)

class MiseryHost {
 public:
  typedef int(__cdecl* BootstrapFn)(const void* root, uint64_t host_handle,
                                    const char* args, int args_length);
  typedef int(__cdecl* FetchReportFn)(char* buffer, int capacity);

  bool Start(const std::string& host_assembly_path, std::string* error) {
    std::wstring assembly = Widen(host_assembly_path);
    std::wstring config = assembly;
    size_t dot = config.find_last_of(L'.');
    if (dot == std::wstring::npos) {
      *error = "the host assembly path has no extension";
      return false;
    }
    config = config.substr(0, dot) + L".runtimeconfig.json";

    HMODULE nethost = LoadLibraryA("nethost.dll");
    if (nethost == nullptr) {
      *error = "nethost.dll could not be loaded; it must sit beside the runtime";
      return false;
    }
    auto get_path = reinterpret_cast<get_hostfxr_path_fn>(
        GetProcAddress(nethost, "get_hostfxr_path"));
    if (get_path == nullptr) {
      *error = "nethost.dll has no get_hostfxr_path";
      return false;
    }

    wchar_t buffer[1024];
    size_t size = 1024;
    if (get_path(buffer, &size, nullptr) != 0) {
      *error = "get_hostfxr_path failed; no .NET runtime is installed";
      return false;
    }

    HMODULE fxr = LoadLibraryW(buffer);
    if (fxr == nullptr) {
      *error = "hostfxr could not be loaded";
      return false;
    }

    auto initialize = reinterpret_cast<hostfxr_initialize_for_runtime_config_fn>(
        GetProcAddress(fxr, "hostfxr_initialize_for_runtime_config"));
    auto get_delegate = reinterpret_cast<hostfxr_get_runtime_delegate_fn>(
        GetProcAddress(fxr, "hostfxr_get_runtime_delegate"));
    close_ = reinterpret_cast<hostfxr_close_fn>(
        GetProcAddress(fxr, "hostfxr_close"));
    if (initialize == nullptr || get_delegate == nullptr) {
      *error = "hostfxr is missing its initialisation exports";
      return false;
    }

    int32_t rc = initialize(config.c_str(), nullptr, &context_);
    // Success codes: 0, or Success_HostAlreadyInitialized/DifferentConfig.
    if ((rc != 0 && rc != 1 && rc != 2) || context_ == nullptr) {
      *error = "hostfxr_initialize_for_runtime_config failed (0x" +
               ToHex(static_cast<uint32_t>(rc)) + ") for " +
               Narrow(config);
      return false;
    }

    void* raw = nullptr;
    rc = get_delegate(context_, kHdtLoadAssemblyAndGetFunctionPointer, &raw);
    if (rc != 0 || raw == nullptr) {
      *error = "hostfxr_get_runtime_delegate failed (0x" +
               ToHex(static_cast<uint32_t>(rc)) + ")";
      return false;
    }
    load_assembly_ =
        reinterpret_cast<load_assembly_and_get_function_pointer_fn>(raw);

    if (!Bind(assembly, L"Misery.ModHost.HostEntry, Misery.ModHost",
              L"Bootstrap", reinterpret_cast<void**>(&bootstrap_), error) ||
        !Bind(assembly, L"Misery.ModHost.HostEntry, Misery.ModHost",
              L"FetchReport", reinterpret_cast<void**>(&fetch_), error)) {
      return false;
    }
    return true;
  }

  int Bootstrap(const MbRoot* root, MbHandle host_handle,
                const std::string& args) {
    if (bootstrap_ == nullptr) {
      return -1;
    }
    return bootstrap_(root, host_handle, args.c_str(),
                      static_cast<int>(args.size()));
  }

  std::string FetchReport() {
    if (fetch_ == nullptr) {
      return "{}";
    }
    int needed = fetch_(nullptr, 0);
    if (needed <= 0) {
      return "{}";
    }
    std::string buffer(static_cast<size_t>(needed) + 1, '\0');
    int written = fetch_(&buffer[0], needed + 1);
    buffer.resize(written > 0 ? static_cast<size_t>(written) : 0);
    return buffer;
  }

  ~MiseryHost() {
    // Deliberately NOT closing the host context. Inside MISERY this object's
    // lifetime is the process, and closing a runtime the game is still using
    // would be worse than leaking a handle at exit.
  }

 private:
  bool Bind(const std::wstring& assembly, const wchar_t* type,
            const wchar_t* method, void** out, std::string* error) {
    int32_t rc = load_assembly_(assembly.c_str(), type, method,
                                MISERY_UNMANAGED_CALLERS_ONLY, nullptr, out);
    if (rc != 0 || *out == nullptr) {
      *error = "could not bind " + Narrow(method) + " (0x" +
               ToHex(static_cast<uint32_t>(rc)) + ")";
      return false;
    }
    return true;
  }

  static std::wstring Widen(const std::string& text) {
    int needed = MultiByteToWideChar(CP_UTF8, 0, text.c_str(),
                                     static_cast<int>(text.size()), nullptr, 0);
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                        &out[0], needed);
    return out;
  }

  static std::string Narrow(const std::wstring& text) {
    int needed = WideCharToMultiByte(CP_UTF8, 0, text.c_str(),
                                     static_cast<int>(text.size()), nullptr, 0,
                                     nullptr, nullptr);
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                        &out[0], needed, nullptr, nullptr);
    return out;
  }

  static std::string ToHex(uint32_t value) {
    char buffer[16];
    sprintf_s(buffer, "%08x", value);
    return buffer;
  }

  hostfxr_handle context_ = nullptr;
  hostfxr_close_fn close_ = nullptr;
  load_assembly_and_get_function_pointer_fn load_assembly_ = nullptr;
  BootstrapFn bootstrap_ = nullptr;
  FetchReportFn fetch_ = nullptr;
};
