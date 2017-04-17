module qiditu.wrapper;

import core.sys.windows.psapi;
import core.sys.windows.winbase;
import core.sys.windows.windef;
import core.sys.windows.winuser;
import std.conv;
import std.stdio;
import std.string;
import std.traits;
import std.utf;

version (X86)
{
    pragma(lib, "public\\x86\\MinHook.lib");
}
else
{
    version (X86_64)
    {
        pragma(lib, "public\\x64\\MinHook.lib");
    }
    else
    {
        static assert(false, "MinHook supports only x86 and x64 systems.");
    }
}

pragma(lib, "Psapi");

/// MinHook Error Codes.
enum MH_STATUS
{
    /// Unknown error. Should not be returned.
    MH_UNKNOWN = -1,

    /// Successful.
    MH_OK,

    /// MinHook is already initialized.
    MH_ERROR_ALREADY_INITIALIZED,

    /// MinHook is not initialized yet, or already uninitialized.
    MH_ERROR_NOT_INITIALIZED,

    /// The hook for the specified target function is already created.
    MH_ERROR_ALREADY_CREATED,

    /// The hook for the specified target function is not created yet.
    MH_ERROR_NOT_CREATED,

    /// The hook for the specified target function is already enabled.
    MH_ERROR_ENABLED,

    /// The hook for the specified target function is not enabled yet, or already
    /// disabled.
    MH_ERROR_DISABLED,

    /// The specified pointer is invalid. It points the address of non-allocated
    /// and/or non-executable region.
    MH_ERROR_NOT_EXECUTABLE,

    /// The specified target function cannot be hooked.
    MH_ERROR_UNSUPPORTED_FUNCTION,

    /// Failed to allocate memory.
    MH_ERROR_MEMORY_ALLOC,

    /// Failed to change the memory protection.
    MH_ERROR_MEMORY_PROTECT,

    /// The specified module is not loaded.
    MH_ERROR_MODULE_NOT_FOUND,

    /// The specified function is not found.
    MH_ERROR_FUNCTION_NOT_FOUND
}

extern (Windows) @system
{
    /**
     *  Initialize the MinHook library. You must call this function EXACTLY ONCE
     *  at the beginning of your program.
     *
     *  Returns: status
     */
    MH_STATUS MH_Initialize();

    /**
     *  Uninitialize the MinHook library. You must call this function EXACTLY
     *  ONCE at the end of your program.
     *
     *  Returns: status
     */
    MH_STATUS MH_Uninitialize();

    /**
     *  Enables an already created hook.
     *  Params:
     *      target = Target function pointer. If this parameter is null,
     *               all created hooks are enabled in one go.
     *
     *
     *  Returns: status
     */
    MH_STATUS MH_EnableHook(void* pTarget);

    /**
     *  Disables an already created hook.
     *  Params:
     *      target = Target function pointer. If this parameter is null,
     *               all created hooks are disabled in one go.
     *
     *
     *  Returns: status
     */
    MH_STATUS MH_DisableHook(void* pTarget);

    /**
     *  Creates a Hook for the specified target function, in disabled state.
     *  Params:
     *      pTarget = Target function pointer, which will be overridden by the
     *                detour function.
     *      pDetour = Detour function pointer, which will override the target
     *                function.
     *      ppOriginal = A trampoline function variant pointer, which will be
     *                   set the function variant to the original target
     *                   function. This parameter could be null.
     *  Returns: status
     */
    MH_STATUS MH_CreateHook(void* pTarget, void* pDetour, void** ppOriginal);

    /**
     *  Creates a Hook for the specified API function, in disabled state.
     *  Params:
     *      pszModule = Loaded module name which contains the target function.
     *      pszProcName = Target function name, which will be overridden by the
     *                    detour function.
     *      pDetour = Detour function pointer, which will override the target
     *                function.
     *      ppOriginal = A trampoline function variant pointer, which will be
     *                   set the function variant to the original target
     *                   function. This parameter could be null.
     *  Returns: status
     */
    MH_STATUS MH_CreateHookApi(const(wchar)* pszModule,
            const(char)* pszProcName, void* pDetour, void** ppOriginal);

    /**
     *  Creates a Hook for the specified API function, in disabled state.
     *  Params:
     *      pszModule = Loaded module name which contains the target function.
     *      pszProcName = Target function name, which will be overridden by the
     *                    detour function.
     *      pDetour = Detour function pointer, which will override the target
     *                function.
     *      ppOriginal = A trampoline function variant pointer, which will be
     *                   set the function variant to the original target
     *                   function. This parameter coudle be null.
     *      ppTarget = A target function variant pointer, which will be set the
     *                 function variant to the other functions. This parameter
     *                 could be null.
     *  Returns: status
     */
    MH_STATUS MH_CreateHookApiEx(const(wchar)* pszModule,
            const(char)* pszProcName, void* pDetour, void* ppOriginal, void* ppTarget);

    /**
     *  Removes an already created hook.
     *  Params:
     *      pTarget = A pointer to the target function.
     *  Returns: status
     */
    MH_STATUS MH_RemoveHook(void* pTarget);

    /**
     *  Queues to enable an already created hook.
     *  Params:
     *      pTarget = Target function pointer. If this parameter is null,
     *                all created hooks are queued to be enabled.
     *  Returns: status
     */
    MH_STATUS MH_QueueEnableHook(void* pTarget);

    /**
     *  Queues to disable an already created hook.
     *  Params:
     *      pTarget = Target function pointer. If this parameter is null,
     *                all created hooks are queued to be disable.
     *  Returns: status
     */
    MH_STATUS MH_QueueDisableHook(void* pTarget);

    /**
     *  Applies all queued changes in one go.
     *  Returns: status
     */
    MH_STATUS MH_ApplyQueued();

    /**
     *  Translates the MH_STATUS to its name as a string.
     *  Params:
     *      status = status;
     *  Returns: status name
     */
    const(char)* MH_StatusToString(MH_STATUS status);
}

class MinHookException : Exception
{
public:
    this(MH_STATUS status = MH_STATUS.MH_UNKNOWN)
    {
        super(to!string(status));
        this.status = status;
    }

    this(string message, Throwable next = null)
    {
        super(message, next);
    }

    MH_STATUS status() @property
    {
        return _status;
    }

    private MH_STATUS _status;
    private void status(MH_STATUS status) @property
    {
        _status = status;
    }
}

class AlreadyInitializedException : MinHookException
{
public:
    this(string message = "MinHook is already initialized.", Throwable next = null)
    {
        super(message, next);
    }

    override MH_STATUS status() @property
    {
        return MH_STATUS.MH_ERROR_ALREADY_INITIALIZED;
    }
}

class NotInitializedException : MinHookException
{
public:
    this(string message = "MinHook is not initialized yet, or already uninitialized.",
            Throwable next = null)
    {
        super(message, next);
    }

    override MH_STATUS status() @property
    {
        return MH_STATUS.MH_ERROR_NOT_INITIALIZED;
    }
}

class AleradyCreatedException : MinHookException
{
public:
    this(string message = "The hook for the specified target function is already created.",
            Throwable next = null)
    {
        super(message, next);
    }

    override MH_STATUS status() @property
    {
        return MH_STATUS.MH_ERROR_ALREADY_CREATED;
    }
}

class TargetNotCreatedException : MinHookException
{
public:
    this(string message = "The hook for the specified target function is not created yet.",
            Throwable next = null)
    {
        super(message, next);
    }

    override MH_STATUS status() @property
    {
        return MH_STATUS.MH_ERROR_NOT_CREATED;
    }
}

class EnabledException : MinHookException
{
public:
    this(string message = "The hook for the specified target function is already enabled.",
            Throwable next = null)
    {
        super(message, next);
    }

    override MH_STATUS status() @property
    {
        return MH_STATUS.MH_ERROR_ENABLED;
    }
}

class DisabledException : MinHookException
{
public:
    this(string message = "The hook for the specified target function is not"
            ~ " enabled yet, or already disabled.", Throwable next = null)
    {
        super(message, next);
    }

    override MH_STATUS status() @property
    {
        return MH_STATUS.MH_ERROR_DISABLED;
    }
}

class NotExecutableException : MinHookException
{
public:
    this(string message = "The specified pointer is invalid. It points the address"
            ~ " of non-allocated  and/or non-executable region.", Throwable next = null)
    {
        super(message, next);
    }

    override MH_STATUS status() @property
    {
        return MH_STATUS.MH_ERROR_NOT_EXECUTABLE;
    }
}

class UnsupportedFunctionException : MinHookException
{
public:
    this(string message = "The specified target function cannot be hooked.", Throwable next = null)
    {
        super(message, next);
    }

    override MH_STATUS status() @property
    {
        return MH_STATUS.MH_ERROR_UNSUPPORTED_FUNCTION;
    }
}

class MemoryAllocException : MinHookException
{
public:
    this(string message = "Failed to allocate memory.", Throwable next = null)
    {
        super(message, next);
    }

    override MH_STATUS status() @property
    {
        return MH_STATUS.MH_ERROR_MEMORY_ALLOC;
    }
}

class MemoryProtectException : MinHookException
{
public:
    this(string message = "Failed to change the memory protection.", Throwable next = null)
    {
        super(message, next);
    }

    override MH_STATUS status() @property
    {
        return MH_STATUS.MH_ERROR_MEMORY_PROTECT;
    }
}

class ModuleNotFoundException : MinHookException
{
public:
    this(string message = "The specified module is not loaded.", Throwable next = null)
    {
        super(message, next);
    }

    override MH_STATUS status() @property
    {
        return MH_STATUS.MH_ERROR_MODULE_NOT_FOUND;
    }
}

class FunctionNotFoundException : MinHookException
{
public:
    this(string message = "The specified function is not found.", Throwable next = null)
    {
        super(message, next);
    }

    override MH_STATUS status() @property
    {
        return MH_STATUS.MH_ERROR_FUNCTION_NOT_FOUND;
    }
}

@trusted class MinHookHelper
{

    /**
     *  Initialize the MinHook library. You must call this function EXACTLY ONCE
     *  at the beginning of your program.
     *  Throws: MinHookException include all subclass.
     */
    public static void initialize()
    {
        MH_STATUS status = MH_Initialize();
        if (status != MH_STATUS.MH_OK)
        {
            throw getExceptionByStatu(status);
        }
    }

    /**
     *  Uninitialize the MinHook library. You must call this function EXACTLY
     *  ONCE at the end of your program.
     *  Throws: MinHookException include all subclass.
     */
    public static void uninitialize()
    {
        MH_STATUS status = MH_Uninitialize();
        if (status != MH_STATUS.MH_OK)
        {
            throw getExceptionByStatu(status);
        }
    }

    /**
     *  Enables an already created hook.
     *  Params:
     *      moduleName = Loaded module name which contains the target function.
     *      procName = Target function name.
     *  Throws: FunctionNotFoundException.
     *          ModuleNotFoundException.
     *          MinHookException include all subclass.
     */
    public static void enableHook(string moduleName, string procName)
    {
        auto address = getProcAddress(moduleName, procName);
        MH_STATUS status = MH_EnableHook(address);
        if (status != MH_STATUS.MH_OK)
        {
            throw getExceptionByStatu(status);
        }
    }

    /**
     *  Enable all created hooks in one go.
     *  Throws: MinHookException include all subclass.
     */
    public static void enableAllHook()
    {
        MH_STATUS status = MH_EnableHook(null);
        if (status != MH_STATUS.MH_OK)
        {
            throw getExceptionByStatu(status);
        }
    }

    /**
     *  Disables an already created hook.
     *  Params:
     *      moduleName = Loaded module name which contains the target function.
     *      procName = Target function name.
     *  Throws: FunctionNotFoundException.
     *          ModuleNotFoundException.
     *          MinHookException include all subclass.
     */
    public static void disableHook(string moduleName, string procName)
    {
        auto address = getProcAddress(moduleName, procName);
        MH_STATUS status = MH_DisableHook(address);
        if (status != MH_STATUS.MH_OK)
        {
            throw getExceptionByStatu(status);
        }
    }

    /**
     *  Disable all created hooks in one go.
     *  Throws: MinHookException include all subclass.
     */
    public static void disnableAllHook()
    {
        MH_STATUS status = MH_DisableHook(null);
        if (status != MH_STATUS.MH_OK)
        {
            throw getExceptionByStatu(status);
        }
    }

    /**
     *  Creates a Hook for the specified target function, in disabled state.
     *  Params:
     *      target = Target function pointer, which will be overridden by the
     *               detour function.
     *      detour = Detour function, which will override the target function.
     *  Throws: MinHookException include all subclass.
     */
    public static void createHook(F)(void* target, F detour) if (isCallable!(F))
    {
        MH_STATUS status = MH_CreateHook(target, cast(void*) detour, null);
        if (status != MH_STATUS.MH_OK)
        {
            throw getExceptionByStatu(status);
        }
    }

    /**
     *  Creates a Hook for the specified target function, in disabled state.
     *  Params:
     *      target = Target function pointer, which will be overridden by the
     *               detour function.
     *      detour = Detour function, which will override the target function.
     *      original = Trampoline function, which will be used to call the original
     *                 target function.
     *  Throws: MinHookException include all subclass.
     */
    public static void createHook(F)(void* target, F detour, out F original)
            if (isCallable!(F))
    {
        F ptr = null;
        MH_STATUS status = MH_CreateHook(target, cast(void*) detour, cast(void**)&ptr);
        if (status != MH_STATUS.MH_OK)
        {
            throw getExceptionByStatu(status);
        }
        original = ptr1;
    }

    /**
     *  Creates a Hook for the specified API function, in disabled state.
     *  Params:
     *      moduleName = Loaded module name which contains the target function.
     *      procName = Target function name.
     *      detour = Detour function, which will override the target function.
     *  Throws: MinHookException include all subclass.
     */
    public static void createHookApi(F)(wstring moduleName, string procName, F detour)
            if (isCallable!(F))
    {
        MH_STATUS status = MH_CreateHookApi(moduleName.ptr, procName.ptr,
                cast(void*) detour, null);
        if (status != MH_STATUS.MH_OK)
        {
            throw getExceptionByStatu(status);
        }
    }

    /**
     *  Creates a Hook for the specified API function, in disabled state.
     *  Params:
     *      moduleName = Loaded module name which contains the target function.
     *      procName = Target function name.
     *      detour = Detour function, which will override the target function.
     *      original = Trampoline function, which will be used to call the original
     *                 target function.
     *  Throws: MinHookException include all subclass.
     */
    public static void createHookApi(F)(wstring moduleName, string procName, F detour, out F original)
            if (isCallable!(F))
    {
        F ptr = null;
        MH_STATUS status = MH_CreateHookApi(moduleName.ptr, procName.ptr,
                cast(void*) detour, cast(void**)&ptr);
        if (status != MH_STATUS.MH_OK)
        {
            throw getExceptionByStatu(status);
        }
        original = ptr;
    }

    /**
     *  Creates a Hook for the specified API function, in disabled state.
     *  Params:
     *      moduleName = Loaded module name which contains the target function.
     *      procName = Target function name. which will be overridden by the detour
     *                 function.
     *      detour = Detour function, which will override the target function.
     *      target = Target function, which will be used with other functions.
     *  Throws: MinHookException include all subclass.
     */
    public static void createHookApiEx(F)(wstring moduleName, string procName, F detour, out F target)
            if (isCallable!(F))
    {
        F ptr = null;
        MH_STATUS status = MH_CreateHookApiEx(moduleName.ptr, procName.ptr,
                cast(void*) detour, null, cast(void**)&ptr);
        if (status != MH_STATUS.MH_OK)
        {
            throw getExceptionByStatu(status);
        }
        target = ptr;
    }

    /**
     *  Creates a Hook for the specified API function, in disabled state.
     *  Params:
     *      moduleName = Loaded module name which contains the target function.
     *      procName = Target function name. which will be overridden by the detour
     *                 function.
     *      detour = Detour function, which will override the target function.
     *      original = Trampoline function, which will be used to call the original
     *                 target function.
     *      target = Target function, which will be used with other functions.
     *  Throws: MinHookException include all subclass.
     */
    public static void createHookApiEx(F)(wstring moduleName, string procName,
            F detour, out F original, out F target) if (isCallable!(F))
    {
        F ptr1 = null;
        F ptr2 = null;
        MH_STATUS status = MH_CreateHookApiEx(moduleName.ptr, procName.ptr,
                cast(void*) detour, cast(void**)&ptr1, cast(void**)&ptr2);
        if (status != MH_STATUS.MH_OK)
        {
            throw getExceptionByStatu(status);
        }
        original = ptr1;
        target = ptr2;
    }

    /**
     *  Queues to enable an already created hook.
     *  Params:
     *      moduleName = Loaded module name which contains the target function.
     *      procName = Target function name.
     *  Throws: FunctionNotFoundException.
     *          ModuleNotFoundException.
     *          MinHookException include all subclass.
     */
    public static void queueEnableHook(string moduleName, string procName)
    {
        auto address = getProcAddress(moduleName, procName);
        MH_STATUS status = MH_QueueEnableHook(address);
        if (status != MH_STATUS.MH_OK)
        {
            throw getExceptionByStatu(status);
        }
    }

    /**
     *  Queues to enable an already all created hook.
     *  Throws: MinHookException include all subclass.
     */
    public static void queueEnableAllHook()
    {
        MH_STATUS status = MH_QueueEnableHook(null);
        if (status != MH_STATUS.MH_OK)
        {
            throw getExceptionByStatu(status);
        }
    }

    /**
     *  Queues to disable an already created hook.
     *  Params:
     *      moduleName = Loaded module name which contains the target function.
     *      procName = Target function name.
     *  Throws: FunctionNotFoundException.
     *          ModuleNotFoundException.
     *          MinHookException include all subclass.
     */
    public static void queueDisableHook(string moduleName, string procName)
    {
        auto address = getProcAddress(moduleName, procName);
        MH_STATUS status = MH_QueueDisableHook(address);
        if (status != MH_STATUS.MH_OK)
        {
            throw getExceptionByStatu(status);
        }
    }

    /**
     *  Queues to disable an already all created hook.
     *  Throws: MinHookException include all subclass.
     */
    public static void queueDisableAllHook()
    {
        MH_STATUS status = MH_QueueDisableHook(null);
        if (status != MH_STATUS.MH_OK)
        {
            throw getExceptionByStatu(status);
        }
    }

    /**
     *  Removes an already created hook.
     *  Params:
     *      moduleName = Loaded module name which contains the target function.
     *      procName = Target function name.
     *  Throws: FunctionNotFoundException.
     *          ModuleNotFoundException.
     *          MinHookException include all subclass.
     */
    public static void removeHook(string moduleName, string procName)
    {
        auto address = getProcAddress(moduleName, procName);
        MH_STATUS status = MH_RemoveHook(address);
        if (status != MH_STATUS.MH_OK)
        {
            throw getExceptionByStatu(status);
        }
    }

    /**
     *  Get module pointer by name.
     *  Params:
     *      moduleName = module name.
     *  Throws: ModuleNotFoundException.
     *  Returns: module pointer;
     */
    public static void* getMoudle(string moduleName)
    {
        if (!endsWith(moduleName, ".dll"))
        {
            moduleName ~= ".dll";
        }
        HANDLE handle = GetCurrentProcess();
        scope (exit)
            CloseHandle(handle);
        void*[] modules = new void*[1024];
        uint cbNeeded;
        if (!EnumProcessModules(handle, modules.ptr, cast(uint)(modules.length), &cbNeeded))
        {
            throw new ModuleNotFoundException();
        }
        modules.length = (cbNeeded / (void*).sizeof);
        wchar[1024] name;
        foreach (modulePtr; modules)
        {
            if (!GetModuleFileNameEx(handle, modulePtr, name.ptr, name.length))
            {
                continue;
            }
            string fullPath = to!string(toLower(name[0 .. indexOf(name, '\0')]));
            string baseName = fullPath[lastIndexOf(fullPath, '\\') + 1 .. $];
            if (baseName == moduleName)
            {
                return modulePtr;
            }
        }
        throw new ModuleNotFoundException();
    }

    /**
     *  Get function pointer by name.
     *  Params:
     *      moduleName = module pointer.
     *      procName = function name.
     *  Throws: FunctionNotFoundException.
     *  Returns: function pointer;
     */
    public static void* getProcAddress(void* modulePtr, string procName)
    {
        void* proc = GetProcAddress(modulePtr, procName.ptr);
        if (proc == null)
        {
            throw new FunctionNotFoundException();
        }
        return proc;
    }

    /**
     *  Get function pointer by name.
     *  Params:
     *      moduleName = module name.
     *      procName = function name.
     *  Throws: FunctionNotFoundException.
     *          ModuleNotFoundException.
     *  Returns: function pointer;
     */
    public static void* getProcAddress(string moduleName, string procName)
    {
        return getProcAddress(getMoudle(moduleName), procName);
    }

    /**
     *  Convert minhook status to exception.
     *  Params:
     *      status = MinHook exception status.
     *  Returns: MinHookException.
     */
    private static MinHookException getExceptionByStatu(MH_STATUS status)
    {
        switch (status)
        {
        case MH_STATUS.MH_ERROR_ALREADY_CREATED:
            {
                return new AleradyCreatedException();
            }
        case MH_STATUS.MH_ERROR_ALREADY_INITIALIZED:
            {
                return new AlreadyInitializedException();
            }
        case MH_STATUS.MH_ERROR_DISABLED:
            {
                return new DisabledException();
            }
        case MH_STATUS.MH_ERROR_ENABLED:
            {
                return new EnabledException();
            }
        case MH_STATUS.MH_ERROR_FUNCTION_NOT_FOUND:
            {
                return new FunctionNotFoundException();
            }
        case MH_STATUS.MH_ERROR_MEMORY_ALLOC:
            {
                return new MemoryAllocException();
            }
        case MH_STATUS.MH_ERROR_MEMORY_PROTECT:
            {
                return new MemoryProtectException();
            }
        case MH_STATUS.MH_ERROR_MODULE_NOT_FOUND:
            {
                return new ModuleNotFoundException();
            }
        case MH_STATUS.MH_ERROR_NOT_CREATED:
            {
                return new TargetNotCreatedException();
            }
        case MH_STATUS.MH_ERROR_NOT_EXECUTABLE:
            {
                return new NotExecutableException();
            }
        case MH_STATUS.MH_ERROR_NOT_INITIALIZED:
            {
                return new NotInitializedException();
            }
        case MH_STATUS.MH_ERROR_UNSUPPORTED_FUNCTION:
            {
                return new UnsupportedFunctionException();
            }
        default:
            {
                return new MinHookException(status);
            }
        }
    }
}

unittest
{
    static extern (Windows) int function(HWND, const(wchar)*, const(wchar)*, uint) fpMessageBoxW = null;

    extern (Windows) int detourMessageBoxW(HWND hwnd, const(wchar)* lpText,
            const(wchar)* lpCaption, uint uType)
    {
        return fpMessageBoxW(hwnd, "Hooked!"w.ptr, lpCaption, uType);
    }

    // Initialize MinHook.
    MinHookHelper.initialize();

    // Create a hook for MessageBoxW, in disabled state.
    MinHookHelper.createHookApi("user32"w, "MessageBoxW", &detourMessageBoxW, fpMessageBoxW);

    // Enable the hook for MessageBoxW.
    MinHookHelper.enableHook("user32", "MessageBoxW");

    // Expected to tell "Hooked!".
    MessageBoxW(null, "Not hooked..."w.ptr, "MinHook Sample"w.ptr, MB_OK);

    // Disable the hook for MessageBoxW.
    MinHookHelper.disableHook("user32", "MessageBoxW");

    // Expected to tell "Hooked!".
    MessageBoxW(null, "Not hooked..."w.ptr, "MinHook Sample"w.ptr, MB_OK);

    // Uninitialize MinHook.
    MinHookHelper.uninitialize();

}
