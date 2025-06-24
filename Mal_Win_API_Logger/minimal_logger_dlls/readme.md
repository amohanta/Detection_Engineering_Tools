🛠️ LummaStealer Analysis Support

This tool is especially useful when analyzing LummaStealer, a known info-stealer that frequently invokes API calls like Sleep and CreateMutex. These behaviors are often used to:

    Evade sandbox detection

    Flood sandbox logs with noise

    Slow down analysis with large delays

📦 What's Included

The provided DLLs:

    ⏩ Accelerate Sleep
    Hooks and accelerates Sleep calls without logging them, reducing wait time during dynamic analysis.

    🚫 Suppress noisy logs
    Disables logging for:

        CreateMutex

        GetProcAddress

        LoadLibrary
        These are called excessively by Lumma and can generate huge log files, reducing visibility of more relevant activity.

