# VT 框架技术分析与开发规划

## 文档概述

本文档旨在对现有的基于 Intel VT-x 的 Hypervisor 框架进行全面的技术剖析，并为后续的功能扩展（包括 Ring 3 EPT Hook 和高级隐蔽 Hook）提供详细的设计与实现规划。

---

## 第一部分：VT 框架核心技术分析

### 1.1 虚拟化生命周期

#### 1.1.1 环境检测与初始化

```mermaid
flowchart TD
    A[driver_entry] --> B[hv::start]
    B --> C{检测 VMX 支持}
    C -->|不支持| D[返回失败]
    C -->|支持| E[create 初始化]
    E --> F[分配 VCPU 数组]
    F --> G[find_offsets<br/>定位内核结构]
    G --> H[prepare_host_page_tables<br/>准备 Host 页表]
    H --> I[逐核虚拟化循环]
    I --> J[KeSetSystemAffinityThreadEx<br/>绑定到目标 CPU]
    J --> K[virtualize_cpu]
    K --> L[cache_cpu_data<br/>缓存 CPU 信息]
    L --> M[enable_vmx_operation<br/>设置 CR4.VMXE]
    M --> N[enter_vmx_operation<br/>执行 VMXON]
    N --> O[load_vmcs_pointer<br/>VMCLEAR & VMPTRLD]
    O --> P[prepare_external_structures<br/>初始化 EPT/GDT/IDT]
    P --> Q[write_vmcs_fields<br/>填充 VMCS]
    Q --> R[vm_launch<br/>执行 VMLAUNCH]
    R --> S{成功?}
    S -->|是| T[虚拟化完成]
    S -->|否| U[VMXOFF<br/>返回失败]
    I --> V{所有核心完成?}
    V -->|否| J
    V -->|是| W[安装 EPT Hooks]
    W --> X[返回成功]
```

- **检测**: 流程始于 `virtualize_cpu` -> `cache_cpu_data`。
  1. 通过 `__cpuid` 指令检查 CPU 是否支持 VMX（`CPUID.01H:ECX.5[VME] = 1`）。
  2. 读取 `IA32_FEATURE_CONTROL` MSR，确保 VMX 在 BIOS/UEFI 中未被锁定禁用。
- **初始化**:
  1. **启用 VMX**: `enable_vmx_operation` 函数设置 `CR4.VMXE` 位，并根据 `IA32_VMX_CR0/CR4_FIXED0/1` MSRs 的要求修正 CR0 和 CR4 的保留位，以满足 VMX 的硬件要求。
  2. **进入 VMX**: `enter_vmx_operation` 函数分配 `VMXON` 区域，并执行 `VMXON` 指令，使处理器进入 VMX root-operation 模式。
  3. **VCPU 虚拟化**: `hv::start()` 函数遍历所有 CPU 核心，通过 `KeSetSystemAffinityThreadEx` 将初始化线程绑定到每个核心上，并逐一调用 `virtualize_cpu()` 对其进行虚拟化。
  4. **执行 VMLAUNCH**: `virtualize_cpu()` 的最后一步是调用 `vm_launch`（位于 `vm-launch.asm`），执行 `VMLAUNCH` 指令。一旦成功，CPU 即在 Guest 模式下运行，Hypervisor 初始化完成。

#### 1.1.2 卸载流程

```mermaid
flowchart TD
    A[driver_unload] --> B[卸载 EPT Hooks]
    B --> C[hv::stop]
    C --> D[逐核卸载循环]
    D --> E[KeSetSystemAffinityThreadEx<br/>绑定到目标 CPU]
    E --> F[VMCALL hypercall_unload]
    F --> G[emulate_vmcall<br/>处理卸载请求]
    G --> H[vcpu->stop_virtualization = true]
    H --> I[skip_instruction]
    I --> J[handle_vm_exit<br/>检测停止标志]
    J --> K[恢复 Guest 状态]
    K --> L[恢复 CR0/CR4]
    L --> M[恢复 DR7]
    M --> N[恢复 MSRs]
    N --> O[恢复 CR3]
    O --> P[恢复 GDT/IDT]
    P --> Q[恢复段寄存器]
    Q --> R[返回 Guest<br/>不执行 VMRESUME]
    R --> S[VMXOFF]
    D --> T{所有核心完成?}
    T -->|否| E
    T -->|是| U[释放 VCPU 内存]
    U --> V[卸载完成]
```

- **发起卸载**: Guest 内核驱动调用 `hv::stop()`。
- **逐核卸载**: 类似于启动过程，通过 `KeSetSystemAffinityThreadEx` 在每个核心上发起 `hypercall_unload` VMCALL。
- **处理卸载**: `emulate_vmcall` 捕捉到该请求，将 `vcpu->stop_virtualization` 标志位置 `true`。
- **恢复现场**: 在下一次 `vm_exit` 的返回路径上 (`handle_vm_exit`)，检测到 `stop_virtualization` 标志，执行完整的现场恢复逻辑（恢复GDT, IDT, CR3, DR7, MSRs 等），并直接返回到 Guest，不再执行 `VMRESUME`。最后执行 `VMXOFF` 退出 VMX 模式。

### 1.2 核心组件深入解析

#### 1.2.1 系统整体架构图

```mermaid
graph TB
    subgraph "Guest Mode (Ring 0-3)"
        G1[Guest OS Kernel]
        G2[Guest Applications]
        G3[Guest Drivers]
    end
    
    subgraph "VMX Root Mode"
        H1[VM-Exit Handler]
        H2[EPT Manager]
        H3[VMCS Manager]
        H4[Hypercall Handler]
        H5[Instruction Emulator]
    end
    
    subgraph "Hardware Layer"
        HW1[CPU with VT-x]
        HW2[EPT Tables]
        HW3[VMCS Region]
        HW4[MSR Bitmap]
    end
    
    G1 -->|VM-Exit| H1
    G2 -->|VMCALL| H4
    G3 -->|Memory Access| H2
    
    H1 --> H5
    H1 --> H3
    H2 --> HW2
    H3 --> HW3
    H4 --> H2
    H5 -->|VMRESUME| G1
    
    HW1 --> HW2
    HW1 --> HW3
    HW1 --> HW4
```

#### 1.2.2 VMCS (Virtual Machine Control Structure)

```mermaid
graph LR
    subgraph "VMCS Structure"
        subgraph "Guest-State Area"
            GS1[CR0/CR3/CR4]
            GS2[RIP/RSP/RFLAGS]
            GS3[Segment Registers]
            GS4[GDTR/IDTR]
            GS5[MSRs]
        end
        
        subgraph "Host-State Area"
            HS1[Host CR0/CR3/CR4]
            HS2[Host RIP/RSP]
            HS3[Host Segment Selectors]
            HS4[Host GDTR/IDTR]
            HS5[Host FS/GS Base]
        end
        
        subgraph "VM-Execution Control"
            EC1[Pin-Based Controls]
            EC2[Primary Proc-Based]
            EC3[Secondary Proc-Based]
            EC4[Exception Bitmap]
            EC5[MSR Bitmap Address]
            EC6[EPT Pointer]
        end
        
        subgraph "VM-Exit Control"
            EX1[Exit Controls]
            EX2[MSR Store/Load]
            EX3[Host Address Space]
        end
        
        subgraph "VM-Entry Control"
            EN1[Entry Controls]
            EN2[MSR Load]
            EN3[Event Injection]
        end
    end
```

VMCS 是 VMX 操作的核心，它精确定义了 Guest 的运行环境以及 Host 的行为。
- **Host-State Area (`write_vmcs_host_fields`)**:
  - `VMCS_HOST_RIP/RSP`: 设置为汇编例程 `vm_exit` 的地址和 Host 栈顶，是所有 VM-Exit 的统一入口。
  - `VMCS_HOST_CR3`: 指向 Hypervisor 自己的页表，确保 VM-Exit 后能切换到正确的地址空间。
  - `VMCS_HOST_FS_BASE`: 指向当前 `vcpu` 结构体地址，这是一个巧妙的设计，使得 Host 代码可以方便地通过 `fs:[0]` 访问当前核心的数据。
- **Guest-State Area (`write_vmcs_guest_fields`)**:
  - 这是一个完整的"现场快照"过程。在 `VMLAUNCH` 之前，将当前 CPU 的所有状态（CR0/3/4, GDT, IDT, CS, SS, RIP, RSP, RFLAGS, MSRs 等）完整地保存到 VMCS 的 Guest 区域。这保证了 Guest 能够从中断的那个点无缝地继续执行。
- **VM-Execution Controls (`write_vmcs_ctrl_fields`)**:
  - 这是 Hypervisor 的"控制面板"，决定了哪些 Guest 事件必须陷入（VM-Exit）到 Hypervisor。
  - **关键设置**:
    - `enable_ept = 1`: **开启 EPT**。这是实现高性能内存虚拟化、也是 EPT Hook 的基础。
    - `use_msr_bitmaps = 1`: 启用 MSR 位图，高效地指定对哪些 MSR 的读写需要拦截。
    - `cr3_load_exiting = 1`: 拦截 `MOV to CR3` 指令，用于追踪 Guest 地址空间切换。
    - `activate_secondary_controls = 1`: 启用 EPT、VPID 等高级功能所必需。

#### 1.2.3 EPT (Extended Page Tables)

```mermaid
graph TD
    subgraph "EPT Page Table Structure"
        PML4[PML4 Table<br/>512 entries]
        PDPT[PDPT Table<br/>512 entries]
        PD[PD Table<br/>512 entries]
        PT[PT Table<br/>512 entries]
        
        PML4 -->|9 bits| PDPT
        PDPT -->|9 bits| PD
        PD -->|9 bits| PT
        PT -->|9 bits| PAGE[4KB Physical Page]
        
        PD -.->|Large Page| LP[2MB Physical Page]
    end
    
    subgraph "Memory Type Calculation"
        MTRR[MTRR Registers]
        MT[calc_mtrr_mem_type]
        EPT_MT[EPT Memory Type]
        
        MTRR --> MT
        MT --> EPT_MT
    end
```

- **构建**: `prepare_ept` 函数构建了覆盖所有物理内存的 1:1 恒等映射（GPA==HPA），并默认使用 2MB 大页进行优化以减少 TLB miss。
- **MTRR 同步**: `enable_mtrr_exiting` 通过设置 MSR Bitmap 拦截所有对 MTRR 相关 MSR 的写操作。当 Guest 修改 MTRR 时，`emulate_wrmsr` 捕获该事件，在允许修改后，立即调用 `update_ept_memory_type` 重新计算 EPT 页表项的内存类型（如 WB、UC），并调用 `vmx_invept` 使缓存失效，从而保持 EPT 与 MTRR 的同步。
- **按需分裂 (`split_ept_pde`)**: EPT Hook 的操作精度是 4KB。当需要在某个 2MB 区域内的一个 4KB 页面上安装 Hook 时，此函数会将一个 2MB 的大页（PDE）"分裂"成 512 个 4KB 的小页（PTE），从而在不牺牲整体性能的前提下，实现精确的 Hook。

#### 1.2.4 VM-Exit 处理流程

```mermaid
flowchart TD
    A[Guest 执行触发 VM-Exit 的操作] --> B[CPU 保存 Guest 状态到 VMCS]
    B --> C[CPU 加载 Host 状态从 VMCS]
    C --> D[跳转到 vm_exit<br/>汇编入口点]
    D --> E[保存额外的 Guest 寄存器]
    E --> F[调用 handle_vm_exit]
    F --> G[读取 VM-Exit Reason]
    G --> H[dispatch_vm_exit]
    
    H --> I{Exit Reason?}
    I -->|CPUID| J[emulate_cpuid]
    I -->|RDMSR| K[emulate_rdmsr]
    I -->|WRMSR| L[emulate_wrmsr]
    I -->|MOV CR| M[handle_mov_cr]
    I -->|EPT Violation| N[handle_ept_violation]
    I -->|VMCALL| O[emulate_vmcall]
    I -->|其他| P[相应处理函数]
    
    J --> Q[更新 Guest 寄存器]
    K --> Q
    L --> Q
    M --> Q
    N --> Q
    O --> Q
    P --> Q
    
    Q --> R[skip_instruction<br/>更新 RIP]
    R --> S[hide_vm_exit_overhead<br/>调整时间戳]
    S --> T{stop_virtualization?}
    T -->|是| U[恢复完整 Guest 状态<br/>返回 Guest]
    T -->|否| V[VMRESUME<br/>继续 Guest 执行]
```

- **统一入口**: 所有 VM-Exit 都从 `vm-exit.asm` 中的 `vm_exit` 开始，保存 Guest 寄存器到栈上。
- **分发**: 汇编代码调用 C++ 函数 `handle_vm_exit`。该函数读取 `VMCS_EXIT_REASON`，并调用 `dispatch_vm_exit` 将控制权分发给具体的模拟函数（如 `emulate_cpuid`, `handle_mov_cr` 等）。
- **VMCALL**: `emulate_vmcall` 是 `VMCALL` 指令的专属处理器。它通过一个 `hypercall_key` 进行校验，然后根据 `RAX` 中的功能号，将请求分发到 `hypercalls.cpp` 中的具体实现，如 `hc::install_ept_hook`。

---

## 第二部分：新功能开发规划

### 2.1 功能规划：Ring 3 EPT Hook 框架

#### 2.1.1 目标
允许一个 Ring 3 应用程序通过一个内核驱动程序作为代理，安全地调用 Hypervisor 提供的 `install_ept_hook` 功能，从而在用户模式下实现对任意代码的 EPT Hook。

#### 2.1.2 架构设计

```mermaid
sequenceDiagram
    participant R3 as R3 Application
    participant R0 as R0 Driver
    participant HV as Hypervisor
    participant EPT as EPT Tables
    
    R3->>R3: 准备 Hook 请求
    R3->>R0: DeviceIoControl(IOCTL_INSTALL_HOOK)
    R0->>R0: 验证请求参数
    R0->>R0: 切换到目标进程上下文
    R0->>R0: 虚拟地址转物理地址
    R0->>R0: 分配 Hook 跳板内存
    R0->>R0: 复制 Hook 代码到跳板
    R0->>HV: VMCALL(install_ept_hook)
    HV->>EPT: 修改 EPT 权限<br/>(Execute = 0)
    HV->>HV: 记录 Hook 信息
    HV-->>R0: 返回成功
    R0-->>R3: 返回操作结果
    
    Note over EPT: 当 Guest 执行被 Hook 的页面时
    EPT->>HV: EPT Violation
    HV->>EPT: 切换到 Hook 页面
    HV->>HV: 恢复 Guest 执行
```

```mermaid
graph TB
    subgraph "Ring 3 层"
        R3_APP[R3 应用程序]
        R3_DLL[Hook 注入 DLL]
    end
    
    subgraph "Ring 0 层"
        subgraph "代理驱动"
            IOCTL[IOCTL 处理器]
            VALIDATOR[参数验证器]
            TRANSLATOR[地址转换器]
            ALLOCATOR[内存分配器]
        end
    end
    
    subgraph "Hypervisor 层"
        VMCALL_HANDLER[VMCALL 处理器]
        EPT_MANAGER[EPT 管理器]
        HOOK_TRACKER[Hook 追踪器]
    end
    
    R3_APP --> R3_DLL
    R3_DLL -->|DeviceIoControl| IOCTL
    IOCTL --> VALIDATOR
    VALIDATOR --> TRANSLATOR
    TRANSLATOR --> ALLOCATOR
    ALLOCATOR -->|VMCALL| VMCALL_HANDLER
    VMCALL_HANDLER --> EPT_MANAGER
    VMCALL_HANDLER --> HOOK_TRACKER
```

#### 2.1.3 实现步骤 (R0 内核驱动)
1.  **定义 IOCTL**: 在驱动头文件中定义一个唯一的 IOCTL 码和通信用的结构体。
    ```cpp
    #define IOCTL_INSTALL_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

    typedef struct _HOOK_REQUEST {
        HANDLE TargetProcessId;
        PVOID  TargetAddress;
        PVOID  HookFunction;
        SIZE_T HookSize;
    } HOOK_REQUEST, *PHOOK_REQUEST;
    ```
2.  **驱动入口 (`DriverEntry`)**:
    - `IoCreateDevice`: 创建一个设备对象。
    - `IoCreateSymbolicLink`: 创建一个用户模式可见的符号链接 (例如, `\\??\\MyHypervisorDevice`)。
    - 注册 `IRP_MJ_CREATE`, `IRP_MJ_CLOSE`, `IRP_MJ_DEVICE_CONTROL` 的调度例程。
3.  **IOCTL 处理例程 (`IrpDeviceControlHandler`)**:
    - 校验 IOCTL 码是否匹配。
    - 从 `Irp->AssociatedIrp.SystemBuffer` 中获取 `HOOK_REQUEST` 结构体。
    - **安全检查**: 验证 `TargetAddress` 和 `HookFunction` 是否是有效的用户模式地址。
    - **地址转换**:
        a. 使用 `PsLookupProcessByProcessId` 获取目标进程的 `EPROCESS` 结构。
        b. 使用 `KeStackAttachProcess` 切换到目标进程的地址空间。
        c. 调用 `MmGetPhysicalAddress` 将 `TargetAddress`（虚拟地址）转换为物理地址。
        d. `KeUnstackDetachProcess` 恢复原地址空间。
    - **分配 Hook 跳板**:
        a. 使用 `ExAllocatePoolWithTag(NonPagedPoolNx, ...)` 在内核中分配一块可执行内存作为跳板（Trampoline）。
        b. 跳板中应包含要执行的 Hook 代码，以及一个跳转回原始函数后续部分的指令。
        c. 使用 `ProbeForRead` 安全地从用户模式的 `HookFunction` 地址读取 Hook 代码，并复制到跳板中。
    - **发起 Hypercall**:
        a. 将目标页面的物理页帧号（PFN）放入 `RCX`。
        b. 将跳板页面的 PFN 放入 `RDX`。
        c. 设置 `RAX` 为 `hypercall_install_ept_hook` 的功能码。
        d. 执行 `VMCALL`。
    - **返回结果**: 将 `RAX` 中 Hypervisor 的返回值通过 `Irp->IoStatus.Information` 返回给 R3 应用。

#### 2.1.4 实现步骤 (R3 客户端)
```cpp
// R3 C++ Client Example
#include <windows.h>
// ... (include IOCTL definition)

int main() {
    HANDLE hDevice = CreateFile(L"\\\\.\\MyHypervisorDevice", ...);
    if (hDevice == INVALID_HANDLE_VALUE) return 1;

    HOOK_REQUEST req = { 0 };
    req.TargetProcessId = GetCurrentProcessId();
    req.TargetAddress = (PVOID)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtOpenFile");
    req.HookFunction = &MyHookFunction; // User-defined hook
    req.HookSize = ...;

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(hDevice, IOCTL_INSTALL_HOOK, &req, sizeof(req), nullptr, 0, &bytesReturned, nullptr);

    // ...
    CloseHandle(hDevice);
    return 0;
}
```

### 2.2 功能规划："CC 隐藏" (单步重定向 Hook)

#### 2.2.1 目标
实现一种高级 EPT Hook。当安装后，对目标页面的所有**读/写**操作都被透明地重定向到一个无害的伪造页，而所有**执行**操作则在原始页面上以**单步模式**执行并被监控。这常用于隐藏断点（如 `0xCC`）或实现无痕 F.I.R.E. (Framework for In-memory Record and Execution)。

#### 2.2.2 核心概念：MTF (Monitor Trap Flag) 循环

```mermaid
stateDiagram-v2
    [*] --> 初始状态: 安装 Stealth Hook
    初始状态 --> 读写重定向: Guest 读/写操作
    读写重定向 --> 初始状态: 返回伪造页内容
    
    初始状态 --> EPT_Violation: Guest 执行操作
    EPT_Violation --> 切换真实页: 修改 EPT
    切换真实页 --> 开启MTF: 设置 Monitor Trap Flag
    开启MTF --> 单步执行: VMRESUME
    单步执行 --> MTF_Exit: 执行一条指令
    MTF_Exit --> 切换伪造页: 修改 EPT
    切换伪造页 --> 关闭MTF: 清除 Monitor Trap Flag
    关闭MTF --> 初始状态: VMRESUME
```

```mermaid
flowchart LR
    subgraph "EPT 页面状态"
        subgraph "State 1: 伪造页激活"
            S1_PTE[EPT PTE]
            S1_FAKE[伪造页<br/>R/W = 1<br/>X = 0]
            S1_PTE -->|指向| S1_FAKE
        end
        
        subgraph "State 2: 真实页激活"
            S2_PTE[EPT PTE]
            S2_REAL[真实页<br/>R/W = 0<br/>X = 1]
            S2_PTE -->|指向| S2_REAL
        end
    end
    
    subgraph "触发条件"
        READ[读操作] --> S1_FAKE
        WRITE[写操作] --> S1_FAKE
        EXEC[执行操作] --> S2_REAL
    end
```

1.  **初始状态**: EPT 指向伪造页（可读写，不可执行）。
2.  **执行触发**: Guest 尝试执行代码 -> EPT Violation -> VM-Exit。
3.  **Host 响应**:
    a. EPT 切换回**真实页**（仅可执行）。
    b. 开启 VMCS 中的 **Monitor Trap Flag (MTF)**。
    c. VM-Resume。
4.  **单步执行**: Guest 在真实页上执行**一条**指令。
5.  **MTF 触发**: 指令执行完毕 -> MTF VM-Exit。
6.  **Host 恢复**:
    a. EPT 切换回**伪造页**（可读写，不可执行）。
    b. 关闭 MTF。
    c. VM-Resume。Guest 返回初始状态，等待下一次执行。

#### 2.2.3 实现步骤 (Hypervisor)

```mermaid
flowchart TD
    A[Guest 访问被 Hook 的页面] --> B{访问类型?}
    
    B -->|读/写| C[访问伪造页]
    C --> D[返回伪造内容]
    
    B -->|执行| E[EPT Violation]
    E --> F[handle_ept_violation]
    F --> G{是 Stealth Hook?}
    G -->|否| H[常规处理]
    G -->|是| I[获取 Hook 信息]
    I --> J[修改 EPT PTE<br/>指向真实页]
    J --> K[设置权限<br/>R=0, W=0, X=1]
    K --> L[开启 MTF]
    L --> M[VMRESUME]
    M --> N[Guest 执行一条指令]
    N --> O[MTF VM-Exit]
    O --> P[handle_monitor_trap_flag]
    P --> Q[修改 EPT PTE<br/>指向伪造页]
    Q --> R[设置权限<br/>R=1, W=1, X=0]
    R --> S[关闭 MTF]
    S --> T[VMRESUME]
    T --> A
```

1.  **新增 Hypercall**:
    - 在 `hypercalls.h` 中定义 `hypercall_install_stealth_hook`。它只需要一个参数：`target_physical_address`。
2.  **数据结构**: 创建一个新的 Hook 追踪结构。
    ```cpp
    typedef struct _STEALTH_HOOK_INFO {
        LIST_ENTRY          Link;
        UINT64              OriginalPfn;
        UINT64              DummyPfn; // PFN of the fake page
    } STEALTH_HOOK_INFO, *PSTEALTH_HOOK_INFO;
    ```
3.  **实现 `hc::install_stealth_hook` (`hypercalls.cpp`)**:
    - 从 `RCX` 获取 `target_physical_address`。
    - 分配一个新的 `STEALTH_HOOK_INFO` 节点和一个伪造页（Dummy Page）。
    - 调用新的底层函数 `ept::install_stealth_hook(target_pfn, dummy_pfn)`。
4.  **实现 `ept::install_stealth_hook` (`ept.cpp`)**:
    - 获取目标页面的 PTE（必要时分裂）。
    - **设置初始状态**:
      - 将 PTE 的 `page_frame_number` 设置为**伪造页**的 PFN。
      - 将 PTE 权限设置为 `Read=1, Write=1, Execute=0`。
    - `vmx_invept` 刷新缓存。
5.  **修改 `handle_ept_violation` (`exit-handlers.cpp`)**:
    - 添加新的逻辑分支：
    - `if (is_stealth_hook(physical_address) && qualification.execute_access)`:
      a. 找到对应的 `STEALTH_HOOK_INFO`。
      b. 获取 PTE，将其 `page_frame_number` 切换回**原始 PFN**。
      c. 设置权限为 `Read=0, Write=0, Execute=1`。
      d. 开启 MTF: `auto ctrl = read_ctrl_proc_based(); ctrl.monitor_trap_flag = 1; write_ctrl_proc_based(ctrl);`
      e. `vmx_invept` 刷新缓存。
      f. **不要** `skip_instruction()`，直接恢复执行。
6.  **修改 `handle_monitor_trap_flag` (`exit-handlers.cpp`)**:
    - 此函数现在是 MTF 循环的关键部分。
    - 从 `VMCS_GUEST_RIP` 推断出当前执行的页面，并找到对应的 `STEALTH_HOOK_INFO`。
    - **恢复初始状态**:
      a. 获取 PTE，将其 `page_frame_number` 切换回**伪造页 PFN**。
      b. 设置权限为 `Read=1, Write=1, Execute=0`。
      c. **关闭 MTF**: 在 `disable_monitor_trap_flag()` 函数中确保 `monitor_trap_flag` 被清零。
      d. `vmx_invept` 刷新缓存。
      e. `skip_instruction()` 并恢复执行。

### 2.3 EPT Hook 工作原理详解

```mermaid
graph TB
    subgraph "正常 EPT Hook 流程"
        subgraph "安装阶段"
            A1[Guest 调用安装 Hook]
            A2[分配 Hook 页面]
            A3[复制 Hook 代码]
            A4[修改 EPT 权限<br/>Execute = 0]
            A5[记录 Hook 信息]
            
            A1 --> A2 --> A3 --> A4 --> A5
        end
        
        subgraph "触发阶段"
            B1[Guest 执行目标地址]
            B2[EPT Violation<br/>因为 X = 0]
            B3[VM-Exit]
            B4[查找 Hook 记录]
            B5[切换 EPT 页面<br/>指向 Hook 页]
            B6[设置权限<br/>R=0, W=0, X=1]
            B7[VMRESUME]
            B8[执行 Hook 代码]
            
            B1 --> B2 --> B3 --> B4 --> B5 --> B6 --> B7 --> B8
        end
        
        subgraph "后续访问"
            C1[Guest 读/写目标地址]
            C2[再次 EPT Violation<br/>因为 R/W = 0]
            C3[切换回原始页<br/>R=1, W=1, X=0]
            C4[完成读/写操作]
            
            C1 --> C2 --> C3 --> C4
        end
    end
```

### 2.4 性能优化考虑

```mermaid
graph LR
    subgraph "性能优化策略"
        OPT1[使用 2MB 大页]
        OPT2[按需分裂页表]
        OPT3[VPID 减少 TLB 刷新]
        OPT4[MSR Bitmap 选择性拦截]
        OPT5[缓存常用数据]
        OPT6[VM-Exit 开销测量]
    end
    
    subgraph "实现位置"
        IMP1[prepare_ept]
        IMP2[split_ept_pde]
        IMP3[VMCS 配置]
        IMP4[enable_mtrr_exiting]
        IMP5[vcpu_cached_data]
        IMP6[measure_vm_exit_*]
    end
    
    OPT1 --> IMP1
    OPT2 --> IMP2
    OPT3 --> IMP3
    OPT4 --> IMP4
    OPT5 --> IMP5
    OPT6 --> IMP6
```

通过以上步骤，即可实现一个功能强大且隐蔽的执行监控 Hook。

---

## 第三部分：安全考虑与最佳实践

### 3.1 安全检查清单

```mermaid
graph TD
    subgraph "输入验证"
        IV1[验证用户输入参数]
        IV2[检查地址有效性]
        IV3[验证进程权限]
        IV4[防止整数溢出]
    end
    
    subgraph "内存安全"
        MS1[使用安全的内存函数]
        MS2[正确处理页面边界]
        MS3[防止 Double Free]
        MS4[清理敏感数据]
    end
    
    subgraph "并发控制"
        CC1[使用自旋锁保护共享数据]
        CC2[避免死锁]
        CC3[原子操作]
        CC4[Per-CPU 数据隔离]
    end
    
    subgraph "异常处理"
        EH1[Host 异常处理机制]
        EH2[Guest 异常注入]
        EH3[错误恢复路径]
        EH4[资源清理]
    end
```

### 3.2 调试与测试建议

1. **单元测试**: 为每个 Hypercall 编写独立的测试用例。
2. **压力测试**: 大量并发的 Hook 安装/卸载操作。
3. **兼容性测试**: 在不同版本的 Windows 上进行测试。
4. **性能基准**: 测量 VM-Exit 开销，优化热点路径。
5. **安全审计**: 定期进行代码审查，使用静态分析工具。

---

## 结语

本文档提供了对现有 VT 框架的深入分析，以及实现高级 EPT Hook 功能的详细规划。通过遵循这些设计和实现指南，可以构建一个功能强大、性能优异且安全可靠的虚拟化安全解决方案。 