/*
 * Copyright (c) 2014 VMware, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * XXX: OVS_USE_NL_INTERFACE is being used to keep the legacy DPIF interface
 * alive while we transition over to the netlink based interface.
 * OVS_USE_NL_INTERFACE = 0 => legacy inteface to use with dpif-windows.c
 * OVS_USE_NL_INTERFACE = 1 => netlink inteface to use with ported dpif-linux.c
 */
#if defined OVS_USE_NL_INTERFACE && OVS_USE_NL_INTERFACE == 1

#include "precomp.h"
#include "Datapath.h"
#include "Jhash.h"
#include "Switch.h"
#include "Vport.h"
#include "Event.h"
#include "User.h"
#include "PacketIO.h"
#include "NetProto.h"
#include "Flow.h"
#include "User.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_DATAPATH
#include "Debug.h"

#define NETLINK_FAMILY_NAME_LEN 48


/*
 * Netlink messages are grouped by family (aka type), and each family supports
 * a set of commands, and can be passed both from kernel -> userspace or
 * vice-versa. To call into the kernel, userspace uses a device operation which
 * is outside of a netlink message.
 *
 * Each command results in the invocation of a handler function to implement the
 * request functionality.
 *
 * Expectedly, only certain combinations of (device operation, netlink family,
 * command) are valid.
 *
 * Here, we implement the basic infrastructure to perform validation on the
 * incoming message, version checking, and also to invoke the corresponding
 * handler to do the heavy-lifting.
 */

/*
 * Handler for a given netlink command. Not all the parameters are used by all
 * the handlers.
 */
typedef NTSTATUS (*NetlinkCmdHandler)(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                                      UINT32 *replyLen);

typedef struct _NETLINK_CMD {
    UINT16 cmd;
    NetlinkCmdHandler handler;
    UINT32 supportedDevOp;      /* Supported device operations. */
    BOOLEAN validateDpIndex;    /* Does command require a valid DP argument. */
} NETLINK_CMD, *PNETLINK_CMD;

/* A netlink family is a group of commands. */
typedef struct _NETLINK_FAMILY {
    CHAR *name;
    UINT32 id;
    UINT8 version;
    UINT8 pad;
    UINT16 maxAttr;
    NETLINK_CMD *cmds;          /* Array of netlink commands and handlers. */
    UINT16 opsCount;
} NETLINK_FAMILY, *PNETLINK_FAMILY;

/*
 * Device operations to tag netlink commands with. This is a bitmask since it is
 * possible that a particular command can be invoked via different device
 * operations.
 */
#define OVS_READ_DEV_OP          (1 << 0)
#define OVS_WRITE_DEV_OP         (1 << 1)
#define OVS_TRANSACTION_DEV_OP   (1 << 2)

/* Handlers for the various netlink commands. */
static NTSTATUS OvsGetPidCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                                    UINT32 *replyLen);

static NTSTATUS OvsGetDpCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                                   UINT32 *replyLen);

/*
 * The various netlink families, along with the supported commands. Most of
 * these families and commands are part of the openvswitch specification for a
 * netlink datapath. In addition, each platform can implement a few families
 * and commands as extensions.
 */

/* Netlink control family: this is a Windows specific family. */
NETLINK_CMD nlControlFamilyCmdOps[] = {
    { .cmd             = OVS_CTRL_CMD_WIN_GET_PID,
      .handler         = OvsGetPidCmdHandler,
      .supportedDevOp  = OVS_TRANSACTION_DEV_OP,
      .validateDpIndex = FALSE
    }
};

NETLINK_FAMILY nlControlFamilyOps = {
    .name     = OVS_WIN_CONTROL_FAMILY,
    .id       = OVS_WIN_NL_CTRL_FAMILY_ID,
    .version  = OVS_WIN_CONTROL_VERSION,
    .maxAttr  = OVS_WIN_CONTROL_ATTR_MAX,
    .cmds     = nlControlFamilyCmdOps,
    .opsCount = ARRAY_SIZE(nlControlFamilyCmdOps)
};

/* Netlink datapath family. */
NETLINK_CMD nlDatapathFamilyCmdOps[] = {
    { .cmd             = OVS_DP_CMD_GET,
      .handler         = OvsGetDpCmdHandler,
      .supportedDevOp  = OVS_WRITE_DEV_OP | OVS_READ_DEV_OP,
      .validateDpIndex = FALSE
    }
};

NETLINK_FAMILY nlDatapathFamilyOps = {
    .name     = OVS_DATAPATH_FAMILY,
    .id       = OVS_WIN_NL_DATAPATH_FAMILY_ID,
    .version  = OVS_DATAPATH_VERSION,
    .maxAttr  = OVS_DP_ATTR_MAX,
    .cmds     = nlDatapathFamilyCmdOps,
    .opsCount = ARRAY_SIZE(nlDatapathFamilyCmdOps)
};

/* Netlink packet family. */
/* XXX: Add commands here. */
NETLINK_FAMILY nlPacketFamilyOps = {
    .name     = OVS_PACKET_FAMILY,
    .id       = OVS_WIN_NL_PACKET_FAMILY_ID,
    .version  = OVS_PACKET_VERSION,
    .maxAttr  = OVS_PACKET_ATTR_MAX,
    .cmds     = NULL, /* XXX: placeholder. */
    .opsCount = 0
};

/* Netlink vport family. */
/* XXX: Add commands here. */
NETLINK_FAMILY nlVportFamilyOps = {
    .name     = OVS_VPORT_FAMILY,
    .id       = OVS_WIN_NL_VPORT_FAMILY_ID,
    .version  = OVS_VPORT_VERSION,
    .maxAttr  = OVS_VPORT_ATTR_MAX,
    .cmds     = NULL, /* XXX: placeholder. */
    .opsCount = 0
};

/* Netlink flow family. */
/* XXX: Add commands here. */
NETLINK_FAMILY nlFLowFamilyOps = {
    .name     = OVS_FLOW_FAMILY,
    .id       = OVS_WIN_NL_FLOW_FAMILY_ID,
    .version  = OVS_FLOW_VERSION,
    .maxAttr  = OVS_FLOW_ATTR_MAX,
    .cmds     = NULL, /* XXX: placeholder. */
    .opsCount = 0
};

static NTSTATUS MapIrpOutputBuffer(PIRP irp,
                                   UINT32 bufferLength,
                                   UINT32 requiredLength,
                                   PVOID *buffer);
static NTSTATUS ValidateNetlinkCmd(UINT32 devOp,
                                   POVS_OPEN_INSTANCE instance,
                                   POVS_MESSAGE ovsMsg,
                                   NETLINK_FAMILY *nlFamilyOps);
static NTSTATUS InvokeNetlinkCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                                        NETLINK_FAMILY *nlFamilyOps,
                                        UINT32 *replyLen);
static NTSTATUS OvsSetupDumpStart(POVS_USER_PARAMS_CONTEXT usrParamsCtx);


/* Handles to the device object for communication with userspace. */
NDIS_HANDLE gOvsDeviceHandle;
PDEVICE_OBJECT gOvsDeviceObject;

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH OvsOpenCloseDevice;

_Dispatch_type_(IRP_MJ_CLEANUP)
DRIVER_DISPATCH OvsCleanupDevice;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH OvsDeviceControl;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, OvsCreateDeviceObject)
#pragma alloc_text(PAGE, OvsOpenCloseDevice)
#pragma alloc_text(PAGE, OvsCleanupDevice)
#pragma alloc_text(PAGE, OvsDeviceControl)
#endif // ALLOC_PRAGMA

/*
 * We might hit this limit easily since userspace opens a netlink descriptor for
 * each thread, and at least one descriptor per vport. Revisit this later.
 */
#define OVS_MAX_OPEN_INSTANCES 512
#define OVS_SYSTEM_DP_NAME     "ovs-system"

POVS_OPEN_INSTANCE ovsOpenInstanceArray[OVS_MAX_OPEN_INSTANCES];
UINT32 ovsNumberOfOpenInstances;
extern POVS_SWITCH_CONTEXT gOvsSwitchContext;

NDIS_SPIN_LOCK ovsCtrlLockObj;
PNDIS_SPIN_LOCK gOvsCtrlLock;


VOID
OvsInit()
{
    gOvsCtrlLock = &ovsCtrlLockObj;
    NdisAllocateSpinLock(gOvsCtrlLock);
    OvsInitEventQueue();
    OvsUserInit();
}

VOID
OvsCleanup()
{
    OvsCleanupEventQueue();
    if (gOvsCtrlLock) {
        NdisFreeSpinLock(gOvsCtrlLock);
        gOvsCtrlLock = NULL;
    }
    OvsUserCleanup();
}

VOID
OvsAcquireCtrlLock()
{
    NdisAcquireSpinLock(gOvsCtrlLock);
}

VOID
OvsReleaseCtrlLock()
{
    NdisReleaseSpinLock(gOvsCtrlLock);
}


/*
 * --------------------------------------------------------------------------
 * Creates the communication device between user and kernel, and also
 * initializes the data associated data structures.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsCreateDeviceObject(NDIS_HANDLE ovsExtDriverHandle)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicDeviceName;
    PDRIVER_DISPATCH dispatchTable[IRP_MJ_MAXIMUM_FUNCTION+1];
    NDIS_DEVICE_OBJECT_ATTRIBUTES deviceAttributes;
    OVS_LOG_TRACE("ovsExtDriverHandle: %p", ovsExtDriverHandle);

    RtlZeroMemory(dispatchTable,
                  (IRP_MJ_MAXIMUM_FUNCTION + 1) * sizeof (PDRIVER_DISPATCH));
    dispatchTable[IRP_MJ_CREATE] = OvsOpenCloseDevice;
    dispatchTable[IRP_MJ_CLOSE] = OvsOpenCloseDevice;
    dispatchTable[IRP_MJ_CLEANUP] = OvsCleanupDevice;
    dispatchTable[IRP_MJ_DEVICE_CONTROL] = OvsDeviceControl;

    NdisInitUnicodeString(&deviceName, OVS_DEVICE_NAME_NT);
    NdisInitUnicodeString(&symbolicDeviceName, OVS_DEVICE_NAME_DOS);

    RtlZeroMemory(&deviceAttributes, sizeof (NDIS_DEVICE_OBJECT_ATTRIBUTES));

    OVS_INIT_OBJECT_HEADER(&deviceAttributes.Header,
                           NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES,
                           NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1,
                           sizeof (NDIS_DEVICE_OBJECT_ATTRIBUTES));

    deviceAttributes.DeviceName = &deviceName;
    deviceAttributes.SymbolicName = &symbolicDeviceName;
    deviceAttributes.MajorFunctions = dispatchTable;
    deviceAttributes.ExtensionSize = sizeof (OVS_DEVICE_EXTENSION);

    status = NdisRegisterDeviceEx(ovsExtDriverHandle,
                                  &deviceAttributes,
                                  &gOvsDeviceObject,
                                  &gOvsDeviceHandle);
    if (status != NDIS_STATUS_SUCCESS) {
        POVS_DEVICE_EXTENSION ovsExt =
            (POVS_DEVICE_EXTENSION)NdisGetDeviceReservedExtension(gOvsDeviceObject);
        ASSERT(gOvsDeviceObject != NULL);
        ASSERT(gOvsDeviceHandle != NULL);

        if (ovsExt) {
            ovsExt->numberOpenInstance = 0;
        }
    } else {
        /* Initialize the associated data structures. */
        OvsInit();
    }
    OVS_LOG_TRACE("DeviceObject: %p", gOvsDeviceObject);
    return status;
}


VOID
OvsDeleteDeviceObject()
{
    if (gOvsDeviceHandle) {
#ifdef DBG
        POVS_DEVICE_EXTENSION ovsExt = (POVS_DEVICE_EXTENSION)
                    NdisGetDeviceReservedExtension(gOvsDeviceObject);
        if (ovsExt) {
            ASSERT(ovsExt->numberOpenInstance == 0);
        }
#endif

        ASSERT(gOvsDeviceObject);
        NdisDeregisterDeviceEx(gOvsDeviceHandle);
        gOvsDeviceHandle = NULL;
        gOvsDeviceObject = NULL;
    }
    OvsCleanup();
}

POVS_OPEN_INSTANCE
OvsGetOpenInstance(PFILE_OBJECT fileObject,
                   UINT32 dpNo)
{
    POVS_OPEN_INSTANCE instance = (POVS_OPEN_INSTANCE)fileObject->FsContext;
    ASSERT(instance);
    ASSERT(instance->fileObject == fileObject);
    if (gOvsSwitchContext == NULL ||
        gOvsSwitchContext->dpNo != dpNo) {
        return NULL;
    }
    return instance;
}


POVS_OPEN_INSTANCE
OvsFindOpenInstance(PFILE_OBJECT fileObject)
{
    UINT32 i, j;
    for (i = 0, j = 0; i < OVS_MAX_OPEN_INSTANCES &&
                       j < ovsNumberOfOpenInstances; i++) {
        if (ovsOpenInstanceArray[i]) {
            if (ovsOpenInstanceArray[i]->fileObject == fileObject) {
                return ovsOpenInstanceArray[i];
            }
            j++;
        }
    }
    return NULL;
}

NTSTATUS
OvsAddOpenInstance(POVS_DEVICE_EXTENSION ovsExt,
                   PFILE_OBJECT fileObject)
{
    POVS_OPEN_INSTANCE instance =
        (POVS_OPEN_INSTANCE) OvsAllocateMemory(sizeof (OVS_OPEN_INSTANCE));
    UINT32 i;

    if (instance == NULL) {
        return STATUS_NO_MEMORY;
    }
    OvsAcquireCtrlLock();
    ASSERT(OvsFindOpenInstance(fileObject) == NULL);

    if (ovsNumberOfOpenInstances >= OVS_MAX_OPEN_INSTANCES) {
        OvsReleaseCtrlLock();
        OvsFreeMemory(instance);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(instance, sizeof (OVS_OPEN_INSTANCE));

    for (i = 0; i < OVS_MAX_OPEN_INSTANCES; i++) {
        if (ovsOpenInstanceArray[i] == NULL) {
            ovsOpenInstanceArray[i] = instance;
            instance->cookie = i;
            break;
        }
    }
    ASSERT(i < OVS_MAX_OPEN_INSTANCES);
    instance->fileObject = fileObject;
    ASSERT(fileObject->FsContext == NULL);
    instance->pid = (UINT32)InterlockedIncrement((LONG volatile *)&ovsExt->pidCount);
    if (instance->pid == 0) {
        /* XXX: check for rollover. */
    }
    fileObject->FsContext = instance;
    OvsReleaseCtrlLock();
    return STATUS_SUCCESS;
}

static VOID
OvsCleanupOpenInstance(PFILE_OBJECT fileObject)
{
    POVS_OPEN_INSTANCE instance = (POVS_OPEN_INSTANCE)fileObject->FsContext;
    ASSERT(instance);
    ASSERT(fileObject == instance->fileObject);
    OvsCleanupEvent(instance);
    OvsCleanupPacketQueue(instance);
}

VOID
OvsRemoveOpenInstance(PFILE_OBJECT fileObject)
{
    POVS_OPEN_INSTANCE instance;
    ASSERT(fileObject->FsContext);
    instance = (POVS_OPEN_INSTANCE)fileObject->FsContext;
    ASSERT(instance->cookie < OVS_MAX_OPEN_INSTANCES);

    OvsAcquireCtrlLock();
    fileObject->FsContext = NULL;
    ASSERT(ovsOpenInstanceArray[instance->cookie] == instance);
    ovsOpenInstanceArray[instance->cookie] = NULL;
    OvsReleaseCtrlLock();
    ASSERT(instance->eventQueue == NULL);
    ASSERT (instance->packetQueue == NULL);
    OvsFreeMemory(instance);
}

NTSTATUS
OvsCompleteIrpRequest(PIRP irp,
                      ULONG_PTR infoPtr,
                      NTSTATUS status)
{
    irp->IoStatus.Information = infoPtr;
    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}


NTSTATUS
OvsOpenCloseDevice(PDEVICE_OBJECT deviceObject,
                   PIRP irp)
{
    PIO_STACK_LOCATION irpSp;
    NTSTATUS status = STATUS_SUCCESS;
    PFILE_OBJECT fileObject;
    POVS_DEVICE_EXTENSION ovsExt =
        (POVS_DEVICE_EXTENSION)NdisGetDeviceReservedExtension(deviceObject);

    ASSERT(deviceObject == gOvsDeviceObject);
    ASSERT(ovsExt != NULL);

    irpSp = IoGetCurrentIrpStackLocation(irp);
    fileObject = irpSp->FileObject;
    OVS_LOG_TRACE("DeviceObject: %p, fileObject:%p, instance: %u",
                  deviceObject, fileObject,
                  ovsExt->numberOpenInstance);

    switch (irpSp->MajorFunction) {
    case IRP_MJ_CREATE:
        status = OvsAddOpenInstance(ovsExt, fileObject);
        if (STATUS_SUCCESS == status) {
            InterlockedIncrement((LONG volatile *)&ovsExt->numberOpenInstance);
        }
        break;
    case IRP_MJ_CLOSE:
        ASSERT(ovsExt->numberOpenInstance > 0);
        OvsRemoveOpenInstance(fileObject);
        InterlockedDecrement((LONG volatile *)&ovsExt->numberOpenInstance);
        break;
    default:
        ASSERT(0);
    }
    return OvsCompleteIrpRequest(irp, (ULONG_PTR)0, status);
}

_Use_decl_annotations_
NTSTATUS
OvsCleanupDevice(PDEVICE_OBJECT deviceObject,
                 PIRP irp)
{

    PIO_STACK_LOCATION irpSp;
    PFILE_OBJECT fileObject;

    NTSTATUS status = STATUS_SUCCESS;
#ifdef DBG
    POVS_DEVICE_EXTENSION ovsExt =
        (POVS_DEVICE_EXTENSION)NdisGetDeviceReservedExtension(deviceObject);
    if (ovsExt) {
        ASSERT(ovsExt->numberOpenInstance > 0);
    }
#else
    UNREFERENCED_PARAMETER(deviceObject);
#endif
    ASSERT(deviceObject == gOvsDeviceObject);
    irpSp = IoGetCurrentIrpStackLocation(irp);
    fileObject = irpSp->FileObject;

    ASSERT(irpSp->MajorFunction == IRP_MJ_CLEANUP);

    OvsCleanupOpenInstance(fileObject);

    return OvsCompleteIrpRequest(irp, (ULONG_PTR)0, status);
}


/*
 * --------------------------------------------------------------------------
 * IOCTL function handler for the device.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsDeviceControl(PDEVICE_OBJECT deviceObject,
                 PIRP irp)
{

    PIO_STACK_LOCATION irpSp;
    NTSTATUS status = STATUS_SUCCESS;
    PFILE_OBJECT fileObject;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    UINT32 inputBufferLen, outputBufferLen;
    UINT32 code, replyLen = 0;
    POVS_OPEN_INSTANCE instance;
    UINT32 devOp;
    OVS_MESSAGE ovsMsgReadOp;
    POVS_MESSAGE ovsMsg;
    NETLINK_FAMILY *nlFamilyOps;
    OVS_USER_PARAMS_CONTEXT usrParamsCtx;

#ifdef DBG
    POVS_DEVICE_EXTENSION ovsExt =
        (POVS_DEVICE_EXTENSION)NdisGetDeviceReservedExtension(deviceObject);
    ASSERT(deviceObject == gOvsDeviceObject);
    ASSERT(ovsExt);
    ASSERT(ovsExt->numberOpenInstance > 0);
#else
    UNREFERENCED_PARAMETER(deviceObject);
#endif

    irpSp = IoGetCurrentIrpStackLocation(irp);

    ASSERT(irpSp->MajorFunction == IRP_MJ_DEVICE_CONTROL);
    ASSERT(irpSp->FileObject != NULL);

    fileObject = irpSp->FileObject;
    instance = (POVS_OPEN_INSTANCE)fileObject->FsContext;
    code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    inputBufferLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    inputBuffer = irp->AssociatedIrp.SystemBuffer;

    /* Concurrent netlink operations are not supported. */
    if (InterlockedCompareExchange((LONG volatile *)&instance->inUse, 1, 0)) {
        status = STATUS_RESOURCE_IN_USE;
        goto done;
    }

    /*
     * Validate the input/output buffer arguments depending on the type of the
     * operation.
     */
    switch (code) {
    case OVS_IOCTL_TRANSACT:
        /* Input buffer is mandatory, output buffer is optional. */
        if (outputBufferLen != 0) {
            status = MapIrpOutputBuffer(irp, outputBufferLen,
                                        sizeof *ovsMsg, &outputBuffer);
            if (status != STATUS_SUCCESS) {
                goto done;
            }
            ASSERT(outputBuffer);
        }

        if (inputBufferLen < sizeof (*ovsMsg)) {
            status = STATUS_NDIS_INVALID_LENGTH;
            goto done;
        }

        ovsMsg = inputBuffer;
        devOp = OVS_TRANSACTION_DEV_OP;
        break;

    case OVS_IOCTL_READ:
        /* Output buffer is mandatory. */
        if (outputBufferLen != 0) {
            status = MapIrpOutputBuffer(irp, outputBufferLen,
                                        sizeof *ovsMsg, &outputBuffer);
            if (status != STATUS_SUCCESS) {
                goto done;
            }
            ASSERT(outputBuffer);
        } else {
            status = STATUS_NDIS_INVALID_LENGTH;
            goto done;
        }

        /*
         * Operate in the mode that read ioctl is similar to ReadFile(). This
         * might change as the userspace code gets implemented.
         */
        inputBuffer = NULL;
        inputBufferLen = 0;

        /*
         * For implementing read (ioctl or otherwise), we need to store some
         * state in the instance to indicate the command that started the dump
         * operation. The state can setup 'ovsMsgReadOp' appropriately. Note
         * that 'ovsMsgReadOp' is needed only in this function to call into the
         * appropraite handler. The handler itself can access the state in the
         * instance.
         *
         * In the absence of a dump start, return 0 bytes.
         */
        if (instance->dumpState.ovsMsg == NULL) {
            replyLen = 0;
            status = STATUS_SUCCESS;
            goto done;
        }
        RtlCopyMemory(&ovsMsgReadOp, instance->dumpState.ovsMsg,
                      sizeof (ovsMsgReadOp));

        /* Create an NL message for consumption. */
        ovsMsg = &ovsMsgReadOp;
        devOp = OVS_READ_DEV_OP;

        break;

    case OVS_IOCTL_WRITE:
        /* Input buffer is mandatory. */
        if (inputBufferLen < sizeof (*ovsMsg)) {
            status = STATUS_NDIS_INVALID_LENGTH;
            goto done;
        }

        ovsMsg = inputBuffer;
        devOp = OVS_WRITE_DEV_OP;
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto done;
    }

    ASSERT(ovsMsg);
    switch (ovsMsg->nlMsg.nlmsgType) {
    case OVS_WIN_NL_CTRL_FAMILY_ID:
        nlFamilyOps = &nlControlFamilyOps;
        break;
    case OVS_WIN_NL_DATAPATH_FAMILY_ID:
        nlFamilyOps = &nlDatapathFamilyOps;
        break;
    case OVS_WIN_NL_PACKET_FAMILY_ID:
    case OVS_WIN_NL_FLOW_FAMILY_ID:
    case OVS_WIN_NL_VPORT_FAMILY_ID:
        status = STATUS_NOT_IMPLEMENTED;
        goto done;

    default:
        status = STATUS_INVALID_PARAMETER;
        goto done;
    }

    /*
     * For read operation, the netlink command has already been validated
     * previously.
     */
    if (devOp != OVS_READ_DEV_OP) {
        status = ValidateNetlinkCmd(devOp, instance, ovsMsg, nlFamilyOps);
        if (status != STATUS_SUCCESS) {
            goto done;
        }
    }

    InitUserParamsCtx(irp, instance, devOp, ovsMsg,
                      inputBuffer, inputBufferLen,
                      outputBuffer, outputBufferLen,
                      &usrParamsCtx);

    status = InvokeNetlinkCmdHandler(&usrParamsCtx, nlFamilyOps, &replyLen);

done:
    KeMemoryBarrier();
    instance->inUse = 0;
    return OvsCompleteIrpRequest(irp, (ULONG_PTR)replyLen, status);
}


/*
 * --------------------------------------------------------------------------
 * Function to validate a netlink command. Only certain combinations of
 * (device operation, netlink family, command) are valid.
 *
 * XXX: Take policy into consideration.
 * --------------------------------------------------------------------------
 */
static NTSTATUS
ValidateNetlinkCmd(UINT32 devOp,
                   POVS_OPEN_INSTANCE instance,
                   POVS_MESSAGE ovsMsg,
                   NETLINK_FAMILY *nlFamilyOps)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    UINT16 i;

    for (i = 0; i < nlFamilyOps->opsCount; i++) {
        if (nlFamilyOps->cmds[i].cmd == ovsMsg->genlMsg.cmd) {
            /* Validate if the command is valid for the device operation. */
            if ((devOp & nlFamilyOps->cmds[i].supportedDevOp) == 0) {
                status = STATUS_INVALID_PARAMETER;
                goto done;
            }

            /* Validate the version. */
            if (nlFamilyOps->version > ovsMsg->genlMsg.version) {
                status = STATUS_INVALID_PARAMETER;
                goto done;
            }

            /* Validate the DP for commands that require a DP. */
            if (nlFamilyOps->cmds[i].validateDpIndex == TRUE) {
                OvsAcquireCtrlLock();
                if (ovsMsg->ovsHdr.dp_ifindex !=
                    (INT)gOvsSwitchContext->dpNo) {
                    status = STATUS_INVALID_PARAMETER;
                    OvsReleaseCtrlLock();
                    goto done;
                }
                OvsReleaseCtrlLock();
            }

            /* Validate the PID. */
            if (ovsMsg->genlMsg.cmd != OVS_CTRL_CMD_WIN_GET_PID) {
                if (ovsMsg->nlMsg.nlmsgPid != instance->pid) {
                    status = STATUS_INVALID_PARAMETER;
                    goto done;
                }
            }

            status = STATUS_SUCCESS;
            break;
        }
    }

done:
    return status;
}

/*
 * --------------------------------------------------------------------------
 * Function to invoke the netlink command handler.
 * --------------------------------------------------------------------------
 */
static NTSTATUS
InvokeNetlinkCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                        NETLINK_FAMILY *nlFamilyOps,
                        UINT32 *replyLen)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    UINT16 i;

    for (i = 0; i < nlFamilyOps->opsCount; i++) {
        if (nlFamilyOps->cmds[i].cmd == usrParamsCtx->ovsMsg->genlMsg.cmd) {
            status = nlFamilyOps->cmds[i].handler(usrParamsCtx, replyLen);
            break;
        }
    }

    return status;
}


/*
 * --------------------------------------------------------------------------
 *  Each handle on the device is assigned a unique PID when the handle is
 *  created. On platforms that support netlink natively, the PID is available
 *  to userspace when the netlink socket is created. However, without native
 *  netlink support on Windows, OVS datapath generates the PID and lets the
 *  userspace query it.
 *
 *  This function implements the query.
 * --------------------------------------------------------------------------
 */
static NTSTATUS
OvsGetPidCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                    UINT32 *replyLen)
{
    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;
    POVS_MESSAGE msgOut = (POVS_MESSAGE)usrParamsCtx->outputBuffer;

    if (usrParamsCtx->outputLength >= sizeof *msgOut) {
        POVS_OPEN_INSTANCE instance =
            (POVS_OPEN_INSTANCE)usrParamsCtx->ovsInstance;

        RtlZeroMemory(msgOut, sizeof *msgOut);
        msgOut->nlMsg.nlmsgSeq = msgIn->nlMsg.nlmsgSeq;
        msgOut->nlMsg.nlmsgPid = instance->pid;
        *replyLen = sizeof *msgOut;
        /* XXX: We might need to return the DP index as well. */
    } else {
        return STATUS_NDIS_INVALID_LENGTH;
    }

    return STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 *  Handler for the get dp command. The function handles the initial call to
 *  setup the dump state, as well as subsequent calls to continue dumping data.
 * --------------------------------------------------------------------------
 */
static NTSTATUS
OvsGetDpCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                   UINT32 *replyLen)
{
    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;
    POVS_MESSAGE msgOut = (POVS_MESSAGE)usrParamsCtx->outputBuffer;
    POVS_OPEN_INSTANCE instance =
        (POVS_OPEN_INSTANCE)usrParamsCtx->ovsInstance;

    if (usrParamsCtx->devOp == OVS_WRITE_DEV_OP) {
        *replyLen = 0;
        OvsSetupDumpStart(usrParamsCtx);
    } else {
        ASSERT(usrParamsCtx->devOp == OVS_READ_DEV_OP);

        if (instance->dumpState.ovsMsg == NULL) {
            ASSERT(FALSE);
            return STATUS_INVALID_DEVICE_STATE;
        }

        /* Dump state must have been deleted after previous dump operation. */
        ASSERT(instance->dumpState.index[0] == 0);
        /* Output buffer has been validated while validating read dev op. */
        ASSERT(msgOut != NULL && usrParamsCtx->outputLength >= sizeof *msgOut);

        /* XXX: Replace this with the netlink set API. */
        msgIn = instance->dumpState.ovsMsg;
        msgOut->nlMsg.nlmsgType = OVS_WIN_NL_DATAPATH_FAMILY_ID;
        msgOut->nlMsg.nlmsgFlags = 0;  /* XXX: ? */
        msgOut->nlMsg.nlmsgSeq = msgIn->nlMsg.nlmsgSeq;
        msgOut->nlMsg.nlmsgPid = msgIn->nlMsg.nlmsgPid;
        msgOut->nlMsg.nlmsgLen = sizeof *msgOut;

        msgOut->genlMsg.cmd = OVS_DP_CMD_GET;
        msgOut->genlMsg.version = nlDatapathFamilyOps.version;
        msgOut->genlMsg.reserved = 0;

        OvsAcquireCtrlLock();
        if (gOvsSwitchContext) {
            msgOut->ovsHdr.dp_ifindex = gOvsSwitchContext->dpNo;
        } else {
            /* Treat this as a dump done. */
            OvsReleaseCtrlLock();
            *replyLen = 0;
            FreeUserDumpState(instance);
            return STATUS_SUCCESS;
        }

        /* XXX: Replace this with the netlink set API. */
        {
            /*
             * Assume that the output buffer is at least 512 bytes. Once the
             * netlink set API is implemented, the netlink buffer manipulation
             * API should provide for checking the remaining number of bytes as
             * we write out the message.
             */
            if (usrParamsCtx->outputLength <= 512) {
                OvsReleaseCtrlLock();
                return STATUS_NDIS_INVALID_LENGTH;
            }
            UINT16 attrTotalSize = 0;
            UINT16 attrSize = 0;
            PNL_ATTR nlAttr = (PNL_ATTR) ((PCHAR)msgOut + sizeof (*msgOut));
            struct ovs_dp_stats *dpStats;
            OVS_DATAPATH *datapath = &gOvsSwitchContext->datapath;

            nlAttr->nlaType = OVS_DP_ATTR_NAME;
            /* 'nlaLen' must not include the pad. */
            nlAttr->nlaLen = sizeof (*nlAttr) + sizeof (OVS_SYSTEM_DP_NAME);
            attrSize = sizeof (*nlAttr) +
                       NLA_ALIGN(sizeof (OVS_SYSTEM_DP_NAME));
            attrTotalSize += attrSize;

            PNL_ATTR nlAttrNext = NlAttrGet(nlAttr);
            RtlCopyMemory((PCHAR)nlAttrNext, OVS_SYSTEM_DP_NAME,
                          sizeof (OVS_SYSTEM_DP_NAME));

            nlAttr = (PNL_ATTR)((PCHAR)nlAttr + attrSize);
            nlAttr->nlaType = OVS_DP_ATTR_STATS;
            nlAttr->nlaLen = sizeof (*nlAttr) + sizeof (*dpStats);
            attrSize = sizeof (*nlAttr) + NLA_ALIGN(sizeof (*dpStats));
            attrTotalSize += attrSize;

            dpStats = NlAttrGet(nlAttr);
            dpStats->n_hit = datapath->hits;
            dpStats->n_missed = datapath->misses;
            dpStats->n_lost = datapath->lost;
            dpStats->n_flows = datapath->nFlows;

            msgOut->nlMsg.nlmsgLen += attrTotalSize;
        }
        OvsReleaseCtrlLock();

        /* Increment the dump index. */
        instance->dumpState.index[0] = 1;
        *replyLen = msgOut->nlMsg.nlmsgLen;
        ASSERT(*replyLen <= 512);

        /* Free up the dump state, since there's no more data to continue. */
        FreeUserDumpState(instance);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
OvsSetupDumpStart(POVS_USER_PARAMS_CONTEXT usrParamsCtx)
{
    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;
    POVS_OPEN_INSTANCE instance =
        (POVS_OPEN_INSTANCE)usrParamsCtx->ovsInstance;

    /* input buffer has been validated while validating write dev op. */
    ASSERT(msgIn != NULL && usrParamsCtx->inputLength >= sizeof *msgIn);

    /* A write operation that does not indicate dump start is invalid. */
    if ((msgIn->nlMsg.nlmsgFlags & NLM_F_DUMP) != NLM_F_DUMP) {
        return STATUS_INVALID_PARAMETER;
    }
    /* XXX: Handle other NLM_F_* flags in the future. */

    /*
     * This operation should be setting up the dump state. If there's any
     * previous state, clear it up so as to set it up afresh.
     */
    if (instance->dumpState.ovsMsg != NULL) {
        FreeUserDumpState(instance);
    }

    return InitUserDumpState(instance, msgIn);
}

/*
 * --------------------------------------------------------------------------
 *  Utility function to map the output buffer in an IRP. The buffer is assumed
 *  to have been passed down using METHOD_OUT_DIRECT (Direct I/O).
 * --------------------------------------------------------------------------
 */
static NTSTATUS
MapIrpOutputBuffer(PIRP irp,
                   UINT32 bufferLength,
                   UINT32 requiredLength,
                   PVOID *buffer)
{
    ASSERT(irp);
    ASSERT(buffer);
    ASSERT(bufferLength);
    ASSERT(requiredLength);
    if (!buffer || !irp || bufferLength == 0 || requiredLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (bufferLength < requiredLength) {
        return STATUS_NDIS_INVALID_LENGTH;
    }
    if (irp->MdlAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *buffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress,
                                           NormalPagePriority);
    if (*buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return STATUS_SUCCESS;
}

#endif /* OVS_USE_NL_INTERFACE */
