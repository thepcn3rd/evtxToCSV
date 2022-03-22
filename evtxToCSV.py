#!/usr/bin/python3

# apt install python3-evtx
# Bash commands to assist in building the repeatative nature of the lines below...
# ./a.py > s.tmp 
# cat s.tmp| grep Missing | awk '{print $4}' | sort | uniq > t
# cat t | awk '{print "\t\t\t\t\telif i[\"@Name\"] == \"" $1 "\": " $1 " = i[\"#text\"]"}' 
# cat t | awk '{print "\t\t" $1 " = \"\""}'

import Evtx.Evtx as evtx
import Evtx.Views as e_views
import xmltodict
import json
from pprint import pprint

evtxFile='Logs/Microsoft-Windows-PowerShell%4Operational.evtx'
#evtxFile='Logs/Security.evtx'
#evtxFile='Logs/System.evtx'

count = 0
# Output CSV Header for all fields
#print('"eventID", "timeCreated", "channel", "computer", "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "NewProcessId", "NewProcessName", "TokenElevationType", "ProcessId", "ProcessName", "CommandLine", "TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId", "TargetProcessId", "TargetProcessName", "ParentProcessName", "MandatoryLabel", "AdvancedOptions", "AuthenticationPackageName", "ConfigAccessPolicy", "DisableIntegrityChecks", "ElevatedToken", "FlightSigning", "HypervisorDebug", "HypervisorLaunchType", "HypervisorLoadOptions", "ImpersonationLevel", "IpAddress", "IpPort", "KernelDebug", "KeyLength", "LmPackageName", "LoadOptions", "LogonGuid", "LogonProcessName", "LogonType", "PrivilegeList", "PuaCount", "PuaPolicyId", "RemoteEventLogging", "RestrictedAdminMode", "SamAccountName", "SidHistory", "TargetLinkedLogonId", "TargetOutboundDomainName", "TargetOutboundUserName", "TargetSid", "TestSigning", "TransmittedServices", "VirtualAccount", "VsmLaunchType", "WorkstationName", "AccessGranted", "AccessRemoved", "AccountExpires", "AllowedToDelegateTo", "CallerProcessId", "CallerProcessName", "ClientProcessId", "CountOfCredentialsReturned", "DisplayName", "DomainBehaviorVersion", "DomainName", "DomainPolicyChanged", "DomainSid", "Dummy", "ForceLogoff", "HandleId", "HomeDirectory", "HomePath", "LockoutDuration", "LockoutObservationWindow", "LockoutThreshold", "LogonHours", "MachineAccountQuota", "MaxPasswordAge", "MemberName", "MemberSid", "MinPasswordAge", "MinPasswordLength", "MixedDomainMode", "NewSd", "NewUacValue", "ObjectName", "ObjectServer", "ObjectType", "OemInformation", "OldSd", "OldUacValue", "PasswordHistoryLength", "PasswordLastSet", "PasswordProperties", "PrimaryGroupId", "ProcessCreationTime", "ProfilePath", "ReadOperation", "ReturnCode", "ScriptPath", "TargetInfo", "TargetLogonGuid", "TargetName", "TargetServerName", "Type", "UserAccountControl", "UserParameters", "UserPrincipalName", "UserWorkstations", "AlgorithmName", "ClientCreationTime", "FailureReason", "Flags", "Identity", "KeyFilePath", "KeyName", "KeyType", "NewTargetUserName", "NewTime", "ObjectCollectionName", "ObjectIdentifyingProperties", "ObjectProperties", "OldTargetUserName", "Operation", "PackageName", "PreviousTime", "ProviderName", "Resource", "Schema", "SchemaFriendlyName", "Status", "SubjectUserDomainName", "SubStatus", "Workstation", "ContextInfo", "MessageNumber", "MessageTotal", "param1", "param2", "Payload", "ScriptBlockId", "ScriptBlockText"')

# CSV Fields for Powershell Logs
print('"eventID", "timeCreated", "channel", "computer", "ContextInfo", "MessageNumber", "MessageTotal", "param1", "param2", "Payload", "ScriptBlockId", "ScriptBlockText"')
with evtx.Evtx(evtxFile) as log:
    for record in log.records():
        eventID = ""
        timeCreated = ""
        channel = ""
        computer = ""
        SubjectUserSid = ""
        SubjectUserName = ""
        SubjectDomainName = ""
        SubjectLogonId = ""
        NewProcessId = ""
        NewProcessName = ""
        TokenElevationType = ""
        ProcessId = ""
        ProcessName = ""
        CommandLine = ""
        TargetUserSid = ""
        TargetUserName = ""
        TargetDomainName = ""
        TargetLogonId = ""
        TargetProcessId = ""
        TargetProcessName = ""
        ParentProcessName = ""
        MandatoryLabel = ""
        AdvancedOptions = ""
        AuthenticationPackageName = ""
        ConfigAccessPolicy = ""
        DisableIntegrityChecks = ""
        ElevatedToken = ""
        FlightSigning = ""
        HypervisorDebug = ""
        HypervisorLaunchType = ""
        HypervisorLoadOptions = ""
        ImpersonationLevel = ""
        IpAddress = ""
        IpPort = ""
        KernelDebug = ""
        KeyLength = ""
        LmPackageName = ""
        LoadOptions = ""
        LogonGuid = ""
        LogonProcessName = ""
        LogonType = ""
        PrivilegeList = ""
        PuaCount = ""
        PuaPolicyId = ""
        RemoteEventLogging = ""
        RestrictedAdminMode = ""
        SamAccountName = ""
        SidHistory = ""
        TargetLinkedLogonId = ""
        TargetOutboundDomainName = ""
        TargetOutboundUserName = ""
        TargetSid = ""
        TestSigning = ""
        TransmittedServices = ""
        VirtualAccount = ""
        VsmLaunchType = ""
        WorkstationName = ""
        AccessGranted = ""
        AccessRemoved = ""
        AccountExpires = ""
        AllowedToDelegateTo = ""
        CallerProcessId = ""
        CallerProcessName = ""
        ClientProcessId = ""
        CountOfCredentialsReturned = ""
        DisplayName = ""
        DomainBehaviorVersion = ""
        DomainName = ""
        DomainPolicyChanged = ""
        DomainSid = ""
        Dummy = ""
        ForceLogoff = ""
        HandleId = ""
        HomeDirectory = ""
        HomePath = ""
        LockoutDuration = ""
        LockoutObservationWindow = ""
        LockoutThreshold = ""
        LogonHours = ""
        MachineAccountQuota = ""
        MaxPasswordAge = ""
        MemberName = ""
        MemberSid = ""
        MinPasswordAge = ""
        MinPasswordLength = ""
        MixedDomainMode = ""
        NewSd = ""
        NewUacValue = ""
        ObjectName = ""
        ObjectServer = ""
        ObjectType = ""
        OemInformation = ""
        OldSd = ""
        OldUacValue = ""
        PasswordHistoryLength = ""
        PasswordLastSet = ""
        PasswordProperties = ""
        PrimaryGroupId = ""
        ProcessCreationTime = ""
        ProfilePath = ""
        ReadOperation = ""
        ReturnCode = ""
        ScriptPath = ""
        TargetInfo = ""
        TargetLogonGuid = ""
        TargetName = ""
        TargetServerName = ""
        Type = ""
        UserAccountControl = ""
        UserParameters = ""
        UserPrincipalName = ""
        UserWorkstations = ""
        AlgorithmName = ""
        ClientCreationTime = ""
        FailureReason = ""
        Flags = ""
        Identity = ""
        KeyFilePath = ""
        KeyName = ""
        KeyType = ""
        NewTargetUserName = ""
        NewTime = ""
        ObjectCollectionName = ""
        ObjectIdentifyingProperties = ""
        ObjectProperties = ""
        OldTargetUserName = ""
        Operation = ""
        PackageName = ""
        PreviousTime = ""
        ProviderName = ""
        Resource = ""
        Schema = ""
        SchemaFriendlyName = ""
        Status = ""
        SubjectUserDomainName = ""
        SubStatus = ""
        Workstation = ""
        ContextInfo = ""
        MessageNumber = ""
        MessageTotal = ""
        param1 = ""
        param2 = ""
        Payload = ""
        ScriptBlockId = ""
        ScriptBlockText = ""
        #print("-"*50 + "\n")
        #print(record.xml())
        #print("\n")
        obj = xmltodict.parse(record.xml())
        eventID = obj['Event']['System']['EventID']['#text']
        timeCreated = obj['Event']['System']['TimeCreated']['@SystemTime']
        channel = obj['Event']['System']['Channel']
        computer = obj['Event']['System']['Computer']
        #pprint(obj['Event'])
        if "EventData" in obj['Event'] and obj['Event']['EventData'] != None:
            if "Data" in obj['Event']['EventData']:
                #print(obj['Event']['EventData']['Data'])
                for i in obj['Event']['EventData']['Data']:
                    #if i["@Name"] == "ScriptBlockText":
                    #    print(i)
                    if "#text" in i:
                        if i["@Name"] == "SubjectUserSid": SubjectUserSid = i['#text']
                        elif i["@Name"] == "SubjectUserName": SubjectUserName = i["#text"]
                        elif i["@Name"] == "SubjectDomainName": SubjectDomainName = i['#text']
                        elif i["@Name"] == "SubjectLogonId": SubjectLogonId = i["#text"]
                        elif i["@Name"] == "NewProcessId": NewProcessId = i["#text"]
                        elif i["@Name"] == "NewProcessName": NewProcessName = i["#text"]
                        elif i["@Name"] == "TokenElevationType": TokenElevationType = i["#text"]
                        elif i["@Name"] == "ProcessId": ProcessId = i["#text"]
                        elif i["@Name"] == "ProcessName": ProcessName = i["#text"]
                        elif i["@Name"] == "CommandLine": CommandLine = i["#text"]
                        elif i["@Name"] == "TargetUserSid": TargetUserSid = i["#text"]
                        elif i["@Name"] == "TargetUserName": TargetUserName = i["#text"]
                        elif i["@Name"] == "TargetDomainName": TargetDomainName = i["#text"]
                        elif i["@Name"] == "TargetLogonId": TargetLogonId = i["#text"]
                        elif i["@Name"] == "TargetProcessId": TargetProcessId = i["#text"]
                        elif i["@Name"] == "TargetProcessName": TargetProcessName = i["#text"]
                        elif i["@Name"] == "ParentProcessName": ParentProcessName = i["#text"]
                        elif i["@Name"] == "MandatoryLabel": MandatoryLabel = i["#text"]
                        elif i["@Name"] == "AdvancedOptions": AdvancedOptions = i["#text"]
                        elif i["@Name"] == "AuthenticationPackageName": AuthenticationPackageName = i["#text"]
                        elif i["@Name"] == "ConfigAccessPolicy": ConfigAccessPolicy = i["#text"]
                        elif i["@Name"] == "DisableIntegrityChecks": DisableIntegrityChecks = i["#text"]
                        elif i["@Name"] == "ElevatedToken": ElevatedToken = i["#text"]
                        elif i["@Name"] == "FlightSigning": FlightSigning = i["#text"]
                        elif i["@Name"] == "HypervisorDebug": HypervisorDebug = i["#text"]
                        elif i["@Name"] == "HypervisorLaunchType": HypervisorLaunchType = i["#text"]
                        elif i["@Name"] == "HypervisorLoadOptions": HypervisorLoadOptions = i["#text"]
                        elif i["@Name"] == "ImpersonationLevel": ImpersonationLevel = i["#text"]
                        elif i["@Name"] == "IpAddress": IpAddress = i["#text"]
                        elif i["@Name"] == "IpPort": IpPort = i["#text"]
                        elif i["@Name"] == "KernelDebug": KernelDebug = i["#text"]
                        elif i["@Name"] == "KeyLength": KeyLength = i["#text"]
                        elif i["@Name"] == "LmPackageName": LmPackageName = i["#text"]
                        elif i["@Name"] == "LoadOptions": LoadOptions = i["#text"]
                        elif i["@Name"] == "LogonGuid": LogonGuid = i["#text"]
                        elif i["@Name"] == "LogonProcessName": LogonProcessName = i["#text"]
                        elif i["@Name"] == "LogonType": LogonType = i["#text"]
                        elif i["@Name"] == "PrivilegeList": PrivilegeList = i["#text"]
                        elif i["@Name"] == "PuaCount": PuaCount = i["#text"]
                        elif i["@Name"] == "PuaPolicyId": PuaPolicyId = i["#text"]
                        elif i["@Name"] == "RemoteEventLogging": RemoteEventLogging = i["#text"]
                        elif i["@Name"] == "RestrictedAdminMode": RestrictedAdminMode = i["#text"]
                        elif i["@Name"] == "SamAccountName": SamAccountName = i["#text"]
                        elif i["@Name"] == "SidHistory": SidHistory = i["#text"]
                        elif i["@Name"] == "TargetLinkedLogonId": TargetLinkedLogonId = i["#text"]
                        elif i["@Name"] == "TargetOutboundDomainName": TargetOutboundDomainName = i["#text"]
                        elif i["@Name"] == "TargetOutboundUserName": TargetOutboundUserName = i["#text"]
                        elif i["@Name"] == "TargetSid": TargetSid = i["#text"]
                        elif i["@Name"] == "TestSigning": TestSigning = i["#text"]
                        elif i["@Name"] == "TransmittedServices": TransmittedServices = i["#text"]
                        elif i["@Name"] == "VirtualAccount": VirtualAccount = i["#text"]
                        elif i["@Name"] == "VsmLaunchType": VsmLaunchType = i["#text"]
                        elif i["@Name"] == "WorkstationName": WorkstationName = i["#text"]
                        elif i["@Name"] == "AccessGranted": AccessGranted = i["#text"]
                        elif i["@Name"] == "AccessRemoved": AccessRemoved = i["#text"]
                        elif i["@Name"] == "AccountExpires": AccountExpires = i["#text"]
                        elif i["@Name"] == "AllowedToDelegateTo": AllowedToDelegateTo = i["#text"]
                        elif i["@Name"] == "CallerProcessId": CallerProcessId = i["#text"]
                        elif i["@Name"] == "CallerProcessName": CallerProcessName = i["#text"]
                        elif i["@Name"] == "ClientProcessId": ClientProcessId = i["#text"]
                        elif i["@Name"] == "CountOfCredentialsReturned": CountOfCredentialsReturned = i["#text"]
                        elif i["@Name"] == "DisplayName": DisplayName = i["#text"]
                        elif i["@Name"] == "DomainBehaviorVersion": DomainBehaviorVersion = i["#text"]
                        elif i["@Name"] == "DomainName": DomainName = i["#text"]
                        elif i["@Name"] == "DomainPolicyChanged": DomainPolicyChanged = i["#text"]
                        elif i["@Name"] == "DomainSid": DomainSid = i["#text"]
                        elif i["@Name"] == "Dummy": Dummy = i["#text"]
                        elif i["@Name"] == "ForceLogoff": ForceLogOff = i["#text"]
                        elif i["@Name"] == "HandleId": HandleId = i["#text"]
                        elif i["@Name"] == "HomeDirectory": HomeDirectory = i["#text"]
                        elif i["@Name"] == "HomePath": HomePath = i["#text"]
                        elif i["@Name"] == "LockoutDuration": LockoutDuration = i["#text"] 
                        elif i["@Name"] == "LockoutObservationWindow": LockoutObservationWindow = i["#text"]
                        elif i["@Name"] == "LockoutThreshold": LockoutThreshold = i["#text"]
                        elif i["@Name"] == "LogonHours": LogonHours = i["#text"]
                        elif i["@Name"] == "MachineAccountQuota": MachineAccountQuota = i["#text"]
                        elif i["@Name"] == "MaxPasswordAge": MaxPasswordAge = i["#text"]
                        elif i["@Name"] == "MemberName": MemberName = i["#text"]
                        elif i["@Name"] == "MemberSid": MemberSid = i["#text"]
                        elif i["@Name"] == "MinPasswordAge": MinPasswordAge = i["#text"]
                        elif i["@Name"] == "MinPasswordLength": MinPasswordLength = i["#text"]
                        elif i["@Name"] == "MixedDomainMode": MixedDomainMode = i["#text"]
                        elif i["@Name"] == "NewSd": NewSd = i["#text"]
                        elif i["@Name"] == "NewUacValue": NewUacValue = i["#text"]
                        elif i["@Name"] == "ObjectName": ObjectName = i["#text"]
                        elif i["@Name"] == "ObjectServer": ObjectServer = i["#text"]
                        elif i["@Name"] == "ObjectType": ObjectType = i["#text"]
                        elif i["@Name"] == "OemInformation": OemInformation = i["#text"]
                        elif i["@Name"] == "OldSd": OldSd = i["#text"]
                        elif i["@Name"] == "OldUacValue": OldUacValue = i["#text"]
                        elif i["@Name"] == "PasswordHistoryLength": PasswordHistoryLength = i["#text"]
                        elif i["@Name"] == "PasswordLastSet": PasswordLastSet = i["#text"]
                        elif i["@Name"] == "PasswordProperties": PasswordProperties = i["#text"]
                        elif i["@Name"] == "PrimaryGroupId": PrimaryGroupId = i["#text"]
                        elif i["@Name"] == "ProcessCreationTime": ProcessCreationTime = i["#text"]
                        elif i["@Name"] == "ProfilePath": ProfilePath = i["#text"]
                        elif i["@Name"] == "ReadOperation": ReadOperation = i["#text"]
                        elif i["@Name"] == "ReturnCode": ReturnCode = i["#text"]
                        elif i["@Name"] == "ScriptPath": ScriptPath = i["#text"]
                        elif i["@Name"] == "TargetInfo": TargetInfo = i["#text"]
                        elif i["@Name"] == "TargetLogonGuid": TargetLogonGuid = i["#text"]
                        elif i["@Name"] == "TargetName": TargetName = i["#text"]
                        elif i["@Name"] == "TargetServerName": TargetServerName = i["#text"]
                        elif i["@Name"] == "Type": Type = i["#text"]
                        elif i["@Name"] == "UserAccountControl": UserAccountControl = i["#text"]
                        elif i["@Name"] == "UserParameters": UserParameters = i["#text"]
                        elif i["@Name"] == "UserPrincipalName": UserPrincipalName = i["#text"]
                        elif i["@Name"] == "UserWorkstations": UserWorkstations = i["#text"]
                        elif i["@Name"] == "AlgorithmName": AlgorithmName = i["#text"]
                        elif i["@Name"] == "ClientCreationTime": ClientCreationTime = i["#text"]
                        elif i["@Name"] == "FailureReason": FailureReason = i["#text"]
                        elif i["@Name"] == "Flags": Flags = i["#text"]
                        elif i["@Name"] == "Identity": Identity = i["#text"]
                        elif i["@Name"] == "KeyFilePath": KeyFilePath = i["#text"]
                        elif i["@Name"] == "KeyName": KeyName = i["#text"]
                        elif i["@Name"] == "KeyType": KeyType = i["#text"]
                        elif i["@Name"] == "NewTargetUserName": NewTargetUserName = i["#text"]
                        elif i["@Name"] == "NewTime": NewTime = i["#text"]
                        elif i["@Name"] == "ObjectCollectionName": ObjectCollectionName = i["#text"]
                        elif i["@Name"] == "ObjectIdentifyingProperties": ObjectIdentifyingProperties = i["#text"]
                        elif i["@Name"] == "ObjectProperties": ObjectProperties = i["#text"]
                        elif i["@Name"] == "OldTargetUserName": OldTargetUserName = i["#text"]
                        elif i["@Name"] == "Operation": Operation = i["#text"]
                        elif i["@Name"] == "PackageName": PackageName = i["#text"]
                        elif i["@Name"] == "PreviousTime": PreviousTime = i["#text"]
                        elif i["@Name"] == "ProviderName": ProviderName = i["#text"]
                        elif i["@Name"] == "Resource": Resource = i["#text"]
                        elif i["@Name"] == "Schema": Schema = i["#text"]
                        elif i["@Name"] == "SchemaFriendlyName": SchemaFriendlyName = i["#text"]
                        elif i["@Name"] == "Status": Status = i["#text"]
                        elif i["@Name"] == "SubjectUserDomainName": SubjectUserDomainName = i["#text"]
                        elif i["@Name"] == "SubStatus": SubStatus = i["#text"]
                        elif i["@Name"] == "Workstation": Workstation = i["#text"]
                        elif i["@Name"] == "ContextInfo": ContextInfo = i["#text"]
                        elif i["@Name"] == "MessageNumber": MessageNumber = i["#text"]
                        elif i["@Name"] == "MessageTotal": MessageTotal = i["#text"]
                        elif i["@Name"] == "param1": param1 = i["#text"]
                        elif i["@Name"] == "param2": param2 = i["#text"]
                        elif i["@Name"] == "Payload": Payload = i["#text"]
                        elif i["@Name"] == "ScriptBlockId": ScriptBlockId = i["#text"]
                        elif i["@Name"] == "ScriptBlockText": 
                            #print(i)
                            ScriptBlockText = i["#text"]
                        else:
                            print("Missing data field: " + i['@Name'])
                eventID = eventID.replace("\"", "@@")
                timeCreated = timeCreated.replace("\"", "@@")
                channel = channel.replace("\"", "@@")
                computer = computer.replace("\"", "@@")
                SubjectUserSid = SubjectUserSid.replace("\"", "@@")
                SubjectUserName = SubjectUserName.replace("\"", "@@")
                SubjectDomainName = SubjectDomainName.replace("\"", "@@")
                SubjectLogonId = SubjectLogonId.replace("\"", "@@")
                NewProcessId = NewProcessId.replace("\"", "@@")
                NewProcessName = NewProcessName.replace("\"", "@@")
                TokenElevationType = TokenElevationType.replace("\"", "@@")
                ProcessId = ProcessId.replace("\"", "@@")
                ProcessName = ProcessName.replace("\"", "@@")
                CommandLine = CommandLine.replace("\"", "@@")
                TargetUserSid = TargetUserSid.replace("\"", "@@")
                TargetUserName = TargetUserName.replace("\"", "@@")
                TargetDomainName = TargetDomainName.replace("\"", "@@")
                TargetLogonId = TargetLogonId.replace("\"", "@@")
                TargetProcessId = TargetProcessId.replace("\"", "@@")
                TargetProcessName = TargetProcessName.replace("\"", "@@")
                ParentProcessName = ParentProcessName.replace("\"", "@@")
                MandatoryLabel = MandatoryLabel.replace("\"", "@@")
                AdvancedOptions = AdvancedOptions.replace("\"", "@@")
                AuthenticationPackageName = AuthenticationPackageName.replace("\"", "@@")
                ConfigAccessPolicy = ConfigAccessPolicy.replace("\"", "@@")
                DisableIntegrityChecks = DisableIntegrityChecks.replace("\"", "@@")
                ElevatedToken = ElevatedToken.replace("\"", "@@")
                FlightSigning = FlightSigning.replace("\"", "@@")
                HypervisorDebug = HypervisorDebug.replace("\"", "@@")
                HypervisorLaunchType = HypervisorLaunchType.replace("\"", "@@")
                HypervisorLoadOptions = HypervisorLoadOptions.replace("\"", "@@")
                ImpersonationLevel = ImpersonationLevel.replace("\"", "@@")
                IpAddress = IpAddress.replace("\"", "@@")
                IpPort = IpPort.replace("\"", "@@")
                KernelDebug = KernelDebug.replace("\"", "@@")
                KeyLength = KeyLength.replace("\"", "@@")
                LmPackageName = LmPackageName.replace("\"", "@@")
                LoadOptions = LoadOptions.replace("\"", "@@")
                LogonGuid = LogonGuid.replace("\"", "@@")
                LogonProcessName = LogonProcessName.replace("\"", "@@")
                LogonType = LogonType.replace("\"", "@@")
                PrivilegeList = PrivilegeList.replace("\"", "@@")
                PuaCount = PuaCount.replace("\"", "@@")
                PuaPolicyId = PuaPolicyId.replace("\"", "@@")
                RemoteEventLogging = RemoteEventLogging.replace("\"", "@@")
                RestrictedAdminMode = RestrictedAdminMode.replace("\"", "@@")
                SamAccountName = SamAccountName.replace("\"", "@@")
                SidHistory = SidHistory.replace("\"", "@@")
                TargetLinkedLogonId = TargetLinkedLogonId.replace("\"", "@@")
                TargetOutboundDomainName = TargetOutboundDomainName.replace("\"", "@@")
                TargetOutboundUserName = TargetOutboundUserName.replace("\"", "@@")
                TargetSid = TargetSid.replace("\"", "@@")
                TestSigning = TestSigning.replace("\"", "@@")
                TransmittedServices = TransmittedServices.replace("\"", "@@")
                VirtualAccount = VirtualAccount.replace("\"", "@@")
                VsmLaunchType = VsmLaunchType.replace("\"", "@@")
                WorkstationName = WorkstationName.replace("\"", "@@")
                AccessGranted = AccessGranted.replace("\"", "@@")
                AccessRemoved = AccessRemoved.replace("\"", "@@")
                AccountExpires = AccountExpires.replace("\"", "@@")
                AllowedToDelegateTo = AllowedToDelegateTo.replace("\"", "@@")
                CallerProcessId = CallerProcessId.replace("\"", "@@")
                CallerProcessName = CallerProcessName.replace("\"", "@@")
                ClientProcessId = ClientProcessId.replace("\"", "@@")
                CountOfCredentialsReturned = CountOfCredentialsReturned.replace("\"", "@@")
                DisplayName = DisplayName.replace("\"", "@@")
                DomainBehaviorVersion = DomainBehaviorVersion.replace("\"", "@@")
                DomainName = DomainName.replace("\"", "@@")
                DomainPolicyChanged = DomainPolicyChanged.replace("\"", "@@")
                DomainSid = DomainSid.replace("\"", "@@")
                Dummy = Dummy.replace("\"", "@@")
                ForceLogoff = ForceLogoff.replace("\"", "@@")
                HandleId = HandleId.replace("\"", "@@")
                HomeDirectory = HomeDirectory.replace("\"", "@@")
                HomePath = HomePath.replace("\"", "@@")
                LockoutDuration = LockoutDuration.replace("\"", "@@")
                LockoutObservationWindow = LockoutObservationWindow.replace("\"", "@@")
                LockoutThreshold = LockoutThreshold.replace("\"", "@@")
                LogonHours = LogonHours.replace("\"", "@@")
                MachineAccountQuota = MachineAccountQuota.replace("\"", "@@")
                MaxPasswordAge = MaxPasswordAge.replace("\"", "@@")
                MemberName = MemberName.replace("\"", "@@")
                MemberSid = MemberSid.replace("\"", "@@")
                MinPasswordAge = MinPasswordAge.replace("\"", "@@")
                MinPasswordLength = MinPasswordLength.replace("\"", "@@")
                MixedDomainMode = MixedDomainMode.replace("\"", "@@")
                NewSd = NewSd.replace("\"", "@@")
                NewUacValue = NewUacValue.replace("\"", "@@")
                ObjectName = ObjectName.replace("\"", "@@")
                ObjectServer = ObjectServer.replace("\"", "@@")
                ObjectType = ObjectType.replace("\"", "@@")
                OemInformation = OemInformation.replace("\"", "@@")
                OldSd = OldSd.replace("\"", "@@")
                OldUacValue = OldUacValue.replace("\"", "@@")
                PasswordHistoryLength = PasswordHistoryLength.replace("\"", "@@")
                PasswordLastSet = PasswordLastSet.replace("\"", "@@")
                PasswordProperties = PasswordProperties.replace("\"", "@@")
                PrimaryGroupId = PrimaryGroupId.replace("\"", "@@")
                ProcessCreationTime = ProcessCreationTime.replace("\"", "@@")
                ProfilePath = ProfilePath.replace("\"", "@@")
                ReadOperation = ReadOperation.replace("\"", "@@")
                ReturnCode = ReturnCode.replace("\"", "@@")
                ScriptPath = ScriptPath.replace("\"", "@@")
                TargetInfo = TargetInfo.replace("\"", "@@")
                TargetLogonGuid = TargetLogonGuid.replace("\"", "@@")
                TargetName = TargetName.replace("\"", "@@")
                TargetServerName = TargetServerName.replace("\"", "@@")
                Type = Type.replace("\"", "@@")
                UserAccountControl = UserAccountControl.replace("\"", "@@")
                UserParameters = UserParameters.replace("\"", "@@")
                UserPrincipalName = UserPrincipalName.replace("\"", "@@")
                UserWorkstations = UserWorkstations.replace("\"", "@@")
                AlgorithmName = AlgorithmName.replace("\"", "@@")
                ClientCreationTime = ClientCreationTime.replace("\"", "@@")
                FailureReason = FailureReason.replace("\"", "@@")
                Flags = Flags.replace("\"", "@@")
                Identity = Identity.replace("\"", "@@")
                KeyFilePath = KeyFilePath.replace("\"", "@@")
                KeyName = KeyName.replace("\"", "@@")
                KeyType = KeyType.replace("\"", "@@")
                NewTargetUserName = NewTargetUserName.replace("\"", "@@")
                NewTime = NewTime.replace("\"", "@@")
                ObjectCollectionName = ObjectCollectionName.replace("\"", "@@")
                ObjectIdentifyingProperties = ObjectIdentifyingProperties.replace("\"", "@@")
                ObjectProperties = ObjectProperties.replace("\"", "@@")
                OldTargetUserName = OldTargetUserName.replace("\"", "@@")
                Operation = Operation.replace("\"", "@@")
                PackageName = PackageName.replace("\"", "@@")
                PreviousTime = PreviousTime.replace("\"", "@@")
                ProviderName = ProviderName.replace("\"", "@@")
                Resource = Resource.replace("\"", "@@")
                Schema = Schema.replace("\"", "@@")
                SchemaFriendlyName = SchemaFriendlyName.replace("\"", "@@")
                Status = Status.replace("\"", "@@")
                SubjectUserDomainName = SubjectUserDomainName.replace("\"", "@@")
                SubStatus = SubStatus.replace("\"", "@@")
                Workstation = Workstation.replace("\"", "@@")
                ContextInfo = ContextInfo.replace("\"", "@@")
                MessageNumber = MessageNumber.replace("\"", "@@")
                MessageTotal = MessageTotal.replace("\"", "@@")
                param1 = param1.replace("\"", "@@")
                param2 = param2.replace("\"", "@@")
                Payload = Payload.replace("\"", "@@")
                ScriptBlockId = ScriptBlockId.replace("\"", "@@")
                ScriptBlockText = ScriptBlockText.replace("\"", "@@")
                # Print all fields...
                #print("\"" + eventID + "\",\""  + timeCreated + "\",\""  + channel + "\",\""  + computer + "\",\""  + SubjectUserSid + "\",\""  + SubjectUserName + "\",\""  + SubjectDomainName + "\",\""  + SubjectLogonId + "\",\""  + NewProcessId + "\",\""  + NewProcessName + "\",\""  + TokenElevationType + "\",\""  + ProcessId + "\",\""  + ProcessName + "\",\""  + CommandLine + "\",\""  + TargetUserSid + "\",\""  + TargetUserName + "\",\""  + TargetDomainName + "\",\""  + TargetLogonId + "\",\""  + TargetProcessId + "\",\""  + TargetProcessName + "\",\""  + ParentProcessName + "\",\""  + MandatoryLabel + "\",\""  + AdvancedOptions + "\",\""  + AuthenticationPackageName + "\",\""  + ConfigAccessPolicy + "\",\""  + DisableIntegrityChecks + "\",\""  + ElevatedToken + "\",\""  + FlightSigning + "\",\""  + HypervisorDebug + "\",\""  + HypervisorLaunchType + "\",\""  + HypervisorLoadOptions + "\",\""  + ImpersonationLevel + "\",\""  + IpAddress + "\",\""  + IpPort + "\",\""  + KernelDebug + "\",\""  + KeyLength + "\",\""  + LmPackageName + "\",\""  + LoadOptions + "\",\""  + LogonGuid + "\",\""  + LogonProcessName + "\",\""  + LogonType + "\",\""  + PrivilegeList + "\",\""  + PuaCount + "\",\""  + PuaPolicyId + "\",\""  + RemoteEventLogging + "\",\""  + RestrictedAdminMode + "\",\""  + SamAccountName + "\",\""  + SidHistory + "\",\""  + TargetLinkedLogonId + "\",\""  + TargetOutboundDomainName + "\",\""  + TargetOutboundUserName + "\",\""  + TargetSid + "\",\""  + TestSigning + "\",\""  + TransmittedServices + "\",\""  + VirtualAccount + "\",\""  + VsmLaunchType + "\",\""  + WorkstationName + "\",\""  + AccessGranted + "\",\""  + AccessRemoved + "\",\""  + AccountExpires + "\",\""  + AllowedToDelegateTo + "\",\""  + CallerProcessId + "\",\""  + CallerProcessName + "\",\""  + ClientProcessId + "\",\""  + CountOfCredentialsReturned + "\",\""  + DisplayName + "\",\""  + DomainBehaviorVersion + "\",\""  + DomainName + "\",\""  + DomainPolicyChanged + "\",\""  + DomainSid + "\",\""  + Dummy + "\",\""  + ForceLogoff + "\",\""  + HandleId + "\",\""  + HomeDirectory + "\",\""  + HomePath + "\",\""  + LockoutDuration + "\",\""  + LockoutObservationWindow + "\",\""  + LockoutThreshold + "\",\""  + LogonHours + "\",\""  + MachineAccountQuota + "\",\""  + MaxPasswordAge + "\",\""  + MemberName + "\",\""  + MemberSid + "\",\""  + MinPasswordAge + "\",\""  + MinPasswordLength + "\",\""  + MixedDomainMode + "\",\""  + NewSd + "\",\""  + NewUacValue + "\",\""  + ObjectName + "\",\""  + ObjectServer + "\",\""  + ObjectType + "\",\""  + OemInformation + "\",\""  + OldSd + "\",\""  + OldUacValue + "\",\""  + PasswordHistoryLength + "\",\""  + PasswordLastSet + "\",\""  + PasswordProperties + "\",\""  + PrimaryGroupId + "\",\""  + ProcessCreationTime + "\",\""  + ProfilePath + "\",\""  + ReadOperation + "\",\""  + ReturnCode + "\",\""  + ScriptPath + "\",\""  + TargetInfo + "\",\""  + TargetLogonGuid + "\",\""  + TargetName + "\",\""  + TargetServerName + "\",\""  + Type + "\",\""  + UserAccountControl + "\",\""  + UserParameters + "\",\""  + UserPrincipalName + "\",\""  + UserWorkstations + "\",\""  + AlgorithmName + "\",\""  + ClientCreationTime + "\",\""  + FailureReason + "\",\""  + Flags + "\",\""  + Identity + "\",\""  + KeyFilePath + "\",\""  + KeyName + "\",\""  + KeyType + "\",\""  + NewTargetUserName + "\",\""  + NewTime + "\",\""  + ObjectCollectionName + "\",\""  + ObjectIdentifyingProperties + "\",\""  + ObjectProperties + "\",\""  + OldTargetUserName + "\",\""  + Operation + "\",\""  + PackageName + "\",\""  + PreviousTime + "\",\""  + ProviderName + "\",\""  + Resource + "\",\""  + Schema + "\",\""  + SchemaFriendlyName + "\",\""  + Status + "\",\""  + SubjectUserDomainName + "\",\""  + SubStatus + "\",\""  + Workstation + "\",\""  + ContextInfo + "\",\""  + MessageNumber + "\",\""  + MessageTotal + "\",\""  + param1 + "\",\""  + param2 + "\",\""  + Payload + "\",\""  + ScriptBlockId + "\",\""  + ScriptBlockText + "\"")
                # Specific Fields for output of powershell logs
                print("\"" + eventID + "\",\""  + timeCreated + "\",\""  + channel + "\",\""  + computer + "\",\""  + ContextInfo + "\",\""  + MessageNumber + "\",\""  + MessageTotal + "\",\""  + param1 + "\",\""  + param2 + "\",\""  + Payload + "\",\""  + ScriptBlockId + "\",\""  + ScriptBlockText + "\"")
        #print(MandatoryLabel)
        #for i in obj['Event']['System']:
        #    print(i['EventID'])
        #pprint(json.dumps(obj))
        #pprint(obj['Event'])
        #print("\n")
        count += 1
        # Counter to limit the number of event logs evaluated to troubleshoot...
        #if count == 1500:
        #    exit()
