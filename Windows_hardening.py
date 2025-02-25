import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import subprocess
import winreg
import json
import os
import shutil
from datetime import datetime
import threading

class StatusIndicator(tk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.configure(bg='#f5f6fa')
       
        self.status_label = tk.Label(
            self,
            text="●",
            font=('Segoe UI', 14, 'bold'),
            bg='#f5f6fa',
            padx=5
        )
        self.status_label.pack(side=tk.LEFT)
       
        self.text_label = tk.Label(
            self,
            text="Unknown",
            font=('Segoe UI', 13),
            bg='#f5f6fa',
            fg='#2f3640'
        )
        self.text_label.pack(side=tk.LEFT)
   
    def update_status(self, status):
        if status == "Enabled":
            self.status_label.configure(fg='#44bd32', text="●")
            self.text_label.configure(text="Enabled")
        elif status == "Disabled":
            self.status_label.configure(fg='#e84118', text="●")
            self.text_label.configure(text="Disabled")
        else:
            self.status_label.configure(fg='#7f8fa6', text="●")
            self.text_label.configure(text="Unknown")

class WindowsHardeningTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows Security Hardening Tool")
        self.root.geometry("800x600")
       
        # Define controls 
        self.controls = {
            "advertising_id": {
                "name": "General Windows Permissions",
                "enable_cmd": '''
               
                    # Create required registry paths
                    $paths = @(
                        "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo",
                        "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Privacy",
                        "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
                        "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SearchSettings",
                        "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
                        "HKCU:\\Control Panel\\International\\User Profile"
                    )

                    foreach ($path in $paths) {
                        if (!(Test-Path $path)) {
                            New-Item -Path $path -Force
                        }
                    }

                    # Enable Advertising ID
                    New-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo" -Name "Enabled" -Value 1 -PropertyType DWord -Force
                   
                    # Enable local content
                    Set-ItemProperty -Path "HKCU:\\Control Panel\\International\\User Profile" -Name "HttpAcceptLanguageOptOut" -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 1 -Type DWord -Force
                   
                    # Enable Start and Search suggestions
                    Set-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SearchSettings" -Name "IsDeviceSearchHistoryEnabled" -Value 1 -Type DWord
                    Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" -Name "ShowSyncProviderNotifications" -Value 1 -Type DWord
                    Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" -Name "Start_TrackProgs" -Value 1 -Type DWord
                    Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 1 -Type DWord
                   
                    # Enable suggested content in Settings app
                    New-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value 1 -PropertyType DWord -Force
                    New-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value 1 -PropertyType DWord -Force
                    New-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value 1 -PropertyType DWord -Force
                ''',
                "disable_cmd": '''

                    # Create required registry paths
                    $paths = @(
                        "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo",
                        "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Privacy",
                        "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
                        "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SearchSettings",
                        "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
                        "HKCU:\\Control Panel\\International\\User Profile"
                    )

                    foreach ($path in $paths) {
                        if (!(Test-Path $path)) {
                            New-Item -Path $path -Force
                        }
                    }

                    # Disable Advertising ID
                    New-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo" -Name "Enabled" -Value 0 -PropertyType DWord -Force
                   
                    # Disable local content
                    Set-ItemProperty -Path "HKCU:\\Control Panel\\International\\User Profile" -Name "HttpAcceptLanguageOptOut" -Value 1 -Type DWord -Force
                    Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -Type DWord -Force
                   
                    # Disable Start and Search suggestions
                    Set-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SearchSettings" -Name "IsDeviceSearchHistoryEnabled" -Value 0 -Type DWord
                    Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" -Name "ShowSyncProviderNotifications" -Value 0 -Type DWord
                    Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" -Name "Start_TrackProgs" -Value 0 -Type DWord
                    Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0 -Type DWord
                   
                    # Disable suggested content in Settings app
                    New-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value 0 -PropertyType DWord -Force
                    New-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value 0 -PropertyType DWord -Force
                    New-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value 0 -PropertyType DWord -Force
                '''
            },
            "location_tracking": {
                "name": "Location Tracking",
                "enable_cmd": '''
                    New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location" -Name "Value" -Value "Allow" -PropertyType String -Force
                ''',
                "disable_cmd": '''
                    New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location" -Name "Value" -Value "Deny" -PropertyType String -Force
                '''
            },
            "microsoft_updates": {
    "name": "Microsoft Updates",
    "enable_cmd": '''
                  #to check --> windows->services
        try {
            # Create Windows Update path if it doesn't exist
            $path = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Services\\7971f918-a847-4430-9279-4a52d1efe18d"
            if (!(Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }

            # Enable Microsoft Updates
            Set-ItemProperty -Path $path -Name "RegisterWithAU" -Value 1 -Type DWord -Force
           
            # Enable the Windows Update service
            Set-Service -Name "wuauserv" -StartupType Automatic
            Start-Service -Name "wuauserv"
           
            # Enable Microsoft Update access in Windows Update
            $updatePath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
            if (!(Test-Path $updatePath)) {
                New-Item -Path $updatePath -Force | Out-Null
            }
            Set-ItemProperty -Path $updatePath -Name "UseWUServer" -Value 0 -Type DWord -Force
           
            # Remove any policy blocks
            $policyPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate"
            if (!(Test-Path $policyPath)) {
                New-Item -Path $policyPath -Force | Out-Null
            }
            Set-ItemProperty -Path $policyPath -Name "DisableMicrosoftUpdateAccess" -Value 0 -Type DWord -Force
           
            # Force Windows Update to check for updates
            wuauclt /resetauthorization /detectnow
           
            Write-Output "Microsoft Product Updates have been enabled"
        } catch {
            Write-Error "Failed to enable Microsoft Product Updates: $_"
            throw $_
        }
    ''',
    "disable_cmd": '''
        try {
            # Create Windows Update path if it doesn't exist
            $path = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Services\\7971f918-a847-4430-9279-4a52d1efe18d"
            if (!(Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }

            # Disable Microsoft Updates
            Set-ItemProperty -Path $path -Name "RegisterWithAU" -Value 0 -Type DWord -Force
           
            # Stop and disable the Windows Update service
            Stop-Service -Name "wuauserv" -Force
            Set-Service -Name "wuauserv" -StartupType Automatic
           
            # Block Microsoft Update access in Windows Update
            $updatePath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
            if (!(Test-Path $updatePath)) {
                New-Item -Path $updatePath -Force | Out-Null
            }
            Set-ItemProperty -Path $updatePath -Name "UseWUServer" -Value 1 -Type DWord -Force
           
            # Add policy block
            $policyPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate"
            if (!(Test-Path $policyPath)) {
                New-Item -Path $policyPath -Force | Out-Null
            }
            Set-ItemProperty -Path $policyPath -Name "DisableMicrosoftUpdateAccess" -Value 1 -Type DWord -Force
           
            Write-Output "Microsoft Product Updates have been disabled"
        } catch {
            Write-Error "Failed to disable Microsoft Product Updates: $_"
            throw $_
        }
    '''
},
            "peer_updates": {
    "name": "Peer Updates",
    "enable_cmd": '''
        try {
            # Enable Delivery Optimization in HKLM (Local Machine)
            Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config" -Name "DODownloadMode" -Value 1 -Type DWord -Force

            # Enable Delivery Optimization in HKCU (Current User)
            Set-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Value 1 -Type DWord -Force

            # Enable Delivery Optimization in Policies (if needed, but avoid locking the UI)
            $policyPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization"
            if (!(Test-Path $policyPath)) {
                New-Item -Path $policyPath -Force | Out-Null
            }
            Set-ItemProperty -Path $policyPath -Name "DODownloadMode" -Value 1 -Type DWord -Force

            # Enable and start the Delivery Optimization service
            $service = Get-Service -Name "DoSvc" -ErrorAction SilentlyContinue
            if ($service) {
                Set-Service -Name "DoSvc" -StartupType Automatic
                Start-Service -Name "DoSvc"
            }

            # Enable BITS service as it's required for Delivery Optimization
            Set-Service -Name "BITS" -StartupType Automatic
            Start-Service -Name "BITS"

            # Refresh the Windows Settings UI
            Stop-Process -Name "SystemSettings" -Force -ErrorAction SilentlyContinue

            Write-Output "Peer Updates have been enabled"
        } catch {
            Write-Error "Failed to enable Peer Updates: $_"
            throw $_
        }
    ''',
    "disable_cmd": '''
        try {
            # Disable Delivery Optimization in HKLM (Local Machine)
            Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config" -Name "DODownloadMode" -Value 0 -Type DWord -Force

            # Disable Delivery Optimization in HKCU (Current User)
            Set-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Value 0 -Type DWord -Force

            # Disable Delivery Optimization in Policies (if needed, but avoid locking the UI)
            $policyPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization"
            if (!(Test-Path $policyPath)) {
                New-Item -Path $policyPath -Force | Out-Null
            }
            Set-ItemProperty -Path $policyPath -Name "DODownloadMode" -Value 0 -Type DWord -Force

            # Stop and disable the Delivery Optimization service
            $service = Get-Service -Name "DoSvc" -ErrorAction SilentlyContinue
            if ($service) {
                Stop-Service -Name "DoSvc" -Force
                Set-Service -Name "DoSvc" -StartupType Disabled
            }

            # Stop and disable the BITS service
            Set-Service -Name "BITS" -StartupType Disabled
            Stop-Service -Name "BITS" -Force

            # Clear the Delivery Optimization cache
            if (Test-Path "$env:WINDIR\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache") {
                Remove-Item "$env:WINDIR\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache\\*" -Recurse -Force -ErrorAction SilentlyContinue
            }

            # Refresh the Windows Settings UI
            Stop-Process -Name "SystemSettings" -Force -ErrorAction SilentlyContinue

            Write-Output "Peer Updates have been disabled"
        } catch {
            Write-Error "Failed to disable Peer Updates: $_"
            throw $_
        }
    '''
},
            "windows_firewall": {
                "name": "Windows Firewall",
                "enable_cmd": '''
                    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
                    Set-NetFirewallProfile -Profile Domain,Public,Private -NotifyOnListen True
                ''',
                "disable_cmd": '''
                    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
                    Set-NetFirewallProfile -Profile Domain,Public,Private -NotifyOnListen False
                '''
            },
           "virus_threat_protection": {
    "name": "Virus & Threat Protection",
    "enable_cmd": '''
        try {
            # Enable Real-time protection
            Set-MpPreference -DisableRealtimeMonitoring $false
           
            # Enable Cloud-delivered protection
            Set-MpPreference -MAPSReporting Advanced
            Set-MpPreference -SubmitSamplesConsent Always
           
            # Enable Automatic sample submission
            Set-MpPreference -SubmitSamplesConsent 1
           
            # Enable all relevant services
            $services = @("WinDefend", "WdNisSvc", "SecurityHealthService")
            foreach ($service in $services) {
                $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
                if ($svc) {
                    if ($svc.Status -ne 'Running') {
                        Start-Service -Name $service
                    }
                    Set-Service -Name $service -StartupType Automatic
                }
            }
           
            # Enable additional protections
            Set-MpPreference -DisableBehaviorMonitoring $false
            Set-MpPreference -DisableBlockAtFirstSeen $false
            Set-MpPreference -DisableIOAVProtection $false
            Set-MpPreference -DisableScriptScanning $false
            Set-MpPreference -DisableArchiveScanning $false
           
            Write-Output "Virus & Threat Protection features have been enabled"
        } catch {
            Write-Error "Failed to enable Virus & Threat Protection features: $_"
            throw $_
        }
    ''',
    "disable_cmd": '''
        try {
            # Disable Real-time protection
            Set-MpPreference -DisableRealtimeMonitoring $true
           
            # Disable Cloud-delivered protection
            Set-MpPreference -MAPSReporting Disabled
            Set-MpPreference -SubmitSamplesConsent Never
           
            # Disable Automatic sample submission
            Set-MpPreference -SubmitSamplesConsent 0
           
            # Disable all relevant services
            $services = @("WinDefend", "WdNisSvc", "SecurityHealthService")
            foreach ($service in $services) {
                $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
                if ($svc) {
                    if ($svc.Status -eq 'Running') {
                        Stop-Service -Name $service
                    }
                    Set-Service -Name $service -StartupType Disabled
                }
            }
           

            # Disable additional protections
            Set-MpPreference -DisableBehaviorMonitoring $true
            Set-MpPreference -DisableBlockAtFirstSeen $true
            Set-MpPreference -DisableIOAVProtection $true
            Set-MpPreference -DisableScriptScanning $true
            Set-MpPreference -DisableArchiveScanning $true
           
            Write-Output "Virus & Threat Protection features have been disabled"
        } catch {
            Write-Error "Failed to disable Virus & Threat Protection features: $_"
            throw $_
        }
    '''
},
            "reputation_based_protection": {
    "name": "Reputation-based Protection",
    "enable_cmd": '''
        try {
            # Enable SmartScreen for apps and files
            $configureSmartScreen = @'
            New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer" -Name "SmartScreenEnabled" -Value "RequireAdmin" -PropertyType String -Force
            New-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer" -Name "SmartScreenEnabled" -Value "RequireAdmin" -PropertyType String -Force
           
            # For Windows 10/11 specific path
            New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost" -Name "EnableWebContentEvaluation" -Value 1 -PropertyType DWord -Force
            New-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost" -Name "EnableWebContentEvaluation" -Value 1 -PropertyType DWord -Force
'@
           
            # Enable SmartScreen Protection for Edge
            $configureEdgeSmartScreen = @'
            $edgePaths = @(
                "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
                "HKCU:\\SOFTWARE\\Policies\\Microsoft\\Edge"
            )
           
            foreach ($path in $edgePaths) {
                if (!(Test-Path $path)) {
                    New-Item -Path $path -Force
                }
                # Enable SmartScreen
                New-ItemProperty -Path $path -Name "SmartScreenEnabled" -Value 1 -PropertyType DWord -Force
                New-ItemProperty -Path $path -Name "SmartScreenPuaEnabled" -Value 1 -PropertyType DWord -Force
               
                # Enhanced protection settings
                New-ItemProperty -Path $path -Name "PreventSmartScreenPromptOverride" -Value 1 -PropertyType DWord -Force
                New-ItemProperty -Path $path -Name "PreventSmartScreenPromptOverrideForFiles" -Value 1 -PropertyType DWord -Force
                New-ItemProperty -Path $path -Name "SmartScreenProtectionMode" -Value 1 -PropertyType DWord -Force
                New-ItemProperty -Path $path -Name "SmartScreenForTrustedDownloadsEnabled" -Value 1 -PropertyType DWord -Force
            }
'@
           
            # Run the SmartScreen configuration commands
            Invoke-Expression $configureSmartScreen
            Invoke-Expression $configureEdgeSmartScreen
           
            # Enable PUA Protection in Windows Defender
            Set-MpPreference -PUAProtection Enabled
           
            Write-Output "Reputation-based protection features have been enabled"
        } catch {
            Write-Error "Failed to enable reputation-based protection features: $_"
            throw $_
        }
    ''',
    "disable_cmd": '''
        try {
            # Disable SmartScreen for apps and files
            $configureSmartScreen = @'
            New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer" -Name "SmartScreenEnabled" -Value "Off" -PropertyType String -Force
            New-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer" -Name "SmartScreenEnabled" -Value "Off" -PropertyType String -Force
           
            # For Windows 10/11 specific path
            New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost" -Name "EnableWebContentEvaluation" -Value 0 -PropertyType DWord -Force
            New-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost" -Name "EnableWebContentEvaluation" -Value 0 -PropertyType DWord -Force
'@
           
            # Disable SmartScreen for Edge
            $configureEdgeSmartScreen = @'
            $edgePaths = @(
                "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
                "HKCU:\\SOFTWARE\\Policies\\Microsoft\\Edge"
            )
           
            foreach ($path in $edgePaths) {
                if (!(Test-Path $path)) {
                    New-Item -Path $path -Force
                }
                # Disable SmartScreen
                New-ItemProperty -Path $path -Name "SmartScreenEnabled" -Value 0 -PropertyType DWord -Force
                New-ItemProperty -Path $path -Name "SmartScreenPuaEnabled" -Value 0 -PropertyType DWord -Force
               
                # Disable enhanced protection settings
                New-ItemProperty -Path $path -Name "PreventSmartScreenPromptOverride" -Value 0 -PropertyType DWord -Force
                New-ItemProperty -Path $path -Name "PreventSmartScreenPromptOverrideForFiles" -Value 0 -PropertyType DWord -Force
                New-ItemProperty -Path $path -Name "SmartScreenProtectionMode" -Value 0 -PropertyType DWord -Force
                New-ItemProperty -Path $path -Name "SmartScreenForTrustedDownloadsEnabled" -Value 0 -PropertyType DWord -Force
            }
'@
           
            # Run the SmartScreen configuration commands
            Invoke-Expression $configureSmartScreen
            Invoke-Expression $configureEdgeSmartScreen
           
            # Disable PUA Protection in Windows Defender
            Set-MpPreference -PUAProtection Disabled
           
            Write-Output "Reputation-based protection features have been disabled"
        } catch {
            Write-Error "Failed to disable reputation-based protection features: $_"
            throw $_
        }
    '''
},  "remote_assistance": {
       "name": "Remote Assistance",
       "enable_cmd": '''
           Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance" -Name "fAllowToGetHelp" -Value 1 -Type DWord
       ''',
       "disable_cmd": '''
           Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -Type DWord
       '''
   },
 "rdp": {
       "name": "Remote Desktop Protocol",
       "enable_cmd": '''
           Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Type DWord
       ''',
       "disable_cmd": '''
           Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" -Name "fDenyTSConnections" -Value 1 -Type DWord
       '''
   },
        "network_level_auth": {
            #to check in ui-->sysdm.cpl-->remote
    "name": "Network Level Authentication",
    "enable_cmd": '''
        try {
            # Enable NLA through Registry
            $path = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp"
            if (!(Test-Path $path)) {
                New-Item -Path $path -Force
            }
            Set-ItemProperty -Path $path -Name "UserAuthentication" -Value 1 -Type DWord
           
            # Also set it via Group Policy
            $gpoPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"
            if (!(Test-Path $gpoPath)) {
                New-Item -Path $gpoPath -Force
            }
            Set-ItemProperty -Path $gpoPath -Name "UserAuthentication" -Value 1 -Type DWord
           
            Write-Output "Network Level Authentication has been enabled"
        } catch {
            Write-Error "Failed to enable Network Level Authentication: $_"
            throw $_
        }
    ''',
    "disable_cmd": '''
        try {
            # Disable NLA through Registry
            $path = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp"
            if (!(Test-Path $path)) {
                New-Item -Path $path -Force
            }
            Set-ItemProperty -Path $path -Name "UserAuthentication" -Value 0 -Type DWord
           
            # Also set it via Group Policy
            $gpoPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"
            if (!(Test-Path $gpoPath)) {
                New-Item -Path $gpoPath -Force
            }
            Set-ItemProperty -Path $gpoPath -Name "UserAuthentication" -Value 0 -Type DWord
           
            Write-Output "Network Level Authentication has been disabled"
        } catch {
            Write-Error "Failed to disable Network Level Authentication: $_"
            throw $_
        }
    '''
}, "autorun": {
       "name": "Autorun",
       "enable_cmd": '''
           Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" -Name "NoDriveTypeAutoRun" -Value 0x91 -Type DWord
       ''',
       "disable_cmd": '''
           Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord
       '''
   },

#to check in ui--> gpedit.msc-->computer config->windows setting->security settings->local polices->security options
        "smb_signing": {
    "name": "SMB Message Signing",
    "enable_cmd": '''
        try {
            # Enable SMB signing for both server and client
            # Server settings
            Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord -Force
       
            # Client settings
            Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord -Force
       
            # Attempt to restart services, but continue if it fails
            try {
                $lanmanServer = Get-Service -Name "LanmanServer" -ErrorAction Stop
                if ($lanmanServer.Status -eq 'Running') {
                    Stop-Service -Name "LanmanServer" -Force -ErrorAction Stop
                    Start-Service -Name "LanmanServer" -ErrorAction Stop
                }
            } catch {
                Write-Warning "Note: LanmanServer service restart was not completed. Changes will take effect after next restart."
            }
           
            try {
                $lanmanWorkstation = Get-Service -Name "LanmanWorkstation" -ErrorAction Stop
                if ($lanmanWorkstation.Status -eq 'Running') {
                    Stop-Service -Name "LanmanWorkstation" -Force -ErrorAction Stop
                    Start-Service -Name "LanmanWorkstation" -ErrorAction Stop
                }
            } catch {
                Write-Warning "Note: LanmanWorkstation service restart was not completed. Changes will take effect after next restart."
            }
       
            Write-Output "SMB Message Signing has been enabled"
            $true  # Return success
        } catch {
            Write-Error "Failed to enable SMB Message Signing: $_"
            throw $_
        }
    ''',
    "disable_cmd": '''
        try {
            # Disable SMB signing for both server and client
            # Server settings
            Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "RequireSecuritySignature" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "EnableSecuritySignature" -Value 0 -Type DWord -Force
       
            # Client settings
            Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" -Name "RequireSecuritySignature" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" -Name "EnableSecuritySignature" -Value 0 -Type DWord -Force
       
            # Attempt to restart services, but continue if it fails
            try {
                $lanmanServer = Get-Service -Name "LanmanServer" -ErrorAction Stop
                if ($lanmanServer.Status -eq 'Running') {
                    Stop-Service -Name "LanmanServer" -Force -ErrorAction Stop
                    Start-Service -Name "LanmanServer" -ErrorAction Stop
                }
            } catch {
                Write-Warning "Note: LanmanServer service restart was not completed. Changes will take effect after next restart."
            }
           
            try {
                $lanmanWorkstation = Get-Service -Name "LanmanWorkstation" -ErrorAction Stop
                if ($lanmanWorkstation.Status -eq 'Running') {
                    Stop-Service -Name "LanmanWorkstation" -Force -ErrorAction Stop
                    Start-Service -Name "LanmanWorkstation" -ErrorAction Stop
                }
            } catch {
                Write-Warning "Note: LanmanWorkstation service restart was not completed. Changes will take effect after next restart."
            }
       
            Write-Output "SMB Message Signing has been disabled"
            $true  # Return success
        } catch {
            Write-Error "Failed to disable SMB Message Signing: $_"
            throw $_
        }
    '''
        },

         "TLS": {
                "name": "Deprecated TLS Protocols",
                "enable_cmd": '''
            # Enable TLSv1.0
            New-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0" -Force
            New-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Client" -Force
            New-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server" -Force
            Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Client" -Name "Enabled" -Value 1 -Type DWord
            Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server" -Name "Enabled" -Value 1 -Type DWord

            # Enable TLSv1.1
            New-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1" -Force
            New-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Client" -Force
            New-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server" -Force
            Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Client" -Name "Enabled" -Value 1 -Type DWord
            Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server" -Name "Enabled" -Value 1 -Type DWord
            ''',
            "disable_cmd": '''
            # Disable TLSv1.0
            New-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0" -Force
            New-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Client" -Force
            New-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server" -Force
            Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Client" -Name "Enabled" -Value 0 -Type DWord
            Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server" -Name "Enabled" -Value 0 -Type DWord

            # Disable TLSv1.1
            New-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1" -Force
            New-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Client" -Force
            New-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server" -Force
            Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Client" -Name "Enabled" -Value 0 -Type DWord
            Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server" -Name "Enabled" -Value 0 -Type DWord
            '''
            },
        "NULL_SESSIONS":{
            "name":"RESTRICT NULL SESSION ACCESS",  
            "enable_cmd":'''
            # Restrict null session access to shares
            Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "RestrictNullSessAccess" -Value 1
            ''',
            "disable_cmd":'''
            # enables null session access to shares
            Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "RestrictNullSessAccess" -Value 0
            ''',
        },
        "weak_cipher_suites": {
   "name": "Weak Cipher Suites",
   "enable_cmd": '''
       # Enable TLS_RSA_WITH_RC4_128_MD5 cipher suite
            New-Item -Path "HKLM://SYSTEM//CurrentControlSet//Control//SecurityProviders//SCHANNEL//Ciphers" -Name "TLS_RSA_WITH_RC4_128_MD5" -Force
            Set-ItemProperty -Path "HKLM://SYSTEM//CurrentControlSet//Control//SecurityProviders//SCHANNEL//Ciphers//TLS_RSA_WITH_RC4_128_MD5" -Name "Enabled" -Value 1

        # Enable TLS_RSA_WITH_RC4_128_SHA cipher suite
            New-Item -Path "HKLM://SYSTEM//CurrentControlSet//Control//SecurityProviders//SCHANNEL//Ciphers" -Name "TLS_RSA_WITH_RC4_128_SHA" -Force
            Set-ItemProperty -Path "HKLM://SYSTEM//CurrentControlSet//Control//SecurityProviders//SCHANNEL//Ciphers//TLS_RSA_WITH_RC4_128_SHA" -Name "Enabled" -Value 1

   ''',
   "disable_cmd": '''
        # Disable TLS_RSA_WITH_RC4_128_MD5 cipher suite
            New-Item -Path "HKLM://SYSTEM//CurrentControlSet//Control//SecurityProviders//SCHANNEL//Ciphers" -Name "TLS_RSA_WITH_RC4_128_MD5" -Force
            Set-ItemProperty -Path "HKLM://SYSTEM//CurrentControlSet//Control//SecurityProviders//SCHANNEL//Ciphers//TLS_RSA_WITH_RC4_128_MD5" -Name "Enabled" -Value 0

        # Disable TLS_RSA_WITH_RC4_128_SHA cipher suite
            New-Item -Path "HKLM://SYSTEM//CurrentControlSet//Control//SecurityProviders//SCHANNEL//Ciphers" -Name "TLS_RSA_WITH_RC4_128_SHA" -Force
            Set-ItemProperty -Path "HKLM://SYSTEM//CurrentControlSet//Control//SecurityProviders//SCHANNEL//Ciphers//TLS_RSA_WITH_RC4_128_SHA" -Name "Enabled" -Value 0

   '''
}

        }
       

        # Initialize custom scripts
        self.custom_scripts = {}
        self.scripts_dir = os.path.join(os.getenv('APPDATA'), "WindowsHardeningTool", "scripts")
        if not os.path.exists(self.scripts_dir):
            os.makedirs(self.scripts_dir)

        # Setup UI
        self.setup_styles()
        self.create_main_interface()
       
    def setup_styles(self):
        # Configure ttk styles
        self.style = ttk.Style()
       
        # Main frame style
        self.style.configure(
            'Main.TFrame',
            background='#f5f6fa'
        )
       
        # Combobox style
        self.style.configure(
            'TCombobox',
            background='#dcdde1',
            fieldbackground='#f5f6fa',
            selectbackground='#273c75',
            selectforeground='white'
        )
       
        # Label style
        self.style.configure(
            'Title.TLabel',
            font=('Segoe UI', 24, 'bold'),
            background='#f5f6fa',
            foreground='#2f3640'
        )
       
        # Section style
        self.style.configure(
            'Section.TLabelframe',
            background='#f5f6fa',
            foreground='#2f3640'
        )
       
        self.style.configure(
            'Section.TLabelframe.Label',
            font=('Segoe UI', 16, 'bold'),
            background='#f5f6fa',
            foreground='#2f3640'
        )

    def create_main_interface(self):
        # Main container
        self.main_frame = ttk.Frame(self.root, style='Main.TFrame')
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Title
        title_label = ttk.Label(
            self.main_frame,
            text="Windows Security Hardening Tool",
            style='Title.TLabel'
        )
        title_label.pack(pady=(0, 20))

        # Create control sections
        self.create_master_controls()
        self.create_builtin_controls()
        self.create_custom_controls()
        self.create_status_section()

    def create_master_controls(self):
        # Master Controls Section
        self.master_frame = ttk.LabelFrame(
            self.main_frame,
            text="Master Controls",
            style='Section.TLabelframe'
        )
        self.master_frame.pack(fill=tk.X, pady=(0, 20))

        # Master Controls Combobox
        self.master_var = tk.StringVar()
        self.master_combo = ttk.Combobox(
            self.master_frame,
            textvariable=self.master_var,
            values=["Maximum Security", "Minimum Security"],
            state="readonly",
            width=30
        )
        self.master_combo.pack(padx=20, pady=10)
        self.master_combo.bind('<<ComboboxSelected>>', self.handle_master_control)

    def create_builtin_controls(self):
        # Built-in Controls Section
        self.builtin_frame = ttk.LabelFrame(
            self.main_frame,
            text="Built-in Controls",
            style='Section.TLabelframe'
        )
        self.builtin_frame.pack(fill=tk.X, pady=(0, 20))

        # Built-in Controls Combobox
        self.builtin_var = tk.StringVar()
        self.builtin_combo = ttk.Combobox(
            self.builtin_frame,
            textvariable=self.builtin_var,
            values=[control["name"] for control in self.controls.values()],
                    state="readonly",
                    width=30
        )
        self.builtin_combo.pack(padx=20, pady=10)
        self.builtin_combo.bind('<<ComboboxSelected>>', self.handle_builtin_control)

    def create_custom_controls(self):
        # Custom Controls Section
        self.custom_frame = ttk.LabelFrame(
            self.main_frame,
            text="Custom Controls",
            style='Section.TLabelframe'
        )
        self.custom_frame.pack(fill=tk.X, pady=(0, 20))

        # Custom Controls Combobox
        self.custom_var = tk.StringVar()
        self.custom_combo = ttk.Combobox(
            self.custom_frame,
            textvariable=self.custom_var,
            values=["Add New Script..."],
            state="readonly",
            width=30
        )
        self.custom_combo.pack(padx=20, pady=10)
        self.custom_combo.bind('<<ComboboxSelected>>', self.handle_custom_control)

    def create_status_section(self):
        # Status Section
        self.status_frame = ttk.LabelFrame(
            self.main_frame,
            text="Status Monitor",
            style='Section.TLabelframe'
        )
        self.status_frame.pack(fill=tk.BOTH, expand=True)

        # Create canvas for scrollable status area
        self.canvas = tk.Canvas(self.status_frame, bg='#f5f6fa', highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self.status_frame, orient="vertical", command=self.canvas.yview)
        self.status_container = ttk.Frame(self.canvas, style='Main.TFrame')

        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        # Grid layout for scrollable area
        self.canvas.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.scrollbar.grid(row=0, column=1, sticky="ns")
       
        self.status_frame.grid_rowconfigure(0, weight=1)
        self.status_frame.grid_columnconfigure(0, weight=1)

        # Create window in canvas
        self.canvas_window = self.canvas.create_window((0, 0), window=self.status_container, anchor="nw")
       
        # Configure canvas scrolling
        self.status_container.bind("<Configure>", self.on_frame_configure)
        self.canvas.bind("<Configure>", self.on_canvas_configure)
       
        # Bind mouse wheel event for scrolling only within the canvas
        self.canvas.bind("<Enter>", lambda _: self.canvas.bind_all("<MouseWheel>", self.on_mouse_wheel))
        self.canvas.bind("<Leave>", lambda _: self.canvas.unbind_all("<MouseWheel>"))

        # Dictionary to store status indicators
        self.status_indicators = {}
       
        # Initialize status indicators for built-in controls
        self.initialize_status_indicators()
       
        # Start status monitoring
        self.update_all_statuses()

    def on_frame_configure(self, event=None):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def on_canvas_configure(self, event):
        self.canvas.itemconfig(self.canvas_window, width=event.width)

    def on_mouse_wheel(self, event):
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    def initialize_status_indicators(self):
        for key, control in self.controls.items():
            status_frame = ttk.Frame(self.status_container, style='Main.TFrame')
            status_frame.pack(fill=tk.X, padx=10, pady=5)
           
            name_label = ttk.Label(
                status_frame,
                text=control["name"],
                style='Title.TLabel',
                font=('Segoe UI', 13)
            )
            name_label.pack(side=tk.LEFT, padx=(0, 10))
           
            status_indicator = StatusIndicator(status_frame)
            status_indicator.pack(side=tk.RIGHT, padx=10)
           
            self.status_indicators[key] = status_indicator
           
            # Add separator
            ttk.Separator(self.status_container, orient='horizontal').pack(fill=tk.X, padx=5, pady=2)

    def handle_master_control(self, event):
        selection = self.master_var.get()
        if selection == "Maximum Security":
            self.apply_max_security()
        elif selection == "Minimum Security":
            self.apply_min_security()
        # Reset combobox
        self.master_combo.set('')

    def handle_builtin_control(self, event):
        selection = self.builtin_var.get()
       
        # Create popup menu for Enable/Disable options
        popup = tk.Menu(self.root, tearoff=0)
       
        # Find the control key based on name
        control_key = next(key for key, control in self.controls.items()
                            if control["name"] == selection)
       
        popup.add_command(
            label="Enable",
            command=lambda: self.enable_feature_with_state(control_key)
        )
        popup.add_command(
            label="Disable",
            command=lambda: self.disable_feature_with_state(control_key)
        )
       
        # Position and show popup menu
        self.root.update()
        x = self.builtin_combo.winfo_rootx()
        y = self.builtin_combo.winfo_rooty() + self.builtin_combo.winfo_height()
        popup.tk_popup(x, y)
       
        # Reset combobox after selection
        self.builtin_combo.set('')

    def handle_custom_control(self, event):
        selection = self.custom_var.get()
       
        if selection == "Add New Script...":
            self.upload_script()
        else:
            # Create popup menu for custom script options
            popup = tk.Menu(self.root, tearoff=0)
           
            # Find the script key based on name
            script_key = next(key for key, script in self.custom_scripts.items()
                            if script["name"] == selection)
           
            popup.add_command(label="Enable",
                            command=lambda: self.enable_feature_with_state(script_key))
            popup.add_command(label="Disable",
                            command=lambda: self.disable_feature_with_state(script_key))
            popup.add_separator()
            popup.add_command(label="Edit",
                            command=lambda: self.edit_script(script_key))
            popup.add_command(label="Delete",
                            command=lambda: self.delete_script(script_key))
           
            # Position and show popup menu
            x = self.custom_combo.winfo_rootx()
            y = self.custom_combo.winfo_rooty() + self.custom_combo.winfo_height()
            popup.tk_popup(x, y)
       
        # Reset combobox
        self.custom_combo.set('')

    def update_custom_scripts_combo(self):
        values = ["Add New Script..."] + [script["name"] for script in self.custom_scripts.values()]
        self.custom_combo['values'] = values

    def update_status_indicators(self):
        # Update status indicators for built-in controls
        for key, indicator in self.status_indicators.items():
            if key in self.controls:
                status = self.get_feature_status(key)
                indicator.update_status(status)

    def get_feature_status(self, feature_key):
        """Check the current status of a feature using registry checks"""
        status_checks = {
            "advertising_id": '''
                try {
                    $adValue = Get-ItemPropertyValue -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo" -Name "Enabled" -ErrorAction SilentlyContinue
                    if ($adValue -eq 0) { "Disabled" } else { "Enabled" }
                } catch {
                    "Unknown"
                }
            ''',
            "location_tracking": '''
                try {
                    $locValue = Get-ItemPropertyValue -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location" -Name "Value" -ErrorAction SilentlyContinue
                    if ($locValue -eq "Deny") { "Disabled" } else { "Enabled" }
                } catch {
                    "Unknown"
                }
            ''',
            "microsoft_updates": '''
                try {
                    $updateService = Get-Service -Name "wuauserv"
                    if ($updateService.Status -eq "Running") { "Enabled" } else { "Disabled" }
                } catch {
                    "Unknown"
                }
            ''',
            "peer_updates": '''
                    # Check the Delivery Optimization service status
                    $doSvc = Get-Service -Name "DoSvc" -ErrorAction SilentlyContinue
                    if ($doSvc.Status -ne "Running") {
                        return "Disabled"
            }

                    # Check the SystemSettingsDownloadMode registry key (HKCU)
                    $systemSettingsMode = Get-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -ErrorAction SilentlyContinue
                    if ($systemSettingsMode.SystemSettingsDownloadMode -eq 0) {
                        return "Disabled"
            }

                    # Check the DODownloadMode registry key (HKLM)
                    $doDownloadMode = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config" -Name "DODownloadMode" -ErrorAction SilentlyContinue
                    if ($doDownloadMode.DODownloadMode -eq 0) {
                        return "Disabled"
            }

                    # If all checks pass, return "Enabled"
                    return "Enabled"
        ''',
            "windows_firewall": '''
                try {
                    $profiles = @("DomainProfile", "PrivateProfile", "PublicProfile")
                    $enabled = $true
                    foreach ($profile in $profiles) {
                        $value = Get-ItemPropertyValue -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\$profile" -Name "EnableFirewall" -ErrorAction SilentlyContinue
                        if ($value -eq 0) {
                            $enabled = $false
                            break
                        }
                    }
                    if ($enabled) { "Enabled" } else { "Disabled" }
                } catch {
                    "Unknown"
                }
            ''',
            "virus_threat_protection": '''
                try {
                    $avValue = Get-ItemPropertyValue -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection" -Name "DisableRealtimeMonitoring" -ErrorAction SilentlyContinue
                    if ($avValue -eq 1) { "Disabled" } else { "Enabled" }
                } catch {
                    "Unknown"
                }
            ''',
            "reputation_based_protection": '''
                try {
                    $smartScreen = Get-ItemPropertyValue -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer" -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue
                    if ($smartScreen -eq "Off") { "Disabled" } else { "Enabled" }
                } catch {
                    "Unknown"
                }
            ''', "remote_assistance": '''
               try {
                   $raValue = Get-ItemPropertyValue -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance" -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue
                   if ($raValue -eq 0) { "Disabled" } else { "Enabled" }
               } catch {
                   "Unknown"
               }
           ''',
                "rdp": '''
                    try {
                        $rdpValue = Get-ItemPropertyValue -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
                        if ($rdpValue -eq 1) { "Disabled" } else { "Enabled" }
                    } catch {
                        "Unknown"
                    }
                ''',
            "network_level_auth": '''
                try {
                    $nlaValue = Get-ItemPropertyValue -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
                    if ($nlaValue -eq 1) { "Enabled" } else { "Disabled" }
                } catch {
                    "Unknown"
                }
            ''',
            "autorun": '''
               try {
                   $autorunValue = Get-ItemPropertyValue -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
                   if ($autorunValue -eq 0xFF) { "Disabled" } else { "Enabled" }
               } catch {
                   "Unknown"
               }
           ''',
            "smb_signing": '''
                try {
                    $serverSigning = Get-ItemPropertyValue -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
                    $clientSigning = Get-ItemPropertyValue -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
                    if ($serverSigning -eq 1 -and $clientSigning -eq 1) { "Enabled" } else { "Disabled" }
                } catch {
                    "Unknown"
                }
            ''',
            "TLS": '''
                try {
                    $tls10Path = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Client"
                    $tls11Path = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Client"
                   
                    $tls10Enabled = (Get-ItemPropertyValue -Path $tls10Path -Name "Enabled" -ErrorAction SilentlyContinue) -eq 1
                    $tls11Enabled = (Get-ItemPropertyValue -Path $tls11Path -Name "Enabled" -ErrorAction SilentlyContinue) -eq 1
                   
                    if ($tls10Enabled -or $tls11Enabled) { "Enabled" } else { "Disabled" }
                } catch {
                    "Unknown"
                }
            ''',
            "NULL_SESSIONS": '''
                try {
                    $nullValue = Get-ItemPropertyValue -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "RestrictNullSessAccess" -ErrorAction SilentlyContinue
                    if ($nullValue -eq 1) { "Enabled" } else { "Disabled" }
                } catch {
                    "Unknown"
                }
            ''',
            "weak_cipher_suites": '''
                try {
                    $rc4md5Path = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\TLS_RSA_WITH_RC4_128_MD5"
                    $rc4shaPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\TLS_RSA_WITH_RC4_128_SHA"
                   
                    $rc4md5Enabled = (Get-ItemPropertyValue -Path $rc4md5Path -Name "Enabled" -ErrorAction SilentlyContinue) -eq 1
                    $rc4shaEnabled = (Get-ItemPropertyValue -Path $rc4shaPath -Name "Enabled" -ErrorAction SilentlyContinue) -eq 1
                   
                    if ($rc4md5Enabled -or $rc4shaEnabled) { "Enabled" } else { "Disabled" }
                } catch {
                    "Unknown"
                }
            '''
        }


        try:
            if feature_key in status_checks:
                result = subprocess.run(['powershell', '-Command', status_checks[feature_key]],
                                        capture_output=True, text=True)
                return result.stdout.strip() or "Unknown"
            return "Unknown"
        except Exception:
            return "Unknown"

    def update_all_statuses(self):
        """Update all status indicators periodically"""
        def update_in_thread():
            try:
                # Create a dictionary to store results
                status_results = {}
               
                # Check status for each feature in the background
                for key in self.status_indicators.keys():
                    if key in self.controls:
                        status_results[key] = self.get_feature_status(key)
               
                # Update UI in the main thread
                self.root.after(0, self.update_indicators_ui, status_results)
            except Exception as e:
                print(f"Error in status update thread: {e}")
       
        # Start background thread
        thread = threading.Thread(target=update_in_thread, daemon=True)
        thread.start()
       
        # Schedule next update
        self.root.after(5000, self.update_all_statuses)

    def update_indicators_ui(self, status_results):
        """Update the UI with status results from the background thread"""
        for key, status in status_results.items():
            if key in self.status_indicators:
                self.status_indicators[key].update_status(status)

    def run_powershell_command(self, command):
        """Execute PowerShell command with proper error handling"""
        try:
            result = subprocess.run(['powershell', '-Command', command],
                                    capture_output=True,
                                    text=True)
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to execute command: {result.stderr}")
                return False
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Command execution failed: {str(e)}")
            return False

    # Add these methods to the WindowsHardeningTool class after the run_powershell_command method:

    def enable_feature_with_state(self, feature_key):
        """Enable a feature and update its status"""
        if feature_key.startswith('custom_'):
            script_dict = self.custom_scripts
        else:
            script_dict = self.controls
           
        if feature_key in script_dict:
            if self.run_powershell_command(script_dict[feature_key]["enable_cmd"]):
                if not feature_key.startswith('custom_'):
                    status = self.get_feature_status(feature_key)
                    self.status_indicators[feature_key].update_status(status)
                messagebox.showinfo("Success", f"{script_dict[feature_key]['name']} has been enabled")

    def disable_feature_with_state(self, feature_key):
        """Disable a feature and update its status"""
        if feature_key.startswith('custom_'):
            script_dict = self.custom_scripts
        else:
            script_dict = self.controls
           
        if feature_key in script_dict:
            if self.run_powershell_command(script_dict[feature_key]["disable_cmd"]):
                if not feature_key.startswith('custom_'):
                    status = self.get_feature_status(feature_key)
                    self.status_indicators[feature_key].update_status(status)
                messagebox.showinfo("Success", f"{script_dict[feature_key]['name']} has been disabled")

    def apply_max_security(self):
        """Apply maximum security settings"""
        security_settings = {
            'advertising_id': 'disable',
            'location_tracking': 'disable',
            'microsoft_updates': 'enable',
            'peer_updates': 'disable',
            'windows_firewall': 'enable',
            'virus_threat_protection': 'enable',
            'reputation_based_protection': 'enable',
            'remote_assistance': 'disable',
            'rdp': 'disable',
            'network_level_auth': 'enable',
            'autorun': 'disable',
            'smb_signing': 'enable',
            'TLS': 'disable',
            'NULL_SESSIONS': 'enable',
            'weak_cipher_suites': 'disable'
        }
       
        for feature_key, action in security_settings.items():
            if feature_key in self.controls:
                if action == 'enable':
                    self.enable_feature_with_state(feature_key)
                else:
                    self.disable_feature_with_state(feature_key)
       
        messagebox.showinfo("Success", "Maximum security settings have been applied")

    def apply_min_security(self):
        """Apply minimum security settings"""
        security_settings = {
            'advertising_id': 'enable',
            'location_tracking': 'enable',
            'microsoft_updates': 'disable',
            'peer_updates': 'enable',
            'windows_firewall': 'disable',
            'virus_threat_protection': 'disable',
            'reputation_based_protection': 'disable',
            'remote_assistance': 'enable',
            'rdp': 'enable',
            'network_level_auth': 'disable',
            'autorun': 'enable',
            'smb_signing': 'disable',
            'TLS': 'enable',
            'NULL_SESSIONS': 'disable',
            'weak_cipher_suites': 'enable'
        }
       
        for feature_key, action in security_settings.items():
            if feature_key in self.controls:
                if action == 'enable':
                    self.enable_feature_with_state(feature_key)
                else:
                    self.disable_feature_with_state(feature_key)
       
        messagebox.showinfo("Success", "Minimum security settings have been applied")

    def upload_script(self):
        """Upload custom PowerShell scripts"""
        try:
            script_name = simpledialog.askstring(
                "Script Name",
                "Enter a name for this control:",
                parent=self.root
            )
           
            if not script_name:
                return
               
            enable_path = filedialog.askopenfilename(
                title="Select ENABLE script",
                filetypes=[("PowerShell Scripts", "*.ps1"), ("All Files", "*.*")]
            )
           
            if not enable_path:
                return
               
            disable_path = filedialog.askopenfilename(
                title="Select DISABLE script",
                filetypes=[("PowerShell Scripts", "*.ps1"), ("All Files", "*.*")]
            )
           
            if not disable_path:
                return
           
            with open(enable_path, 'r') as f:
                enable_content = f.read()
            with open(disable_path, 'r') as f:
                disable_content = f.read()
               
                       
            script_key = f"custom_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.custom_scripts[script_key] = {
                "name": script_name,
                "enable_cmd": enable_content,
                "disable_cmd": disable_content
            }
           
            self.save_custom_scripts()
            self.update_custom_scripts_combo()
           
            messagebox.showinfo("Success", f"Script '{script_name}' has been uploaded successfully")
           
        except Exception as e:
            messagebox.showerror("Error", f"Failed to upload scripts: {str(e)}")

    def edit_script(self, script_key):
        """Edit existing custom script"""
        try:
            script_name = self.custom_scripts[script_key]['name']
           
            enable_path = filedialog.askopenfilename(
                title=f"Select new ENABLE script for {script_name}",
                filetypes=[("PowerShell Scripts", "*.ps1"), ("All Files", "*.*")]
            )
           
            if not enable_path:
                return
               
            disable_path = filedialog.askopenfilename(
                title=f"Select new DISABLE script for {script_name}",
                filetypes=[("PowerShell Scripts", "*.ps1"), ("All Files", "*.*")]
            )
           
            if not disable_path:
                return
           
            with open(enable_path, 'r') as f:
                enable_content = f.read()
            with open(disable_path, 'r') as f:
                disable_content = f.read()
               
                     
            self.custom_scripts[script_key].update({
                "enable_cmd": enable_content,
                "disable_cmd": disable_content
            })
           
            self.save_custom_scripts()
            messagebox.showinfo("Success", f"Scripts for '{script_name}' have been updated")
           
        except Exception as e:
            messagebox.showerror("Error", f"Failed to edit scripts: {str(e)}")

    def delete_script(self, script_key):
        """Delete custom script"""
        if messagebox.askyesno("Confirm Delete",
                                f"Are you sure you want to delete '{self.custom_scripts[script_key]['name']}'?"):
            del self.custom_scripts[script_key]
            self.save_custom_scripts()
            self.update_custom_scripts_combo()

    def save_custom_scripts(self):
        """Save custom scripts to JSON file"""
        scripts_data = {
            key: {
                "name": script["name"],
                "enable_cmd": script["enable_cmd"],
                "disable_cmd": script["disable_cmd"]
            }
            for key, script in self.custom_scripts.items()
        }
       
        json_path = os.path.join(self.scripts_dir, "custom_scripts.json")
        with open(json_path, 'w') as f:
            json.dump(scripts_data, f, indent=4)

    def load_custom_scripts(self):
        """Load custom scripts from JSON file"""
        try:
            json_path = os.path.join(self.scripts_dir, "custom_scripts.json")
            if os.path.exists(json_path):
                with open(json_path, 'r') as f:
                    self.custom_scripts = json.load(f)
                self.update_custom_scripts_combo()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load custom scripts: {str(e)}")

if __name__ == "__main__":
    try:
        if not subprocess.run(["powershell", "-Command", "([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"], capture_output=True).stdout.decode().strip() == "True":
            messagebox.showerror("Error", "This application requires administrator privileges. Please run as administrator.")
            exit(1)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to check administrator privileges: {str(e)}")
        exit(1)
       
    root = tk.Tk()
    app = WindowsHardeningTool(root)
    app.load_custom_scripts()
    root.mainloop()