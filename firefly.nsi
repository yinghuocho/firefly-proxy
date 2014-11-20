; example2.nsi
;
; This script is based on example1.nsi, but it remember the directory, 
; has uninstall support and (optionally) installs start menu shortcuts.
;
; It will install example2.nsi into a directory that the user selects,

;--------------------------------

; The name of the installer
Name "萤火虫翻墙代理"

; The file to write
OutFile "firefly-proxy-win-0.1.3-install.exe"

; The default installation directory
InstallDir $DESKTOP\Firefly

; Request application privileges for Windows Vista
RequestExecutionLevel user

;--------------------------------

; Pages
Page components
Page directory
Page instfiles

UninstPage uninstConfirm
UninstPage instfiles

;--------------------------------

; The stuff to install
Section "萤火虫翻墙代理"

  SectionIn RO
  
  ; Set output path to the installation directory.
  SetOutPath $INSTDIR
  
  ; Put file there
  File /r "build\exe.win32-2.7\*.*"
  
  WriteUninstaller "uninstall.exe"
  
SectionEnd

; Optional section (can be disabled by the user)
Section "开始菜单"

  CreateDirectory "$SMPROGRAMS\Firefly"
  CreateShortcut "$SMPROGRAMS\Firefly\Uninstall.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0
  CreateShortcut "$SMPROGRAMS\Firefly\萤火虫翻墙代理.lnk" "$INSTDIR\firefly.exe"
  
SectionEnd

Section "快捷方式"

  CreateShortcut "$DESKTOP\萤火虫翻墙代理.lnk" "$INSTDIR\firefly.exe"
  
SectionEnd

;--------------------------------

; Uninstaller

Section "Uninstall"
 
  ; Remove files and uninstaller
  Delete "$INSTDIR\*.*"

  ; Remove shortcuts, if any
  Delete "$SMPROGRAMS\Firefly\*.*"
  Delete "$DESKTOP\萤火虫翻墙代理.lnk"

  ; Remove directories used
  RMDir /r "$SMPROGRAMS\Firefly"
  RMDir /r "$INSTDIR"

SectionEnd

