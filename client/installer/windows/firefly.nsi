Name "萤火虫翻墙代理"

OutFile "firefly-__VERSION__-install.exe"

InstallDir $DESKTOP\Firefly

RequestExecutionLevel user

;--------------------------------

; Pages
Page components
Page directory
Page instfiles

UninstPage uninstConfirm
UninstPage instfiles

;--------------------------------
; install
Section "萤火虫翻墙代理"

  SectionIn RO
 
  SetOutPath $INSTDIR
  
  File firefly.exe
  
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
; uninstall

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

