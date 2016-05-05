##shellcode64
A tiny shellcode extractor which helps in the process of extracting shellcode from 64-bit PE binaries (.exe files). The shellcode extractor extracts to pure binary (.bin files) and to the pcileech custom format (.ksh files).

Download the most recent binary distrubution for Windows x64 [here](https://github.com/ufrisk/shellcode64/raw/master/Releases/shellcode64_v1_0_0.zip) or check out the source code and compile it yourself in Visual Studio.

######Syntax:
shellcode64 [&lt;options&gt;] &lt;PE_file&gt; [&lt;printf_format_string_for_ksh&gt;]<br>
The &lt;printf_format_string_for_ksh&gt; supports \\\\n but not \\\\t and \\\\\\\\<br>
Available options: -&lt;options&gt; (in one single argument):<br>
&nbsp;&nbsp;&nbsp;o = overwrite existing .bin and .ksh files. <br>
&nbsp;&nbsp;&nbsp;b = show binary output if shorter than 8kB.<br>
&nbsp;&nbsp;&nbsp;i = ignore data directories which may invalidate the extracted shellcode.<br>
