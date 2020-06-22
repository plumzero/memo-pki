
@echo off

set para=%1
if %para% == "" (
	echo "specify the destination string to search"
	goto :Exit
)

title search the string "%para%"

REM show LINE and case-nonsensitive
for /R "%CD%" %%B in (*) do (
	findstr /N /I /A:71 "\<%para%\>" "%%B" && echo %%B
)

:Exit
title  %ComSpec%
@echo on
@pause