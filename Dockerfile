FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS base

WORKDIR /home/txnproc/
COPY ["/config", "config"]
COPY ["/syncfusion/QtBinariesLinux", "syncfusion/QtBinariesLinux"]