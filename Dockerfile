FROM mcr.microsoft.com/dotnet/aspnet:5.0 AS base

WORKDIR /home/txnproc/
COPY ["/config", "config"]
COPY ["/syncfusion/BlinkBinariesLinux", "syncfusion/BlinkBinariesLinux"]