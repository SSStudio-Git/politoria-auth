# Multi-stage Dockerfile for Politoria.Auth.Server
# Build context expected: politoria-auth/src

# Stage 1: restore
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS restore
WORKDIR /src

COPY Politoria.Auth.Domain/Politoria.Auth.Domain.csproj Politoria.Auth.Domain/
COPY Politoria.Auth.Application/Politoria.Auth.Application.csproj Politoria.Auth.Application/
COPY Politoria.Auth.Infrastructure/Politoria.Auth.Infrastructure.csproj Politoria.Auth.Infrastructure/
COPY Politoria.Auth.Server/Politoria.Auth.Server.csproj Politoria.Auth.Server/

RUN dotnet restore Politoria.Auth.Server/Politoria.Auth.Server.csproj

# Stage 2: publish
FROM restore AS publish
COPY . .
RUN dotnet publish Politoria.Auth.Server/Politoria.Auth.Server.csproj \
    --no-restore -c Release -o /app/publish

# Stage 3: runtime
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=publish /app/publish .

ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "Politoria.Auth.Server.dll"]
