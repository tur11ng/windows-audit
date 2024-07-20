# Use the official .NET SDK 8 image as a parent image
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS base

# Set the working directory
WORKDIR /workspace

# Install any additional dependencies here

# Copy the content of the current directory to the working directory
COPY . .

# Set up a non-root user for better security
RUN useradd -m coder && \
    chown -R coder:coder /workspace
USER coder
