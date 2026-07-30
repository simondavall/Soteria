# Soteria Deployment Guide

## 1. Purpose

This document defines the deployment architecture and operational procedures for Soteria.

It records the agreed deployment architecture, operational procedures and
verification steps for the current implementation. The document is intended to
evolve alongside the project and become the authoritative operational guide for
deploying and maintaining Soteria.

---

## 2. Deployment Scope

The initial deployment targets a single-machine installation of Soteria for
development and evaluation purposes.

Current scope:

- Operating System: Windows 11 Pro
- Web Server: IIS
- Application URL: https://soteria.local
- Database: SQLite
- Database migrations applied manually
- Database backed up before migrations are applied
- Single Soteria application deployment
- Reference Web Application excluded
- Reference API excluded

Future phases may introduce support for additional deployment topologies,
database providers and production hosting environments.

---

## 3. Deployment Architecture

### 3.1 Target Environment

The current deployment architecture consists of a single Windows machine hosting
both the Soteria application and its SQLite database.

Characteristics:

- Single server deployment
- Local IIS hosting
- Local SQLite database
- Local application storage
- HTTPS endpoint exposed via IIS
- No external infrastructure dependencies beyond the .NET runtime and IIS

This deployment model provides a simple baseline that can later be extended to
support larger or distributed production environments.

### 3.2 Hosting Model
### 3.3 Directory Structure
### 3.4 Network Topology

## 4. Prerequisites

### 4.1 Software
### 4.2 IIS Features
### 4.3 .NET Runtime
### 4.4 Certificates
### 4.5 Required Accounts and Permissions

## 5. Configuration

### 5.1 Configuration Sources
### 5.2 Application Settings
### 5.3 Environment Variables
### 5.4 Secrets
### 5.5 Data Protection
### 5.6 OpenIddict Credentials

## 6. Database

### 6.1 Database Location
### 6.2 First Deployment
### 6.3 Applying Migrations
### 6.4 Backup
### 6.5 Restore

## 7. Deployment Procedure

### 7.1 Prepare the Host
### 7.2 Publish Soteria
### 7.3 Configure IIS
### 7.4 Configure Application
### 7.5 Start the Application
### 7.6 Verify Deployment

## 8. Operational Procedures

### 8.1 Routine Deployment
### 8.2 Upgrading
### 8.3 Rollback
### 8.4 Certificate Renewal
### 8.5 Secret Rotation

## 9. Verification

### 9.1 Platform Verification
### 9.2 Identity Verification
### 9.3 OpenIddict Verification
### 9.4 Security Verification

## 10. Troubleshooting

## 11. Known Limitations

## 12. Future Enhancements

## Appendix A - Configuration Reference

## Appendix B - Directory Layout

## Appendix C - Deployment Checklist

## Appendix D - Recovery Checklist