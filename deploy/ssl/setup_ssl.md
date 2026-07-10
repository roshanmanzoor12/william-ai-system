# ============================================================
# William / Jarvis Multi-Agent AI SaaS System
# Digital Promotix
# File: deploy/ssl/setup_ssl.md
# Purpose: SSL setup guide
# Agent/Module: Deployment Prompt Bible
# Required class/component name: SetupSsl
# ============================================================

# William / Jarvis SSL Setup Guide

This guide configures HTTPS for the William / Jarvis SaaS platform using Nginx and Let's Encrypt Certbot.

It is designed for a production VPS or cloud VM where:

- The William dashboard runs behind Nginx.
- The William API runs behind Nginx.
- PostgreSQL and Redis stay private.
- Internal agent routes stay private.
- TLS certificates are issued and renewed automatically.
- No real secrets are written into Nginx, Git, or this guide.

---

## 1. Production domain plan

Recommended domain layout:

```text
Dashboard:
https://william.example.com

API:
https://william.example.com/api