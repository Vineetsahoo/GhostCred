# Demo Repository

This directory contains a safe, synthetic repository used to test and demonstrate GhostCred's capabilities.

## Overview
The `demo-repo` is intentionally vulnerable and contains dummy (fake) secrets scattered across code files, `.env` files, and simulated AI config files (like MCP configurations). 

## Usage
It is used heavily by the automated test suite (`tests/`) to verify that the scanner correctly identifies multiple secret types in various contexts without triggering actual security alerts in production tools.

**Do not put real credentials in this directory.**
