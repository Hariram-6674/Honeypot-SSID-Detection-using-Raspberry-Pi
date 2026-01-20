# Honeypot SSID Detection using Raspberry Pi

This project implements a Raspberry Pi–based wireless security system that detects suspicious or honeypot Wi-Fi SSIDs, triggers real-time email alerts, and visualizes all detected activity through a web dashboard.

## Overview

The Raspberry Pi continuously scans nearby Wi-Fi networks and applies detection logic to identify SSIDs that may represent fake or malicious access points. When a potential honeypot SSID is detected, the system immediately sends an email alert and records the event for later analysis.

To reduce false positives, trusted devices and networks can be whitelisted. The system also estimates whether a suspicious SSID is likely positioned among legitimate networks by checking the presence of nearby trusted Wi-Fi points. This proximity-based approach improves confidence in honeypot detection without relying on precise location data.

All alerts and statistics are displayed on a web-based dashboard, providing a clear and centralized view of detected threats and system activity.

## Core Capabilities

The system supports automatic email alerting for suspicious SSIDs, maintains a history of detected events, and tracks how many alert emails have been sent. A graphical dashboard presents alert details such as SSID information, timestamps, signal strength, and overall alert statistics.

A whitelist mechanism allows known and trusted devices or networks to be excluded from detection logic, helping focus the system only on unknown or suspicious activity. Using these trusted networks as reference points, the system can approximately infer whether a detected SSID is likely acting as a honeypot based on its surrounding Wi-Fi environment.

## Architecture & Technologies

The backend is built using Python and Flask, handling wireless scanning, detection logic, email notifications, alert storage, and API services. The system runs efficiently on a Raspberry Pi, making it portable and low-cost.

The frontend is developed using React, providing a responsive and user-friendly dashboard that communicates with the Flask backend to display alerts, statistics, and whitelist information.

## Purpose

This project is intended for educational, academic, and security research use. It demonstrates practical concepts in wireless security, honeypot detection, alerting systems, and full-stack integration using embedded hardware.
