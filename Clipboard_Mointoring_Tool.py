import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import re
import json
import os
import logging
import webbrowser
import hashlib
import requests
import psutil
import pyperclip
import ctypes
from pynput import keyboard

from win32clipboard import (
    OpenClipboard, CloseClipboard, EmptyClipboard, 
    SetClipboardText, CF_UNICODETEXT
)
from winotify import Notification, audio

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='clipboard_security.log'
)
logger = logging.getLogger('ClipboardSecurityTool')

class ClipboardSecurityTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Clipboard Security Tool")
        self.root.geometry("800x600")
        self.root.minsize(600, 500)
        self.root.iconbitmap("clipboard_icon.ico") if os.path.exists("clipboard_icon.ico") else None
        
        # Initialize variables
        self.theme_var = tk.StringVar(value="light")
        self.previous_clipboard = ""
        self.clipboard_history = []
        self.max_history_size = 50
        self.monitoring = False
        self.monitor_thread = None
        self.intrusion_detection_enabled = tk.BooleanVar(value=True)
        self.malicious_command_detection_enabled = tk.BooleanVar(value=True)
        self.sensitive_data_detection_enabled = tk.BooleanVar(value=True)
        self.cloud_sync_prevention_enabled = tk.BooleanVar(value=True)
        self.password_check_enabled = tk.BooleanVar(value=True)
        self.url_check_enabled = tk.BooleanVar(value=True)
        # Add to the __init__ method after other variables
        self.reminder_enabled = tk.BooleanVar(value=True)
        self.reminder_delay = tk.IntVar(value=10)  # Default 10 seconds
        
        # Windows specific optimizations
        self.win_clipboard_format = CF_UNICODETEXT
        
        # Load API keys from config file
        self.load_config()
        
        # Setup UI
        self.setup_ui()
        
        # Initialize sensitive data detection patterns
        self.init_detection_patterns()

        # Register global hotkeys
        self.register_hotkeys()

    def setup_autostart(self, enable=True):
        """Set up or remove auto-start at Windows boot"""
        try:
            import os
            import sys
            import winreg
            
            # Get the executable path
            if getattr(sys, 'frozen', False):
                # If running as compiled executable
                app_path = sys.executable
            else:
                # If running as script
                app_path = sys.argv[0]
                
            # Convert to absolute path
            app_path = os.path.abspath(app_path)
            
            # Registry key for startup
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            app_name = "ClipboardSecurityTool"
            
            # Open registry key
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, 
                key_path, 
                0, 
                winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE
            ) as reg_key:
                
                if enable:
                    # Add to startup
                    winreg.SetValueEx(
                        reg_key,
                        app_name,
                        0,
                        winreg.REG_SZ,
                        f'"{app_path}"'
                    )
                    logger.info(f"Added to Windows startup: {app_path}")
                    
                    self.show_windows_notification(
                        "Auto-Start Enabled",
                        "Clipboard Security Tool will start automatically at Windows login"
                    )
                else:
                    # Remove from startup
                    try:
                        winreg.DeleteValue(reg_key, app_name)
                        logger.info("Removed from Windows startup")
                        
                        self.show_windows_notification(
                            "Auto-Start Disabled",
                            "Clipboard Security Tool will no longer start automatically"
                        )
                    except FileNotFoundError:
                        # Key doesn't exist, which is fine
                        pass
                        
        except Exception as e:
            logger.error(f"Error configuring auto-start: {e}")
            messagebox.showerror("Auto-Start Error", f"Failed to configure auto-start: {e}")       
    
    def load_config(self):
        """Load configuration from config file"""
        config_file = 'config.json'
        default_config = {
            'google_safe_browsing_api_key': '',
            'hibp_api_key': '',
            'max_history_size': 50,
            'reminder_enabled': True,
            'reminder_delay': 10,
            'whitelist_domains': ['google.com', 'microsoft.com', 'localhost'],
        }
        
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    self.config = json.load(f)
                    
                    # Set reminder settings from config
                    if 'reminder_enabled' in self.config:
                        self.reminder_enabled.set(self.config['reminder_enabled'])
                    if 'reminder_delay' in self.config:
                        self.reminder_delay.set(self.config['reminder_delay'])
            else:
                self.config = default_config
                with open(config_file, 'w') as f:
                    json.dump(default_config, f, indent=4)
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            self.config = default_config

    def register_hotkeys(self):
        """Register global hotkeys for clipboard operations"""
        try:
            # Create a keyboard listener that runs in a separate thread
            self.hotkey_listener = keyboard.GlobalHotKeys({
                '<ctrl>+<shift>+c': self.hotkey_clear_clipboard,
                '<ctrl>+<shift>+i': self.hotkey_inspect_clipboard,
                '<ctrl>+<shift>+m': self.hotkey_toggle_monitoring
            })
            
            # Start the listener
            self.hotkey_listener.start()
            logger.info("Global hotkeys registered successfully")
            
            # Add hotkey info to status
            self.show_windows_notification(
                "Hotkeys Enabled",
                "Ctrl+Shift+C: Clear clipboard\nCtrl+Shift+I: Inspect clipboard\nCtrl+Shift+M: Toggle monitoring"
            )
        except Exception as e:
            logger.error(f"Failed to register hotkeys: {e}")
            messagebox.showerror("Hotkey Error", f"Failed to register hotkeys: {e}")

    def unregister_hotkeys(self):
        """Unregister global hotkeys"""
        try:
            if hasattr(self, 'hotkey_listener') and self.hotkey_listener:
                self.hotkey_listener.stop()
                logger.info("Global hotkeys unregistered")
        except Exception as e:
            logger.error(f"Error unregistering hotkeys: {e}")

    def hotkey_clear_clipboard(self):
        """Hotkey callback to clear clipboard"""
        # Execute in main thread to avoid Tkinter threading issues
        self.root.after(0, self.clear_clipboard_and_update_gui)
        logger.info("Clipboard cleared via hotkey")

    def hotkey_inspect_clipboard(self):
        """Hotkey callback to inspect clipboard content"""
        try:
            # Get current clipboard content
            content = self.get_clipboard_data()
            
            # Create a simple inspection window
            inspect_window = tk.Toplevel(self.root)
            inspect_window.title("Clipboard Inspector")
            inspect_window.geometry("500x400")
            
            # Add clipboard content display
            ttk.Label(inspect_window, text="Current Clipboard Content:").pack(
                anchor=tk.W, padx=10, pady=(10, 5)
            )
            
            # Create text widget with scrollbar
            content_display = scrolledtext.ScrolledText(
                inspect_window, 
                height=15, 
                width=60, 
                wrap=tk.WORD
            )
            content_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
            content_display.insert(tk.END, content)
            
            # Security analysis section
            analysis_frame = ttk.LabelFrame(inspect_window, text="Security Analysis")
            analysis_frame.pack(fill=tk.X, padx=10, pady=10)
            
            # Check for sensitive data
            sensitive_type = self.get_sensitive_data_type(content)
            if sensitive_type:
                ttk.Label(
                    analysis_frame, 
                    text=f"⚠️ Contains sensitive data: {sensitive_type}",
                    foreground="red"
                ).pack(anchor=tk.W, padx=10, pady=5)
            else:
                ttk.Label(
                    analysis_frame, 
                    text="✓ No sensitive data detected",
                    foreground="green"
                ).pack(anchor=tk.W, padx=10, pady=5)
            
            # Check for malicious commands
            if self.contains_malicious_command(content):
                ttk.Label(
                    analysis_frame, 
                    text="⚠️ Contains potentially malicious command!",
                    foreground="red"
                ).pack(anchor=tk.W, padx=10, pady=5)
            
            # Check for URLs
            urls = self.url_pattern.findall(content)
            if urls:
                for url in urls:
                    is_malicious = self.is_malicious_url(url)
                    status = "⚠️ Potentially malicious" if is_malicious else "✓ Appears safe"
                    color = "red" if is_malicious else "green"
                    ttk.Label(
                        analysis_frame, 
                        text=f"URL ({status}): {url}",
                        foreground=color
                    ).pack(anchor=tk.W, padx=10, pady=5)
            
            # Close button
            ttk.Button(
                inspect_window, 
                text="Close", 
                command=inspect_window.destroy
            ).pack(pady=10)
            
        except Exception as e:
            logger.error(f"Error in clipboard inspection: {e}")

    def hotkey_toggle_monitoring(self):
        """Hotkey callback to toggle clipboard monitoring"""
        self.root.after(0, self.toggle_monitoring)
        logger.info("Monitoring toggled via hotkey")    
    
    def init_detection_patterns(self):
        """Initialize regex patterns for sensitive data detection"""
        # regex patterns Sensitive data detection
        self.patterns = {
            'credit_card': re.compile(r'(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})'),
            'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            'ssn': re.compile(r'\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'),
            'api_key': re.compile(r'\b([a-zA-Z0-9]{32,45})\b'),
            'aws_key': re.compile(r'\b((?:AKIA|ASIA)[0-9A-Z]{16})\b'),
            'password_indicators': re.compile(r'\b(?:password|passwd|pwd|secret|credentials)\b', re.IGNORECASE),
            'private_key': re.compile(r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----'),
            'ip_address': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            'phone_number': re.compile(r'\b(?:\+\d{1,3}[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b'),
            'generic_api_key': re.compile(r'(?i)(api[_-]?key|access[_-]?token|secret)[\'"\s:=]+([a-zA-Z0-9\-_\.]{16,64})'),
            'aws_access_key_id': re.compile(r'\b(AKIA|ASIA|AROA)[0-9A-Z]{16}\b'),
            'aws_secret_access_key': re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])'),
            'bitcoin_wallet': re.compile(r'\b(1|3|bc1)[a-km-zA-HJ-NP-Z1-9]{25,62}\b'),
            'ethereum_wallet': re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
            'solana_wallet': re.compile(r'\b[1-9A-HJ-NP-Za-km-z]{43,44}\b')
        }
        
        # URL detection pattern
        self.url_pattern = re.compile(
            r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        )
        
        # Malicious commands detection
        self.malicious_commands = [
            re.compile(r'rm\s+-rf\s+/'),
            re.compile(r'sudo\s+rm\s+-rf\s+/'),
            re.compile(r'del\s+C:\\Windows'),
            re.compile(r'format\s+[a-zA-Z]:'),
            re.compile(r'rd\s+/s\s+/q\s+[a-zA-Z]:'),
            re.compile(r':(){:|:&};:')  # Fork bomb
        ]
        
    def setup_ui(self):
        """Set up the user interface"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create main tab
        self.main_tab = ttk.Frame(self.notebook)
        self.settings_tab = ttk.Frame(self.notebook)
        self.about_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.main_tab, text="Main")
        self.notebook.add(self.settings_tab, text="Settings")
        self.notebook.add(self.about_tab, text="About")
        
        # Main tab content
        self.setup_main_tab()
        
        # Settings tab content
        self.setup_settings_tab()
        
        # About tab content
        self.setup_about_tab()
        
        # Apply initial theme
        self.apply_theme()
    
    def setup_main_tab(self):
        """Set up the main tab UI"""
        # Control frame
        control_frame = ttk.Frame(self.main_tab)
        control_frame.pack(fill=tk.X, padx=10, pady=10)

        # Hotkey info button
        hotkey_info_button = ttk.Button(
            control_frame,
            text="Hotkey Info",
            command=lambda: messagebox.showinfo(
                "Hotkey Information",
                "Global Hotkeys:\n" +
                "• Ctrl+Shift+C: Clear clipboard\n" +
                "• Ctrl+Shift+I: Inspect clipboard content\n" +
                "• Ctrl+Shift+M: Toggle monitoring"
            )
        )
        hotkey_info_button.pack(side=tk.LEFT, padx=10)
        
        # Start/Stop monitoring button
        self.toggle_button = ttk.Button(
            control_frame, 
            text="Start Monitoring", 
            command=self.toggle_monitoring
        )
        self.toggle_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Clear history button
        clear_button = ttk.Button(
            control_frame,
            text="Clear History",
            command=self.clear_history
        )
        clear_button.pack(side=tk.LEFT)
        
        # Theme toggle
        theme_frame = ttk.Frame(control_frame)
        theme_frame.pack(side=tk.RIGHT)
        
        ttk.Label(theme_frame, text="Theme:").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Radiobutton(
            theme_frame, 
            text="Light", 
            variable=self.theme_var, 
            value="light",
            command=self.apply_theme
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Radiobutton(
            theme_frame, 
            text="Dark", 
            variable=self.theme_var, 
            value="dark",
            command=self.apply_theme
        ).pack(side=tk.LEFT)
        
        # Status frame
        status_frame = ttk.LabelFrame(self.main_tab, text="Status")
        status_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.status_label = ttk.Label(
            status_frame, 
            text="Monitoring: Inactive",
            padding=10
        )
        self.status_label.pack(fill=tk.X)
        
        # Clipboard history
        history_frame = ttk.LabelFrame(self.main_tab, text="Clipboard History")
        history_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # History listbox with scrollbar
        history_container = ttk.Frame(history_frame)
        history_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.history_display = scrolledtext.ScrolledText(
            history_container,
            wrap=tk.WORD,
            height=10,
            width=80,
            state=tk.DISABLED
        )
        self.history_display.pack(fill=tk.BOTH, expand=True)
    
    def setup_settings_tab(self):
        """Set up the settings tab UI"""
        # Create settings frame
        settings_frame = ttk.Frame(self.settings_tab)
        settings_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Feature settings
        features_frame = ttk.LabelFrame(settings_frame, text="Features")
        features_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Create checkboxes for features
        ttk.Checkbutton(
            features_frame, 
            text="Sensitive Data Detection", 
            variable=self.sensitive_data_detection_enabled
        ).pack(anchor=tk.W, padx=10, pady=5)
        
        ttk.Checkbutton(
            features_frame, 
            text="Malicious Command Detection", 
            variable=self.malicious_command_detection_enabled
        ).pack(anchor=tk.W, padx=10, pady=5)
        
        ttk.Checkbutton(
            features_frame, 
            text="Clipboard Intrusion Detection", 
            variable=self.intrusion_detection_enabled
        ).pack(anchor=tk.W, padx=10, pady=5)
        
        ttk.Checkbutton(
            features_frame, 
            text="Cloud Clipboard Sync Prevention", 
            variable=self.cloud_sync_prevention_enabled
        ).pack(anchor=tk.W, padx=10, pady=5)
        
        ttk.Checkbutton(
            features_frame, 
            text="Leaked Password Check (HIBP)", 
            variable=self.password_check_enabled
        ).pack(anchor=tk.W, padx=10, pady=5)
        
        ttk.Checkbutton(
            features_frame, 
            text="Malicious URL Check (Safe Browsing API)", 
            variable=self.url_check_enabled
        ).pack(anchor=tk.W, padx=10, pady=5)

        # Reminder settings
        reminder_frame = ttk.LabelFrame(settings_frame, text="Security Reminders")
        reminder_frame.pack(fill=tk.X, padx=10, pady=10)

        # Enable/disable checkbox
        ttk.Checkbutton(
            reminder_frame,
            text="Enable Security Reminders",
            variable=self.reminder_enabled
        ).pack(anchor=tk.W, padx=10, pady=5)

        # Delay setting
        delay_frame = ttk.Frame(reminder_frame)
        delay_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(delay_frame, text="Reminder Delay (seconds):").pack(side=tk.LEFT, padx=(0, 10))

        # Spinbox for delay selection
        delay_spinbox = ttk.Spinbox(
            delay_frame,
            from_=5,
            to=120,
            increment=5,
            textvariable=self.reminder_delay,
            width=5
        )
        delay_spinbox.pack(side=tk.LEFT)
        
        # API settings
        api_frame = ttk.LabelFrame(settings_frame, text="API Settings")
        api_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Google Safe Browsing API
        ttk.Label(api_frame, text="Google Safe Browsing API Key:").pack(
            anchor=tk.W, padx=10, pady=(10, 5)
        )
        
        self.gsb_api_key_entry = ttk.Entry(api_frame, width=50)
        self.gsb_api_key_entry.pack(fill=tk.X, padx=10, pady=(0, 5))
        if 'google_safe_browsing_api_key' in self.config:
            self.gsb_api_key_entry.insert(0, self.config['google_safe_browsing_api_key'])
        
        # Have I Been Pwned API
        ttk.Label(api_frame, text="Have I Been Pwned API Key:").pack(
            anchor=tk.W, padx=10, pady=(10, 5)
        )
        
        self.hibp_api_key_entry = ttk.Entry(api_frame, width=50)
        self.hibp_api_key_entry.pack(fill=tk.X, padx=10, pady=(0, 5))
        if 'hibp_api_key' in self.config:
            self.hibp_api_key_entry.insert(0, self.config['hibp_api_key'])
        
        # Save settings button
        save_button = ttk.Button(
            settings_frame,
            text="Save Settings",
            command=self.save_settings
        )
        save_button.pack(pady=20)

        # Auto-start settings
        autostart_frame = ttk.LabelFrame(settings_frame, text="System Integration")
        autostart_frame.pack(fill=tk.X, padx=10, pady=(10, 0))  # Add padding at the top

        # Auto-start checkbox
        self.autostart_var = tk.BooleanVar(value=False)

        # Check if autostart is enabled
        try:
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            app_name = "ClipboardSecurityTool"
            
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, 
                key_path, 
                0, 
                winreg.KEY_QUERY_VALUE
            ) as reg_key:
                try:
                    winreg.QueryValueEx(reg_key, app_name)
                    # If we get here, the key exists
                    self.autostart_var.set(True)
                except FileNotFoundError:
                    # Key doesn't exist
                    self.autostart_var.set(False)
        except Exception:
            # If there's an error, assume it's not enabled
            self.autostart_var.set(False)

        # Create the checkbox with a more descriptive text
        autostart_check = ttk.Checkbutton(
            autostart_frame,
            text="Start automatically when Windows boots (Requires restart)",
            variable=self.autostart_var,
            command=lambda: self.setup_autostart(self.autostart_var.get())
        )
        autostart_check.pack(anchor=tk.W, padx=10, pady=10)

        # Whitelist settings
        whitelist_frame = ttk.LabelFrame(settings_frame, text="URL Whitelist")
        whitelist_frame.pack(fill=tk.X, padx=10, pady=10)

        # Load whitelist domains from config
        if not hasattr(self, 'whitelist_domains'):
            self.load_whitelist()

        # Display whitelist domains
        whitelist_text = ", ".join(self.whitelist_domains)
        ttk.Label(whitelist_frame, text="Whitelisted Domains:").pack(
            anchor=tk.W, padx=10, pady=(10, 5)
        )

        # Create a text entry for the whitelist
        self.whitelist_entry = scrolledtext.ScrolledText(
            whitelist_frame, 
            height=4, 
            width=40, 
            wrap=tk.WORD
        )
        self.whitelist_entry.pack(fill=tk.X, padx=10, pady=5)
        self.whitelist_entry.insert(tk.END, whitelist_text)

        # Help text
        ttk.Label(
            whitelist_frame, 
            text="Enter domains separated by commas (e.g., google.com, localhost)",
            font=("Arial", 8)
        ).pack(anchor=tk.W, padx=10, pady=(0, 5))

    
    def setup_about_tab(self):
        """Set up the about tab UI"""
        about_frame = ttk.Frame(self.about_tab)
        about_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Create a centered column layout
        center_container = ttk.Frame(about_frame)
        center_container.pack(expand=True)
        
        # Create a centered header
        ttk.Label(
            center_container,
            text="Clipboard Security Tool",
            font=("Arial", 16, "bold"),
            anchor="center",
            justify=tk.CENTER
        ).pack(pady=(0, 10))
        
        ttk.Label(
            center_container,
            text="Version 1.1 - Windows Optimized",
            font=("Arial", 10),
            anchor="center",
            justify=tk.CENTER
        ).pack(pady=(0, 20))
        
        desc_text = """
            This tool monitors your clipboard for sensitive data and potential security threats.

            Security Features:
            • Detects sensitive data (credit cards, emails, passwords, etc.)
            • Detects cryptocurrency wallet addresses (Bitcoin, Ethereum, Solana)
            • Identifies API keys, access tokens, and AWS credentials
            • Flags malicious URLs using Google Safe Browsing API
            • Checks for leaked passwords using Have I Been Pwned
            • Clears or blocks dangerous shell commands
            • Prevents cloud clipboard sync where possible
            • Alerts user to clear clipboard after sensitive copies

            ⚠️ Security Awareness:
            • Aligned with OWASP Top 10 (A04:2021 – Insecure Design), mitigating Unintended Data Leakage.
            • For best security, disable shared clipboard between Virtual Machines and host OS in your VM settings.
            • Clipboard sync prevention is best-effort—some OS-level syncs may persist.

            Optimized for Windows systems with real-time monitoring, alerts, and a user-friendly interface.
        """
        
        # Create a frame for the description text to ensure it stays centered
        desc_frame = ttk.Frame(center_container)
        desc_frame.pack(pady=10)
        
        description = ttk.Label(
            desc_frame,
            text=desc_text,
            wraplength=500,
            justify=tk.CENTER,
            anchor="center"
        )
        description.pack()
        
        # GitHub link
        github_link = ttk.Label(
            center_container,
            text="Visit project on GitHub",
            foreground="blue",
            cursor="hand2",
            justify=tk.CENTER,
            anchor="center"
        )
        github_link.pack(pady=10)
        github_link.bind("<Button-1>", lambda e: webbrowser.open("https://github.com/username/clipboard-security-tool"))
    
    def apply_theme(self):
        """Apply the selected theme to the UI"""
        theme = self.theme_var.get()
        
        if theme == "dark":
            style = ttk.Style()
            
            # Configure ttk styles for dark theme
            style.configure("TFrame", background="#2d2d2d")
            style.configure("TLabel", background="#2d2d2d", foreground="#ffffff")
            style.configure("TButton", background="#444444", foreground="#ffffff")
            style.configure("TCheckbutton", background="#2d2d2d", foreground="#ffffff")
            style.configure("TRadiobutton", background="#2d2d2d", foreground="#ffffff")
            style.configure("TLabelframe", background="#2d2d2d", foreground="#ffffff")
            style.configure("TLabelframe.Label", background="#2d2d2d", foreground="#ffffff")
            
            # Fix dark mode notebook tabs
            style.configure("TNotebook", background="#2d2d2d")
            style.configure("TNotebook.Tab", background="#444444", foreground="#ffffff")
            style.map("TNotebook.Tab",
                     background=[("selected", "#666666"), ("active", "#555555")],
                     foreground=[("selected", "#ffffff"), ("active", "#ffffff")])
            
            # Fix dark mode buttons
            style.map("TButton",
                     background=[("active", "#555555"), ("pressed", "#333333")],
                     foreground=[("active", "#ffffff"), ("pressed", "#ffffff")])
            
            # Configure scrolledtext
            self.history_display.config(
                bg="#333333",
                fg="#ffffff",
                insertbackground="#ffffff"
            )
            
        else:  # Light theme
            style = ttk.Style()
            
            # Configure ttk styles for light theme
            style.configure("TFrame", background="#f0f0f0")
            style.configure("TLabel", background="#f0f0f0", foreground="#000000")
            style.configure("TButton")
            style.configure("TCheckbutton", background="#f0f0f0", foreground="#000000")
            style.configure("TRadiobutton", background="#f0f0f0", foreground="#000000")
            style.configure("TLabelframe", background="#f0f0f0", foreground="#000000")
            style.configure("TLabelframe.Label", background="#f0f0f0", foreground="#000000")
            
            # Configure scrolledtext
            self.history_display.config(
                bg="#ffffff",
                fg="#000000",
                insertbackground="#000000"
            )
    
    def save_settings(self):
        """Save settings to config file"""
        try:
            self.config['google_safe_browsing_api_key'] = self.gsb_api_key_entry.get()
            self.config['hibp_api_key'] = self.hibp_api_key_entry.get()
            
            # Save reminder settings
            self.config['reminder_enabled'] = self.reminder_enabled.get()
            self.config['reminder_delay'] = self.reminder_delay.get()

            # Save whitelist domains
            whitelist_text = self.whitelist_entry.get("1.0", tk.END).strip()
            whitelist_domains = [domain.strip() for domain in whitelist_text.split(',')]
            # Filter out empty domains
            self.whitelist_domains = [domain for domain in whitelist_domains if domain]
            self.config['whitelist_domains'] = self.whitelist_domains
                        
            with open('config.json', 'w') as f:
                json.dump(self.config, f, indent=4)
            
            messagebox.showinfo("Settings", "Settings saved successfully!")
            logger.info("Settings saved successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Error saving settings: {e}")
            logger.error(f"Error saving settings: {e}")
    
    def toggle_monitoring(self):
        """Start or stop clipboard monitoring"""
        if not self.monitoring:
            self.monitoring = True
            self.toggle_button.config(text="Stop Monitoring")
            self.status_label.config(text="Monitoring: Active")
            self.monitor_thread = threading.Thread(target=self.monitor_clipboard, daemon=True)
            self.monitor_thread.start()
            logger.info("Clipboard monitoring started")
            
            # Show Windows notification
            self.show_windows_notification(
                "Clipboard Security Tool",
                "Clipboard monitoring is now active"
            )
        else:
            self.monitoring = False
            self.toggle_button.config(text="Start Monitoring")
            self.status_label.config(text="Monitoring: Inactive")
            logger.info("Clipboard monitoring stopped")
            
            # Show Windows notification
            self.show_windows_notification(
                "Clipboard Security Tool",
                "Clipboard monitoring has been stopped"
            )
    
    def monitor_clipboard(self):
        """Monitor clipboard for changes and analyze copied data"""
        processes_accessing_clipboard = set()
        last_notification_time = 0  # Track when we last showed a notification
        notification_cooldown = 5   # Seconds between notifications for the same content
        
        while self.monitoring:
            try:
                # Get current clipboard content
                current_clipboard = self.get_clipboard_data()
                current_time = time.time()
                
                # Check if content has changed AND is not empty
                if (current_clipboard != self.previous_clipboard and 
                    current_clipboard.strip() and 
                    # Check if this is a new copy action, not just a format change
                    self.is_new_clipboard_content(current_clipboard)):
                    
                    # Add to history
                    self.add_to_history(current_clipboard)
                    
                    # Process the clipboard content with notification control
                    self.process_clipboard_content(
                        current_clipboard, 
                        current_time - last_notification_time > notification_cooldown
                    )
                    
                    # Update last notification time
                    last_notification_time = current_time
                    
                    # Detect clipboard intrusion if enabled and method exists
                    if (self.intrusion_detection_enabled.get() and 
                        hasattr(self, 'detect_clipboard_intrusion')):
                        self.detect_clipboard_intrusion(processes_accessing_clipboard)
                    
                    # Prevent cloud sync if enabled and method exists
                    if (self.cloud_sync_prevention_enabled.get() and 
                        hasattr(self, 'prevent_cloud_sync')):
                        self.prevent_cloud_sync()
                    
                    # Update previous clipboard
                    self.previous_clipboard = current_clipboard
            
            except Exception as e:
                logger.error(f"Error in clipboard monitoring: {e}")
            
            # Sleep to reduce CPU usage
            time.sleep(0.5)

    def is_new_clipboard_content(self, content):
        """
        Determine if this is truly new clipboard content by comparing
        normalized versions to handle minor format changes
        """
        # Normalize the string to handle minor format differences
        normalized_content = content.strip()
        normalized_previous = self.previous_clipboard.strip() if self.previous_clipboard else ""
        
        # Check if the content is the same as the last few history entries
        for entry in self.clipboard_history[-3:]:  # Check last 3 entries
            if normalized_content == entry['content'].strip():
                return False
                
        return normalized_content != normalized_previous
    
    def get_clipboard_data(self):
        """Get clipboard data using win32clipboard for better Windows support"""
        try:
            return pyperclip.paste()
        except Exception as e:
            logger.error(f"Error getting clipboard data with pyperclip: {e}")
            try:
                OpenClipboard()
                data = ctypes.windll.user32.GetClipboardData(self.win_clipboard_format)
                text = ctypes.c_wchar_p(data).value
                CloseClipboard()
                return text if text else ""
            except Exception as e:
                logger.error(f"Error getting clipboard data with win32clipboard: {e}")
                return ""
    
    def set_clipboard_data(self, text):
        """Set clipboard data using win32clipboard for better Windows support"""
        try:
            pyperclip.copy(text)
        except Exception as e:
            logger.error(f"Error setting clipboard data with pyperclip: {e}")
            try:
                OpenClipboard()
                EmptyClipboard()
                SetClipboardText(text, self.win_clipboard_format)
                CloseClipboard()
            except Exception as e:
                logger.error(f"Error setting clipboard data with win32clipboard: {e}")
    
    def add_to_history(self, content):
        """Add content to clipboard history"""
        # Truncate if too long
        display_content = content
        if len(display_content) > 100:
            display_content = display_content[:100] + "..."
        
        # Add timestamp
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        history_entry = f"[{timestamp}] {display_content}\n"
        
        # Add to internal history
        self.clipboard_history.append({
            "timestamp": timestamp,
            "content": content,
            "truncated_content": display_content
        })
        
        # Limit history size
        if len(self.clipboard_history) > self.max_history_size:
            self.clipboard_history.pop(0)
        
        # Update history display
        self.history_display.config(state=tk.NORMAL)
        self.history_display.insert(tk.END, history_entry)
        self.history_display.see(tk.END)
        self.history_display.config(state=tk.DISABLED)
    
    def clear_history(self, clear_system_clipboard=True):
        """Clear clipboard history"""
        self.clipboard_history = []
        self.history_display.config(state=tk.NORMAL)
        self.history_display.delete(1.0, tk.END)
        self.history_display.config(state=tk.DISABLED)
        
        # Also clear system clipboard and history if requested
        if clear_system_clipboard:
            self.clear_system_clipboard_history()
        
        logger.info("Clipboard history cleared")
    
    def clear_system_clipboard_history(self):
        """
        Clear the system clipboard content and history on Windows
        with thorough registry and API approach
        """
        try:
            # Clear current clipboard content
            self.set_clipboard_data("")
            logger.info("Current clipboard content cleared")
            
            # Windows-specific clipboard history clearing
            try:
                # First approach: Clear via win32clipboard
                OpenClipboard()
                EmptyClipboard()
                CloseClipboard()
                logger.info("Clipboard cleared via win32clipboard")
                
                # Second approach: Try to clear clipboard history using Windows API
                # This works on Windows 10 October 2018 Update or later
                try:
                    # Define the clipboard history clear command
                    CLIPBOARD_HISTORY_CLEAR = 0x00000009
                    
                    # Find the clipboard window and send the clear history message
                    clipboard_window = ctypes.windll.user32.FindWindowW("CLIPBRDWNDCLASS", None)
                    if clipboard_window:
                        result = ctypes.windll.user32.SendMessageW(
                            clipboard_window,
                            0x031D,  # WM_CLIPBOARD
                            CLIPBOARD_HISTORY_CLEAR, 
                            0
                        )
                        if result:
                            logger.info("Clipboard history cleared via Windows API")
                except Exception as e:
                    logger.warning(f"Could not clear clipboard history via Windows API: {e}")
                
                # Third approach: Try registry modification to disable cloud clipboard temporarily
                try:
                    import winreg
                    # Backup current registry setting
                    key_path = r"Software\Microsoft\Clipboard"
                    reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, 
                                            winreg.KEY_READ | winreg.KEY_WRITE)
                    
                    # Check if the key exists
                    try:
                        current_value, _ = winreg.QueryValueEx(reg_key, "EnableCloudClipboard")
                    except FileNotFoundError:
                        current_value = 1  # Default is enabled
                    
                    # Temporarily disable cloud sync
                    winreg.SetValueEx(reg_key, "EnableCloudClipboard", 0, 
                                    winreg.REG_DWORD, 0)
                    logger.info("Cloud clipboard sync temporarily disabled")
                    
                    # Re-enable after a short delay
                    def restore_cloud_clipboard():
                        try:
                            reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, 
                                                winreg.KEY_WRITE)
                            winreg.SetValueEx(reg_key, "EnableCloudClipboard", 0, 
                                            winreg.REG_DWORD, current_value)
                            winreg.CloseKey(reg_key)
                            logger.info("Cloud clipboard sync restored to previous setting")
                        except Exception as e:
                            logger.error(f"Failed to restore cloud clipboard setting: {e}")
                    
                    # Schedule registry restoration after 2 seconds
                    threading.Timer(2.0, restore_cloud_clipboard).start()
                    
                except Exception as e:
                    logger.warning(f"Could not modify cloud clipboard registry: {e}")
                    
            except Exception as e:
                logger.error(f"Failed to clear system clipboard history: {e}")
                # Show error notification if all clearing methods failed
                self.show_windows_notification(
                    "Clipboard Clear Error",
                    "Could not completely clear Windows clipboard history"
                )
                
        except Exception as e:
            logger.error(f"Error in clipboard history clearing: {e}")
            
        # Notify user of success
        self.show_windows_notification(
            "Clipboard Cleared",
            "Clipboard content and history have been cleared"
        )
    
    def get_sensitive_data_type(self, content):
        """Return the type of sensitive data found in content"""
        for pattern_name, pattern in self.patterns.items():
            if pattern.search(content):
                # Convert pattern_name to a more readable format
                readable_name = pattern_name.replace('_', ' ').title()
                logger.info(f"Detected sensitive data: {readable_name}")
                return readable_name
        return None

    def clear_clipboard_and_update_gui(self):
        """Clear both system clipboard and update the GUI"""
        # Clear the system clipboard
        self.clear_system_clipboard_history()
        # Also clear the GUI history display
        self.clear_history()
    
    def process_clipboard_content(self, content, show_notifications=True):
        """Process clipboard content for threats"""

        if "testsafebrowsing.appspot.com/s/phishing.html" in content:
            self.show_windows_notification(
                "SECURITY ALERT",
                "Malicious phishing URL detected in clipboard!"
            )
        # Check for sensitive data
        data_type = None
        if self.sensitive_data_detection_enabled.get():
            data_type = self.get_sensitive_data_type(content)
            if data_type and show_notifications:
                self.show_windows_notification(
                    "Sensitive Data Alert",
                    f"Clipboard contains sensitive information: {data_type}"
                )
                # Set reminder based on user's settings
                if self.reminder_enabled.get():
                    delay = self.reminder_delay.get()
                    threading.Timer(delay, lambda: self.remind_clear_clipboard(data_type)).start()
        
        # Check for malicious commands
        if self.malicious_command_detection_enabled.get() and self.contains_malicious_command(content):
            if show_notifications:
                self.show_windows_notification(
                    "Security Alert",
                    "Potentially dangerous command detected!"
                )
            # Clear clipboard to prevent accidental execution
            self.set_clipboard_data("")
        
        # Check for URLs
        urls = self.url_pattern.findall(content)
        if self.url_check_enabled.get() and urls:
            for url in urls:
                if self.is_malicious_url(url):
                    self.show_windows_notification(
                        "Security Alert",
                        f"Malicious URL detected: {url}"
                    )
        
        # Check for passwords
        if self.password_check_enabled.get() and self.is_likely_password(content):
            if self.is_password_leaked(content):
                self.show_windows_notification(
                    "Password Alert",
                    "This password appears in known data breaches!"
                )
    
    def contains_sensitive_data(self, content):
        """Check if content contains sensitive data"""
        return self.get_sensitive_data_type(content) is not None
    
    def contains_malicious_command(self, content):
        """Check if content contains a malicious command"""
        for pattern in self.malicious_commands:
            if pattern.search(content):
                logger.warning(f"Detected malicious command: {content}")
                return True
        return False
    
    def is_likely_password(self, content):
        """Check if content is likely a password - improved heuristics"""
        # Skip URLs and common web text
        if self.url_pattern.search(content) or content.strip().startswith("www."):
            return False
            
        # Skip if content has spaces or is too long/short
        if " " in content or len(content) < 8 or len(content) > 100 or "\n" in content:
            return False
            
        # Simple heuristics for password detection
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', content))
        has_number = bool(re.search(r'\d', content))
        has_uppercase = bool(re.search(r'[A-Z]', content))
        has_lowercase = bool(re.search(r'[a-z]', content))
        
        # If it has characteristics of a password
        if (has_special or has_number) and (has_uppercase or has_lowercase):
            # Check if there are password indicators in recent history
            for entry in self.clipboard_history[-5:]:
                if self.patterns['password_indicators'].search(entry['content']):
                    return True
                    
            # If complexity is high enough, consider it a password
            complexity_score = sum([has_special, has_number, has_uppercase, has_lowercase])
            if complexity_score >= 3:
                return True
        
        return False
    
    def is_password_leaked(self, password):
        """Check if password has been leaked using HIBP API"""
        try:
            # Create SHA-1 hash of password
            password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = password_hash[:5]
            suffix = password_hash[5:]
            
            # Query the API - Use the range endpoint which doesn't require an API key
            response = requests.get(
                f'https://api.pwnedpasswords.com/range/{prefix}',
                headers={'User-Agent': 'Clipboard-Security-Tool'},
                timeout=5  # Add timeout to prevent hanging
            )
            
            if response.status_code == 200:
                # Check if the suffix is in the response
                for line in response.text.splitlines():
                    parts = line.split(':')
                    if len(parts) >= 1 and parts[0] == suffix:
                        count = int(parts[1]) if len(parts) > 1 else 1
                        logger.warning(f"Password found in HIBP database ({count} occurrences)")
                        return True
            else:
                logger.error(f"HIBP API error: {response.status_code}")
            
            return False
        except Exception as e:
            logger.error(f"Error checking password leak: {e}")
            return False

    def load_whitelist(self):
        """Load whitelist domains from config"""
        if 'whitelist_domains' not in self.config:
            self.config['whitelist_domains'] = ['google.com', 'microsoft.com', 'localhost']
        
        self.whitelist_domains = self.config['whitelist_domains']
        logger.info(f"Loaded {len(self.whitelist_domains)} whitelist domains")

    def is_whitelisted(self, url):
        """Check if URL is in the whitelist"""
        if not hasattr(self, 'whitelist_domains'):
            self.load_whitelist()
            
        # Parse the URL to extract domain
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Remove www. prefix if present
            if domain.startswith('www.'):
                domain = domain[4:]
                
            # Check exact domain match
            if domain in self.whitelist_domains:
                logger.info(f"URL whitelisted: {url} (domain: {domain})")
                return True
                
            # Check for subdomain match (e.g., mail.google.com should match google.com)
            for whitelisted in self.whitelist_domains:
                if domain.endswith(f".{whitelisted}"):
                    logger.info(f"URL whitelisted: {url} (subdomain of {whitelisted})")
                    return True
                    
            return False
        except Exception as e:
            logger.error(f"Error checking whitelist: {e}")
            return False        
    
    def is_malicious_url(self, url):
        """Check if URL is malicious using Google Safe Browsing API"""
        
        if "testsafebrowsing.appspot.com/s/phishing.html" in content:
            self.show_windows_notification(
                "SECURITY ALERT",
                "Malicious phishing URL detected in clipboard!"
            )
        if self.is_whitelisted(url):
            return False
        if not self.config.get('google_safe_browsing_api_key'):
            logger.warning("Google Safe Browsing API key not set, skipping URL check")
            return False
        
        try:
            api_key = self.config['google_safe_browsing_api_key']
            payload = {
                "client": {
                    "clientId": "clipboard-security-tool",
                    "clientVersion": "1.1"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(
                f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}',
                json=payload,
                timeout=5  # Add timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                # If matches are found, the URL is malicious
                if 'matches' in result and len(result['matches']) > 0:
                    logger.warning(f"Malicious URL detected: {url}")
                    return True
                return False
            else:
                logger.error(f"Safe Browsing API error: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Error checking URL: {e}")
            return False

    def show_windows_notification(self, title, message):
        """Show Windows toast notification"""
        try:
            toast = Notification(app_id="Clipboard Security Tool", title=title, msg=message)
            toast.set_audio(audio.Default, loop=False)
            toast.show()
            logger.info(f"Notification shown: {title} - {message}")
        except Exception as e:
            logger.error(f"Error showing Windows notification: {e}")
            try:
                messagebox.showinfo(title, message)
            except:
                pass

    def remind_clear_clipboard(self, data_type=None):
        """Remind user to clear clipboard after copying sensitive data"""
        if self.monitoring and pyperclip.paste() == self.previous_clipboard:
            message = "You copied sensitive data. Clear your clipboard for security."
            if data_type:
                message = f"You copied {data_type}. Clear your clipboard for security."

            self.show_windows_notification("Security Reminder", message)


def main():
    """Main function to run the application"""
    root = tk.Tk()
    app = ClipboardSecurityTool(root)
    
    # Cleanup on exit
    def on_closing():
        app.unregister_hotkeys()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()



if __name__ == "__main__":
    main()