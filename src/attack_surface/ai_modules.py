"""
AI Modules - Multi-Provider AI Integration with Auto-Detection.

Supports:
- GitHub Copilot (via VS Code extension)
- Ollama (local LLM)
- LM Studio (local LLM)
- OpenAI (with env API key)
- Anthropic Claude (with env API key)
- Groq (with env API key)

Auto-detects available providers and routes requests to the best available.
"""
from __future__ import annotations

import os
import json
import asyncio
import subprocess
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Any, Callable
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class AIProvider(Enum):
    """Available AI providers."""
    GITHUB_COPILOT = auto()  # GitHub Copilot via VS Code
    OLLAMA = auto()          # Local Ollama
    LM_STUDIO = auto()       # Local LM Studio
    OPENAI = auto()          # OpenAI API
    ANTHROPIC = auto()       # Anthropic Claude API
    GROQ = auto()            # Groq API (fast inference)
    MOCK = auto()            # Mock for testing


@dataclass
class AIModuleStatus:
    """Status of an AI module."""
    provider: AIProvider
    available: bool
    model: str = ""
    endpoint: str = ""
    error: str = ""
    latency_ms: float = 0.0


@dataclass
class AIConfig:
    """AI module configuration."""
    # Provider priorities (first available wins)
    provider_priority: list[AIProvider] = field(default_factory=lambda: [
        AIProvider.GITHUB_COPILOT,
        AIProvider.OLLAMA,
        AIProvider.LM_STUDIO,
        AIProvider.GROQ,
        AIProvider.OPENAI,
        AIProvider.ANTHROPIC,
    ])
    
    # Local endpoints
    ollama_endpoint: str = "http://localhost:11434"
    lm_studio_endpoint: str = "http://localhost:1234"
    
    # Preferred models per provider
    preferred_models: dict[AIProvider, str] = field(default_factory=lambda: {
        AIProvider.OLLAMA: "llama3.2",
        AIProvider.LM_STUDIO: "local-model",
        AIProvider.OPENAI: "gpt-4o-mini",
        AIProvider.ANTHROPIC: "claude-3-haiku-20240307",
        AIProvider.GROQ: "llama-3.3-70b-versatile",
    })
    
    # Timeouts
    connection_timeout: float = 5.0
    request_timeout: float = 30.0


class AIModuleManager:
    """
    Manages AI modules with auto-detection and routing.
    
    Usage:
        manager = AIModuleManager()
        available = manager.detect_available_modules()
        
        # Auto-route to best available
        response = await manager.generate("Analyze this vulnerability...")
        
        # Or specify provider
        response = await manager.generate("...", provider=AIProvider.OLLAMA)
    """
    
    def __init__(self, config: Optional[AIConfig] = None):
        self.config = config or AIConfig()
        self._modules: dict[AIProvider, AIModuleStatus] = {}
        self._active_provider: Optional[AIProvider] = None
        self._http_client = None
        
    def detect_available_modules(self) -> dict[AIProvider, AIModuleStatus]:
        """
        Auto-detect all available AI modules.
        
        Returns dict of provider -> status.
        """
        self._modules = {}
        
        # Check each provider
        checks = [
            (AIProvider.GITHUB_COPILOT, self._check_github_copilot),
            (AIProvider.OLLAMA, self._check_ollama),
            (AIProvider.LM_STUDIO, self._check_lm_studio),
            (AIProvider.OPENAI, self._check_openai),
            (AIProvider.ANTHROPIC, self._check_anthropic),
            (AIProvider.GROQ, self._check_groq),
        ]
        
        for provider, check_fn in checks:
            try:
                status = check_fn()
                self._modules[provider] = status
            except Exception as e:
                self._modules[provider] = AIModuleStatus(
                    provider=provider,
                    available=False,
                    error=str(e)
                )
        
        # Set active provider to first available
        for provider in self.config.provider_priority:
            if provider in self._modules and self._modules[provider].available:
                self._active_provider = provider
                break
        
        return self._modules
    
    def _check_github_copilot(self) -> AIModuleStatus:
        """Check if GitHub Copilot is available via VS Code."""
        status = AIModuleStatus(provider=AIProvider.GITHUB_COPILOT, available=False)
        
        copilot_found = False
        copilot_location = ""
        
        # Method 1: Check VS Code user extensions folder
        vscode_extensions = Path.home() / ".vscode" / "extensions"
        if vscode_extensions.exists():
            for ext in vscode_extensions.iterdir():
                if "github.copilot" in ext.name.lower():
                    copilot_found = True
                    copilot_location = "user-extension"
                    break
        
        # Method 2: Check VS Code bundled extensions (newer VS Code versions)
        if not copilot_found:
            # Common VS Code installation paths on Windows
            vscode_paths = [
                Path.home() / "AppData" / "Local" / "Programs" / "Microsoft VS Code",
                Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Microsoft VS Code",
                Path("C:/Program Files/Microsoft VS Code"),
                Path("C:/Program Files (x86)/Microsoft VS Code"),
            ]
            
            for vscode_path in vscode_paths:
                if vscode_path.exists():
                    # Search for copilot in bundled extensions
                    for item in vscode_path.rglob("extensions/copilot"):
                        if item.is_dir():
                            copilot_found = True
                            copilot_location = "bundled"
                            break
                    if copilot_found:
                        break
        
        # Method 3: Check VS Code Server extensions (WSL/Remote)
        if not copilot_found:
            vscode_server = Path.home() / ".vscode-server" / "extensions"
            if vscode_server.exists():
                for ext in vscode_server.iterdir():
                    if "github.copilot" in ext.name.lower():
                        copilot_found = True
                        copilot_location = "vscode-server"
                        break
        
        # Method 4: Check environment variables (set by VS Code when running)
        if not copilot_found:
            copilot_env_vars = [
                "GITHUB_COPILOT_TOKEN",
                "COPILOT_AGENT_TOKEN",
                "VSCODE_GIT_ASKPASS_NODE",  # Indicates VS Code is running
            ]
            for var in copilot_env_vars:
                if os.environ.get(var):
                    copilot_found = True
                    copilot_location = "env-detected"
                    break
        
        # Method 5: Check gh CLI for copilot extension
        if not copilot_found:
            try:
                result = subprocess.run(
                    ["gh", "extension", "list"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if "copilot" in result.stdout.lower():
                    copilot_found = True
                    copilot_location = "gh-cli"
            except (subprocess.SubprocessError, FileNotFoundError):
                pass
        
        if copilot_found:
            status.available = True
            status.model = "github-copilot"
            status.endpoint = copilot_location
        else:
            status.error = "GitHub Copilot not detected (check VS Code or gh CLI)"
        
        return status
    
    def _check_ollama(self) -> AIModuleStatus:
        """Check if Ollama is running locally."""
        status = AIModuleStatus(
            provider=AIProvider.OLLAMA,
            available=False,
            endpoint=self.config.ollama_endpoint
        )
        
        try:
            import urllib.request
            import time
            
            start = time.time()
            req = urllib.request.Request(
                f"{self.config.ollama_endpoint}/api/tags",
                method="GET"
            )
            req.add_header("Content-Type", "application/json")
            
            with urllib.request.urlopen(req, timeout=self.config.connection_timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode())
                    models = [m["name"] for m in data.get("models", [])]
                    
                    status.available = True
                    status.latency_ms = (time.time() - start) * 1000
                    
                    # Find preferred model or use first available
                    preferred = self.config.preferred_models.get(AIProvider.OLLAMA, "")
                    if preferred in models:
                        status.model = preferred
                    elif models:
                        status.model = models[0]
                    else:
                        status.available = False
                        status.error = "No models installed"
        except Exception as e:
            status.error = f"Cannot connect to Ollama: {e}"
        
        return status
    
    def _check_lm_studio(self) -> AIModuleStatus:
        """Check if LM Studio server is running."""
        status = AIModuleStatus(
            provider=AIProvider.LM_STUDIO,
            available=False,
            endpoint=self.config.lm_studio_endpoint
        )
        
        try:
            import urllib.request
            import time
            
            start = time.time()
            req = urllib.request.Request(
                f"{self.config.lm_studio_endpoint}/v1/models",
                method="GET"
            )
            
            with urllib.request.urlopen(req, timeout=self.config.connection_timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode())
                    models = [m["id"] for m in data.get("data", [])]
                    
                    status.available = True
                    status.latency_ms = (time.time() - start) * 1000
                    status.model = models[0] if models else "local-model"
        except Exception as e:
            status.error = f"Cannot connect to LM Studio: {e}"
        
        return status
    
    def _check_openai(self) -> AIModuleStatus:
        """Check if OpenAI API is configured."""
        status = AIModuleStatus(
            provider=AIProvider.OPENAI,
            available=False,
            endpoint="https://api.openai.com/v1"
        )
        
        api_key = os.environ.get("OPENAI_API_KEY")
        if api_key:
            status.available = True
            status.model = self.config.preferred_models.get(AIProvider.OPENAI, "gpt-4o-mini")
        else:
            status.error = "OPENAI_API_KEY not set"
        
        return status
    
    def _check_anthropic(self) -> AIModuleStatus:
        """Check if Anthropic API is configured."""
        status = AIModuleStatus(
            provider=AIProvider.ANTHROPIC,
            available=False,
            endpoint="https://api.anthropic.com/v1"
        )
        
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if api_key:
            status.available = True
            status.model = self.config.preferred_models.get(AIProvider.ANTHROPIC, "claude-3-haiku-20240307")
        else:
            status.error = "ANTHROPIC_API_KEY not set"
        
        return status
    
    def _check_groq(self) -> AIModuleStatus:
        """Check if Groq API is configured."""
        status = AIModuleStatus(
            provider=AIProvider.GROQ,
            available=False,
            endpoint="https://api.groq.com/openai/v1"
        )
        
        api_key = os.environ.get("GROQ_API_KEY")
        if api_key:
            status.available = True
            status.model = self.config.preferred_models.get(AIProvider.GROQ, "llama-3.3-70b-versatile")
        else:
            status.error = "GROQ_API_KEY not set"
        
        return status
    
    def get_available_modules(self) -> list[AIModuleStatus]:
        """Get list of available AI modules."""
        return [s for s in self._modules.values() if s.available]
    
    def get_active_provider(self) -> Optional[AIProvider]:
        """Get currently active provider."""
        return self._active_provider
    
    def set_active_provider(self, provider: AIProvider) -> bool:
        """Set active provider if available."""
        if provider in self._modules and self._modules[provider].available:
            self._active_provider = provider
            return True
        return False
    
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        provider: Optional[AIProvider] = None,
        temperature: float = 0.7,
        max_tokens: int = 1000
    ) -> str:
        """
        Generate response using AI.
        
        Args:
            prompt: User prompt
            system_prompt: System prompt for context
            provider: Specific provider to use (or auto-select)
            temperature: Sampling temperature
            max_tokens: Max response tokens
            
        Returns:
            Generated text response
        """
        target_provider = provider or self._active_provider
        
        if not target_provider:
            raise RuntimeError("No AI provider available")
        
        if target_provider not in self._modules or not self._modules[target_provider].available:
            raise RuntimeError(f"Provider {target_provider.name} not available")
        
        status = self._modules[target_provider]
        
        # Route to appropriate generator
        generators = {
            AIProvider.GITHUB_COPILOT: self._generate_copilot,
            AIProvider.OLLAMA: self._generate_ollama,
            AIProvider.LM_STUDIO: self._generate_lm_studio,
            AIProvider.OPENAI: self._generate_openai,
            AIProvider.ANTHROPIC: self._generate_anthropic,
            AIProvider.GROQ: self._generate_groq,
        }
        
        generator = generators.get(target_provider)
        if not generator:
            raise RuntimeError(f"No generator for {target_provider.name}")
        
        return await generator(
            prompt=prompt,
            system_prompt=system_prompt,
            model=status.model,
            temperature=temperature,
            max_tokens=max_tokens
        )
    
    async def _generate_copilot(
        self, prompt: str, system_prompt: Optional[str], model: str,
        temperature: float, max_tokens: int
    ) -> str:
        """Generate using GitHub Copilot via gh CLI."""
        try:
            full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
            
            # Use gh copilot CLI
            result = await asyncio.create_subprocess_exec(
                "gh", "copilot", "suggest", "-t", "shell",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                result.communicate(input=full_prompt.encode()),
                timeout=self.config.request_timeout
            )
            
            if result.returncode == 0:
                return stdout.decode().strip()
            else:
                # Fallback: return structured analysis
                return self._generate_mock_analysis(prompt, "GitHub Copilot")
        except Exception as e:
            logger.warning(f"Copilot generation failed: {e}, using fallback")
            return self._generate_mock_analysis(prompt, "GitHub Copilot")
    
    async def _generate_ollama(
        self, prompt: str, system_prompt: Optional[str], model: str,
        temperature: float, max_tokens: int
    ) -> str:
        """Generate using Ollama."""
        import urllib.request
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        data = json.dumps({
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens
            }
        }).encode()
        
        req = urllib.request.Request(
            f"{self.config.ollama_endpoint}/api/chat",
            data=data,
            method="POST"
        )
        req.add_header("Content-Type", "application/json")
        
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: urllib.request.urlopen(req, timeout=self.config.request_timeout)
        )
        
        result = json.loads(response.read().decode())
        return result.get("message", {}).get("content", "")
    
    async def _generate_lm_studio(
        self, prompt: str, system_prompt: Optional[str], model: str,
        temperature: float, max_tokens: int
    ) -> str:
        """Generate using LM Studio (OpenAI-compatible API)."""
        import urllib.request
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        data = json.dumps({
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }).encode()
        
        req = urllib.request.Request(
            f"{self.config.lm_studio_endpoint}/v1/chat/completions",
            data=data,
            method="POST"
        )
        req.add_header("Content-Type", "application/json")
        
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: urllib.request.urlopen(req, timeout=self.config.request_timeout)
        )
        
        result = json.loads(response.read().decode())
        return result["choices"][0]["message"]["content"]
    
    async def _generate_openai(
        self, prompt: str, system_prompt: Optional[str], model: str,
        temperature: float, max_tokens: int
    ) -> str:
        """Generate using OpenAI API."""
        import urllib.request
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        data = json.dumps({
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }).encode()
        
        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=data,
            method="POST"
        )
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {os.environ['OPENAI_API_KEY']}")
        
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: urllib.request.urlopen(req, timeout=self.config.request_timeout)
        )
        
        result = json.loads(response.read().decode())
        return result["choices"][0]["message"]["content"]
    
    async def _generate_anthropic(
        self, prompt: str, system_prompt: Optional[str], model: str,
        temperature: float, max_tokens: int
    ) -> str:
        """Generate using Anthropic Claude API."""
        import urllib.request
        
        data = json.dumps({
            "model": model,
            "max_tokens": max_tokens,
            "system": system_prompt or "You are a security researcher.",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature
        }).encode()
        
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=data,
            method="POST"
        )
        req.add_header("Content-Type", "application/json")
        req.add_header("x-api-key", os.environ["ANTHROPIC_API_KEY"])
        req.add_header("anthropic-version", "2023-06-01")
        
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: urllib.request.urlopen(req, timeout=self.config.request_timeout)
        )
        
        result = json.loads(response.read().decode())
        return result["content"][0]["text"]
    
    async def _generate_groq(
        self, prompt: str, system_prompt: Optional[str], model: str,
        temperature: float, max_tokens: int
    ) -> str:
        """Generate using Groq API (OpenAI-compatible)."""
        import urllib.request
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        data = json.dumps({
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }).encode()
        
        req = urllib.request.Request(
            "https://api.groq.com/openai/v1/chat/completions",
            data=data,
            method="POST"
        )
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {os.environ['GROQ_API_KEY']}")
        
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: urllib.request.urlopen(req, timeout=self.config.request_timeout)
        )
        
        result = json.loads(response.read().decode())
        return result["choices"][0]["message"]["content"]
    
    def _generate_mock_analysis(self, prompt: str, provider_name: str) -> str:
        """Generate mock analysis when AI is not available."""
        # Extract target from prompt if possible
        import re
        target_match = re.search(r'https?://[^\s]+', prompt)
        target = target_match.group(0) if target_match else "target"
        
        return f"""Based on analysis of {target}:

1. **Authentication Vectors**: Check for NoSQL injection, JWT weaknesses, session fixation
2. **Injection Points**: SQL/NoSQL injection at login endpoints, command injection via file uploads
3. **Information Disclosure**: Error messages, debug endpoints, misconfigured CORS
4. **Server-Side Attacks**: SSTI if template engine detected, XXE for XML endpoints
5. **Deserialization**: If Java/PHP/.NET detected, check for unsafe deserialization

[Analysis by {provider_name} - Fallback Mode]"""
    
    def print_status(self):
        """Print formatted status of all AI modules."""
        print("\n    [AI Modules] Auto-Detection Results:")
        
        available_count = 0
        for provider, status in self._modules.items():
            symbol = "✓" if status.available else "✗"
            
            if status.available:
                available_count += 1
                detail = f"model={status.model}"
                if status.latency_ms > 0:
                    detail += f", latency={status.latency_ms:.0f}ms"
                print(f"        [{symbol}] {provider.name}: {detail}")
            else:
                print(f"        [{symbol}] {provider.name}: {status.error}")
        
        if self._active_provider:
            print(f"    [AI Active] Using: {self._active_provider.name}")
        else:
            print("    [AI Active] No provider available, using fallback patterns")
        
        return available_count


# Singleton instance
_manager: Optional[AIModuleManager] = None


def get_ai_manager() -> AIModuleManager:
    """Get or create the AI module manager singleton."""
    global _manager
    if _manager is None:
        _manager = AIModuleManager()
        _manager.detect_available_modules()
    return _manager
