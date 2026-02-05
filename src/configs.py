"""
This module is used to store the configurations.
"""

import re

# Keywords are not enabled by current version.
KEYWORDS = [
    # Core OpenAI Terms
    "openai",
    "openai api",
    "openai key",
    "openai apikey",
    "openai_api_key",
    "OPENAI_API_KEY",
    "sk-proj-",
    "sk-svcacct-",
    
    # GPT Model Terms
    "gpt",
    "gpt-3",
    "gpt-3.5",
    "gpt-4",
    "gpt4",
    "gpt4o",
    "gpt-4-turbo",
    "chatgpt",
    "chatgpt api",
    
    # Environment Variables (High Value)
    "api_key",
    "apikey",
    "api key",
    "API_KEY",
    "secret_key",
    "SECRET_KEY",
    "access_token",
    "bearer token",
    
    # Configuration Patterns
    ".env",
    "dotenv",
    "config",
    "configuration",
    "settings",
    "credentials",
    "secrets",
    
    # AI/ML Terms
    "llm",
    "large language model",
    "language model",
    "ai model",
    "machine learning",
    "deep learning",
    "neural network",
    "natural language processing",
    "nlp",
    
    # Framework/Library Terms
    "langchain",
    "llama",
    "llama.cpp",
    "autogpt",
    "agent",
    "multi-agent",
    "rag",
    "retrieval-augmented",
    "embedding",
    "embeddings",
    
    # Development Context
    "experiment",
    "project",
    "demo",
    "test",
    "testing",
    "dev",
    "development",
    "production",
    "prod",
    "staging",
    
    # Common Mistakes
    "hardcoded",
    "hardcode",
    "leaked",
    "exposed",
    "committed",
    
    # Research Terms
    "CoT",
    "chain of thought",
    "DPO",
    "RLHF",
    "reinforcement learning",
    "fine-tuning",
    "finetuning",
    
    # Competitor/Alternative Terms
    "azure openai",
    "anthropic",
    "claude",
    "palm",
    "gemini api",
    "huggingface",
    "replicate",
    
    # International Terms (Chinese)
    "密钥",
    "接口密钥",
    "语言模型",
    "人工智能",
    "测试",
    "实验",
    
    # International Terms (Spanish/Portuguese)
    "chave api",
    "clave api",
    
    # International Terms (Japanese/Korean)
    "APIキー",
    "API키",
]

LANGUAGES = [
    # High-Value Config Files
    "Dotenv",
    "YAML",
    "TOML",
    "INI",
    "JSON",
    "XML",
    
    # Plain Text & Docs
    "Text",
    "Markdown",
    "reStructuredText",
    
    # Web Languages
    "JavaScript",
    "TypeScript",
    "HTML",
    "Vue",
    
    # Backend Languages
    "Python",
    "Java",
    "Go",
    "Ruby",
    "PHP",
    "Rust",
    "C%23",  # C#
    "C%2B%2B",  # C++
    "Kotlin",
    "Swift",
    "Scala",
    
    # DevOps & Scripts
    "Shell",
    "Dockerfile",
    "Makefile",
    "Terraform",
    
    # Notebooks
    '"Jupyter Notebook"',
    "R",
]

PATHS = [
    "path:.xml OR path:.json OR path:.properties OR path:.sql OR path:.txt OR path:.log OR path:.tmp OR path:.backup OR path:.bak OR path:.enc",
    "path:.yml OR path:.yaml OR path:.toml OR path:.ini OR path:.config OR path:.conf OR path:.cfg OR path:.env OR path:.envrc OR path:.prod",
    "path:.secret OR path:.private OR path:*.key",
]

# regex, have_many_results (if true, using AND to filter out keywords), result_too_lang (if true, the result needs to be expanded)
REGEX_LIST = [
    # Named Project API Key (no matter normal or restricted) still valid until Dec 2, 2024
    (re.compile(r"sk-proj-[A-Za-z0-9-_]{74}T3BlbkFJ[A-Za-z0-9-_]{73}A"), True, True),

    # Service Account key (new format, valid until Oct 13, 2025)
    (re.compile(r"sk-svcacct-[A-Za-z0-9-_]{74}T3BlbkFJ[A-Za-z0-9-_]{73}A"), False, True),

    # Old Project API Key (as of Oct 13, 2025, not sure if still valid)
    (re.compile(r"sk-proj-[A-Za-z0-9-_]{58}T3BlbkFJ[A-Za-z0-9-_]{58}"), True, True),

    # Service Account Key (not valid since Oct 13, 2025)
    # (re.compile(r"sk-svcacct-[A-Za-z0-9-_]\+T3BlbkFJ[A-Za-z0-9-_]+"), False, False), # No search results on Oct 14, 2025

    (re.compile(r"sk-proj-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"), True, False),
    # (re.compile(r"sk-[a-zA-Z0-9]{48}"), True, False), # OpenAI deprecated these format, because the keys are only "sk-proj" "sk-svcacct-"
]
