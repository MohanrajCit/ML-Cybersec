"""
Environment Setup Helper
========================
Loads environment variables from .env file for the CVE system.
"""

import os
from pathlib import Path


def load_env_file(env_path=None):
    """
    Load environment variables from .env file.
    
    Args:
        env_path (str, optional): Path to .env file. If None, looks in current directory first, then parent.
    
    Returns:
        dict: Dictionary of loaded environment variables
    """
    if env_path is None:
        current_dir = Path(__file__).parent
        # First check current directory (backend/.env)
        env_path = current_dir / ".env"
        # If not found, check parent directory
        if not env_path.exists():
            env_path = current_dir.parent / ".env"
    
    env_path = Path(env_path)
    
    if not env_path.exists():
        # Silently continue without .env - this is not an error
        return {}
    
    loaded_vars = {}
    
    try:
        with open(env_path, 'r', encoding='utf-8') as f:
            for line in f:
                # Skip comments and empty lines
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Parse KEY=VALUE
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # Remove quotes if present
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    elif value.startswith("'") and value.endswith("'"):
                        value = value[1:-1]
                    
                    # Set environment variable
                    os.environ[key] = value
                    loaded_vars[key] = value
        
        print(f"✅ Loaded {len(loaded_vars)} environment variable(s) from {env_path.name}")
        for key in loaded_vars:
            print(f"   - {key}")
        
        return loaded_vars
    
    except Exception as e:
        print(f"❌ Error loading .env file: {e}")
        return {}


def get_nvd_api_key():
    """
    Get NVD API key from environment.
    
    Returns:
        str or None: API key if found, None otherwise
    """
    api_key = os.getenv("NVD_API_KEY")
    
    if api_key:
        print(f"✅ NVD API Key found (length: {len(api_key)})")
    else:
        print("⚠️  NVD API Key not found in environment")
        print("   Set it in .env file or as environment variable")
    
    return api_key


def setup_environment():
    """
    Complete environment setup: Load .env and verify API key.
    
    Returns:
        dict: Environment configuration
    """
    print("\n🔧 Setting up environment...")
    print("-" * 60)
    
    # Load .env file
    env_vars = load_env_file()
    
    # Get API key
    api_key = get_nvd_api_key()
    
    print("-" * 60)
    
    return {
        "env_vars": env_vars,
        "nvd_api_key": api_key
    }


if __name__ == "__main__":
    """
    Test environment setup
    """
    print("\n" + "="*60)
    print("ENVIRONMENT SETUP TEST")
    print("="*60)
    
    config = setup_environment()
    
    if config["nvd_api_key"]:
        print("\n✅ Environment is properly configured!")
    else:
        print("\n⚠️  Warning: NVD API key not found")
        print("   The system will work but with API rate limits")
    
    print("\n" + "="*60 + "\n")
