
import google.generativeai as genai
import os
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class ModelSelector:
    """
    Automatically detects and selects the best available Gemini models
    for different tasks (fast vs. intelligent).
    """
    
    _instance = None
    _models_cache = []
    
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(ModelSelector, cls).__new__(cls)
        return cls._instance

    def __init__(self, api_key: Optional[str] = None):
        # Always try to get the latest key if not provided
        raw_key = api_key or os.getenv('GEMINI_API_KEY')
        self.api_key = raw_key.strip() if raw_key else None
        
        if self.api_key:
            try:
                genai.configure(api_key=self.api_key)
                if not ModelSelector._models_cache:
                    self.refresh_models()
            except Exception as e:
                print(f"[WARN] Error configuring Gemini API: {e}")
        
        # Defaults if not detected yet
        self.fast_model = getattr(self, 'fast_model', 'gemini-2.5-flash')
        self.intelligent_model = getattr(self, 'intelligent_model', 'gemini-2.5-flash')

    def refresh_models(self):
        """Fetch available models from the API"""
        # Lazy load key if missing
        if not self.api_key:
            self.api_key = os.getenv('GEMINI_API_KEY')
            
        if not self.api_key:
            print("⚠️ Warning: No API key available for model discovery")
            return

        try:
            genai.configure(api_key=self.api_key)
            available = []
            models = list(genai.list_models())
            for m in models:
                if 'generateContent' in m.supported_generation_methods:
                    name = m.name.replace('models/', '')
                    available.append(name)
            
            ModelSelector._models_cache = available
            print(f"DEBUG: Available models: {available}")
            self._auto_select_best_models()
        except Exception as e:
            print(f"[WARN] Could not list Gemini models: {e}")
            # Fallback to defaults if listing fails
            if not ModelSelector._models_cache:
                ModelSelector._models_cache = ['gemini-2.5-flash']
            self._auto_select_best_models()

    def _auto_select_best_models(self):
        """Rank and select the best models for each role"""
        # User ENFORCED: Gemini 2.5 models only
        intelligent_candidates = [
            'gemini-2.5-flash',
            'gemini-2.5-pro'
        ]
        
        # Ranked preference for 'fast' role
        fast_candidates = [
            'gemini-2.5-flash'
        ]
        
        # Find best intelligent model
        self.intelligent_model = next((m for m in intelligent_candidates if m in ModelSelector._models_cache), None)
        if not self.intelligent_model:
            # Default to 2.5-flash if API list doesn't show it (trusting user config)
            self.intelligent_model = 'gemini-2.5-flash'
        
        # Find best fast model
        self.fast_model = next((m for m in fast_candidates if m in ModelSelector._models_cache), None)
        if not self.fast_model:
            self.fast_model = 'gemini-2.5-flash'
        
        print(f"[INFO] Gemini Model Selector: Intelligent={self.intelligent_model}, Fast={self.fast_model}")

    def get_model_for_role(self, role: str) -> str:
        """
        Get the best model name for a specific role ('fast' or 'intelligent')
        """
        if role == 'fast':
            return self.fast_model
        return self.intelligent_model

    def validate_model(self, model_name: str) -> str:
        """
        Check if a specific model exists, if not return the best intelligent model
        """
        name_only = model_name.replace('models/', '')
        if name_only in ModelSelector._models_cache:
            return model_name
        return self.intelligent_model

    def get_all_available_models(self) -> List[str]:
        return ModelSelector._models_cache

model_selector = ModelSelector()
