import os
import yaml


class Config:
    def __init__(self, config_file_yaml):
        with open(config_file_yaml) as f:
            self.config = yaml.safe_load(f)

    def get(self, key: str, default=None):
        value = self.__get(key)
        if value is None and default is not None:
            return default
        return value
    
    def get_required(self, key: str):
        value = self.__get(key)
        if value is None:
            raise KeyError(f"Missing required configuration key: {key}")
        return value

    def __get(self, key: str):
        keys = key.lower().split(".")
        key_for_env = f"ENV_{key.replace('.', '__').upper()}"
        if key_for_env in os.environ:
            return os.environ[key_for_env]
        else:
            found = False
            value = self.config
            for k in keys:
                if isinstance(value, dict) and k in value:
                    found = True
                    value = value[k]
                else:
                    found = False
                    return None
            
            if found:
                return value
            else:
                return None
