# core/azure_secrets.py

import os
import logging
from typing import Dict
from dotenv import load_dotenv

from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from azure.core.exceptions import AzureError
from langchain_openai import AzureChatOpenAI, AzureOpenAIEmbeddings


# Logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

load_dotenv()

class ConfigError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


class AzureSecrets:
    
    # Key vault and Service priciples required env vars and secrets
    REQUIRED_ENV_VARS = [
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_VAULT_URL",
    ]

    # Secrets to retrieve from Key Vault

    REQUIRED_SECRETS = [
        "aoai-api-key",
        "aoai-endpoint",
    ]

    # Initialization and storin in Cahe
    def __init__(self) -> None:
        self._validate_env()

        self.credential = self._create_credential()
        self.kv_client = self._create_kv_client()

        self.secrets = self._load_secrets()

        os.environ["AZURE_OPENAI_API_KEY"] = self.secrets["aoai-api-key"]
        os.environ["AZURE_OPENAI_ENDPOINT"] = self.secrets["aoai-endpoint"]

        logger.info(" AzureSecrets initialized successfully")


    # Validation
    def _validate_env(self) -> None:
        missing = [v for v in self.REQUIRED_ENV_VARS if not os.getenv(v)]
        if missing:
            raise ConfigError(
                f"Missing required environment variables: {', '.join(missing)}"
            )

   
    # Azure Setup
    def _create_credential(self) -> ClientSecretCredential:
        try:
            return ClientSecretCredential(
                tenant_id=os.environ["AZURE_TENANT_ID"],
                client_id=os.environ["AZURE_CLIENT_ID"],
                client_secret=os.environ["AZURE_CLIENT_SECRET"],
            )
        except Exception as exc:
            raise ConfigError("Failed to create Azure credentials") from exc
 

    # Internal Helper Functions
    def _create_kv_client(self) -> SecretClient:
        try:
            return SecretClient(
                vault_url=os.environ["AZURE_VAULT_URL"],
                credential=self.credential
            )
        except Exception as exc:
            raise ConfigError("Failed to connect to Azure Key Vault") from exc

    
    # Secrets
    def _load_secrets(self) -> Dict[str, str]:
        secrets = {}

        for key in self.REQUIRED_SECRETS:
            try:
                secrets[key] = self.kv_client.get_secret(key).value
            except AzureError as exc:
                raise ConfigError(
                    f"Required secret '{key}' not found in Key Vault"
                ) from exc

        return secrets
    

    # get any secret by name
    def get_secret(self, name: str) -> str:
        """
        Public accessor for secrets.
        """
        if name not in self.secrets:
            raise ConfigError(f"Secret '{name}' not loaded or does not exist")
        return self.secrets[name]

    
    # OpenAI Helper
    
    def get_chat_llm(
        self,
        deployment_name: str,
        api_version: str,
        temperature: float = 0.3
    ) -> AzureChatOpenAI:
        return AzureChatOpenAI(
            azure_deployment=deployment_name,
            api_version=api_version,
            temperature=temperature
        )

    # Embeddings Helper
    def get_embeddings(
        self,
        api_version: str,
        model: str = "text-embedding-ada-002"
    ) -> AzureOpenAIEmbeddings:
        return AzureOpenAIEmbeddings(
            azure_endpoint=self.secrets["aoai-endpoint"],
            api_version=api_version,
            model=model
        )
