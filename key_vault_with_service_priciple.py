import os
import logging
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from azure.core.exceptions import AzureError
from langchain_openai import AzureChatOpenAI, AzureOpenAIEmbeddings
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


class AzureSecrets:
    def __init__(self):
        #  Explicit Service Principal authentication (FAST)
        self.credential = ClientSecretCredential(
            tenant_id=os.environ["AZURE_TENANT_ID"],
            client_id=os.environ["AZURE_CLIENT_ID"],
            client_secret=os.environ["AZURE_CLIENT_SECRET"],
        )

        self.kv_client = SecretClient(
            vault_url=os.environ["AZURE_VAULT_URL"],
            credential=self.credential
        )

        #  Fetch only required secrets ONCE
        self.secrets_cache = {}
        for key in ["aoai-api-key", "aoai-endpoint"]:
            try:
                self.secrets_cache[key] = self.kv_client.get_secret(key).value
            except AzureError as e:
                logger.error("Failed to fetch secret '%s': %s", key, e)
                raise RuntimeError(f"Secret '{key}' could not be retrieved") from e

        #  Inject for LangChain auto-detection
        os.environ["AZURE_OPENAI_API_KEY"] = self.secrets_cache["aoai-api-key"]
        os.environ["AZURE_OPENAI_ENDPOINT"] = self.secrets_cache["aoai-endpoint"]

    def get_secret(self, name: str) -> str:
        if name in self.secrets_cache:
            return self.secrets_cache[name]
        raise RuntimeError(f"Secret '{name}' not found")

    def get_chat_llm(
        self,
        deployment_name: str,
        api_version: str,
        temperature: float = 0.2
    ) -> AzureChatOpenAI:
        return AzureChatOpenAI(
            azure_deployment=deployment_name,
            api_version=api_version,
            temperature=temperature
        )

    def get_embeddings(
        self,
        api_version: str,
        model: str = "text-embedding-ada-002"
    ) -> AzureOpenAIEmbeddings:
        return AzureOpenAIEmbeddings(
            azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
            api_version=api_version,
            model=model
        )
