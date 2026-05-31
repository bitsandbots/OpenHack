"""
Supabase security vulnerability detection prompts, organized by attack surface.
"""

from .rls import SUPABASE_RLS_PROMPT
from .postgrest import SUPABASE_POSTGREST_PROMPT
from .rpc_functions import SUPABASE_RPC_PROMPT
from .storage import SUPABASE_STORAGE_PROMPT
from .realtime import SUPABASE_REALTIME_PROMPT
from .graphql import SUPABASE_GRAPHQL_PROMPT
from .auth_tokens import SUPABASE_AUTH_PROMPT
from .edge_functions import SUPABASE_EDGE_FUNCTIONS_PROMPT
from .tenant_isolation import SUPABASE_TENANT_ISOLATION_PROMPT

# Assembled dictionary for code that looks up prompts by category key
SUPABASE_PROMPTS = {
    "supabase_rls": SUPABASE_RLS_PROMPT,
    "supabase_postgrest": SUPABASE_POSTGREST_PROMPT,
    "supabase_rpc": SUPABASE_RPC_PROMPT,
    "supabase_storage": SUPABASE_STORAGE_PROMPT,
    "supabase_realtime": SUPABASE_REALTIME_PROMPT,
    "supabase_graphql": SUPABASE_GRAPHQL_PROMPT,
    "supabase_auth": SUPABASE_AUTH_PROMPT,
    "supabase_edge_functions": SUPABASE_EDGE_FUNCTIONS_PROMPT,
    "supabase_tenant_isolation": SUPABASE_TENANT_ISOLATION_PROMPT,
}

__all__ = [
    "SUPABASE_PROMPTS",
    "SUPABASE_RLS_PROMPT",
    "SUPABASE_POSTGREST_PROMPT",
    "SUPABASE_RPC_PROMPT",
    "SUPABASE_STORAGE_PROMPT",
    "SUPABASE_REALTIME_PROMPT",
    "SUPABASE_GRAPHQL_PROMPT",
    "SUPABASE_AUTH_PROMPT",
    "SUPABASE_EDGE_FUNCTIONS_PROMPT",
    "SUPABASE_TENANT_ISOLATION_PROMPT",
]
