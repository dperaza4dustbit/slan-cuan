"""Pulp REST API constants."""

# Authentication types
AUTH_TYPE_TBR: str = "tbr"
AUTH_TYPE_CERT: str = "cert"
AUTH_TYPES: frozenset[str] = frozenset({AUTH_TYPE_TBR, AUTH_TYPE_CERT})

# HTTP client and error handling constants
DEFAULT_TIMEOUT_SECONDS: float = 300.0

# Task polling configuration
TASK_CANCEL_TIMEOUT_SECONDS: float = 15.0

# Content API URL path templates
CONTENT_API_PATH_TEMPLATE: str = (
    "/api/pulp/{domain}/api/v3/content/maven/artifact/upload/"
)
METADATA_API_PATH_TEMPLATE: str = (
    "/api/pulp/{domain}/api/v3/content/maven/metadata/upload/"
)
REPO_API_PATH_TEMPLATE: str = (
    "/api/pulp/{domain}/api/v3/repositories/maven/maven/"
)
MAVEN_DISTRIBUTION_API_PATH_TEMPLATE: str = (
    "/api/pulp/{domain}/api/v3/distributions/maven/maven/"
)

# Pulp File plugin API URL path templates
FILE_CONTENT_API_PATH_TEMPLATE: str = (
    "/api/pulp/{domain}/api/v3/content/file/files/"
)
FILE_REPO_API_PATH_TEMPLATE: str = (
    "/api/pulp/{domain}/api/v3/repositories/file/file/"
)
FILE_DISTRIBUTION_API_PATH_TEMPLATE: str = (
    "/api/pulp/{domain}/api/v3/distributions/file/file/"
)

# Pulp npm plugin API URL path templates
NPM_REPO_API_PATH_TEMPLATE: str = (
    "/api/pulp/{domain}/api/v3/repositories/npm/npm/"
)
NPM_CONTENT_API_PATH_TEMPLATE: str = (
    "/api/pulp/{domain}/api/v3/content/npm/packages/"
)
NPM_VERSIONS_API_PATH_TEMPLATE: str = "{repository_href}versions/"

# Task polling configuration
TASK_POLL_INITIAL_INTERVAL_SECONDS = 2.0
TASK_POLL_MAX_INTERVAL_SECONDS = 30.0
TASK_POLL_BACKOFF_FACTOR = 1.5
TASK_POLL_JITTER_FACTOR = 0.2
TASK_POLL_TIMEOUT_SECONDS = 2700.0
